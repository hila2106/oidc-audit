#!/usr/bin/env python3
"""
oidc-audit: find misconfigured GitHub/GitLab/Terraform Cloud OIDC trust policies in AWS and GCP.

Checks trust policy conditions and provider attribute conditions for common
misconfigurations: wildcards, missing sub, missing branch pins, claimable org
names, org-prefix-without-slash patterns, and no-condition providers.

Read-only. AWS: IAM List*/Get* APIs only. GCP: get/list calls only.
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error


PROVIDERS = {
    "github": "token.actions.githubusercontent.com",
    "gitlab": "gitlab.com",
    "terraform": "app.terraform.io",
}

# --- small helpers ----------------------------------------------------------

def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def provider_host_from_principal(statement):
    principal = statement.get("Principal", {})
    federated = as_list(principal.get("Federated"))
    for arn in federated:
        if "oidc-provider/" in arn:
            return arn.split("oidc-provider/", 1)[1]
    return None


def extract_org_names(sub_values, conditions=None):
    """Pull org/user names from sub conditions for claimable checking."""
    names = set()
    for sv in sub_values:
        m = re.match(r"repo:([^/]+)/", sv)
        if m:
            names.add(m.group(1))
    return names


def check_github_claimable(name):
    """Check if a GitHub org/user name is available (claimable)."""
    for kind in ["orgs", "users"]:
        try:
            req = urllib.request.Request(
                f"https://api.github.com/{kind}/{name}",
                headers={"User-Agent": "oidc-audit", "Accept": "application/vnd.github+json"},
            )
            urllib.request.urlopen(req, timeout=5)
            return False  # exists
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            return False  # rate-limited or error → assume exists
        except Exception:
            return False
    return True  # 404 on both → claimable


# --- link 1: the trust policy gate (AWS) ------------------------------------

def analyze_trust_policy(trust_doc, want_host, check_claimable=False):
    findings = []
    matched = False

    for stmt in as_list(trust_doc.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        actions = [a.lower() for a in as_list(stmt.get("Action"))]
        if "sts:assumerolewithwebidentity" not in actions:
            continue

        host = provider_host_from_principal(stmt)
        if host != want_host:
            continue
        matched = True

        sub_key = f"{host}:sub"
        aud_key = f"{host}:aud"
        owner_id_key = f"{host}:repository_owner_id"

        conditions = stmt.get("Condition", {}) or {}

        sub_values = []
        all_keys = set()
        uses_set_operator = False
        for operator, kv in conditions.items():
            if operator.startswith(("ForAllValues:", "ForAnyValue:")):
                uses_set_operator = True
            for key, val in (kv or {}).items():
                all_keys.add(key)
                if key == sub_key:
                    sub_values.extend(as_list(val))

        if not any(k == sub_key for k in all_keys):
            findings.append({
                "id": "missing_sub",
                "severity": "critical",
                "detail": "No sub condition. Any workflow on this provider can assume the role.",
            })
        else:
            for sv in sub_values:
                if re.match(r"^repo:[^/]+/\*$", sv):
                    findings.append({
                        "id": "org_wide_wildcard",
                        "severity": "critical",
                        "detail": f"Subject '{sv}' trusts every repo in the org.",
                    })
                elif re.match(r"^repo:[^/\*]+\*", sv) and "/" not in sv.split("repo:", 1)[1].split("*", 1)[0]:
                    findings.append({
                        "id": "org_prefix_no_slash",
                        "severity": "critical",
                        "detail": f"Subject '{sv}' has no slash before the wildcard — matches any org starting with that prefix.",
                    })
                elif sv.endswith(":*"):
                    findings.append({
                        "id": "subject_wildcard",
                        "severity": "high",
                        "detail": f"Subject '{sv}' matches any branch, event, and fork PR.",
                    })
                elif ":ref:refs/heads/*" in sv or ":ref:refs/tags/*" in sv:
                    findings.append({
                        "id": "any_ref_wildcard",
                        "severity": "high",
                        "detail": f"Subject '{sv}' matches any branch/tag via refs/* wildcard.",
                    })
                elif sv.count("*") and ":environment:" not in sv and ":pull_request" not in sv:
                    findings.append({
                        "id": "subject_wildcard",
                        "severity": "high",
                        "detail": f"Subject '{sv}' contains a wildcard in a permissive position.",
                    })

            if check_claimable and want_host == PROVIDERS["github"]:
                for name in extract_org_names(sub_values):
                    if check_github_claimable(name):
                        findings.append({
                            "id": "claimable_owner",
                            "severity": "critical",
                            "detail": f"Account '{name}' does not exist on GitHub and can be registered by anyone.",
                        })

        if uses_set_operator:
            findings.append({
                "id": "set_operator_allow",
                "severity": "high",
                "detail": "ForAllValues:/ForAnyValue: in an Allow. Accepts a token with the claim missing.",
            })

        if not any(k == aud_key for k in all_keys):
            findings.append({
                "id": "missing_aud",
                "severity": "medium",
                "detail": "No aud condition.",
            })

        if want_host == PROVIDERS["github"] and owner_id_key not in all_keys:
            findings.append({
                "id": "no_owner_id",
                "severity": "low",
                "detail": "Conditions key on the org/repo name, not repository_owner_id.",
            })

    return matched, findings


# --- GCP support ------------------------------------------------------------

def _gcp_import():
    try:
        from google.cloud import iam_admin_v1
        from google.cloud import resourcemanager_v3
        import google.auth
        return iam_admin_v1, resourcemanager_v3, google.auth
    except ImportError:
        return None, None, None


def _gcp_rest_get(url, credentials):
    """Make an authenticated GET request to GCP REST API."""
    import google.auth.transport.requests
    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {credentials.token}",
        "Accept": "application/json",
    })
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"GCP API {e.code}: {body}")


def analyze_gcp_condition(cond_text, check_claimable=False):
    """Analyze a GCP provider attribute condition (CEL expression)."""
    findings = []
    if not cond_text or cond_text.strip().lower() in ("true", ""):
        findings.append({
            "id": "no_condition",
            "severity": "critical",
            "detail": "No attribute condition. Any GitHub workflow can federate into this pool.",
        })
        return findings

    c = cond_text.lower()

    has_repo_owner = "repository_owner" in c
    has_repo = "repository" in c and "repository_owner" not in c
    has_branch = ("refs/heads/" in c or "refs/tags/" in c)
    has_env = "environment" in c
    has_owner_id = "repository_owner_id" in c

    if not has_repo_owner and not has_repo:
        findings.append({
            "id": "no_repo_condition",
            "severity": "critical",
            "detail": "Condition doesn't restrict by repository or owner. Any GitHub workflow qualifies.",
        })

    if not has_branch and not has_env:
        findings.append({
            "id": "no_branch_env",
            "severity": "high",
            "detail": "No branch or environment restriction. Any branch in the accepted repos can federate.",
        })

    if has_repo_owner and not has_owner_id:
        findings.append({
            "id": "name_based_owner",
            "severity": "low",
            "detail": "Uses repository_owner (name) not repository_owner_id (numeric). Vulnerable to namespace recycling.",
        })

    if check_claimable:
        for m in re.finditer(r"""repository_owner\s*==\s*["']([^"']+)["']""", cond_text):
            name = m.group(1)
            if check_github_claimable(name):
                findings.append({
                    "id": "claimable_owner",
                    "severity": "critical",
                    "detail": f"Account '{name}' does not exist on GitHub and can be registered by anyone.",
                })

    return findings


def audit_gcp(project_id, check_claimable=False, verbose=False):
    """Audit GCP Workload Identity Federation pools in a project."""
    import google.auth
    import google.auth.transport.requests

    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )

    base = f"https://iam.googleapis.com/v1/projects/{project_id}/locations/global"
    results = []

    if verbose:
        print(f"Listing workload identity pools in {project_id}...", file=sys.stderr)

    pools_resp = _gcp_rest_get(f"{base}/workloadIdentityPools", credentials)
    pools = pools_resp.get("workloadIdentityPools", [])

    if not pools:
        print(f"No workload identity pools found in {project_id}.", file=sys.stderr)
        return results

    for pool in pools:
        pool_name = pool["name"]
        pool_short = pool_name.split("/")[-1]
        state = pool.get("state", "ACTIVE")
        if state != "ACTIVE":
            continue

        if verbose:
            print(f"  Pool: {pool_short}", file=sys.stderr)

        providers_resp = _gcp_rest_get(f"https://iam.googleapis.com/v1/{pool_name}/providers", credentials)
        providers = providers_resp.get("workloadIdentityPoolProviders", [])

        for prov in providers:
            prov_name = prov["name"]
            prov_short = prov_name.split("/")[-1]
            issuer = prov.get("oidc", {}).get("issuerUri", "") or prov.get("saml", {}).get("idpMetadataXml", "")

            if "github" not in issuer.lower() and "githubusercontent" not in issuer.lower():
                continue

            cond = prov.get("attributeCondition", "")
            cond_findings = analyze_gcp_condition(cond, check_claimable=check_claimable)

            if verbose:
                print(f"    Provider: {prov_short} (GitHub)", file=sys.stderr)

            results.append({
                "pool": pool_short,
                "provider": prov_short,
                "issuer": issuer,
                "condition": cond,
                "findings": cond_findings,
                "score": score_findings(cond_findings),
                "errors": [],
                "cloud": "gcp",
            })

    return results


# --- scoring ----------------------------------------------------------------

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def score_findings(findings):
    if not findings:
        return {"severity": 0, "label": "clean"}
    severity = max(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    label = next(k for k, v in SEVERITY_WEIGHT.items() if v == severity)
    return {"severity": severity, "label": label}


# --- output -----------------------------------------------------------------

COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
    "reset": "\033[0m",
}


def colorize(text, label, use_color):
    if not use_color:
        return text
    return f"{COLOR.get(label, '')}{text}{COLOR['reset']}"


def print_report(results, use_color):
    if not results:
        print("No OIDC-connected roles/providers found. Nothing to report.")
        return

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "clean": 4}
    results.sort(key=lambda r: (order.get(r["score"]["label"], 5), -r["score"]["severity"]))

    counts = {}
    for r in results:
        counts[r["score"]["label"]] = counts.get(r["score"]["label"], 0) + 1
    summary = "  ".join(
        colorize(f"{lbl}: {counts[lbl]}", lbl, use_color)
        for lbl in ["critical", "high", "medium", "low", "clean"] if lbl in counts
    )
    print(f"\n{len(results)} OIDC role(s)   {summary}\n")

    for r in results:
        label = r["score"]["label"]
        cloud = r.get("cloud", "aws")

        if cloud == "gcp":
            header = f"[{label.upper()}] {r['pool']}/{r['provider']}"
        else:
            header = f"[{label.upper()}] {r['role']}  ({r['provider']})"

        print(colorize(header, label, use_color))

        if r["findings"]:
            for f in r["findings"]:
                print(f"  - ({f['severity']}) {f['detail']}")
        else:
            print("  - clean")

        if r.get("errors"):
            for e in r["errors"]:
                print(f"  ! {e}")
        print()


# --- main -------------------------------------------------------------------

def audit_aws(args, hosts, host_to_name):
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    iam = session.client("iam")

    results = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                trust_doc = role.get("AssumeRolePolicyDocument", {})
                for host in hosts:
                    matched, findings = analyze_trust_policy(
                        trust_doc, host, check_claimable=args.check_claimable
                    )
                    if not matched:
                        continue
                    results.append({
                        "role": role["RoleName"],
                        "arn": role["Arn"],
                        "provider": host_to_name.get(host, host),
                        "findings": findings,
                        "score": score_findings(findings),
                        "errors": [],
                        "cloud": "aws",
                    })
    except NoCredentialsError:
        sys.exit("No AWS credentials found. Configure a profile or environment credentials.")
    except (ClientError, BotoCoreError) as e:
        sys.exit(f"AWS error while listing roles: {e}")

    return results


def main():
    ap = argparse.ArgumentParser(
        description="Find misconfigured OIDC trust policies in AWS and GCP.",
    )
    ap.add_argument("--cloud", choices=["aws", "gcp"], default="aws",
                    help="Which cloud to audit (default: aws)")
    ap.add_argument("--profile", help="AWS profile name (AWS only)")
    ap.add_argument("--region", help="AWS region (AWS only)")
    ap.add_argument("--project", help="GCP project ID (GCP only)")
    ap.add_argument("--provider", choices=list(PROVIDERS) + ["all"], default="github",
                    help="Which OIDC provider to audit (default: github)")
    ap.add_argument("--check-claimable", action="store_true",
                    help="Check GitHub for claimable org/user names (makes API calls to github.com)")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a report")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    ap.add_argument("--verbose", action="store_true", help="Print progress to stderr")
    args = ap.parse_args()

    if args.cloud == "gcp":
        if not args.project:
            sys.exit("--project is required for GCP mode")
        try:
            import google.auth
        except ImportError:
            sys.exit("google-auth is required for GCP mode. Install with:  pip install google-auth")
        results = audit_gcp(args.project, check_claimable=args.check_claimable, verbose=args.verbose)
    else:
        try:
            import boto3
        except ImportError:
            sys.exit("boto3 is required for AWS mode. Install with:  pip install boto3")
        hosts = list(PROVIDERS.values()) if args.provider == "all" else [PROVIDERS[args.provider]]
        host_to_name = {v: k for k, v in PROVIDERS.items()}
        results = audit_aws(args, hosts, host_to_name)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print_report(results, use_color=not args.no_color and sys.stdout.isatty())


if __name__ == "__main__":
    main()
