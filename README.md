# oidc-audit

Find misconfigured GitHub Actions OIDC trust policies in AWS and GCP.

OIDC federation replaced long-lived keys with short-lived tokens — but the
trust policies that accept those tokens are misconfigured more often than not.
This tool checks each OIDC role's trust policy (AWS) or provider condition (GCP)
for common misconfigurations.

## Read-only

It only ever calls read APIs. It makes no changes. Run it against prod.

**AWS** — IAM `List*` / `Get*`:
```
iam:ListRoles
```

**GCP** — Workload Identity Federation read:
```
iam.workloadIdentityPools.list
iam.workloadIdentityPoolProviders.list
```

## Install

```bash
pip install -r requirements.txt
```

For AWS-only, `boto3` is sufficient. For GCP, `google-auth` is required.

## Use

```bash
# AWS: audit GitHub OIDC roles in the default profile
python oidc_audit.py

# AWS: specific profile, all supported providers
python oidc_audit.py --profile prod --provider all

# AWS: check if org names in trust policies are claimable on GitHub
python oidc_audit.py --check-claimable

# GCP: audit a specific project
python oidc_audit.py --cloud gcp --project my-project-id

# GCP: with claimable check
python oidc_audit.py --cloud gcp --project my-project-id --check-claimable

# Machine-readable output
python oidc_audit.py --json > oidc-roles.json
```

## What it flags

### AWS

| Finding | Severity | Meaning |
|---|---|---|
| `missing_sub` | critical | No `sub` condition. Any workflow on that provider can assume the role. |
| `org_wide_wildcard` | critical | Subject like `repo:org/*`. Every repo in the org is trusted. |
| `claimable_owner` | critical | The org/user name doesn't exist on GitHub — anyone can register it. |
| `org_prefix_no_slash` | critical | Subject like `repo:org-name*` (no `/` before `*`). Matches any org starting with that prefix. |
| `subject_wildcard` | high | Subject like `repo:org/repo:*`. Any branch, any event, fork PRs included. |
| `any_ref_wildcard` | high | Subject like `repo:org/repo:ref:refs/heads/*`. Any branch accepted. |
| `set_operator_allow` | high | `ForAllValues:`/`ForAnyValue:` under Allow. Accepts a token with the claim missing entirely. |
| `missing_aud` | medium | No `aud` condition. |
| `no_owner_id` | low | Keys on the mutable org/repo name, not `repository_owner_id`. |

### GCP

| Finding | Severity | Meaning |
|---|---|---|
| `no_condition` | critical | No attribute condition. Any GitHub workflow can federate. |
| `no_repo_condition` | critical | Condition doesn't restrict by repository or owner. |
| `claimable_owner` | critical | The account name in the condition doesn't exist on GitHub. |
| `no_branch_env` | high | No branch or environment restriction. Any branch qualifies. |
| `name_based_owner` | low | Uses `repository_owner` (name) not `repository_owner_id` (numeric). |

## Claimable owner check

With `--check-claimable`, the tool calls the GitHub API to verify whether
org/user names referenced in trust policies actually exist. If a name returns
404, it means anyone can register it and assume the role.

This makes unauthenticated API calls to `api.github.com`. Rate limits apply
(60/hour without a token). For accounts with many roles, you may hit the limit.

## Caveats

- AWS detection looks at `Allow` statements. It does not evaluate explicit
  `Deny`, SCPs, or permissions boundaries.
- GCP detection checks provider attribute conditions only, not IAM bindings.
- The `--check-claimable` flag makes network calls to GitHub. Without authentication,
  it's limited to 60 requests per hour.
