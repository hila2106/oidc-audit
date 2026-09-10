#!/usr/bin/env python3
"""Unit tests for oidc_audit.analyze_trust_policy, focused on the GitHub
subject-claim checks (legacy mutable format vs. the newer immutable
owner-ID/repo-ID format).

Run with:  python3 -m unittest test_oidc_audit.py -v
"""

import unittest

from oidc_audit import analyze_trust_policy, PROVIDERS

GITHUB_HOST = PROVIDERS["github"]


def trust_doc_for(sub_values, operator="StringLike", extra_condition=None):
    """Build a minimal AWS trust policy document trusting GitHub Actions OIDC."""
    condition = {operator: {f"{GITHUB_HOST}:sub": sub_values}}
    if extra_condition:
        for op, kv in extra_condition.items():
            condition.setdefault(op, {}).update(kv)
    return {
        "Statement": [{
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {"Federated": f"arn:aws:iam::123456789012:oidc-provider/{GITHUB_HOST}"},
            "Condition": condition,
        }]
    }


def finding_ids(findings):
    return {f["id"] for f in findings}


class AnalyzeTrustPolicyTests(unittest.TestCase):

    def test_matches_only_the_requested_provider(self):
        matched, findings = analyze_trust_policy(trust_doc_for(["repo:acme/*"]), PROVIDERS["gitlab"])
        self.assertFalse(matched)
        self.assertEqual(findings, [])

    def test_missing_sub_and_no_owner_restriction_is_flagged(self):
        trust_doc = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Principal": {"Federated": f"arn:aws:iam::123456789012:oidc-provider/{GITHUB_HOST}"},
                "Condition": {},
            }]
        }
        matched, findings = analyze_trust_policy(trust_doc, GITHUB_HOST)
        self.assertTrue(matched)
        self.assertIn("missing_sub", finding_ids(findings))

    def test_org_wide_wildcard(self):
        _, findings = analyze_trust_policy(trust_doc_for(["repo:acme-org/*"]), GITHUB_HOST)
        self.assertIn("org_wide_wildcard", finding_ids(findings))

    def test_legacy_org_prefix_without_slash_is_still_critical(self):
        # No "/" and no "@" before the wildcard: matches any org name sharing
        # this prefix (e.g. "acme-org" also matches "acme-org-evil").
        _, findings = analyze_trust_policy(trust_doc_for(["repo:acme-org*"]), GITHUB_HOST)
        ids = finding_ids(findings)
        self.assertIn("org_prefix_no_slash", ids)
        self.assertNotIn("immutable_id_wildcarded", ids)

    def test_immutable_owner_id_wildcarded_is_not_misclassified_as_org_prefix(self):
        # Regression test: "repo:org@*" pins the org name and delimits it
        # with "@" (immutable-format separator), but wildcards the numeric
        # owner ID. This used to be misreported as org_prefix_no_slash
        # ("matches any org starting with that prefix"), which isn't what
        # this subject actually does.
        _, findings = analyze_trust_policy(trust_doc_for(["repo:acme-org@*"]), GITHUB_HOST)
        ids = finding_ids(findings)
        self.assertIn("immutable_id_wildcarded", ids)
        self.assertNotIn("org_prefix_no_slash", ids)

    def test_fully_pinned_immutable_subject_has_no_wildcard_finding(self):
        sub = "repo:acme-org@123456/myrepo@789:ref:refs/heads/main"
        _, findings = analyze_trust_policy(trust_doc_for([sub]), GITHUB_HOST)
        wildcard_ids = {"org_wide_wildcard", "org_prefix_no_slash", "immutable_id_wildcarded", "subject_wildcard", "any_ref_wildcard"}
        self.assertEqual(finding_ids(findings) & wildcard_ids, set())

    def test_wildcarded_repo_id_is_only_caught_by_the_generic_catch_all(self):
        # Known gap: immutable_id_wildcarded only inspects the org segment
        # (before the first "/"). A wildcard on the repo ID instead of the
        # owner ID isn't given its own diagnosis yet — it still gets flagged,
        # but via the generic subject_wildcard catch-all rather than a
        # message that names the immutable-ID protection being defeated.
        sub = "repo:acme-org@123456/myrepo@*"
        _, findings = analyze_trust_policy(trust_doc_for([sub]), GITHUB_HOST)
        ids = finding_ids(findings)
        self.assertNotIn("immutable_id_wildcarded", ids)
        self.assertIn("subject_wildcard", ids)

    def test_missing_aud_condition(self):
        _, findings = analyze_trust_policy(trust_doc_for(["repo:acme-org@123456/myrepo@789:ref:refs/heads/main"]), GITHUB_HOST)
        self.assertIn("missing_aud", finding_ids(findings))

    def test_set_operator_on_allow_is_flagged(self):
        _, findings = analyze_trust_policy(
            trust_doc_for(["repo:acme-org@123456/myrepo@789:ref:refs/heads/main"], operator="ForAnyValue:StringLike"),
            GITHUB_HOST,
        )
        self.assertIn("set_operator_allow", finding_ids(findings))


if __name__ == "__main__":
    unittest.main()
