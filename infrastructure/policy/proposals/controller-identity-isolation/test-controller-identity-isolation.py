#!/usr/bin/env python3
"""Offline historical-document/delta checks, NOT an IAM authorization evaluator.

Action matching below only checks membership of finite named regression cases in
this draft's NotAction list. It does not evaluate requests, principals, resources,
conditions, trust, other policies, AWS API support or effective authorization.
"""

import argparse
from copy import deepcopy
from fnmatch import fnmatchcase
from hashlib import sha256
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
ROLES = ("plan", "apply")
BASELINE_DIGESTS = {
    "plan": "30745294419fe300f96f810d8b272defd31578c6d613ea2bf2478fe3417cf3a6",
    "apply": "bfaef172af786b2c3bd9387c70e3f808022630908d2a67048cca41cb0bea5ee5",
}
SIZES = {
    "plan-before.json": 3393, "plan-after.json": 3393,
    "plan-boundary.json": 4223, "apply-before.json": 3936,
    "apply-after.json": 3485, "apply-boundary.json": 4641,
}
IDENTITY_READS = {"iam:List*", "iam:Get*", "rolesanywhere:List*", "rolesanywhere:Get*"}
REMOVED = {
    "iam:UpdateAssumeRolePolicy", "iam:TagUser", "iam:TagRole", "iam:TagPolicy",
    "iam:SetDefaultPolicyVersion", "iam:PutUserPolicy", "iam:DeletePolicyVersion",
    "iam:CreateUser", "iam:CreateRole", "iam:CreatePolicyVersion", "iam:CreatePolicy",
    "iam:AttachRolePolicy", "rolesanywhere:Update*", "rolesanywhere:UntagResource",
    "rolesanywhere:TagResource", "rolesanywhere:Put*", "rolesanywhere:Enable*",
    "rolesanywhere:Disable*", "rolesanywhere:Delete*", "rolesanywhere:Create*",
}
# Target labels document case intent; Resource '*' and no Condition are checked
# independently. These are not request fixtures or invented live resource ARNs.
FORBIDDEN = {
    "oidc": ("shared GitHub ARN and any other issuer", [
        "iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider",
        "iam:UpdateOpenIDConnectProviderThumbprint", "iam:AddClientIDToOpenIDConnectProvider",
        "iam:RemoveClientIDFromOpenIDConnectProvider", "iam:TagOpenIDConnectProvider",
        "iam:UntagOpenIDConnectProvider"]),
    "self_policy_and_trust": ("both controller roles and attached policies", [
        "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
        "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:DeletePolicyVersion", "iam:DeletePolicy", "iam:UpdateAssumeRolePolicy",
        "iam:TagPolicy", "iam:UntagPolicy", "iam:TagRole", "iam:UntagRole"]),
    "outside_principals": ("outside users/roles and recovery user", [
        "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateRoleDescription",
        "iam:CreateUser", "iam:DeleteUser", "iam:UpdateUser", "iam:PutUserPolicy",
        "iam:DeleteUserPolicy", "iam:AttachUserPolicy", "iam:DetachUserPolicy",
        "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
        "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:TagUser", "iam:UntagUser",
        "iam:AddUserToGroup", "iam:PutGroupPolicy", "iam:AttachGroupPolicy",
        "iam:CreateServiceLinkedRole", "iam:CreateInstanceProfile", "iam:AddRoleToInstanceProfile"]),
    "boundary": ("both controllers, outside principals and both ceiling policies", [
        "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
        "iam:PutUserPermissionsBoundary", "iam:DeleteUserPermissionsBoundary",
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicyVersion",
        "iam:DeletePolicy"]),
    "passing_and_assumption": ("any role, including privileged execution/owner role", [
        "iam:PassRole", "sts:AssumeRole", "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity", "sts:TagSession", "sts:SetSourceIdentity",
        "sts:GetFederationToken", "sts:GetSessionToken"]),
    "roles_anywhere": ("existing and alternate profiles/roles/anchors/CRLs", [
        "rolesanywhere:CreateProfile", "rolesanywhere:UpdateProfile", "rolesanywhere:DeleteProfile",
        "rolesanywhere:EnableProfile", "rolesanywhere:DisableProfile", "rolesanywhere:CreateTrustAnchor",
        "rolesanywhere:UpdateTrustAnchor", "rolesanywhere:DeleteTrustAnchor",
        "rolesanywhere:EnableTrustAnchor", "rolesanywhere:DisableTrustAnchor",
        "rolesanywhere:PutAttributeMapping", "rolesanywhere:DeleteAttributeMapping",
        "rolesanywhere:PutNotificationSettings", "rolesanywhere:ResetNotificationSettings",
        "rolesanywhere:ImportCrl", "rolesanywhere:UpdateCrl", "rolesanywhere:DeleteCrl",
        "rolesanywhere:EnableCrl", "rolesanywhere:DisableCrl",
        "rolesanywhere:TagResource", "rolesanywhere:UntagResource", "rolesanywhere:CreateSession"]),
    "owning_stack": ("diloreto-amplify-hosting and any other CloudFormation stack", [
        "cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:DeleteStack",
        "cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet",
        "cloudformation:SetStackPolicy", "cloudformation:UpdateTerminationProtection",
        "cloudformation:ContinueUpdateRollback", "cloudformation:RollbackStack",
        "cloudformation:DescribeStacks", "cloudformation:GetTemplate"]),
}


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(name):
    return json.loads((ROOT / name).read_text(), object_pairs_hook=reject_duplicates)


def actions(statement):
    value = statement["Action"]
    return [value] if isinstance(value, str) else value


def expected_after(before, role):
    result = deepcopy(before)
    if role == "apply":
        result["Statement"][7]["Action"] = ["iam:List*", "iam:Get*"]
        result["Statement"][8]["Action"] = ["rolesanywhere:List*", "rolesanywhere:Get*"]
    return result


def expected_exceptions(before, role):
    return sorted({a for s in expected_after(before, role)["Statement"] for a in actions(s)})


class ControllerIdentityIsolationTests(unittest.TestCase):
    def setUp(self):
        self.before = {r: load(f"{r}-before.json") for r in ROLES}
        self.after = {r: load(f"{r}-after.json") for r in ROLES}
        self.boundary = {r: load(f"{r}-boundary.json") for r in ROLES}

    def test_historical_document_pins(self):
        for role in ROLES:
            with self.subTest(role=role):
                canonical = json.dumps(self.before[role], sort_keys=True, separators=(",", ":"))
                self.assertEqual(sha256(canonical.encode()).hexdigest(), BASELINE_DIGESTS[role])

    def test_exact_identity_delta(self):
        for role in ROLES:
            with self.subTest(role=role):
                self.assertEqual(self.after[role], expected_after(self.before[role], role))
                old = {a for s in self.before[role]["Statement"] for a in actions(s)}
                new = {a for s in self.after[role]["Statement"] for a in actions(s)}
                self.assertEqual(old - new, REMOVED if role == "apply" else set())
                self.assertEqual(new - old, set())
        self.assertEqual((ROOT / "plan-before.json").read_bytes(), (ROOT / "plan-after.json").read_bytes())

    def test_non_identity_statements_preserved(self):
        for role in ROLES:
            with self.subTest(role=role):
                self.assertEqual(self.after[role]["Statement"][:7], self.before[role]["Statement"][:7])

    def test_boundary_exact_allow_coverage(self):
        for role in ROLES:
            with self.subTest(role=role):
                self.assertEqual(set(self.boundary[role]), {"Version", "Statement"})
                self.assertEqual(self.boundary[role]["Version"], "2012-10-17")
                self.assertEqual(self.boundary[role]["Statement"][:-1], expected_after(self.before[role], role)["Statement"])

    def test_explicit_ceiling_structure(self):
        for role in ROLES:
            with self.subTest(role=role):
                self.assertEqual(self.boundary[role]["Statement"][-1], {
                    "Sid": "DenyActionsOutsideRetainedBaseline", "Effect": "Deny",
                    "NotAction": expected_exceptions(self.before[role], role), "Resource": "*",
                })

    def test_identity_metadata_only(self):
        for role in ROLES:
            with self.subTest(role=role):
                actual = {a for s in self.after[role]["Statement"] for a in actions(s)
                          if a.startswith(("iam:", "rolesanywhere:"))}
                self.assertEqual(actual, IDENTITY_READS)
                exceptions = self.boundary[role]["Statement"][-1]["NotAction"]
                self.assertEqual({a for a in exceptions if "*" in a or "?" in a}, IDENTITY_READS)

    def test_exact_managed_policy_sizes(self):
        for name, expected in SIZES.items():
            with self.subTest(document=name):
                text = (ROOT / name).read_text()
                # Drafts are ASCII and contain no whitespace within JSON strings;
                # compact serialization must have exactly the same quota count.
                count = len("".join(text.split()))
                self.assertTrue(text.isascii())
                self.assertEqual(count, len(json.dumps(load(name), separators=(",", ":"))))
                self.assertEqual(count, expected)
                self.assertLessEqual(count, 6144)

    def test_manifest_hashes_and_sizes(self):
        manifest = load("provenance.json")
        self.assertEqual(set(manifest["documents"]), set(SIZES))
        for name, expected in SIZES.items():
            with self.subTest(document=name):
                self.assertEqual(manifest["documents"][name], {
                    "sha256": sha256((ROOT / name).read_bytes()).hexdigest(),
                    "non_whitespace_characters": expected,
                })
        for role, version in [("plan", "v11"), ("apply", "v13")]:
            self.assertEqual(manifest["sources"][role]["version"], version)
            self.assertEqual(manifest["sources"][role]["document_canonical_sha256"], BASELINE_DIGESTS[role])

    def test_state_lock_contract(self):
        for role in ROLES:
            with self.subTest(role=role):
                statements = self.after[role]["Statement"]
                self.assertEqual(len(statements[0]["Condition"]["StringLike"]["s3:prefix"]), 10)
                self.assertEqual(len(statements[1]["Resource"]), 10)
                self.assertEqual(len(statements[2]["Resource"]), 5)
                self.assertTrue(all(r.endswith(".tflock") for r in statements[2]["Resource"]))
                self.assertEqual(set(actions(statements[1])), {"s3:GetObject"} if role == "plan" else {"s3:GetObject", "s3:PutObject"})
                self.assertEqual(set(actions(statements[2])), {"s3:PutObject", "s3:DeleteObject"} if role == "plan" else {"s3:DeleteObject"})

    def test_crypto_asymmetry(self):
        plan = self.after["plan"]["Statement"][3]
        apply = self.after["apply"]["Statement"][3]
        self.assertEqual(set(plan["Action"]), {"kms:GenerateDataKey", "kms:Encrypt", "kms:DescribeKey", "kms:Decrypt"})
        self.assertEqual(plan["Action"], apply["Action"])
        self.assertEqual(len(plan["Resource"]), 2)
        self.assertIsInstance(apply["Resource"], str)
        self.assertIn(apply["Resource"], plan["Resource"])

    def test_retained_administration_is_not_hidden(self):
        statements = self.after["apply"]["Statement"]
        self.assertIn("s3:PutBucketPolicy", actions(statements[4]))
        self.assertNotIn("Condition", statements[4])
        self.assertIn("kms:PutKeyPolicy", actions(statements[6]))
        self.assertEqual(statements[6]["Resource"], "*")
        for role in ROLES:
            self.assertIn("s3:ListBucket", actions(self.after[role]["Statement"][4]))
            self.assertNotIn("Condition", self.after[role]["Statement"][4])

    def check_forbidden_cases(self, category):
        target, cases = FORBIDDEN[category]
        for role in ROLES:
            ceiling = self.boundary[role]["Statement"][-1]
            self.assertEqual(ceiling["Effect"], "Deny")
            self.assertEqual(ceiling["Resource"], "*")
            self.assertNotIn("Condition", ceiling)
            self.assertNotIn("NotResource", ceiling)
            for action in cases:
                with self.subTest(role=role, category=category, target=target, action=action):
                    self.assertFalse(any(fnmatchcase(action.lower(), pattern.lower()) for pattern in ceiling["NotAction"]),
                                     f"forbidden case entered exception list: {action}")

    def test_forbidden_oidc_cases(self):
        self.check_forbidden_cases("oidc")

    def test_forbidden_self_policy_and_trust_cases(self):
        self.check_forbidden_cases("self_policy_and_trust")

    def test_forbidden_outside_principal_cases(self):
        self.check_forbidden_cases("outside_principals")

    def test_forbidden_boundary_cases(self):
        self.check_forbidden_cases("boundary")

    def test_forbidden_passing_and_assumption_cases(self):
        self.check_forbidden_cases("passing_and_assumption")

    def test_forbidden_alternate_roles_anywhere_cases(self):
        self.check_forbidden_cases("roles_anywhere")

    def test_forbidden_owning_stack_cases(self):
        self.check_forbidden_cases("owning_stack")

    def test_no_active_infrastructure_documents(self):
        self.assertFalse(list(ROOT.rglob("*.tf")))
        self.assertFalse(list(ROOT.rglob("*.tf.json")))

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"Effect":"Deny","Effect":"Allow"}', object_pairs_hook=reject_duplicates)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal-dir", type=Path, default=ROOT,
                        help="synthetic draft copy for intentional red tests; never live configuration")
    args, remaining = parser.parse_known_args()
    ROOT = args.proposal_dir.resolve()
    print(f"Structural only: {sum(len(cases) for _, cases in FORBIDDEN.values())} named forbidden action cases x 2 roles; no AWS authorization simulation.", flush=True)
    unittest.main(argv=[__file__, *remaining])
