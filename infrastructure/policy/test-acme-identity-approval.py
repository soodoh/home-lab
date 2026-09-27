#!/usr/bin/env python3
"""Synthetic tests for the private, plan-bound ACME IAM exception."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

POLICY = Path(__file__).with_name("inspect-plan.py")
DIGEST = "a" * 64
USER = "home-lab-ts-ingress-acme"
RESOURCES = [
    {"address": "aws_iam_user.tail_ingress_acme", "type": "aws_iam_user", "mode": "managed",
     "change": {"actions": ["create"], "before": None, "after": {"name": USER},
                "after_unknown": {"arn": True}}},
    {"address": "aws_iam_policy.tail_ingress_acme", "type": "aws_iam_policy", "mode": "managed",
     "change": {"actions": ["create"], "before": None, "after": {"name": USER + "-dns01", "policy": "{\"Version\":\"2012-10-17\"}"}}},
    {"address": "aws_iam_user_policy_attachment.tail_ingress_acme",
     "type": "aws_iam_user_policy_attachment", "mode": "managed",
     "change": {"actions": ["create"], "before": None, "after": {"user": USER, "policy_arn": None},
                "after_unknown": {"policy_arn": True}}},
    {"address": "aws_iam_policy.state_plan", "type": "aws_iam_policy", "mode": "managed",
     "change": {"actions": ["update"], "before": {"name": "home-lab-opentofu-state-plan", "policy": "old"},
                "after": {"name": "home-lab-opentofu-state-plan", "policy": "new"}}},
]


class AcmeApprovalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.plan = {"complete": True, "errored": False, "resource_changes": deepcopy(RESOURCES)}

    def approval(self, resources=None):
        return {"root": "aws-foundation", "saved_plan_sha256": DIGEST, "identity_mutations": [
            {"address": item["address"], "type": item["type"],
             "actions": item["change"]["actions"]} for item in (resources or RESOURCES)
        ]}

    def inspect(self, plan=None, approval=None, digest=DIGEST, mode="normal", permissions=0o600):
        (self.base / "plan.json").write_text(json.dumps(self.plan if plan is None else plan))
        command = [sys.executable, "-B", str(POLICY), str(self.base / "plan.json"), "--mode", mode,
                   "--plan-root", "aws-foundation"]
        if approval is not None:
            (self.base / "approval.json").write_text(json.dumps(approval))
            os.chmod(self.base / "approval.json", permissions)
            command += ["--saved-plan-sha256", digest, "--approve-identity-file", str(self.base / "approval.json")]
        return subprocess.run(command, text=True, capture_output=True, check=False, timeout=10)

    def test_exact_private_approval_and_default_denial(self):
        self.assertNotEqual(self.inspect().returncode, 0)
        accepted = self.inspect(approval=self.approval())
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertNotEqual(self.inspect(approval=self.approval(), digest="b" * 64).returncode, 0)
        self.assertNotEqual(self.inspect(approval=self.approval(), permissions=0o644).returncode, 0)
        self.assertNotEqual(self.inspect(approval=self.approval(), mode="vm-start-prerequisite").returncode, 0)
        wrong_root = self.approval()
        wrong_root["root"] = "other"
        self.assertNotEqual(self.inspect(approval=wrong_root).returncode, 0)

    def test_enumeration_and_narrow_resource_actions(self):
        self.assertNotEqual(self.inspect(approval=self.approval(RESOURCES[:-1])).returncode, 0)
        for address, kind, actions in [
            ("aws_iam_access_key.tail_ingress_acme", "aws_iam_access_key", ["create"]),
            ("aws_iam_user.other", "aws_iam_user", ["create"]),
            ("aws_iam_policy.state_apply", "aws_iam_policy", ["delete", "create"]),
        ]:
            with self.subTest(address=address):
                extra = {"address": address, "type": kind, "mode": "managed", "change": {
                    "actions": actions, "before": None, "after": {"name": USER}}}
                changed = deepcopy(self.plan)
                changed["resource_changes"].append(extra)
                self.assertNotEqual(self.inspect(plan=changed, approval=self.approval(RESOURCES + [extra])).returncode, 0)
        repeated = deepcopy(self.plan)
        repeated["resource_changes"].append(deepcopy(RESOURCES[0]))
        self.assertNotEqual(self.inspect(plan=repeated, approval=self.approval()).returncode, 0)

    def test_drift_deferred_import_unknown_ownership_and_sensitive_changes(self):
        for modification in ("drift", "deferred", "import", "move", "wrong-name", "unknown-name", "sensitive"):
            with self.subTest(modification=modification):
                changed = deepcopy(self.plan)
                item = changed["resource_changes"][0]
                if modification == "drift":
                    changed["resource_drift"] = [deepcopy(item)]
                elif modification == "deferred":
                    changed["deferred_changes"] = [{"resource_change": deepcopy(item)}]
                elif modification == "import":
                    item["change"]["importing"] = {"id": USER}
                elif modification == "move":
                    item["previous_address"] = "aws_iam_user.old"
                elif modification == "wrong-name":
                    item["change"]["after"]["name"] = "another-identity"
                elif modification == "unknown-name":
                    item["change"]["after"]["name"] = None
                    item["change"]["after_unknown"] = {"name": True}
                elif modification == "sensitive":
                    item["change"]["after_sensitive"] = {"password": True}
                self.assertNotEqual(self.inspect(plan=changed, approval=self.approval()).returncode, 0)
        oidc = deepcopy(self.plan)
        oidc["planned_values"] = {"root_module": {"resources": [{
            "address": "aws_iam_openid_connect_provider.bad", "type": "aws_iam_openid_connect_provider",
            "mode": "managed"}]}}
        self.assertNotEqual(self.inspect(plan=oidc, approval=self.approval()).returncode, 0)

    def test_unknown_policy_and_attachment_target_are_denied(self):
        policy = deepcopy(self.plan)
        policy["resource_changes"][1]["change"]["after_unknown"] = {"policy": True}
        self.assertNotEqual(self.inspect(plan=policy, approval=self.approval()).returncode, 0)
        target = deepcopy(self.plan)
        target["resource_changes"][2]["change"]["after"]["user"] = "another-user"
        self.assertNotEqual(self.inspect(plan=target, approval=self.approval()).returncode, 0)
        wrong_policy = deepcopy(self.plan)
        wrong_policy["resource_changes"][2]["change"]["after"]["policy_arn"] = "arn:aws:iam::123:policy/other"
        self.assertNotEqual(self.inspect(plan=wrong_policy, approval=self.approval()).returncode, 0)
        extra_update = deepcopy(self.plan)
        extra_update["resource_changes"][3]["change"]["after"]["description"] = "unexpected"
        self.assertNotEqual(self.inspect(plan=extra_update, approval=self.approval()).returncode, 0)

    def test_approval_shape_and_plan_completeness(self):
        approval = self.approval()
        for value in (dict(approval, extra=True), dict(approval, identity_mutations=[]),
                      dict(approval, identity_mutations=approval["identity_mutations"] * 2)):
            self.assertNotEqual(self.inspect(approval=value).returncode, 0)
        for change in ({"complete": False}, {"errored": True}):
            self.assertNotEqual(self.inspect(plan=dict(self.plan, **change), approval=approval).returncode, 0)


if __name__ == "__main__":
    unittest.main()
