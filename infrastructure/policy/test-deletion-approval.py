#!/usr/bin/env python3
"""Destructive actions require an exact private approval for one saved plan."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

POLICY = Path(__file__).with_name("inspect-plan.py")
DIGEST = "a" * 64
RESOURCE = {
    "address": 'authentik_application.applications["omada"]',
    "type": "authentik_application",
    "change": {"actions": ["delete"], "before": {"uuid": "omada-id"}, "after": None},
}


class DeletionApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.plan = {"complete": True, "errored": False, "resource_changes": [RESOURCE]}

    def inspect(self, approval=None, digest=DIGEST, plan=None, mode="normal") -> subprocess.CompletedProcess:
        (self.base / "plan.json").write_text(json.dumps(plan or self.plan))
        command = [sys.executable, str(POLICY), str(self.base / "plan.json"), "--mode", mode]
        if approval is not None:
            path = self.base / "approval.json"
            path.write_text(json.dumps(approval))
            os.chmod(path, 0o600)
            command += ["--saved-plan-sha256", digest, "--approve-deletion-file", str(path)]
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def approval(self, actions=None):
        return {"saved_plan_sha256": DIGEST, "deletions": [{
            "address": RESOURCE["address"], "type": RESOURCE["type"],
            "actions": actions or ["delete"],
        }]}

    def test_denies_by_default_and_accepts_exact_saved_plan(self):
        self.assertNotEqual(self.inspect().returncode, 0)
        self.assertEqual(self.inspect(self.approval()).returncode, 0)

    def test_approval_is_bound_to_plan_and_exact_action_set(self):
        self.assertNotEqual(self.inspect(self.approval(), digest="b" * 64).returncode, 0)
        self.assertNotEqual(self.inspect(self.approval(["delete", "create"])).returncode, 0)
        extra = json.loads(json.dumps(self.plan))
        extra["resource_changes"].append({
            "address": "other", "type": "authentik_provider_proxy",
            "change": {"actions": ["delete"], "before": {}, "after": None},
        })
        self.assertNotEqual(self.inspect(self.approval(), plan=extra).returncode, 0)
        replaced = json.loads(json.dumps(self.plan))
        replaced["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        self.assertEqual(self.inspect(self.approval(["delete", "create"]), plan=replaced).returncode, 0)

    def test_approval_cannot_bypass_identity_ownership_or_prerequisite(self):
        iam = json.loads(json.dumps(self.plan))
        iam["resource_changes"][0]["type"] = "aws_iam_role"
        self.assertNotEqual(self.inspect(self.approval(), plan=iam).returncode, 0)
        self.assertNotEqual(self.inspect(self.approval(), mode="vm-start-prerequisite").returncode, 0)
        drift = json.loads(json.dumps(self.plan))
        drift["resource_drift"] = [RESOURCE]
        self.assertNotEqual(self.inspect(self.approval(), plan=drift).returncode, 0)

    def test_requires_private_file_and_complete_plan(self):
        approval = self.approval()
        self.inspect(approval)
        os.chmod(self.base / "approval.json", 0o644)
        # Run directly so inspect() does not reset the permissions.
        result = subprocess.run([
            sys.executable, str(POLICY), str(self.base / "plan.json"),
            "--saved-plan-sha256", DIGEST, "--approve-deletion-file", str(self.base / "approval.json"),
        ], text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        incomplete = dict(self.plan, complete=False)
        self.assertNotEqual(self.inspect(approval, plan=incomplete).returncode, 0)


if __name__ == "__main__":
    unittest.main()
