#!/usr/bin/env python3
"""Behavior tests for independent access ownership and native snippet adoption."""
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
ACCESS_TYPES = (
    "proxmox_acl", "proxmox_virtual_environment_acl",
    "proxmox_virtual_environment_role", "proxmox_virtual_environment_group",
    "proxmox_virtual_environment_user", "proxmox_user_token",
    "proxmox_virtual_environment_user_token",
    "proxmox_cluster_options", "proxmox_virtual_environment_cluster_options",
)


def resource(kind, actions=None):
    return {"address": f"{kind}.example", "type": kind, "mode": "managed",
            "change": {"actions": actions or ["no-op"],
                       "before": {"id": "synthetic"}, "after": {"id": "synthetic"}}}


class ProxmoxOwnershipTests(unittest.TestCase):
    def inspect(self, plan, root="proxmox", mode="normal", allow=None, approval=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "plan.json").write_text(json.dumps(plan))
            args = [sys.executable, str(POLICY), str(path / "plan.json"),
                    "--plan-root", root, "--mode", mode]
            if allow is not None:
                (path / "allow").write_text("\n".join(allow) + "\n")
                args += ["--allow-change-file", str(path / "allow")]
            if approval is not None:
                (path / "approval.json").write_text(json.dumps(approval))
                os.chmod(path / "approval.json", 0o600)
                args += ["--approve-deletion-file", str(path / "approval.json"),
                         "--saved-plan-sha256", DIGEST]
            return subprocess.run(args, capture_output=True, text=True, check=False)

    def test_access_ownership_cannot_be_allowlisted_into_normal_automation(self):
        for kind in ACCESS_TYPES:
            for actions in (["no-op"], ["create"], ["update"], ["delete"]):
                item = resource(kind, actions)
                for mode in ("normal", "vm-start-prerequisite"):
                    with self.subTest(kind=kind, actions=actions, mode=mode):
                        result = self.inspect({"resource_changes": [item]}, mode=mode,
                                              allow=[item["address"]])
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                        self.assertIn("independent proxmox-access root", result.stderr)
            item = resource(kind)
            item["change"]["importing"] = {"id": "existing"}
            result = self.inspect({"resource_changes": [item]}, allow=[item["address"]])
            self.assertEqual(result.returncode, 1)

    def test_nested_and_retained_access_ownership_is_checked(self):
        for kind in ("proxmox_acl", "proxmox_cluster_options"):
            item = resource(kind)
            for location in ("configuration", "planned_values", "prior_state"):
                values = {"root_module": {"child_modules": [{"resources": [item]}]}}
                plan = {location: {"values": values} if location == "prior_state" else values}
                self.assertEqual(self.inspect(plan).returncode, 1)
                self.assertEqual(self.inspect(plan, root="proxmox-access").returncode, 0)
            item["mode"] = "data"
            self.assertEqual(self.inspect({"resource_changes": [item]}).returncode, 0)

    def test_access_mutations_still_require_review_in_owner_root(self):
        for kind in ACCESS_TYPES:
            item = resource(kind, ["update"])
            plan = {"resource_changes": [item]}
            self.assertEqual(self.inspect(plan, root="proxmox-access").returncode, 1)
            self.assertEqual(self.inspect(plan, root="proxmox-access", allow=[item["address"]]).returncode, 0)
            item["change"] = {"actions": ["no-op"], "before": {}, "after": {}, "importing": {"id": "existing"}}
            self.assertEqual(self.inspect(plan, root="proxmox-access").returncode, 1)
            self.assertEqual(self.inspect(plan, root="proxmox-access", allow=["import:" + item["address"]]).returncode, 0)

    def test_node_and_file_mutations_require_explicit_review(self):
        for kind in ("proxmox_virtual_environment_dns", "proxmox_virtual_environment_time",
                     "proxmox_virtual_environment_file"):
            item = resource(kind, ["update"])
            plan = {"resource_changes": [item]}
            self.assertEqual(self.inspect(plan).returncode, 1)
            self.assertEqual(self.inspect(plan, allow=[item["address"]]).returncode, 0)

    def snippet_plan(self):
        item = resource("proxmox_virtual_environment_file", ["delete", "create"])
        item["change"].update({
            "importing": {"id": "pve/local:snippets/test.yaml"},
            "before": {"node_name": "pve", "datastore_id": "local", "content_type": "snippets", "file_name": "test.yaml"},
            "after": {"node_name": "pve", "datastore_id": "local", "content_type": "snippets",
                      "source_raw": [{"file_name": "test.yaml", "data": "#cloud-config\n"}]},
        })
        plan = {"complete": True, "errored": False, "resource_changes": [item]}
        approval = {"saved_plan_sha256": DIGEST, "deletions": [{
            "address": item["address"], "type": item["type"], "actions": ["delete", "create"],
        }]}
        return plan, item["address"], approval

    def test_imported_snippet_replacement_needs_both_exact_approval_and_mutation_review(self):
        plan, address, approval = self.snippet_plan()
        for allow, approved in ((None, None), ([address], None), (None, approval), (["import:" + address], approval)):
            self.assertEqual(self.inspect(plan, allow=allow, approval=approved).returncode, 1)
        self.assertEqual(self.inspect(plan, allow=[address], approval=approval).returncode, 0)
        mismatched = deepcopy(approval)
        mismatched["saved_plan_sha256"] = "b" * 64
        self.assertEqual(self.inspect(plan, allow=[address], approval=mismatched).returncode, 1)

    def test_snippet_exception_cannot_retarget_or_create_before_destroy(self):
        plan, address, approval = self.snippet_plan()
        for field, value in (("node_name", "other"), ("datastore_id", "other"), ("content_type", "iso")):
            changed = deepcopy(plan)
            changed["resource_changes"][0]["change"]["after"][field] = value
            self.assertEqual(self.inspect(changed, allow=[address], approval=approval).returncode, 1)
        changed = deepcopy(plan)
        changed["resource_changes"][0]["change"]["after"]["source_raw"][0]["file_name"] = "other.yaml"
        self.assertEqual(self.inspect(changed, allow=[address], approval=approval).returncode, 1)
        changed["resource_changes"][0]["change"]["actions"] = ["create", "delete"]
        approval["deletions"][0]["actions"] = ["create", "delete"]
        self.assertEqual(self.inspect(changed, allow=[address], approval=approval).returncode, 1)

    def test_snippet_replacement_rejects_missing_or_unknown_identity(self):
        plan, address, approval = self.snippet_plan()
        for key in ("node_name", "datastore_id"):
            for value in (None, "", [], {}):
                changed = deepcopy(plan)
                for side in ("before", "after"):
                    changed["resource_changes"][0]["change"][side][key] = value
                result = self.inspect(changed, allow=[address], approval=approval)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("Traceback", result.stderr)

    def test_owner_state_is_excluded_from_normal_controller_grants(self):
        manifest = json.loads((POLICY.parents[1] / "tofu/aws-foundation/state-objects.json").read_text())
        self.assertNotIn("home-lab/proxmox-access/tofu.tfstate", manifest["active"])


if __name__ == "__main__":
    unittest.main()
