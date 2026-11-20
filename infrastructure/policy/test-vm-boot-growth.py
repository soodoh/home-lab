#!/usr/bin/env python3
"""Only an exact approval can admit in-place growth of the adopted boot disk."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

POLICY = Path(__file__).with_name("inspect-plan.py")
DIGEST = "a" * 64


class VmBootGrowthTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.approval = {"saved_plan_sha256": DIGEST, "from_gib": 64, "to_gib": 384}
        self.before = {
            "vm_id": 100, "node_name": "proxmox", "protection": True, "started": True,
            "boot_order": ["scsi3", "net0"],
            "disk": [
                {"interface": "scsi1", "path_in_datastore": "/dev/disk/by-id/games"},
                {"interface": "scsi2", "size": 128, "datastore_id": "local-lvm"},
                {"interface": "scsi3", "size": 64, "datastore_id": "local-lvm",
                 "path_in_datastore": "vm-100-disk-2", "serial": "HOME-LAB-DEBIAN-64G", "file_format": "raw"},
            ],
        }
        self.after = copy.deepcopy(self.before)
        self.after["disk"][2]["size"] = 384
        self.change = {"actions": ["update"], "before": self.before, "after": self.after, "after_unknown": {"disk": [{}, {}, {}]}}
        self.resource = {
            "address": "proxmox_virtual_environment_vm.debian", "type": "proxmox_virtual_environment_vm",
            "mode": "managed", "change": self.change,
        }
        self.plan = {"format_version": "1.2", "errored": False, "complete": True, "resource_changes": [self.resource]}

    def inspect(self, *, approved=True, digest=DIGEST, root="proxmox", permissions=0o600, extra=()):
        plan_file = self.base / "plan.json"
        plan_file.write_text(json.dumps(self.plan))
        args = [sys.executable, str(POLICY), str(plan_file), "--plan-root", root, "--saved-plan-sha256", digest]
        if approved:
            path = self.base / "approval.json"
            path.write_text(json.dumps(self.approval))
            os.chmod(path, permissions)
            args += ["--approve-vm-boot-growth-file", str(path)]
        return subprocess.run(args + list(extra), capture_output=True, text=True, check=False)

    def denied(self, **kwargs):
        result = self.inspect(**kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("DENY:", result.stderr)

    def test_default_refuses_and_exact_approval_accepts(self):
        self.denied(approved=False)
        result = self.inspect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("64 to 384 GiB", result.stdout)

    def test_requires_private_file_exact_digest_proxmox_root_and_standalone_admission(self):
        self.denied(digest="b" * 64)
        self.denied(root="unknown")
        self.denied(permissions=0o644)
        self.denied(extra=("--mode", "vm-start-prerequisite"))
        self.denied(extra=("--allow-change-file", "not-used"))

    def test_refuses_shrink_and_unknown_or_unapproved_result(self):
        self.approval["to_gib"] = 63
        self.after["disk"][2]["size"] = 63
        self.denied()
        self.approval["to_gib"] = 384
        self.denied()
        self.after["disk"][2]["size"] = 384
        self.change["after_unknown"] = {"disk": [{}, {}, {"size": True}]}
        self.denied()

    def test_refuses_other_disk_changes_or_replacement(self):
        self.after["disk"][1]["size"] = 256
        self.denied()
        self.after["disk"][1]["size"] = 128
        self.after["disk"][2]["path_in_datastore"] = "new-volume"
        self.denied()
        self.after["disk"][2]["path_in_datastore"] = "vm-100-disk-2"
        self.change["actions"] = ["delete", "create"]
        self.denied()

    def test_refuses_unprotected_vm_and_unrelated_lifecycle_changes(self):
        self.after["protection"] = False
        self.denied()
        self.before["protection"] = False
        self.denied()
        self.before["protection"] = self.after["protection"] = True
        self.after["started"] = False
        self.denied()

    def test_accepts_only_expected_clock_and_disabled_agent_readback(self):
        time = {"address": "proxmox_virtual_environment_time.node", "type": "proxmox_virtual_environment_time",
                "mode": "managed", "change": {"actions": ["update"],
                    "before": {"node_name": "proxmox", "time_zone": "America/Los_Angeles", "local_time": "old", "utc_time": "old"},
                    "after": {"node_name": "proxmox", "time_zone": "America/Los_Angeles", "local_time": "new", "utc_time": "new"}}}
        old_wait = {"disabled": True, "cidrs": None, "interfaces": None}
        new_wait = {"disabled": True, "cidrs": [], "interfaces": []}
        vm = copy.deepcopy(self.resource)
        vm["change"]["after"] = copy.deepcopy(self.before)
        vm["change"]["before"]["agent"] = [{"wait_for_ip": [old_wait]}]
        vm["change"]["after"]["agent"] = [{"wait_for_ip": [new_wait]}]
        self.plan["resource_drift"] = [time, vm]
        result = self.inspect()
        self.assertEqual(result.returncode, 0, result.stderr)
        new_wait["interfaces"] = ["eth0"]
        self.denied()
        new_wait["interfaces"] = []
        time["change"]["after"]["time_zone"] = "UTC"
        self.denied()

    def test_refuses_drift_imports_incomplete_plan_and_additional_actions(self):
        for key, value in (("complete", False), ("resource_drift", [self.resource]),
                           ("output_changes", {"other": {"actions": ["update"]}})):
            with self.subTest(key=key):
                original = self.plan.copy()
                self.plan[key] = value
                self.denied()
                self.plan = original
        self.change["importing"] = {"id": "100"}
        self.denied()
        del self.change["importing"]
        self.plan["resource_changes"].append({
            "address": "example.other", "type": "example", "mode": "managed", "change": {"actions": ["update"]},
        })
        self.denied()


if __name__ == "__main__":
    unittest.main()
