#!/usr/bin/env python3
"""Regression tests for the one-time VM 100 candidate-disk attachment."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/proxmox-vm-100-candidate-disk.py"
SPEC = importlib.util.spec_from_file_location("candidate_attachment", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CandidateAttachmentTests(unittest.TestCase):
    def test_exact_candidate_config_is_closed(self) -> None:
        value = (
            "local-lvm:vm-100-disk-1,backup=1,cache=none,discard=ignore,iothread=1,"
            "replicate=1,serial=QUAL-NIXOS-128G,size=128G,ssd=0"
        )
        self.assertTrue(MODULE.candidate_is_exact(value))
        self.assertFalse(MODULE.candidate_is_exact(value.replace("QUAL-NIXOS-128G", "WRONG")))
        self.assertFalse(MODULE.candidate_is_exact(value.replace("size=128G", "size=129G")))
        self.assertFalse(MODULE.candidate_is_exact(value.replace("backup=1", "backup=0")))

    def test_attachment_is_an_exact_guarded_opentofu_action(self) -> None:
        source = SCRIPT.read_text()
        tofu = (ROOT / "infrastructure/tofu/proxmox/candidate-attachment.tf").read_text()
        vm = (ROOT / "infrastructure/tofu/proxmox/main.tf").read_text()
        self.assertIn('remote("/usr/sbin/qm", "set", str(VMID), "--scsi2", ATTACH_VALUE)', source)
        self.assertIn('if head != upstream or run(("git", "status"', source)
        self.assertIn('before["pid"] != after["pid"]', source)
        self.assertNotIn("shell=True", source)
        self.assertIn('resource "terraform_data" "vm_100_candidate_disk_attachment"', tofu)
        self.assertIn('HOMELAB_VM100_CANDIDATE_ATTACHMENT = "reviewed-opentofu-action"', tofu)
        self.assertIn("prevent_destroy = true", tofu)
        self.assertIn("ignore_changes = [disk]", vm)


if __name__ == "__main__":
    unittest.main()
