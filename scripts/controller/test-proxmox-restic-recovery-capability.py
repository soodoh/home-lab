#!/usr/bin/env python3
"""Tests for the fixed Restic recovery capability and caller migration."""
from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = ROOT / "infrastructure/proxmox-access/host/proxmox-restic-recovery-transport.py"
SPEC = importlib.util.spec_from_file_location("restic_recovery_transport", HELPER_PATH)
HELPER = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(HELPER)


class ResticRecoveryCapabilityTests(unittest.TestCase):
    def test_recovery_caller_has_no_conventional_root_ssh_dependency(self) -> None:
        source = (ROOT / "scripts/prove-restic-recovery-vm").read_text()
        self.assertNotIn("root@proxmox", source)
        self.assertNotIn("home-lab-arch-ansible", source)
        self.assertIn("ansible-deploy@proxmox", source)
        provider = (ROOT / "infrastructure/tofu/proxmox-restic-recovery-qualification/main.tf").read_text()
        self.assertNotIn("ssh {", provider)
        self.assertNotIn('username = "root"', provider)

    def test_deploy_transport_rejects_recovery_injection(self) -> None:
        transport = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
        result = subprocess.run((str(transport), "-c", "restic-recovery stage-snippet invalid;id"), capture_output=True)
        self.assertEqual(result.returncode, 64)

    def test_helper_rejects_unknown_commands(self) -> None:
        original = HELPER.os.geteuid
        HELPER.os.geteuid = lambda: 0
        try:
            with self.assertRaises(SystemExit) as raised:
                HELPER.sys.argv = [str(HELPER_PATH), "shell", "id"]
                HELPER.main()
            self.assertEqual(raised.exception.code, 64)
        finally:
            HELPER.os.geteuid = original

    def test_dangling_snippet_symlink_is_rejected_for_stage_and_remove(self) -> None:
        raw = b"#cloud-config\n"; digest = HELPER.sha(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); snippet = root / "home-lab-restic-recovery-cloud-init.yaml"; snippet.symlink_to(root / "missing"); lock = root / "lock"
            def descriptor() -> int: return os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
            with mock.patch.object(HELPER, "SNIPPET_DIRECTORY", root), mock.patch.object(HELPER, "SNIPPET", snippet), mock.patch.object(HELPER, "PROTECTED_LOCKS", ()), mock.patch.object(HELPER, "require_snippet_directory"), mock.patch.object(HELPER, "acquire_lock", side_effect=descriptor), mock.patch.object(HELPER.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw))):
                with self.assertRaises(SystemExit) as staged: HELPER.stage_snippet(digest)
                self.assertEqual(staged.exception.code, 73)
                with self.assertRaises(SystemExit) as removed: HELPER.remove_snippet(digest)
                self.assertEqual(removed.exception.code, 73)
            self.assertTrue(snippet.is_symlink())

    def test_helper_scope_is_exact_vm_and_snippet(self) -> None:
        self.assertEqual(HELPER.VMID, 9900)
        self.assertEqual(HELPER.SNIPPET, Path("/var/lib/vz/snippets/home-lab-restic-recovery-cloud-init.yaml"))
        source = HELPER_PATH.read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)

    def test_installer_has_resumable_phase_boundaries(self) -> None:
        source = (ROOT / "scripts/controller/proxmox-restic-recovery-capability.py").read_text()
        preparing = source.index('set_state("preparing")')
        self.assertLess(preparing, source.index('for path,item in payload["after"].items()', preparing))
        self.assertIn('set_state("rolling-back");restore();set_state("rolled-back")', source)
        self.assertIn('set_state("candidate")', source)
        self.assertIn('value["status"]="committed"', source)
        self.assertIn("resume_status", source)
        self.assertIn("RESTORE_ORDER = (SUDOERS, HELPER, TRANSPORT)", source)
        self.assertIn('for path in payload["restore_order"]', source)


if __name__ == "__main__": unittest.main()
