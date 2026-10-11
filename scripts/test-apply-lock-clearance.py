#!/usr/bin/env python3
"""Exercise failed-lock recovery through the real Ansible playbook on synthetic paths."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class NativePlaybookTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="apply-lock-clearance-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.lock = self.work / "production.lock"
        self.variables = {
            "compose_native_apply_lock_path": str(self.lock),
            "restic_systemd": {"lock_path": str(self.work / "backup.guard")},
            "iac_failed_lock_expected_operation": "compose-native-deploy",
            "iac_lock_clear_confirmed": True,
            "ansible_connection": "local", "ansible_become": False,
        }

    def clear(self, *, check=False, **overrides):
        variable_file = self.work / "variables.json"
        variable_file.write_text(json.dumps(self.variables | overrides))
        environment = os.environ.copy()
        environment.update({
            "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(self.work / "ansible"),
            "TMPDIR": str(self.work), "PYTHONDONTWRITEBYTECODE": "1",
        })
        return subprocess.run(
            ["ansible-playbook", "-i", "docker-host,", "-c", "local",
             str(ROOT / "ansible/playbooks/clear-failed-apply-lock.yml"),
             "-e", f"@{variable_file}", *(["--check"] if check else [])],
            env=environment, text=True, capture_output=True, timeout=60, check=False,
        )


class InputTests(NativePlaybookTest):
    def test_unapproved_clearance_is_refused_before_inspection(self):
        result = self.clear(iac_lock_clear_confirmed=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clearance requires confirmation", result.stdout)
        self.assertFalse((self.work / "backup.guard").exists())

    def test_unknown_controller_is_refused_before_inspection(self):
        result = self.clear(iac_failed_lock_expected_controller="unknown")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clearance requires confirmation", result.stdout)
        self.assertFalse((self.work / "backup.guard").exists())

    def test_invalid_operation_is_refused_before_inspection(self):
        result = self.clear(iac_failed_lock_expected_operation="compose; false")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clearance requires confirmation", result.stdout)
        self.assertFalse((self.work / "backup.guard").exists())


@unittest.skipUnless(
    platform.system() == "Linux" and os.geteuid() == 0
    and os.environ.get("HOME_LAB_LOCK_TEST_DISPOSABLE") == "true",
    "native root-owned lock fixture requires explicitly disposable Linux execution",
)
class ClearanceTests(NativePlaybookTest):
    def create_lock(self, controller):
        self.lock.mkdir(mode=0o700)
        self.owner = self.lock / "owner"
        self.owner_bytes = (
            f"controller={controller}\noperation=compose-native-deploy\n"
            "started=2000-01-01T00:00:00Z\n"
        ).encode()
        self.owner.write_bytes(self.owner_bytes)
        self.owner.chmod(0o600)

    def assert_preserved(self):
        self.assertTrue(self.lock.is_dir())
        self.assertEqual(self.owner.read_bytes(), self.owner_bytes)
        self.assertEqual(self.owner.stat().st_mode & 0o777, 0o600)

    def test_manual_owner_clears_with_existing_default(self):
        self.create_lock("ansible-deploy")
        result = self.clear()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.lock.exists())

    def test_scheduled_owner_clears_with_explicit_root_expectation(self):
        self.create_lock("root")
        result = self.clear(iac_failed_lock_expected_controller="root")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.lock.exists())

    def test_scheduled_owner_is_not_admitted_by_manual_default(self):
        self.create_lock("root")
        result = self.clear()
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved()

    def test_manual_owner_is_not_admitted_by_root_expectation(self):
        self.create_lock("ansible-deploy")
        result = self.clear(iac_failed_lock_expected_controller="root")
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved()

    def test_check_reports_each_expected_controller_without_clearing(self):
        for controller in ("ansible-deploy", "root"):
            with self.subTest(controller=controller):
                self.create_lock(controller)
                result = self.clear(check=True, iac_lock_clear_confirmed=False,
                                    iac_failed_lock_expected_controller=controller)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f'"controller": "{controller}"', result.stdout)
                self.assert_preserved()
                self.owner.unlink()
                self.lock.rmdir()

    def test_wrong_operation_retains_scheduled_owner(self):
        self.create_lock("root")
        result = self.clear(iac_failed_lock_expected_controller="root",
                            iac_failed_lock_expected_operation="another-operation")
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved()

    def test_missing_confirmation_retains_scheduled_owner(self):
        self.create_lock("root")
        result = self.clear(iac_failed_lock_expected_controller="root",
                            iac_lock_clear_confirmed=False)
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved()

    def test_additional_lock_contents_refuse_clearance(self):
        self.create_lock("root")
        journal = self.lock / "journal"
        journal.write_text("unresolved\n")
        result = self.clear(iac_failed_lock_expected_controller="root")
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved()
        self.assertEqual(journal.read_text(), "unresolved\n")


if __name__ == "__main__":
    unittest.main()
