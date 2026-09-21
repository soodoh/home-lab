#!/usr/bin/env python3
"""Focused behavior tests for the recurring Restic consistency adapter."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
RUNNER_PATH = ROOT / "scripts/restic-backup"
POLICY_PATH = ROOT / "services/data/restic/policy.json"


class ResticRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = runpy.run_path(str(RUNNER_PATH))

    def test_reviewed_policy_matches_the_small_runtime_interface(self):
        policy = json.loads(POLICY_PATH.read_text())
        source = RUNNER_PATH.read_bytes()

        self.assertEqual(policy["runner"]["sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(policy["runner"]["path"], "/usr/local/libexec/home-lab/restic-backup")
        self.assertGreater(len((ROOT / "services/data/restic/files-from").read_text().splitlines()), 0)
        self.assertGreater(len((ROOT / "services/data/restic/excludes").read_text().splitlines()), 0)
        for duplicate in ("sources", "classified_paths", "excludes", "critical_fixtures"):
            self.assertNotIn(duplicate, policy)
        self.assertNotIn("accepted_path", policy["runner"])
        self.assertNotIn("proton", policy)
        self.assertEqual(policy["retention"]["read_data_subset"], "10%")
        self.assertNotIn("maintenance_state_path", policy["runner"])
        self.assertNotIn("start_order", policy["stop_groups"])
        for duplicate in ("identity_local", "identity_proton", "units"):
            self.assertNotIn(duplicate, policy["runner"])
        self.assertEqual(self.runner["SUBCOMMANDS"], {
            "preflight", "daily-local", "daily-proton", "diagnose-proton", "maintenance", "status",
        })
        text = source.decode()
        for retired in ("pending", "quota", "repair_proton_index", "first_run"):
            self.assertNotIn(retired, text)

    def test_proton_replication_selects_one_current_tagged_snapshot(self):
        select = self.runner["select_current_snapshot"]
        workflow_error = self.runner["WorkflowError"]
        snapshot = "3" * 64
        required = {"cadence=daily", "policy=" + "1" * 64, "artifact=" + "2" * 64}
        current = {"id": snapshot, "tags": sorted(required)}

        self.assertEqual(select([current], required), snapshot)
        for records in ([], [current, current], [{"id": snapshot, "tags": ["cadence=daily"]}]):
            with self.subTest(records=records), self.assertRaises(workflow_error):
                select(records, required)

    def test_daily_proton_uses_one_native_snapshot_copy(self):
        daily_proton = self.runner["daily_proton"]
        policy_hash = "1" * 64
        artifact = "2" * 64
        source = "3" * 64
        destination = "4" * 64
        preflight = mock.Mock()
        current_snapshot = mock.Mock(return_value=source)
        copy_snapshot = mock.Mock(return_value=destination)

        with mock.patch.dict(daily_proton.__globals__, {
            "preflight": preflight,
            "artifact_hash": mock.Mock(return_value=artifact),
            "current_snapshot": current_snapshot,
            "copy_snapshot": copy_snapshot,
        }), mock.patch("builtins.print") as report:
            daily_proton({}, policy_hash)

        preflight.assert_called_once_with({}, ["games", "proton"])
        current_snapshot.assert_called_once_with({}, policy_hash, artifact)
        copy_snapshot.assert_called_once_with({}, "games", "proton", source)
        report.assert_called_once_with(
            f"restic_backup=proton source_snapshot={source} proton_snapshot={destination}"
        )

    def test_monthly_retention_delegates_to_forget_and_prune(self):
        retention = self.runner["retention"]
        policy = {"retention": {
            "keep_daily": 7,
            "keep_weekly": 5,
            "keep_monthly": 12,
            "group_by": "host,paths",
            "required_tags": ["cadence=daily"],
            "prune_max_repack_size": "10G",
            "prune_max_unused": "10%",
        }}
        result = subprocess.CompletedProcess([], 0, "", "")
        restic_result = mock.Mock(return_value=result)

        with mock.patch.dict(retention.__globals__, {"restic_result": restic_result}):
            retention(policy, "games")

        self.assertEqual(restic_result.call_count, 2)
        self.assertEqual(restic_result.call_args_list[0].args[2][0], "forget")
        self.assertNotIn("--dry-run", restic_result.call_args_list[0].args[2])
        self.assertEqual(restic_result.call_args_list[1].args[2], [
            "prune", "--max-repack-size", "10G", "--max-unused", "10%",
        ])

    def test_partial_snapshot_is_always_a_failure(self):
        with self.assertRaisesRegex(self.runner["WorkflowError"], "restic_partial_source"):
            self.runner["require_success"](subprocess.CompletedProcess([], 3, "", ""), "backup")

    def test_runner_refuses_deployment_after_acquiring_backup_lock(self):
        with tempfile.TemporaryDirectory(prefix="restic-deploy-lock-test-") as directory:
            root = Path(directory)
            policy_path = root / "etc/home-lab/restic-policy.json"
            policy_path.parent.mkdir(parents=True)
            policy_path.write_text(json.dumps({
                "policy_version": 1,
                "runner": {
                    "lock_path": "/run/lock/home-lab-backup.lock",
                    "deploy_lock_path": "/var/lib/iac-ansible-production.lock",
                },
            }))
            policy_path.chmod(0o600)
            (root / "var/lib/iac-ansible-production.lock").mkdir(parents=True)
            result = subprocess.run(
                [str(RUNNER_PATH), "status"],
                env={
                    **os.environ,
                    "HOME_LAB_RESTIC_TESTING": "1",
                    "HOME_LAB_RESTIC_TEST_ROOT": str(root),
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "restic_backup=failed reason=concurrent_deploy\n")
            self.assertTrue((root / "run/lock/home-lab-backup.lock").is_file())


if __name__ == "__main__":
    unittest.main()
