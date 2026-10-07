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
        self.assertEqual(policy["retention"]["read_data_subset"], "10%")
        self.assertEqual(self.runner["SUBCOMMANDS"], {
            "preflight", "daily-local", "daily-proton", "diagnose-proton", "maintenance", "status",
        })

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
        self.assertEqual(report.call_args_list[-1], mock.call(
            f"restic_backup=proton source_snapshot={source} proton_snapshot={destination}"
        ))
        self.assertRegex(report.call_args_list[0].args[0], r"^restic_backup=phase name=proton_copy seconds=\d+\.\d$")

    def test_daily_local_reports_bounded_phases_and_restarts_before_copy(self):
        daily_local = self.runner["daily_local"]
        snapshot = "3" * 64
        copied = "4" * 64
        policy = {
            "stop_groups": {"applications": ["app"], "databases": ["db"]},
            "runner": {"files_from_path": "/etc/files-from", "exclude_file_path": "/etc/excludes"},
        }
        events = []
        result = subprocess.CompletedProcess([], 0, json.dumps({
            "message_type": "summary", "snapshot_id": snapshot,
        }), "")
        copy = mock.Mock(side_effect=lambda *args: (events.append("copy"), copied)[1])
        restart = mock.Mock(side_effect=lambda *args: events.append("restart"))
        compose = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        with mock.patch.dict(daily_local.__globals__, {
            "recover_interruption": mock.Mock(),
            "preflight": mock.Mock(),
            "artifact_hash": mock.Mock(return_value="2" * 64),
            "declared_services": mock.Mock(return_value={"app", "db"}),
            "service_running": mock.Mock(return_value=True),
            "atomic_json": mock.Mock(),
            "journal_path": mock.Mock(return_value=Path("/tmp/journal")),
            "compose": compose,
            "restic_result": mock.Mock(return_value=result),
            "restart_recorded": restart,
            "copy_snapshot": copy,
        }), mock.patch("time.monotonic", side_effect=range(8)), mock.patch("builtins.print") as report:
            daily_local(policy, "1" * 64)

        self.assertEqual(compose.call_args_list, [
            mock.call(policy, ["stop", "--timeout", "120", "app"]),
            mock.call(policy, ["stop", "--timeout", "120", "db"]),
        ])
        self.assertEqual(events, ["restart", "copy"])
        for phase in ("stop", "scan", "restart", "nfs_copy"):
            self.assertIn(mock.call(f"restic_backup=phase name={phase} seconds=1.0"), report.call_args_list)

    def test_failed_batch_stop_restarts_only_recorded_running_services(self):
        daily_local = self.runner["daily_local"]
        policy = {
            "stop_groups": {"applications": ["app", "inactive"], "databases": ["db"]},
            "runner": {"files_from_path": "/etc/files-from", "exclude_file_path": "/etc/excludes"},
        }
        compose = mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", ""))
        restart = mock.Mock()
        with mock.patch.dict(daily_local.__globals__, {
            "recover_interruption": mock.Mock(),
            "preflight": mock.Mock(),
            "artifact_hash": mock.Mock(return_value="2" * 64),
            "declared_services": mock.Mock(return_value={"app", "inactive", "db"}),
            "service_running": mock.Mock(side_effect=lambda _policy, service: service != "inactive"),
            "atomic_json": mock.Mock(),
            "journal_path": mock.Mock(return_value=Path("/tmp/journal")),
            "compose": compose,
            "restart_recorded": restart,
        }), mock.patch("builtins.print"):
            with self.assertRaisesRegex(self.runner["WorkflowError"], "service_stop"):
                daily_local(policy, "1" * 64)
        compose.assert_called_once_with(policy, ["stop", "--timeout", "120", "app"])
        self.assertEqual(restart.call_args.args[1]["running_services"], ["app", "db"])

    def test_new_policy_writers_wait_for_declaration_but_missing_declared_containers_refuse(self):
        daily_local = self.runner["daily_local"]
        policy = {
            "stop_groups": {"applications": ["app", "candidate"], "databases": ["db"]},
            "runner": {"files_from_path": "/etc/files-from", "exclude_file_path": "/etc/excludes"},
        }
        snapshot = "3" * 64
        for candidate_declared, candidate_present in ((False, False), (True, False), (True, True)):
            with self.subTest(candidate_declared=candidate_declared, candidate_present=candidate_present):
                declarations = "app\ndb\n" + ("candidate\n" if candidate_declared else "")
                events = []

                def compose(_policy, arguments):
                    events.append(arguments)
                    if arguments == ["config", "--services"]:
                        return subprocess.CompletedProcess([], 0, declarations, "")
                    if arguments[:3] == ["ps", "--all", "--quiet"]:
                        service = arguments[3]
                        if service == "candidate" and not candidate_present:
                            return subprocess.CompletedProcess([], 0 if candidate_declared else 1, "", "")
                        return subprocess.CompletedProcess([], 0, "a" * 64 + "\n", "")
                    return subprocess.CompletedProcess([], 0, "", "")

                journal = mock.Mock()
                backup = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps({
                    "message_type": "summary", "snapshot_id": snapshot,
                }), ""))
                restart = mock.Mock()
                with mock.patch.dict(daily_local.__globals__, {
                    "recover_interruption": mock.Mock(), "preflight": mock.Mock(),
                    "artifact_hash": mock.Mock(return_value="2" * 64),
                    "compose": compose,
                    "run": mock.Mock(return_value=subprocess.CompletedProcess([], 0, "true\n", "")),
                    "atomic_json": journal,
                    "journal_path": mock.Mock(return_value=Path("/tmp/journal")),
                    "restic_result": backup, "restart_recorded": restart,
                    "copy_snapshot": mock.Mock(return_value="4" * 64),
                }), mock.patch("builtins.print"):
                    if candidate_declared and not candidate_present:
                        with self.assertRaisesRegex(self.runner["WorkflowError"], "service_inventory_output"):
                            daily_local(policy, "1" * 64)
                        journal.assert_not_called()
                        backup.assert_not_called()
                        restart.assert_not_called()
                        self.assertFalse(any(arguments[0] == "stop" for arguments in events))
                    else:
                        daily_local(policy, "1" * 64)
                        if not candidate_declared:
                            self.assertNotIn(["ps", "--all", "--quiet", "candidate"], events)
                        applications = ["app", "candidate"] if candidate_present else ["app"]
                        self.assertEqual(journal.call_args.args[1]["running_services"], [*applications, "db"])
                        self.assertEqual([arguments for arguments in events if arguments[0] == "stop"], [
                            ["stop", "--timeout", "120", *applications], ["stop", "--timeout", "120", "db"],
                        ])
                        backup.assert_called_once()
                        restart.assert_called_once()

    def test_service_declarations_refuse_failed_empty_duplicate_or_malformed_output(self):
        declared = self.runner["declared_services"]
        for result in (
            subprocess.CompletedProcess([], 1, "app\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "app\napp\n", ""),
            subprocess.CompletedProcess([], 0, "app\n../candidate\n", ""),
        ):
            with self.subTest(result=result), mock.patch.dict(declared.__globals__, {
                "compose": mock.Mock(return_value=result),
            }), self.assertRaises(self.runner["WorkflowError"]):
                declared({})

    def test_reviewed_network_namespace_services_restart_after_gluetun(self):
        policy = json.loads(POLICY_PATH.read_text())
        running = ["sonarr", "flaresolverr", "qbittorrent", "gluetun", "recyclarr", "postgres"]
        journal = {"version": 1, "running_services": running}
        compose = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        with mock.patch.dict(self.runner["restart_recorded"].__globals__, {
            "compose": compose,
            "service_healthy": mock.Mock(return_value=True),
            "journal_path": mock.Mock(return_value=Path("/tmp/journal")),
            "durable_unlink": mock.Mock(),
        }):
            self.runner["restart_recorded"](policy, journal)

        started = [call.args[1][1] for call in compose.call_args_list]
        self.assertEqual(started, ["postgres", "gluetun", "qbittorrent", "flaresolverr", "sonarr", "recyclarr"])

    def test_gluetun_health_precedes_network_namespace_restart(self):
        policy = {"stop_groups": {"applications": ["qbittorrent", "gluetun"], "databases": []}}
        journal = {"running_services": ["qbittorrent", "gluetun"]}
        events = []
        responses = iter([False, True])

        def healthy(_policy, service):
            events.append(f"health:{service}")
            return next(responses, True) if service == "gluetun" else True

        def compose(_policy, arguments):
            events.append(f"start:{arguments[1]}")
            return subprocess.CompletedProcess([], 0, "", "")

        with mock.patch.dict(self.runner["restart_recorded"].__globals__, {
            "compose": compose,
            "service_healthy": healthy,
            "journal_path": mock.Mock(return_value=Path("/tmp/journal")),
            "durable_unlink": mock.Mock(),
        }), mock.patch("time.sleep", side_effect=lambda _: events.append("wait")):
            self.runner["restart_recorded"](policy, journal)

        self.assertEqual(events[:5], [
            "start:gluetun", "health:gluetun", "wait", "health:gluetun", "start:qbittorrent",
        ])

    def test_unhealthy_gluetun_retains_journal_and_does_not_start_dependent(self):
        policy = {"stop_groups": {"applications": ["qbittorrent", "gluetun"], "databases": []}}
        journal = {"running_services": ["qbittorrent", "gluetun"]}
        compose = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        unlink = mock.Mock()
        with mock.patch.dict(self.runner["restart_recorded"].__globals__, {
            "compose": compose,
            "service_healthy": mock.Mock(return_value=False),
            "durable_unlink": unlink,
            "testing": mock.Mock(return_value=True),
        }), mock.patch("time.monotonic", side_effect=[0, 1, 4]), mock.patch("time.sleep"):
            with self.assertRaisesRegex(self.runner["WorkflowError"], "service_health"):
                self.runner["restart_recorded"](policy, journal)

        compose.assert_called_once_with(policy, ["start", "gluetun"])
        unlink.assert_not_called()

    def test_failed_scan_still_restarts_services(self):
        daily_local = self.runner["daily_local"]
        policy = {
            "stop_groups": {"applications": [], "databases": []},
            "runner": {"files_from_path": "/etc/files-from", "exclude_file_path": "/etc/excludes"},
        }
        restart = mock.Mock()
        with mock.patch.dict(daily_local.__globals__, {
            "recover_interruption": mock.Mock(),
            "preflight": mock.Mock(),
            "artifact_hash": mock.Mock(return_value="2" * 64),
            "atomic_json": mock.Mock(),
            "journal_path": mock.Mock(return_value=Path("/tmp/journal")),
            "declared_services": mock.Mock(return_value={"stateless"}),
            "restic_result": mock.Mock(return_value=subprocess.CompletedProcess([], 3, "", "")),
            "restart_recorded": restart,
        }), mock.patch("builtins.print"):
            with self.assertRaisesRegex(self.runner["WorkflowError"], "restic_partial_source"):
                daily_local(policy, "1" * 64)
        restart.assert_called_once()

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
