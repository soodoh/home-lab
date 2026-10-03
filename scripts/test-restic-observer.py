#!/usr/bin/env python3
"""Tests for complete-chain selection in the live Restic observer."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
import contextlib
import hashlib
import io
import json
import os
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("restic_observer", ROOT / "scripts/observe-restic-backups.py")
assert SPEC and SPEC.loader
OBSERVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OBSERVER
SPEC.loader.exec_module(OBSERVER)

POLICY = "a" * 64
ARTIFACT = "b" * 64
TAGS = ["cadence=daily", f"policy={POLICY}", f"artifact={ARTIFACT}"]


def snapshot(identity: str, timestamp: str, *, original: str | None = None, tags: list[str] | None = None):
    value = {"id": identity, "time": timestamp, "tags": list(TAGS if tags is None else tags)}
    if original is not None:
        value["original"] = original
    return value


class ResticObserverTests(unittest.TestCase):
    def test_selects_newest_complete_chain_not_newest_incomplete_source(self):
        complete = "1" * 64
        incomplete = "2" * 64
        games = [
            snapshot(incomplete, "2026-09-21T08:00:00Z"),
            snapshot(complete, "2026-09-21T07:00:00Z"),
        ]
        nfs = [snapshot("3" * 64, "2026-09-21T07:00:00Z", original=complete)]
        proton = [snapshot("4" * 64, "2026-09-21T07:00:00Z", original=complete)]
        selected = OBSERVER.select_chain(games, nfs, proton, POLICY, ARTIFACT)
        self.assertEqual(selected[0]["id"], complete)

    def test_requires_current_policy_artifact_cadence_and_matching_tags(self):
        source = "1" * 64
        games = [snapshot(source, "2026-09-21T07:00:00Z", tags=["cadence=daily"])]
        nfs = [snapshot("3" * 64, "2026-09-21T07:00:00Z", original=source)]
        proton = [snapshot("4" * 64, "2026-09-21T07:00:00Z", original=source)]
        with self.assertRaisesRegex(OBSERVER.ObservationError, "complete_chain_missing"):
            OBSERVER.select_chain(games, nfs, proton, POLICY, ARTIFACT)

    def test_refuses_ambiguous_destination_mapping(self):
        source = "1" * 64
        games = [snapshot(source, "2026-09-21T07:00:00Z")]
        nfs = [
            snapshot("3" * 64, "2026-09-21T07:00:00Z", original=source),
            snapshot("5" * 64, "2026-09-21T07:01:00Z", original=source),
        ]
        proton = [snapshot("4" * 64, "2026-09-21T07:00:00Z", original=source)]
        with self.assertRaisesRegex(OBSERVER.ObservationError, "snapshot_mapping_ambiguous"):
            OBSERVER.select_chain(games, nfs, proton, POLICY, ARTIFACT)

    def test_routine_accepts_previous_artifact_without_remote_copies(self):
        local = snapshot("1" * 64, "2026-09-21T07:00:00Z",
                         tags=["cadence=daily", f"policy={POLICY}", f"artifact={'c' * 64}"])
        local["paths"] = ["/state", "/credentials"]
        self.assertEqual(OBSERVER.select_local([local], POLICY, ["/state/auths", "/credentials"]), local)

    def test_routine_refuses_missing_coverage_or_changed_policy(self):
        local = snapshot("1" * 64, "2026-09-21T07:00:00Z")
        local["paths"] = ["/state-other"]
        for policy, paths in [(POLICY, ["/state"]), ("c" * 64, ["/state-other"])]:
            with self.assertRaisesRegex(OBSERVER.ObservationError, "local_snapshot_missing"):
                OBSERVER.select_local([local], policy, paths)

    def test_routine_requires_valid_snapshot_artifact_tag(self):
        local = snapshot("1" * 64, "2026-09-21T07:00:00Z",
                         tags=["cadence=daily", f"policy={POLICY}"])
        local["paths"] = ["/state"]
        with self.assertRaisesRegex(OBSERVER.ObservationError, "local_snapshot_missing"):
            OBSERVER.select_local([local], POLICY, ["/state"])

    def test_freshness_is_independent_of_deployment_version(self):
        now = datetime(2026, 9, 21, 8, tzinfo=timezone.utc)
        for age in [timedelta(hours=48), timedelta(seconds=-1)]:
            local = snapshot("1" * 64, (now - age).isoformat())
            with self.assertRaisesRegex(OBSERVER.ObservationError, "snapshot_freshness"):
                OBSERVER.require_fresh(local, now)
        OBSERVER.require_fresh(snapshot("1" * 64, (now - timedelta(hours=24)).isoformat()), now)

    def test_routine_remote_lag_is_reported_but_wrong_identity_is_refused(self):
        local = snapshot("1" * 64, "2026-09-21T07:00:00Z")
        self.assertIsNone(OBSERVER.match_copy(local, []))
        wrong_tags = snapshot("3" * 64, "2026-09-21T07:00:00Z", original=local["id"], tags=["cadence=daily"])
        self.assertIsNone(OBSERVER.match_copy(local, [wrong_tags]))
        good = snapshot("3" * 64, "2026-09-21T07:00:00Z", original=local["id"])
        with self.assertRaisesRegex(OBSERVER.ObservationError, "snapshot_mapping_ambiguous"):
            OBSERVER.match_copy(local, [good, good])
        with self.assertRaisesRegex(OBSERVER.ObservationError, "repository_identity"):
            OBSERVER.require_repository_identity({"id": "wrong"}, "a" * 64)

    def test_routine_still_blocks_running_or_unknown_writers(self):
        for active, sub in [("active", "running"), ("activating", "start"), ("unknown", "unknown")]:
            with self.assertRaisesRegex(OBSERVER.ObservationError, "backup_writer_state"):
                OBSERVER.validate_unit_state("daily-local.service", {"ActiveState": active, "SubState": sub}, routine=True)
        failed = {"ActiveState": "failed", "SubState": "failed", "Result": "exit-code"}
        OBSERVER.validate_unit_state("daily-proton.service", failed, routine=True)
        for unit, routine in [("daily-local.service", True), ("daily-proton.service", False)]:
            with self.assertRaises(OBSERVER.ObservationError):
                OBSERVER.validate_unit_state(unit, failed, routine=routine)

    def test_unknown_owners_and_interruption_are_never_routine_exceptions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root / "apply.lock"
            journal = root / "journal"
            owner.mkdir(mode=0o700)
            (owner / "owner").write_text("this-run")
            (owner / "owner").chmod(0o600)
            digest = hashlib.sha256(b"this-run").hexdigest()
            original_lstat = Path.lstat

            def root_metadata(path):
                values = list(original_lstat(path))
                values[4] = 0
                return os.stat_result(values)

            with patch.object(OBSERVER, "OWNERS", (owner, root / "other.lock")), patch.object(Path, "lstat", root_metadata):
                with self.assertRaisesRegex(OBSERVER.ObservationError, "operation_owner_active"):
                    OBSERVER.validate_owners(journal, None)
                with self.assertRaisesRegex(OBSERVER.ObservationError, "reviewed_source_drift"):
                    OBSERVER.validate_owners(journal, "0" * 64)
                OBSERVER.validate_owners(journal, digest)
                journal.write_text("interrupted")
                with self.assertRaisesRegex(OBSERVER.ObservationError, "operation_owner_active"):
                    OBSERVER.validate_owners(journal, digest)
                journal.unlink()
                (root / "other.lock").mkdir()
                with self.assertRaisesRegex(OBSERVER.ObservationError, "operation_owner_active"):
                    OBSERVER.validate_owners(journal, digest)

    def test_main_routine_reports_remote_failure_and_strict_keeps_artifact_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = {"runner": {"lock_path": str(root / "lock"), "journal_path": str(root / "journal"),
                                 "path": "/runner", "files_from_path": str(root / "files-from"),
                                 "exclude_file_path": "/excludes", "sha256": POLICY,
                                 "artifact_hash_path": str(root / "artifact")},
                      "tools": {name: {"installed_path": f"/{name}"} for name in ["restic", "rclone"]},
                      "repositories": {name: {"id": POLICY} for name in ["games", "nfs", "proton"]}}
            (root / "policy").write_text(json.dumps(policy))
            policy_hash = hashlib.sha256((root / "policy").read_bytes()).hexdigest()
            (root / "artifact").write_text(ARTIFACT)
            (root / "files-from").write_text("/state/auths\n/credentials\n")
            local = snapshot("1" * 64, datetime.now(timezone.utc).isoformat(),
                             tags=["cadence=daily", f"policy={policy_hash}", f"artifact={'c' * 64}"])
            local["paths"] = ["/state", "/credentials"]

            def local_read(policy, repo, arguments):
                if arguments == ["cat", "config"]:
                    return json.dumps({"id": POLICY})
                return json.dumps([local] if repo == "games" else [])

            flags = [f"--{name}" for name in ["runner-sha256", "policy-sha256", "files-from-sha256",
                     "excludes-sha256", "restic-sha256", "rclone-sha256", "games-id", "nfs-id", "proton-id"]]
            argv = ["observer", *[item for flag in flags for item in [flag, POLICY]]]
            with patch.object(OBSERVER, "POLICY_PATH", root / "policy"), patch.object(OBSERVER, "LOCK_PATH", root / "lock"), \
                    patch.object(OBSERVER, "require_regular"), patch.object(OBSERVER, "validate_owners"), \
                    patch.object(OBSERVER, "validate_units", return_value={}), \
                    patch.object(OBSERVER, "local_restic", side_effect=local_read), \
                    patch.object(OBSERVER, "proton_restic", side_effect=OBSERVER.ObservationError("command_failed")):
                with patch.object(sys, "argv", argv + ["--admission", "routine"]), contextlib.redirect_stdout(io.StringIO()) as output:
                    OBSERVER.main()
                result = json.loads(output.getvalue())
                self.assertEqual(result["admission"], "routine")
                self.assertEqual(result["warnings"], ["proton_unavailable", "nfs_replication_lag", "proton_replication_lag"])
                self.assertIsNone(result["repositories"]["proton"])
                with patch.object(sys, "argv", argv):
                    with self.assertRaisesRegex(OBSERVER.ObservationError, "command_failed"):
                        OBSERVER.main()
                with patch.object(OBSERVER, "proton_restic", side_effect=lambda policy, args: json.dumps({"id": POLICY} if args == ["cat", "config"] else [])):
                    with patch.object(sys, "argv", argv):
                        with self.assertRaisesRegex(OBSERVER.ObservationError, "complete_chain_missing"):
                            OBSERVER.main()

    def test_accepts_scheduled_daily_history(self):
        parsed = {"home-lab-restic-daily.timer": {"LastTriggerUSec": "scheduled"}}
        self.assertTrue(OBSERVER.daily_history_present(parsed))

    def test_accepts_completed_manual_daily_chain_after_reboot(self):
        parsed = {
            "home-lab-restic-daily.timer": {"LastTriggerUSec": ""},
            "home-lab-restic-daily-local.service": {
                "ExecMainStartTimestamp": "started",
                "ExecMainExitTimestamp": "finished",
            },
            "home-lab-restic-daily-proton.service": {
                "ExecMainStartTimestamp": "started",
                "ExecMainExitTimestamp": "finished",
            },
        }
        self.assertTrue(OBSERVER.daily_history_present(parsed))

    def test_refuses_incomplete_manual_daily_history(self):
        parsed = {
            "home-lab-restic-daily.timer": {"LastTriggerUSec": ""},
            "home-lab-restic-daily-local.service": {
                "ExecMainStartTimestamp": "started",
                "ExecMainExitTimestamp": "finished",
            },
            "home-lab-restic-daily-proton.service": {
                "ExecMainStartTimestamp": "started",
                "ExecMainExitTimestamp": "",
            },
        }
        self.assertFalse(OBSERVER.daily_history_present(parsed))


if __name__ == "__main__":
    unittest.main()
