#!/usr/bin/env python3
"""Unit tests for the physical-console root/apex retirement executor."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import inspect
from pathlib import Path
import tempfile
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("root_group_retirement_host", ROOT / "scripts/controller/proxmox-root-group-retirement-host.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class RootGroupHostTests(unittest.TestCase):
    def test_canary_requires_every_positive_boundary(self) -> None:
        names = {"ansible_plan", "ansible_deploy", "firewall_apply", "human_tailscale", "root_group_state", "retained_assets", "pve_tokens"}
        receipt = {"format": "home-lab-proxmox-root-group-canary-v1", "plan_sha256": "a" * 64,
                   "captured_at": datetime.now(timezone.utc).isoformat(), "checks": {name: True for name in names}}
        MODULE.validate_canary(receipt, "a" * 64)
        receipt["checks"]["pve_tokens"] = False
        with self.assertRaises(SystemExit):
            MODULE.validate_canary(receipt, "a" * 64)

    def test_watchdog_rollback_accepts_every_mutation_phase(self) -> None:
        source = inspect.getsource(MODULE.rollback)
        for status in ("prepared", "mutation-started", "awaiting-canary"):
            self.assertIn(status, source)
        self.assertIn("acquire_lock(blocking=True)", source)

    def test_immediate_failure_restores_without_reacquiring_lock(self) -> None:
        source = inspect.getsource(MODULE.apply)
        self.assertIn("restore_from_journal(journal, current)", source)
        self.assertNotIn("rollback(journal)", source)

    def test_planner_and_host_regular_metadata_schemas_match(self) -> None:
        planner_source = (ROOT / "scripts/controller/proxmox-root-group-retirement.py").read_text()
        self.assertIn('"directory":stat.S_ISDIR(s.st_mode)', planner_source)
        with tempfile.NamedTemporaryFile() as handle:
            value = MODULE.retained_metadata(handle.name)
        self.assertEqual(set(value), {"exists", "uid", "gid", "mode", "nlink", "regular", "directory", "symlink", "size", "sha256"})

    def test_preconditions_reject_token_drift(self) -> None:
        records = {path: "apex-record" for path in MODULE.DATABASE_PATHS}
        plan = {"before": {"root_groups": ["apex", "root"], "apex": {"exists": True, "gid": 1000, "members": ["root"]},
                           "database_records": {path: {"count": 1, "line": line, "sha256": "a" * 64} for path, line in records.items()}},
                "retained_assets_before": {}, "retained_pve_tokens": MODULE.EXPECTED_TOKENS}
        with mock.patch.object(MODULE, "database_records", return_value=records), mock.patch.object(MODULE, "sha", return_value="a" * 64), \
             mock.patch.object(MODULE, "root_group_state", return_value={"root_groups": ["apex", "root"], "apex": {"exists": True, "gid": 1000, "members": ["root"]}}), \
             mock.patch.object(MODULE, "retained_metadata_valid", return_value=True), mock.patch.object(MODULE, "pve_tokens", return_value=[]):
            self.assertFalse(MODULE.before_matches(plan))

    def test_postcondition_requires_exact_group_and_gshadow_records(self) -> None:
        plan = {"after": {"root_groups": ["root"], "apex": {"exists": True, "gid": 1000, "members": []},
                          "database_records": {"/etc/group": {"line": "expected"}, "/etc/gshadow": {"line": "expected"}}}}
        with mock.patch.object(MODULE, "root_group_state", return_value={"root_groups": ["root"], "apex": {"exists": True, "gid": 1000, "members": []}}), \
             mock.patch.object(MODULE, "database_state", return_value={"/etc/group": {"line": "expected"}, "/etc/gshadow": {"line": "stale"}}):
            self.assertFalse(MODULE.postcondition_matches(plan))

    def test_restore_targets_only_group_databases(self) -> None:
        self.assertEqual(set(MODULE.DATABASE_PATHS), {"/etc/group", "/etc/gshadow"})
        current = {"before_sha256": "b" * 64}
        before = {"database_records": {path: "apex-record" for path in MODULE.DATABASE_PATHS},
                  "root_group_state": {"root_groups": ["apex", "root"], "apex": {"exists": True, "gid": 1000, "members": ["root"]}}}
        plan = {"retained_assets_before": {}, "retained_pve_tokens": MODULE.EXPECTED_TOKENS}
        completed = mock.Mock(returncode=0)
        with mock.patch.object(MODULE, "load_private", side_effect=[(before, b"before"), (plan, b"plan")]), mock.patch.object(MODULE, "sha", return_value="b" * 64), \
             mock.patch.object(MODULE, "restore_database_records") as restore, mock.patch.object(MODULE, "root_group_state", return_value=before["root_group_state"]), \
             mock.patch.object(MODULE, "database_records", return_value=before["database_records"]), mock.patch.object(MODULE, "retained_metadata_valid", return_value=True), \
             mock.patch.object(MODULE, "pve_tokens", return_value=MODULE.EXPECTED_TOKENS), mock.patch.object(MODULE.subprocess, "run", return_value=completed):
            MODULE.restore_from_journal(Path("/journal"), current)
        restore.assert_called_once_with(before["database_records"])


if __name__ == "__main__":
    unittest.main()
