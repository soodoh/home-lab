#!/usr/bin/env python3
"""Unit tests for the physical-console tofu identity retirement executor."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import inspect
from pathlib import Path
import stat
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("tofu_retirement_host", ROOT / "scripts/controller/proxmox-tofu-identity-retirement-host.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def host_plan(identity: str = "tofu-apply") -> dict:
    sequence = 2 if identity == "tofu-apply" else 1
    assets = {
        f"/home/{identity}": {"exists": True},
        f"/home/{identity}/.ssh": {"exists": True},
        f"/home/{identity}/.ssh/authorized_keys": {"exists": True},
        f"/etc/sudoers.d/{identity}": {"exists": True},
    }
    if identity == "tofu-apply":
        assets["/usr/local/libexec/home-lab/proxmox-apply-transport"] = {"exists": True}
    return {
        "format": "home-lab-proxmox-tofu-identity-retirement-plan-v1", "sequence": sequence,
        "kind": f"host-{identity}-retirement", "scope": "proxmox-host", "authorized": False,
        "before": {"account": {"exists": True, "active_pids": []}, "group": {"exists": True}, "assets": assets},
        "after": {"account": {"exists": False}, "group": {"exists": False},
                  "assets": {path: {"exists": False} for path in assets}},
    }


class HostRetirementExecutorTests(unittest.TestCase):
    def test_identity_is_bound_to_exact_host_plan(self) -> None:
        self.assertEqual(MODULE.identity_from_plan(host_plan("tofu-plan")), "tofu-plan")
        self.assertEqual(MODULE.identity_from_plan(host_plan("tofu-apply")), "tofu-apply")
        invalid = host_plan(); invalid["scope"] = "controller"
        with self.assertRaises(SystemExit):
            MODULE.identity_from_plan(invalid)

    def test_rollback_capture_excludes_global_databases_and_uses_only_top_level_home(self) -> None:
        paths = MODULE.backup_paths(host_plan(), "tofu-apply")
        self.assertEqual(paths[0], "/home/tofu-apply")
        self.assertTrue(set(MODULE.DATABASE_PATHS).isdisjoint(paths))
        self.assertNotIn("/home/tofu-apply/.ssh", paths)
        self.assertNotIn("/home/tofu-apply/.ssh/authorized_keys", paths)
        self.assertIn("/etc/sudoers.d/tofu-apply", paths)
        self.assertIn("/usr/local/libexec/home-lab/proxmox-apply-transport", paths)

    def test_access_evidence_requires_every_replacement_proof(self) -> None:
        evidence = {"proofs": {"strict_host_key": True,
            "plan_observer": {"positive": True, "injection_rejected": True},
            "deploy_transport": {"positive": True, "injection_rejected": True},
            "firewall_transport": {"positive": True, "injection_rejected": True},
            "human_session": {"positive": True}, "tailnet_policy": {"tests_present": True, "live_plan_noop": True},
            "root_keys": {"complete": True},
            "console": {"attested": True, "method": "physical-console-bootstrap-install-and-verify"}}}
        self.assertTrue(MODULE.access_proofs_complete(evidence))
        evidence["proofs"]["firewall_transport"]["positive"] = False
        self.assertFalse(MODULE.access_proofs_complete(evidence))

    def test_canary_requires_all_positive_independent_checks(self) -> None:
        checks = {name: True for name in (
            "ansible_plan", "ansible_deploy", "firewall_apply", "human_tailscale",
            "retired_identity_rejected", "retained_assets_unchanged",
        )}
        receipt = {"format": "home-lab-proxmox-tofu-retirement-canary-v1", "plan_sha256": "a" * 64,
                   "identity": "tofu-plan", "captured_at": datetime.now(timezone.utc).isoformat(), "checks": checks}
        MODULE.validate_canary(receipt, "a" * 64, "tofu-plan")
        receipt["checks"]["firewall_apply"] = False
        with self.assertRaises(SystemExit):
            MODULE.validate_canary(receipt, "a" * 64, "tofu-plan")

    def test_physical_console_gate_rejects_nonroot_or_ssh(self) -> None:
        with mock.patch.object(MODULE.os, "geteuid", return_value=1000):
            with self.assertRaises(SystemExit):
                MODULE.require_root_console()
        with mock.patch.object(MODULE.os, "geteuid", return_value=0), mock.patch.dict(MODULE.os.environ, {"SSH_CONNECTION": "present"}):
            with self.assertRaises(SystemExit):
                MODULE.require_root_console()

    def test_watchdog_name_is_plan_bound(self) -> None:
        self.assertEqual(MODULE.watchdog_unit("b" * 64), "home-lab-tofu-retirement-bbbbbbbbbbbbbbbb")

    def test_private_journal_directory_accepts_normal_directory_link_count(self) -> None:
        path = mock.Mock(); path.lstat.return_value = mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_nlink=3)
        MODULE.ensure_private_directory(path)
        path.mkdir.assert_called_once_with(mode=0o700, exist_ok=True)

    def test_mutation_uses_userdel_without_unreviewed_remove_side_effects(self) -> None:
        plan = host_plan("tofu-plan")
        completed = mock.Mock(returncode=0)
        directory_info = mock.Mock(st_mode=stat.S_IFDIR | 0o700)
        with mock.patch.object(MODULE.Path, "unlink"), mock.patch.object(MODULE.subprocess, "run", return_value=completed) as run, \
             mock.patch.object(MODULE, "group", return_value={"exists": False}), mock.patch.object(MODULE.os, "lstat", return_value=directory_info), \
             mock.patch.object(MODULE.shutil, "rmtree"):
            MODULE.mutate(plan, "tofu-plan")
        self.assertEqual(run.call_args_list[0].args[0], ("/usr/sbin/userdel", "tofu-plan"))

    def test_rollback_restores_only_target_identity_database_records(self) -> None:
        state = {"rollback_archive_sha256": "a" * 64}; before = {"rollback_archive_sha256": "a" * 64,
                "identity": "tofu-plan", "identity_database_records": {path: "record" for path in MODULE.DATABASE_PATHS}}
        info = mock.Mock(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1); completed = mock.Mock(returncode=0)
        with mock.patch.object(MODULE, "journal_state", return_value=state), mock.patch.object(MODULE, "load_private", return_value=(before, b"before\n")), \
             mock.patch.object(MODULE.Path, "lstat", return_value=info), mock.patch.object(MODULE.Path, "read_bytes", return_value=b"archive"), \
             mock.patch.object(MODULE, "sha", return_value="a" * 64), mock.patch.object(MODULE.subprocess, "run", return_value=completed), \
             mock.patch.object(MODULE, "restore_identity_database_records") as restore:
            MODULE.restore_archive(Path("/journal"))
        restore.assert_called_once_with("tofu-plan", before["identity_database_records"])

    def test_commit_persists_committed_state_before_watchdog_disarm(self) -> None:
        source = inspect.getsource(MODULE.commit)
        self.assertLess(source.index("set_journal_state(journal, committed)"), source.index("disarm_watchdog(digest)"))

    def test_watchdog_rollback_uses_blocking_lock(self) -> None:
        source = inspect.getsource(MODULE.rollback_journal)
        self.assertIn("acquire_lock(blocking=True)", source)


if __name__ == "__main__":
    unittest.main()
