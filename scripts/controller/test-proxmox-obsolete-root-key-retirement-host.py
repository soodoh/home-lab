#!/usr/bin/env python3
"""Safety tests for the obsolete Proxmox root-key host transaction."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import inspect
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("obsolete_root_key_host", ROOT / "scripts/controller/proxmox-obsolete-root-key-retirement-host.py")
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)


class ObsoleteRootKeyHostTests(unittest.TestCase):
    def test_canary_requires_root_lan_recovery_and_every_boundary(self) -> None:
        names = {"ansible_plan", "ansible_deploy", "firewall_apply", "human_tailscale", "root_lan_recovery", "obsolete_keys_absent", "retained_keys_exact", "retained_assets", "pve_tokens", "sshd_policy"}
        receipt = {"format": "home-lab-proxmox-obsolete-root-key-canary-v1", "plan_sha256": "a" * 64, "captured_at": datetime.now(timezone.utc).isoformat(), "checks": {name: True for name in names}}
        MODULE.validate_canary(receipt, "a" * 64)
        receipt["checks"]["root_lan_recovery"] = False
        with self.assertRaises(SystemExit): MODULE.validate_canary(receipt, "a" * 64)

    def test_watchdog_accepts_every_mutation_phase(self) -> None:
        source = inspect.getsource(MODULE.rollback)
        for status in ("prepared", "mutation-started", "awaiting-canary"): self.assertIn(status, source)

    def test_relocated_watchdog_bundle_imports_without_repository_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory); shutil.copy2(ROOT / "scripts/controller/proxmox-obsolete-root-key-retirement-host.py", target / "rollback-executor.py"); shutil.copy2(ROOT / "scripts/controller/proxmox-obsolete-root-key-retirement.py", target / "proxmox-obsolete-root-key-retirement.py")
            result = subprocess.run((sys.executable, str(target / "rollback-executor.py"), "--help"), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_watchdog_lock_blocks_instead_of_consuming_timer_attempt(self) -> None:
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
        with mock.patch.object(MODULE.os, "open", return_value=7), mock.patch.object(MODULE.os, "fstat", return_value=info), mock.patch.object(MODULE.fcntl, "flock") as flock:
            self.assertEqual(MODULE.acquire_lock(blocking=True), 7)
        flock.assert_called_once_with(7, MODULE.fcntl.LOCK_EX)

    def test_concurrent_drift_is_captured_and_restored_without_overwrite(self) -> None:
        before = b"before-exact"; after = b"candidate-exact"; unknown = b"concurrent-recovery-key"; digest = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "authorized_keys"; key.write_bytes(before); candidate = key.with_name(f".authorized_keys.home-lab-{digest}.candidate"); backup = key.with_name(f".authorized_keys.home-lab-{digest}.rollback")
            plan = {"before": {"bytes_hex": before.hex()}, "after": {"bytes_hex": after.hex()}}
            def create(path: Path, raw: bytes):
                path.write_bytes(raw); key.write_bytes(unknown)
            def no_replace(source: Path, target: Path):
                if target.exists(): raise FileExistsError(target)
                os.rename(source, target)
            with mock.patch.object(MODULE, "KEY_PATH", key), mock.patch.object(MODULE, "verify_noreplace_support"), mock.patch.object(MODULE, "create_candidate", side_effect=create), mock.patch.object(MODULE, "rename_noreplace", side_effect=no_replace), mock.patch.object(MODULE, "fsync_key_directory"):
                with self.assertRaises(RuntimeError): MODULE.install_candidate(plan, digest)
            self.assertEqual(key.read_bytes(), unknown); self.assertFalse(candidate.exists()); self.assertFalse(backup.exists())

    def test_transactional_install_failure_is_followed_by_exact_rollback(self) -> None:
        plan = {"before": {"bytes_hex": "01"}, "after": {"bytes_hex": "00"}}; current_state = {"status": "mutation-started", "plan_sha256": "a" * 64, "before_sha256": "b" * 64}
        with mock.patch.object(MODULE, "require_root_console"), mock.patch.object(MODULE, "acquire_lock", return_value=9), mock.patch.object(MODULE, "reject_protected_locks"), mock.patch.object(MODULE, "validate_plan", return_value=(plan, b"plan", "a" * 64)), mock.patch.object(MODULE, "validate_approval"), mock.patch.dict(MODULE.os.environ, {"PROXMOX_OBSOLETE_ROOT_KEY_RETIREMENT_CONFIRMED": f"apply-proxmox-obsolete-root-keys-{'a' * 64}"}), mock.patch.object(MODULE, "capture"), mock.patch.object(MODULE, "exact_before_matches", return_value=True), mock.patch.object(MODULE, "arm"), mock.patch.object(MODULE, "state", return_value=current_state), mock.patch.object(MODULE, "set_state"), mock.patch.object(MODULE, "install_candidate", side_effect=RuntimeError("transactional failure")), mock.patch.object(MODULE, "restore_from_journal") as restore, mock.patch.object(MODULE, "disarm") as disarm, mock.patch.object(MODULE.os, "close"):
            with self.assertRaises(RuntimeError): MODULE.apply(Path("/plan"), Path("/evidence"), Path("/authorization"))
        restore.assert_called_once(); disarm.assert_called_once_with("a" * 64)

    def test_post_capture_preconditions_are_revalidated_before_watchdog(self) -> None:
        source = inspect.getsource(MODULE.apply)
        self.assertLess(source.index("capture("), source.index("exact_before_matches"))
        self.assertLess(source.index("exact_before_matches"), source.index("arm("))

    def test_watchdog_durability_failure_prevents_mutation_entry(self) -> None:
        plan = {"before": {"bytes_hex": "01"}, "after": {"bytes_hex": "00"}}; digest = "a" * 64
        with mock.patch.object(MODULE, "require_root_console"), mock.patch.object(MODULE, "acquire_lock", return_value=9), mock.patch.object(MODULE, "reject_protected_locks"), mock.patch.object(MODULE, "validate_plan", return_value=(plan, b"plan", digest)), mock.patch.object(MODULE, "validate_approval"), mock.patch.dict(MODULE.os.environ, {"PROXMOX_OBSOLETE_ROOT_KEY_RETIREMENT_CONFIRMED": f"apply-proxmox-obsolete-root-keys-{digest}"}), mock.patch.object(MODULE, "capture"), mock.patch.object(MODULE, "exact_before_matches", return_value=True), mock.patch.object(MODULE, "arm", side_effect=SystemExit("durability barrier")), mock.patch.object(MODULE, "set_state") as set_state, mock.patch.object(MODULE, "install_candidate") as install, mock.patch.object(MODULE.os, "close"):
            with self.assertRaises(SystemExit): MODULE.apply(Path("/plan"), Path("/evidence"), Path("/authorization"))
        set_state.assert_not_called(); install.assert_not_called()

    def test_exact_after_rejects_missing_retained_key(self) -> None:
        plan = {"after": {"records": []}}
        current = {"records": [{"fingerprint": MODULE.PLANNER.RETAINED_FINGERPRINTS[0]}]}
        with mock.patch.object(MODULE, "key_snapshot", return_value=current), mock.patch.object(MODULE, "retained_matches", return_value=True):
            self.assertFalse(MODULE.exact_after_matches(plan))

    def test_rollback_restores_exact_backup_transactionally(self) -> None:
        before = b"before"; after = b"candidate"; digest = "a" * 64; plan = {"before": {"exact": True}, "after": {"bytes_hex": after.hex()}}; current = {"plan_sha256": digest, "before_sha256": digest}
        info = mock.Mock(st_mode=0o100600, st_uid=0, st_nlink=1); before_path = mock.Mock(); before_path.lstat.return_value = info; before_path.read_bytes.return_value = before; journal = mock.MagicMock(); journal.__truediv__.side_effect = lambda name: before_path if name == "before.bin" else Path("/plan.json")
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "authorized_keys"; key.write_bytes(after); candidate = Path(directory) / "candidate"; backup = Path(directory) / "backup"; backup.write_bytes(before)
            def no_replace(source: Path, target: Path):
                if target.exists(): raise FileExistsError(target)
                os.rename(source, target)
            with mock.patch.object(MODULE, "KEY_PATH", key), mock.patch.object(MODULE, "transaction_paths", return_value=(candidate, backup)), mock.patch.object(MODULE, "rename_noreplace", side_effect=no_replace), mock.patch.object(MODULE, "fsync_key_directory"), mock.patch.object(MODULE, "sha", return_value=digest), mock.patch.object(MODULE, "load_private", return_value=(plan, b"plan")), mock.patch.object(MODULE, "key_snapshot", return_value=plan["before"]), mock.patch.object(MODULE, "retained_matches", return_value=True): MODULE.restore_from_journal(journal, current)
            self.assertEqual(key.read_bytes(), before); self.assertFalse(candidate.exists()); self.assertFalse(backup.exists())

    def test_unknown_drift_blocks_rollback_without_overwrite(self) -> None:
        before = b"before"; after = b"candidate"; unknown = b"unknown"; digest = "a" * 64; plan = {"before": {"exact": True}, "after": {"bytes_hex": after.hex()}}; current = {"plan_sha256": digest, "before_sha256": digest}
        info = mock.Mock(st_mode=0o100600, st_uid=0, st_nlink=1); before_path = mock.Mock(); before_path.lstat.return_value = info; before_path.read_bytes.return_value = before; journal = mock.MagicMock(); journal.__truediv__.side_effect = lambda name: before_path if name == "before.bin" else Path("/plan.json")
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "authorized_keys"; key.write_bytes(unknown); candidate = Path(directory) / "candidate"; backup = Path(directory) / "backup"; backup.write_bytes(before)
            with mock.patch.object(MODULE, "KEY_PATH", key), mock.patch.object(MODULE, "transaction_paths", return_value=(candidate, backup)), mock.patch.object(MODULE, "sha", return_value=digest), mock.patch.object(MODULE, "load_private", return_value=(plan, b"plan")):
                with self.assertRaises(SystemExit): MODULE.restore_from_journal(journal, current)
            self.assertEqual(key.read_bytes(), unknown); self.assertEqual(backup.read_bytes(), before)

    def test_authorization_rejects_future_extended_and_overbound_timestamps(self) -> None:
        base = datetime.now(timezone.utc).replace(microsecond=0); evidence_raw = b"evidence"; evidence_digest = MODULE.sha(evidence_raw)
        evidence = {"format": "home-lab-proxmox-access-evidence-v1", "commit": "c", "contract_sha256": "d", "inventory_sha256": "i", "host_key_fingerprint": MODULE.PLANNER.FINGERPRINT, "expires_at": (base + timedelta(minutes=20)).isoformat().replace("+00:00", "Z")}
        plan = {"commit": "c", "contract_sha256": "d", "inventory_sha256": "i", "expires_at": (base + timedelta(minutes=20)).isoformat().replace("+00:00", "Z"), "blockers": ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"], "findings": []}
        cases = [(base + timedelta(minutes=1), base + timedelta(minutes=2), plan["expires_at"]), (base - timedelta(seconds=1), base + timedelta(minutes=16), plan["expires_at"]), (base - timedelta(seconds=1), base + timedelta(minutes=10), (base + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"))]
        for created, expires, plan_expiry in cases:
            candidate_plan = {**plan, "expires_at": plan_expiry}; confirmation = f"authorize-proxmox-obsolete-root-keys-{'a' * 64}-{evidence_digest}"; authorization = {"format": "home-lab-proxmox-obsolete-root-key-retirement-authorization-v1", "plan_sha256": "a" * 64, "evidence_sha256": evidence_digest, "created_at": created.isoformat().replace("+00:00", "Z"), "expires_at": expires.isoformat().replace("+00:00", "Z"), "confirmation": confirmation, "authorized": True}
            with self.subTest(created=created, expires=expires), mock.patch.object(MODULE, "load_private", side_effect=[(evidence, evidence_raw), (authorization, b"authorization")]), mock.patch.object(MODULE, "access_proofs_complete", return_value=True), mock.patch.object(MODULE.PLANNER, "evidence_keys_match", return_value=True):
                with self.assertRaises(SystemExit): MODULE.validate_approval(candidate_plan, "a" * 64, Path("/evidence"), Path("/authorization"))

    def test_commit_write_failure_never_disarms_watchdog(self) -> None:
        plan_raw = b"plan"; digest = MODULE.sha(plan_raw); canary_raw = b"canary"; confirmation = f"commit-proxmox-obsolete-root-keys-{digest}-{MODULE.sha(canary_raw)}"
        with mock.patch.object(MODULE, "require_root_console"), mock.patch.object(MODULE, "acquire_lock", return_value=9), mock.patch.object(MODULE, "state", return_value={"status": "awaiting-canary"}), mock.patch.object(MODULE, "load_private", side_effect=[({}, plan_raw), ({}, canary_raw)]), mock.patch.object(MODULE, "validate_canary"), mock.patch.dict(MODULE.os.environ, {"PROXMOX_OBSOLETE_ROOT_KEY_RETIREMENT_CONFIRMED": confirmation}), mock.patch.object(MODULE, "exact_after_matches", return_value=True), mock.patch.object(MODULE, "write_private", side_effect=[None, OSError("receipt fsync failure")]), mock.patch.object(MODULE, "disarm") as disarm, mock.patch.object(MODULE.os, "close"):
            with self.assertRaises(OSError): MODULE.commit(Path("/journal"), Path("/canary"))
        disarm.assert_not_called()

    def test_commit_persists_receipt_before_disarming(self) -> None:
        source = inspect.getsource(MODULE.commit)
        self.assertLess(source.index('write_private(journal / "receipt.json"'), source.index("disarm(digest)"))


if __name__ == "__main__": unittest.main()
