#!/usr/bin/env python3
import importlib.util
import inspect
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "openssh_host", ROOT / "scripts/controller/proxmox-openssh-tightening-host.py"
)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class Tests(unittest.TestCase):
    def test_watchdog_accepts_every_mutation_phase(self):
        source = inspect.getsource(M.rollback)
        for phase in ("prepared", "mutation-started", "awaiting-canary"):
            self.assertIn(phase, source)

    def test_watchdog_uses_reboot_persistent_absolute_deadline(self):
        source = inspect.getsource(M.arm)
        self.assertIn("OnCalendar=", source)
        self.assertIn("Persistent=true", source)
        apply_source = inspect.getsource(M.apply)
        self.assertLess(
            apply_source.index('"watchdog_deadline"'),
            apply_source.index("arm(j, digest, deadline)"),
        )
        self.assertLess(
            apply_source.index("arm(j, digest, deadline)"),
            apply_source.index('"status": "mutation-started"'),
        )

    def test_shared_gate_and_committed_final_key_receipt_are_mandatory(self):
        self.assertEqual(str(M.LOCK), M.P.B.SHARED_LOCK)
        source = inspect.getsource(M.before)
        self.assertIn("final_key_receipt()", source)

    def test_install_validates_candidate_and_active_config_before_reload(self):
        source = inspect.getsource(M.install)
        self.assertLess(
            source.index('("/usr/sbin/sshd", "-t", "-f"'), source.index("os.replace")
        )
        self.assertLess(
            source.rindex('("/usr/sbin/sshd", "-t")'), source.index("reload_ssh()")
        )

    def test_unknown_active_drift_blocks_rollback_without_overwrite(self):
        plan = {"before": {"config": {"bytes_hex": b"prior".hex()}}}
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / "config"
            config.write_bytes(b"unknown")
            journal = Path(d) / "journal"
            journal.mkdir()
            with (
                mock.patch.object(M, "CONFIG", config),
                mock.patch.object(M, "candidate", return_value=journal / "candidate"),
                mock.patch.object(M, "load_private", return_value=(plan, b"")),
            ):
                with self.assertRaises(SystemExit):
                    M.restore(journal, {})
            self.assertEqual(config.read_bytes(), b"unknown")

    def test_crash_candidate_is_removed_before_exact_prior_reload(self):
        plan = {"before": {"config": {"bytes_hex": b"prior".hex()}}}
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / "config"
            config.write_bytes(M.P.DESIRED)
            journal = Path(d) / "journal"
            journal.mkdir()
            candidate = journal / "candidate"
            candidate.write_bytes(M.P.DESIRED)
            with (
                mock.patch.object(M, "CONFIG", config),
                mock.patch.object(M, "candidate", return_value=candidate),
                mock.patch.object(M, "load_private", return_value=(plan, b"")),
                mock.patch.object(
                    M, "write_config", side_effect=lambda p, r: p.write_bytes(r)
                ),
                mock.patch.object(M, "fsync_dir"),
                mock.patch.object(
                    M.subprocess, "run", return_value=mock.Mock(returncode=0)
                ),
                mock.patch.object(M, "reload_ssh"),
                mock.patch.object(M, "before", return_value=True),
            ):
                M.restore(journal, {})
            self.assertFalse(candidate.exists())
            self.assertEqual(config.read_bytes(), b"prior")

    def test_partial_owned_candidate_is_removed_during_retry(self):
        plan = {"before": {"config": {"bytes_hex": b"prior".hex()}}}
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.write_bytes(b"prior")
            journal = Path(directory) / "journal"
            journal.mkdir()
            candidate = journal / "candidate"
            candidate.write_bytes(M.P.DESIRED[:8])
            with (
                mock.patch.object(M, "CONFIG", config),
                mock.patch.object(M, "candidate", return_value=candidate),
                mock.patch.object(M, "load_private", return_value=(plan, b"")),
                mock.patch.object(
                    M.subprocess, "run", return_value=mock.Mock(returncode=0)
                ),
                mock.patch.object(M, "reload_ssh"),
                mock.patch.object(M, "before", return_value=True),
            ):
                M.restore(journal, {})
            self.assertFalse(candidate.exists())
            self.assertEqual(config.read_bytes(), b"prior")

    def test_relocated_watchdog_bundle_imports(self):
        with tempfile.TemporaryDirectory() as d:
            for name in (
                "proxmox-final-key-retirement.py",
                "proxmox-openssh-tightening.py",
                "proxmox-openssh-tightening-host.py",
            ):
                shutil.copy2(ROOT / "scripts/controller" / name, Path(d) / name)
            result = subprocess.run(
                (
                    sys.executable,
                    str(Path(d) / "proxmox-openssh-tightening-host.py"),
                    "--help",
                ),
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_receipt_is_persisted_before_watchdog_disarm(self):
        source = inspect.getsource(M.commit)
        self.assertLess(
            source.index('write_private(j / "receipt.json"'),
            source.index("disarm(digest)"),
        )


if __name__ == "__main__":
    unittest.main()
