#!/usr/bin/env python3
import importlib.util
import inspect
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "final_keys_host", ROOT / "scripts/controller/proxmox-final-key-retirement-host.py"
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

    def test_shared_access_transaction_lock_is_used(self):
        self.assertEqual(str(M.LOCK), M.P.SHARED_LOCK)

    def test_firewall_restore_sets_ownership_before_writing_secret_bytes(self):
        source = inspect.getsource(M.restore_file)
        self.assertLess(source.index("os.fchown"), source.index("h.write(raw)"))
        self.assertLess(
            source.index("rollback ownership differs before write"),
            source.index("h.write(raw)"),
        )

    def test_rollback_restores_pmxcfs_target_before_symlink_and_firewall(self):
        calls = []
        plan = {"before": {str(path): {} for path in (M.ROOT, M.LINK, M.FIREWALL)}}
        with (
            mock.patch.object(M, "load_private", return_value=(plan, b"")),
            mock.patch.object(
                M, "restore_file", side_effect=lambda j, p, i: calls.append(p)
            ),
            mock.patch.object(M, "exact_before", return_value=True),
        ):
            M.restore(Path("/journal"), {})
        self.assertEqual(calls, [M.ROOT, M.LINK, M.FIREWALL])

    def test_unknown_drift_is_preserved(self):
        item = {
            "exists": True,
            "uid": 0,
            "gid": 0,
            "mode": "0600",
            "regular": True,
            "symlink": False,
            "nlink": 1,
            "size": 1,
            "sha256": "0" * 64,
            "bytes_hex": "00",
        }
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory)
            with (
                mock.patch.object(
                    M, "meta", return_value={"exists": True, "sha256": "f" * 64}
                ),
                self.assertRaises(SystemExit),
            ):
                M.restore_file(journal, Path("/target"), item)

    def test_owned_partial_restore_is_retried_from_durable_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "journal"
            journal.mkdir()
            target = Path(directory) / "target"
            expected = b"complete"
            target.write_bytes(expected[:3])
            target.chmod(0o600)
            info = target.lstat()
            item = {
                "exists": True,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": "0600",
                "regular": True,
                "symlink": False,
                "nlink": 1,
                "size": len(expected),
                "sha256": M.sha(expected),
                "bytes_hex": expected.hex(),
            }
            marker, marker_value = M.rollback_marker(journal, target, item)
            M.write_private(marker, M.canonical(marker_value))
            with (
                mock.patch.object(M, "fsync_dir"),
                mock.patch.object(
                    M,
                    "load_private",
                    return_value=(marker_value, M.canonical(marker_value)),
                ),
            ):
                M.restore_file(journal, target, item)
            self.assertEqual(target.read_bytes(), expected)
            self.assertFalse(marker.exists())

    def test_crash_after_partial_unlink_can_restore_all_owned_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"
            link = Path(d) / "link"
            firewall = Path(d) / "firewall"
            root.write_bytes(b"r")
            os.symlink(str(root), link)
            firewall.write_bytes(b"f")
            for p, uid, gid in (
                (root, os.getuid(), os.getgid()),
                (firewall, os.getuid(), os.getgid()),
            ):
                os.chmod(p, 0o600)
            before = {str(p): M.meta(p) for p in (root, link, firewall)}
            link.unlink()
            firewall.unlink()
            plan = {"before": before}
            journal = Path(d) / "j"
            journal.mkdir()
            (journal / "plan.json").write_text("{}")
            with (
                mock.patch.object(M, "ROOT", root),
                mock.patch.object(M, "LINK", link),
                mock.patch.object(M, "FIREWALL", firewall),
                mock.patch.object(M, "PATHS", (root, link, firewall)),
                mock.patch.object(M, "load_private", return_value=(plan, b"")),
                mock.patch.object(M, "exact_before", return_value=True),
            ):
                M.restore(journal, {})
            self.assertTrue(link.is_symlink())
            self.assertEqual(firewall.read_bytes(), b"f")

    def test_relocated_watchdog_bundle_imports(self):
        with tempfile.TemporaryDirectory() as d:
            for name in (
                "proxmox-final-key-retirement.py",
                "proxmox-final-key-retirement-host.py",
            ):
                shutil.copy2(ROOT / "scripts/controller" / name, Path(d) / name)
            result = subprocess.run(
                (
                    sys.executable,
                    str(Path(d) / "proxmox-final-key-retirement-host.py"),
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
