#!/usr/bin/env python3
"""Fault injection for storage-token ownership and exact inactive-unit proof.

All device/systemd operations are mocks; no mounts or root privileges are used.
"""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ansible/roles/debian_lifecycle_transaction/files/debian-lifecycle-host-transaction"


class StorageRollbackTests(unittest.TestCase):
    def setUp(self):
        loader = importlib.machinery.SourceFileLoader("storage_rollback_executor", str(SOURCE))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.host = importlib.util.module_from_spec(spec)
        loader.exec_module(self.host)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.token = self.root / "token"
        self.mount = {"path": "/mnt/synthetic", "mode": "0755"}
        self.plan = {"request": {"parameters": {
            "devices": [], "mounts": [self.mount], "activation_path": str(self.token),
        }}}
        self.digest = "a" * 64
        self.commands = []
        self.active = set()
        self.failure = None
        self.mount_checks = []
        self.host.safe_directory = lambda path: Path(path)
        self.host.verify_mount = lambda item, active: self.mount_checks.append(active)
        self.host.run = self.run_command
        patcher = patch.object(self.host.os, "fchown")
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_command(self, argv, **kwargs):
        self.commands.append(tuple(argv))
        if argv[0] == "/usr/bin/systemd-escape":
            unit = argv[-1].strip("/").replace("/", "-") + ".mount"
            return subprocess.CompletedProcess(argv, 0, unit + "\n", "")
        if argv[1] == "show":
            active = argv[2] in self.active
            return subprocess.CompletedProcess(argv, 0,
                "LoadState=loaded\nActiveState=" + ("active" if active else "inactive") +
                "\nSubState=" + ("mounted" if active else "dead") + "\n", "")
        if argv[1] == "start":
            self.active.add(argv[2])
        if argv[1] == "stop":
            self.active.discard(argv[2])
        if self.failure:
            self.failure(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def run_storage(self):
        self.host.storage(self.plan, self.digest)

    def assert_no_starts_or_stops(self):
        self.assertFalse(any(command[1] in {"start", "stop"} for command in self.commands))

    def test_success_keeps_exact_token(self):
        self.run_storage()
        self.assertEqual(self.token.read_bytes(), f"plan_sha256={self.digest}\n".encode())
        self.assertEqual(self.active, {"mnt-synthetic.mount"})
        self.assertEqual(self.token.stat().st_mode & 0o777, 0o600)

    def test_reload_failure_or_interruption_revokes_token(self):
        for error in (OSError("reload failed"), InterruptedError("interrupted")):
            with self.subTest(error=type(error).__name__):
                def fail(argv):
                    if argv[1] == "daemon-reload":
                        raise error
                self.failure = fail
                with self.assertRaises(type(error)):
                    self.run_storage()
                self.assertFalse(self.token.exists())
                self.assert_no_starts_or_stops()

    def test_publication_fsync_failure_revokes_token(self):
        original = self.host.os.fsync
        calls = []
        def fail_first(fd):
            calls.append(fd)
            if len(calls) == 1:
                raise OSError("token fsync failed")
            return original(fd)
        with patch.object(self.host.os, "fsync", side_effect=fail_first):
            with self.assertRaisesRegex(OSError, "token fsync failed"):
                self.run_storage()
        self.assertFalse(self.token.exists())
        self.assertGreaterEqual(len(calls), 2)  # revocation directory is fsynced
        self.assert_no_starts_or_stops()

    def test_short_write_revokes_partial_owned_token(self):
        original = self.host.os.write
        with patch.object(self.host.os, "write", side_effect=lambda fd, data: original(fd, data[:3])):
            with self.assertRaisesRegex(RuntimeError, "short storage token write"):
                self.run_storage()
        self.assertFalse(self.token.exists())
        self.assert_no_starts_or_stops()

    def test_existing_token_is_never_removed(self):
        self.token.write_bytes(b"preexisting authority\n")
        with self.assertRaises(FileExistsError):
            self.run_storage()
        self.assertEqual(self.token.read_bytes(), b"preexisting authority\n")
        self.assert_no_starts_or_stops()

    def test_replaced_token_is_not_deleted_even_with_identical_bytes(self):
        def replace_token(argv):
            if argv[1] == "daemon-reload":
                other = self.root / "replacement"
                other.write_bytes(self.token.read_bytes())
                os.replace(other, self.token)
                raise InterruptedError("replacement during reload")
        self.failure = replace_token
        with self.assertRaisesRegex(RuntimeError, "storage rollback postcondition failed"):
            self.run_storage()
        self.assertTrue(self.token.exists())
        self.assert_no_starts_or_stops()

    def test_modified_token_is_not_deleted(self):
        def change_token(argv):
            if argv[1] == "daemon-reload":
                self.token.write_bytes(b"different authority\n")
                raise OSError("changed during reload")
        self.failure = change_token
        with self.assertRaisesRegex(RuntimeError, "storage rollback postcondition failed"):
            self.run_storage()
        self.assertEqual(self.token.read_bytes(), b"different authority\n")

    def test_partial_start_stops_only_attempted_unit_and_verifies_mount_absence(self):
        self.plan["request"]["parameters"]["mounts"].append({"path": "/mnt/unattempted"})
        original_run = self.host.run
        def run(argv, **kwargs):
            if argv[0] == "/usr/bin/systemd-escape" and argv[-1] == "/mnt/unattempted":
                return subprocess.CompletedProcess(argv, 0, "mnt-unattempted.mount\n", "")
            return original_run(argv, **kwargs)
        self.host.run = run
        def partial_start(argv):
            if argv[1] == "start":
                raise InterruptedError("partial mount start")
        self.failure = partial_start
        with self.assertRaises(InterruptedError):
            self.run_storage()
        self.assertFalse(self.token.exists())
        self.assertFalse(self.active)
        self.assertIn(("/usr/bin/systemctl", "stop", "mnt-synthetic.mount"), self.commands)
        self.assertNotIn(("/usr/bin/systemctl", "stop", "mnt-unattempted.mount"), self.commands)
        self.assertEqual(self.mount_checks, [False, False, False])

    def test_failed_revocation_still_stops_attempted_mount(self):
        def partial_start(argv):
            if argv[1] == "start":
                raise InterruptedError("partial mount start")
        self.failure = partial_start
        with patch.object(Path, "unlink", side_effect=OSError("revocation failed")):
            with self.assertRaisesRegex(RuntimeError, "storage rollback postcondition failed"):
                self.run_storage()
        self.assertTrue(self.token.exists())
        self.assertFalse(self.active)

    def test_two_mount_rollback_continues_and_verifies_each_attempt(self):
        second = {"path": "/mnt/second", "mode": "0755"}
        self.plan["request"]["parameters"]["mounts"].append(second)
        for mode in ("verified", "stop-error", "inactive-proof-error", "still-mounted"):
            with self.subTest(mode=mode):
                self.commands.clear()
                self.mount_checks.clear()
                self.active.clear()
                def run(argv, **kw):
                    if argv[:3] == ["/usr/bin/systemctl", "stop", "mnt-second.mount"] and mode == "stop-error":
                        self.commands.append(tuple(argv))
                        return subprocess.CompletedProcess(argv, 1, "", "stop failed")
                    result = self.run_command(argv, **kw)
                    if argv[:3] == ["/usr/bin/systemctl", "start", "mnt-second.mount"]:
                        raise InterruptedError("second mount partly started")
                    if argv[:3] == ["/usr/bin/systemctl", "show", "mnt-second.mount"] and mode == "inactive-proof-error" and ("/usr/bin/systemctl", "stop", "mnt-second.mount") in self.commands:
                        return subprocess.CompletedProcess(argv, 0, "LoadState=loaded\nActiveState=failed\nSubState=failed\n", "")
                    return result
                def mount(item, active):
                    self.mount_checks.append((item["path"], active))
                    if mode == "still-mounted" and not active and item == second and ("/usr/bin/systemctl", "stop", "mnt-second.mount") in self.commands:
                        raise SystemExit("mount target already active")
                self.host.run = run
                self.host.verify_mount = mount
                expected = InterruptedError if mode == "verified" else RuntimeError
                with self.assertRaises(expected) as raised:
                    self.run_storage()
                if mode != "verified":
                    self.assertIn("storage rollback postcondition failed", str(raised.exception))
                self.assertFalse(self.token.exists())
                self.assertNotIn("mnt-synthetic.mount", self.active)
                self.assertEqual([command[2] for command in self.commands if command[1] == "stop"], ["mnt-second.mount", "mnt-synthetic.mount"])
                self.assertEqual(self.mount_checks[-2:], [("/mnt/synthetic", False), ("/mnt/second", False)])

    def test_active_mount_postcheck_failure_rolls_back_successful_start(self):
        def mount(item, active):
            self.mount_checks.append(active)
            if active:
                raise SystemExit("active mount identity differs")
        self.host.verify_mount = mount
        with self.assertRaisesRegex(SystemExit, "active mount identity differs"):
            self.run_storage()
        self.assertFalse(self.token.exists())
        self.assertFalse(self.active)
        self.assertEqual(self.mount_checks, [False, True, False])

    def test_publication_metadata_failures_revoke_owned_token(self):
        for name in ("fchown", "fchmod"):
            with self.subTest(name=name), patch.object(self.host.os, name, side_effect=OSError(name)):
                with self.assertRaisesRegex(OSError, name):
                    self.run_storage()
            self.assertFalse(self.token.exists())
            self.assert_no_starts_or_stops()

    def test_directory_fsync_failure_requires_verified_revocation(self):
        original = self.host.fsync_parent
        calls = []
        def fail_publication(path):
            calls.append(path)
            if len(calls) == 1:
                raise OSError("publication directory fsync failed")
            return original(path)
        self.host.fsync_parent = fail_publication
        with self.assertRaisesRegex(OSError, "publication directory fsync failed"):
            self.run_storage()
        self.assertFalse(self.token.exists())
        self.assertEqual(calls, [self.token, self.token])
        self.assert_no_starts_or_stops()

    def test_revocation_fsync_failure_still_stops_mounts(self):
        original = self.host.fsync_parent
        def fail_revocation(path):
            if not self.token.exists():
                raise OSError("revocation directory fsync failed")
            return original(path)
        def partial_start(argv):
            if argv[1] == "start":
                raise InterruptedError("partial mount start")
        self.host.fsync_parent = fail_revocation
        self.failure = partial_start
        with self.assertRaisesRegex(RuntimeError, "storage rollback postcondition failed"):
            self.run_storage()
        self.assertFalse(self.token.exists())
        self.assertFalse(self.active)

    def test_hardlinked_token_is_preserved_on_rollback(self):
        def hardlink(argv):
            if argv[1] == "daemon-reload":
                os.link(self.token, self.root / "alias")
                raise InterruptedError("hardlinked during reload")
        self.failure = hardlink
        with self.assertRaisesRegex(RuntimeError, "storage rollback postcondition failed"):
            self.run_storage()
        self.assertTrue(self.token.exists())
        self.assertEqual(self.token.stat().st_nlink, 2)

    def test_token_descriptor_closes_once_on_success_and_failure(self):
        original_open = os.open
        original_close = os.close
        for mode in ("success", "reload-error", "replaced-token", "cleanup-error"):
            with self.subTest(mode=mode):
                if self.token.exists():
                    self.token.unlink()
                self.active.clear()
                token_fds = []
                closed = []
                def open_fd(path, flags, *args, **kw):
                    fd = original_open(path, flags, *args, **kw)
                    if path == self.token:
                        token_fds.append(fd)
                    return fd
                def close_fd(fd):
                    closed.append(fd)
                    return original_close(fd)
                def fail(argv):
                    if argv[1] == "daemon-reload" and mode != "success":
                        if mode == "replaced-token":
                            replacement = self.root / "replacement"
                            replacement.write_bytes(self.token.read_bytes())
                            os.replace(replacement, self.token)
                        raise InterruptedError("reload interrupted")
                self.failure = fail
                original_sync = self.host.fsync_parent
                def sync(path):
                    if mode == "cleanup-error" and not self.token.exists():
                        raise OSError("cleanup fsync failed")
                    return original_sync(path)
                with patch.object(self.host.os, "open", side_effect=open_fd), patch.object(self.host.os, "close", side_effect=close_fd), patch.object(self.host, "fsync_parent", side_effect=sync):
                    if mode == "success":
                        self.run_storage()
                    else:
                        with self.assertRaises((InterruptedError, RuntimeError)):
                            self.run_storage()
                self.assertEqual(len(token_fds), 1)
                self.assertEqual(closed.count(token_fds[0]), 1)
                with self.assertRaises(OSError):
                    os.fstat(token_fds[0])

    def test_inactive_state_requires_successful_exact_observation(self):
        observations = [
            (0, "LoadState=loaded\nActiveState=failed\nSubState=failed\n"),
            (0, "LoadState=loaded\nActiveState=activating\nSubState=start\n"),
            (0, "LoadState=loaded\nActiveState=deactivating\nSubState=stop\n"),
            (0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"),
            (1, "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"),
            (0, ""),
            (0, "LoadState=loaded\nActiveState=inactive\nActiveState=inactive\nSubState=dead\n"),
        ]
        for code, output in observations:
            with self.subTest(code=code, output=output):
                def observe(argv, **kw):
                    if argv[:2] == ["/usr/bin/systemctl", "show"]:
                        self.commands.append(tuple(argv))
                        return subprocess.CompletedProcess(argv, code, output, "")
                    return self.run_command(argv, **kw)
                self.host.run = observe
                with self.assertRaisesRegex(RuntimeError, "not verifiably loaded and inactive"):
                    self.run_storage()
                self.assertFalse(self.token.exists())

    def test_rollback_observer_error_is_not_inactivity(self):
        calls = []
        def broken_observer(argv, **kw):
            calls.append(argv)
            if argv[1] == "show":
                raise OSError("D-Bus unavailable")
            return subprocess.CompletedProcess(argv, 0, "", "")
        self.host.run = broken_observer
        self.assertTrue(self.host.stop_started_units(["first.mount", "second.mount"]))
        self.assertEqual([argv[2] for argv in calls if argv[1] == "stop"], ["second.mount", "first.mount"])

    def test_findmnt_error_does_not_prove_mount_absence(self):
        # Exercise the real mount observer without a Linux mount or root ownership.
        loader = importlib.machinery.SourceFileLoader("real_mount_observer", str(SOURCE))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        host = importlib.util.module_from_spec(spec)
        loader.exec_module(host)
        host.safe_directory = lambda path: self.root
        metadata = SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40755)
        for code, output, error in [(2, "", "error"), (1, "", "error"), (1, "unexpected", "")]:
            with self.subTest(code=code, output=output, error=error):
                host.run = lambda argv, **kw: subprocess.CompletedProcess(argv, code, output, error)
                with patch.object(host.os, "lstat", return_value=metadata):
                    with self.assertRaisesRegex(SystemExit, "absence is unverifiable"):
                        host.verify_mount(self.mount, False)


if __name__ == "__main__":
    unittest.main()
