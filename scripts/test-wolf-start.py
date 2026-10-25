#!/usr/bin/env python3
"""Exercise the crash-dump boundary before a real child process is executed."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
START = ROOT / "services/data/wolf/start-wolf"


class WolfStart(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="wolf-start-")
        self.addCleanup(self.work.cleanup)
        self.cfg = Path(self.work.name)
        self.pending = self.cfg / "backtrace.dump"
        self.previous = self.cfg / "backtrace.previous.dump"
        self.env = {**os.environ, "WOLF_CFG_FOLDER": str(self.cfg)}
        self.command = ["/bin/sh", str(START), sys.executable, "-c"]

    def run_start(self, child="import sys; sys.exit(17)", env=None):
        return subprocess.run(
            [*self.command, child], env=self.env if env is None else env,
            capture_output=True, timeout=5,
        )

    def test_no_dump_executes_child_and_preserves_exit_status(self):
        result = self.run_start()
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertFalse(self.previous.exists())

    def test_empty_truncated_and_valid_dumps_never_reach_child(self):
        for payload in (b"", b"\x01", b"\xff" * 8, b"\x00" * 8):
            with self.subTest(payload=payload):
                self.pending.write_bytes(payload)
                result = self.run_start(
                    "import os,pathlib; "
                    "assert not (pathlib.Path(os.environ['WOLF_CFG_FOLDER']) / 'backtrace.dump').exists()"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.previous.read_bytes(), payload)

    def test_internal_restarts_replace_only_previous_dump(self):
        config = self.cfg / "config.toml"
        config.write_bytes(b"settings unchanged")
        key = self.cfg / "key.pem"
        key.write_bytes(b"synthetic pairing key")
        for payload in (b"first", b"second"):
            self.pending.write_bytes(payload)
            self.pending.chmod(0o600)
            self.assertEqual(self.run_start().returncode, 17)
            self.assertEqual(self.previous.read_bytes(), payload)
            self.assertEqual(self.previous.stat().st_mode & 0o777, 0o600)
        self.assertEqual(config.read_bytes(), b"settings unchanged")
        self.assertEqual(key.read_bytes(), b"synthetic pairing key")
        self.assertEqual(len(list(self.cfg.glob("backtrace*"))), 1)

    def test_unsafe_paths_refuse_to_start_child(self):
        marker = self.cfg / "child-ran"
        child = f"from pathlib import Path; Path({str(marker)!r}).touch()"
        target = self.cfg / "target"
        target.write_bytes(b"unchanged")
        self.pending.symlink_to(target)
        self.assertNotEqual(self.run_start(child).returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(target.read_bytes(), b"unchanged")
        self.pending.unlink()
        self.pending.write_bytes(b"")
        self.previous.mkdir()
        self.assertNotEqual(self.run_start(child).returncode, 0)
        self.assertFalse(marker.exists())
        self.previous.rmdir()
        self.previous.symlink_to(target)
        self.assertNotEqual(self.run_start(child).returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(target.read_bytes(), b"unchanged")

    def test_missing_configuration_directory_refuses_start(self):
        env = dict(self.env)
        env.pop("WOLF_CFG_FOLDER")
        self.assertNotEqual(self.run_start(env=env).returncode, 17)
        env["WOLF_CFG_FOLDER"] = str(self.cfg / "missing")
        self.assertNotEqual(self.run_start(env=env).returncode, 17)

    def test_exec_preserves_signal_delivery(self):
        result = self.run_start("import os,signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual(result.returncode, -signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
