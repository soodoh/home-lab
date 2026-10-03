#!/usr/bin/env python3
"""Exercise mount consumers against native rsync's inode-preserving publication."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import contextlib
import io
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compose_mounts", ROOT / "scripts/compose-mounts.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
# Load in setUpClass so the test file itself can run before the adapter exists.


class ComposeMountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SPEC.loader.exec_module(MODULE)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.current = self.root / "current"
        self.incoming = self.root / "incoming"
        self.credentials = self.root / "credentials"
        for path in [self.current, self.incoming, self.credentials]:
            path.mkdir()
        (self.current / "config").write_text("original")
        (self.incoming / "config").write_text("original")
        (self.current / "scripts").mkdir()
        (self.incoming / "scripts").mkdir()
        for path in [self.current, self.incoming]:
            (path / "scripts" / "hook").write_text("hook")
        (self.credentials / "secret").write_text("secret-never-in-observation")
        self.mounts = {
            "app": [self.mount(self.current / "config")],
            "directory-app": [self.mount(self.current / "scripts")],
            "secret-app": [self.mount(self.credentials / "secret")],
            "database": [self.mount(self.root / "mutable-state", rw=True)],
        }

    @staticmethod
    def mount(path, rw=False):
        return {"Type": "bind", "Source": str(path), "RW": rw}

    def snapshot(self):
        return MODULE.observe_mounts(self.mounts, self.current, self.credentials)

    def publish(self):
        subprocess.run(["rsync", "--archive", "--checksum", "--delete", "--delay-updates",
                        str(self.incoming) + "/", str(self.current) + "/"], check=True, capture_output=True)

    def test_image_only_change_preserves_file_and_directory_mounts(self):
        before = self.snapshot()
        (self.incoming / "compose.yml").write_text("new-image")
        self.publish()
        self.assertEqual(before, self.snapshot())

    def test_source_file_change_recreates_only_consumer(self):
        before = self.snapshot()
        (self.incoming / "config").write_text("changed!")
        self.publish()
        after = self.snapshot()
        self.assertEqual([k for k in before if before[k] != after[k]], ["app"])
        self.assertEqual((self.current / "config").read_text(), "changed!")

    def test_directory_addition_and_deletion_recreate_only_consumer(self):
        for change in ["add", "delete"]:
            with self.subTest(change=change):
                before = self.snapshot()
                if change == "add":
                    (self.incoming / "scripts" / "new").write_text("new")
                else:
                    (self.incoming / "scripts" / "new").unlink()
                self.publish()
                after = self.snapshot()
                self.assertEqual([k for k in before if before[k] != after[k]], ["directory-app"])

    def test_atomic_secret_replacement_recreates_only_consumer_without_secret_hash(self):
        before = self.snapshot()
        staged = self.credentials / "staged"
        staged.write_text("replacement-secret")
        staged.replace(self.credentials / "secret")
        after = self.snapshot()
        self.assertEqual([k for k in before if before[k] != after[k]], ["secret-app"])
        self.assertNotIn("replacement-secret", json.dumps(after))
        self.assertNotIn("secret-never-in-observation", json.dumps(before))

    def test_removal_is_observable_and_mutable_state_is_ignored(self):
        before = self.snapshot()
        (self.incoming / "config").unlink()
        self.publish()
        after = self.snapshot()
        self.assertNotEqual(before["app"], after["app"])
        self.assertEqual(before["database"], after["database"])

    def test_native_docker_projection_excludes_environments_and_oneoffs(self):
        calls = []

        def docker(arguments):
            calls.append(arguments)
            if arguments[1] == "ps":
                return "container-id\n"
            return json.dumps(self.mounts["app"]) + " app\n"

        argv = ["mounts", "--project", "example", "--source-root", str(self.current),
                "--credentials-root", str(self.credentials)]
        with patch.object(MODULE, "run", side_effect=docker), patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            MODULE.main()
        self.assertEqual(json.loads(output.getvalue()), {"app": self.snapshot()["app"]})
        self.assertIn("label=com.docker.compose.oneoff=False", calls[0])
        self.assertNotIn(".Config.Env", calls[1][3])

    def test_permission_only_credential_change_recreates_consumer(self):
        before = self.snapshot()
        (self.credentials / "secret").chmod(0o400)
        self.assertNotEqual(before["secret-app"], self.snapshot()["secret-app"])

    def test_managed_writable_mounts_and_symlinks_are_refused(self):
        self.mounts["app"][0]["RW"] = True
        with self.assertRaises(ValueError):
            self.snapshot()
        self.mounts["app"][0]["RW"] = False
        (self.current / "config").unlink()
        (self.current / "config").symlink_to(self.credentials / "secret")
        with self.assertRaises(ValueError):
            self.snapshot()


if __name__ == "__main__":
    unittest.main()
