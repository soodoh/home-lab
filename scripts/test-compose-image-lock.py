#!/usr/bin/env python3
"""Operation-specific image-lock regression tests; Docker calls stay mocked."""
from argparse import Namespace
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "compose_image_lock", Path(__file__).with_name("compose-image-lock.py")
)
LOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCK)


class ComposeImageLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.args = Namespace(
            current=root / "current.json",
            previous=root / "previous.json",
            check_registry=False,
        )
        self.write(self.args.current, "a", "example/app:current")
        self.write(self.args.previous, "b", "example/app:previous")
        self.addCleanup(patch.stopall)
        self.run = patch.object(LOCK.subprocess, "run", side_effect=self.docker).start()
        self.output = contextlib.ExitStack()
        self.addCleanup(self.output.close)
        self.stdout = io.StringIO()
        self.output.enter_context(contextlib.redirect_stdout(self.stdout))
        self.output.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def write(self, path, image, reference):
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "images": [
                        {
                            "service": "app",
                            "reference": reference,
                            "image_id": "sha256:" + image * 64,
                            "repo_digests": ["example/app@sha256:" + image * 64],
                        }
                    ],
                }
            )
        )

    def docker(self, args, **kwargs):
        if args[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "[{}]")
        if args[1:3] == ["image", "tag"]:
            return subprocess.CompletedProcess(args, 0, "")
        if args[1:3] == ["manifest", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "")
        raise AssertionError(f"Unexpected Docker operation: {args[:3]}")

    def test_verify_checks_only_explicit_operation_locks(self):
        LOCK.verify(self.args)
        inspected = {
            args[-1]
            for args in (call.args[0] for call in self.run.call_args_list)
            if args[1:3] == ["image", "inspect"]
        }
        self.assertEqual(inspected, {"sha256:" + x * 64 for x in "ab"})
        self.assertIn("current_services=1 previous_services=1", self.stdout.getvalue())
        self.assertNotIn("retained", self.stdout.getvalue())

    def test_registry_check_remains_for_explicit_recovery(self):
        self.args.check_registry = True
        LOCK.verify(self.args)
        manifests = [
            call.args[0]
            for call in self.run.call_args_list
            if call.args[0][1:3] == ["manifest", "inspect"]
        ]
        self.assertEqual(len(manifests), 2)

    def test_missing_or_empty_previous_lock_refuses(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                if missing:
                    self.args.previous.unlink(missing_ok=True)
                else:
                    self.args.previous.write_text('{"schema":1,"images":[]}')
                with self.assertRaises(SystemExit):
                    LOCK.verify(self.args)
                self.run.reset_mock()

    def test_difference_and_activation_remain_for_nextcloud_rollback(self):
        LOCK.difference(self.args)
        self.assertEqual(json.loads(self.stdout.getvalue().splitlines()[-1]), ["app"])
        LOCK.activate(Namespace(lock=self.args.previous))
        calls = [call.args[0] for call in self.run.call_args_list]
        self.assertIn(
            ["docker", "image", "tag", "sha256:" + "b" * 64, "example/app:previous"],
            calls,
        )

    def test_generic_prune_command_is_retired(self):
        source = Path(__file__).with_name("compose-image-lock.py").read_text()
        self.assertNotIn("def prune(", source)
        self.assertNotIn('add_parser("prune")', source)
        self.assertNotIn("home-lab-prune-protection", source)


if __name__ == "__main__":
    unittest.main()
