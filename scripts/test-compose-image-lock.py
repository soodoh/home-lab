#!/usr/bin/env python3
"""Image retention regression tests; every Docker call is replaced locally."""
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
    "compose_image_lock", Path(__file__).with_name("compose-image-lock.py"))
LOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCK)


class ComposeImageLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.args = Namespace(current=root / "current.json", previous=root / "previous.json",
                              retained_root=root / "retained-images", check_registry=False, until="168h")
        self.write(self.args.current, "a")
        self.write(self.args.previous, "b")
        self.addCleanup(patch.stopall)
        self.run = patch.object(LOCK.subprocess, "run", side_effect=self.docker).start()
        self.output = contextlib.ExitStack()
        self.addCleanup(self.output.close)
        self.output.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.output.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def write(self, path, image):
        path.write_text(json.dumps({"schema": 1, "images": [{
            "service": "app", "reference": "example/app:1",
            "image_id": "sha256:" + image * 64,
            "repo_digests": ["example/app@sha256:" + image * 64]}]}))

    def docker(self, args, **kwargs):
        if args[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "[{}]")
        if args[1] == "create":
            return subprocess.CompletedProcess(args, 0, "container-" + args[-1][-1])
        if args[1:3] in (["image", "prune"], ["container", "rm"]):
            return subprocess.CompletedProcess(args, 0, "")
        raise AssertionError(f"Unexpected Docker operation: {args[:3]}")

    def test_prune_protects_both_generations_before_removing_images(self):
        LOCK.prune(self.args)
        calls = [call.args[0] for call in self.run.call_args_list]
        creates = [args for args in calls if args[1] == "create"]
        self.assertEqual({args[-1] for args in creates}, {"sha256:" + x * 64 for x in "ab"})
        prune = next(args for args in calls if args[1:3] == ["image", "prune"])
        self.assertTrue(all(calls.index(args) < calls.index(prune) for args in creates))
        self.assertEqual(prune, ["docker", "image", "prune", "--all", "--force", "--filter", "until=168h"])
        self.assertEqual(calls[-1], ["docker", "container", "rm", "--force", "container-a", "container-b"])
        self.assertFalse(any("manifest" in args for args in calls))

    def test_retained_and_interrupted_generations_are_also_protected(self):
        self.args.retained_root.mkdir()
        self.write(self.args.retained_root / "older.json", "c")
        self.write(self.args.current.parent / "deploy-candidate-previous-images.json", "d")
        LOCK.prune(self.args)
        calls = [call.args[0] for call in self.run.call_args_list]
        creates = [args for args in calls if args[1] == "create"]
        self.assertEqual({args[-1] for args in creates}, {"sha256:" + x * 64 for x in "abcd"})
        prune = next(args for args in calls if args[1:3] == ["image", "prune"])
        self.assertTrue(all(calls.index(args) < calls.index(prune) for args in creates))

    def test_verify_ignores_historical_locks_without_explicit_scope(self):
        self.args.retained_root.mkdir()
        (self.args.retained_root / "unrelated.json").write_text('{"schema":1,"images":[]}')
        self.args.retained_root = None
        LOCK.verify(self.args)
        inspected = {
            args[-1] for args in (call.args[0] for call in self.run.call_args_list)
            if args[1:3] == ["image", "inspect"]
        }
        self.assertEqual(inspected, {"sha256:" + x * 64 for x in "ab"})

    def test_verify_checks_historical_locks_when_explicitly_requested(self):
        self.args.retained_root.mkdir()
        self.write(self.args.retained_root / "older.json", "c")
        LOCK.verify(self.args)
        inspected = {
            args[-1] for args in (call.args[0] for call in self.run.call_args_list)
            if args[1:3] == ["image", "inspect"]
        }
        self.assertEqual(inspected, {"sha256:" + x * 64 for x in "abc"})

    def test_missing_or_empty_previous_lock_refuses_before_prune(self):
        for missing in (True, False):
            if missing:
                self.args.previous.unlink()
            else:
                self.args.previous.write_text('{"schema":1,"images":[]}')
            with self.assertRaises(SystemExit):
                LOCK.prune(self.args)
            self.run.assert_not_called()

    def test_failed_protection_never_prunes_and_cleans_only_created_containers(self):
        def fail_second(args, **kwargs):
            if args[1] == "create" and args[-1].endswith("b"):
                raise subprocess.CalledProcessError(1, args)
            return self.docker(args, **kwargs)
        self.run.side_effect = fail_second
        with self.assertRaises(SystemExit):
            LOCK.prune(self.args)
        calls = [call.args[0] for call in self.run.call_args_list]
        self.assertFalse(any(args[1:3] == ["image", "prune"] for args in calls))
        self.assertEqual(calls[-1], ["docker", "container", "rm", "--force", "container-a"])


if __name__ == "__main__":
    unittest.main()
