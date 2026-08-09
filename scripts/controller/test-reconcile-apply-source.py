#!/usr/bin/env python3
"""Focused tests for exact committed-revision infrastructure applies."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

HELPER = Path(__file__).with_name("reconcile-apply-source.py")


def load_helper():
    spec = importlib.util.spec_from_file_location("reconcile_apply_source", HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {HELPER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source = load_helper()
COMMIT = "a" * 40


class FakeGit:
    def __init__(self, commit: str = COMMIT) -> None:
        self.commit = commit
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, arguments: tuple[str, ...]) -> str:
        self.calls.append(arguments)
        if arguments != ("rev-parse", "HEAD"):
            raise AssertionError(f"unexpected branch or remote lookup: {arguments}")
        return self.commit


class ApplySourceTests(unittest.TestCase):
    def test_any_branch_or_detached_revision_is_accepted(self) -> None:
        for environment in ({}, {"CONTROLLER_CONTEXT": "feature"}, {"CONTROLLER_CONTEXT": "detached"}):
            with self.subTest(environment=environment):
                git = FakeGit()
                source.validate_apply_source(environment, git)
                self.assertEqual(git.calls, [("rev-parse", "HEAD")])

    def test_invalid_commit_identity_is_rejected(self) -> None:
        for commit in ("", "main", "A" * 40, "a" * 39, "a" * 41):
            with self.subTest(commit=commit), self.assertRaises(source.ApplySourceError):
                source.validate_apply_source({}, FakeGit(commit))


if __name__ == "__main__":
    unittest.main()
