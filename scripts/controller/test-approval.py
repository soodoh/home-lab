#!/usr/bin/env python3
"""Tests for consumed approval binding at the reconciler apply boundary."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
CLAIM = REPOSITORY / "scripts/controller/claim-approval.py"
COMMIT = "a" * 40
MANIFEST_SHA = "b" * 64


def approval(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "commit": COMMIT,
        "operation": "steady",
        "manifest_sha256": MANIFEST_SHA,
        "approved_at": "2026-08-10T00:00:00+00:00",
        "consumed": True,
        "consumed_at": "2026-08-10T00:00:01+00:00",
    }
    value.update(overrides)
    return value


class ApprovalTests(unittest.TestCase):
    def claim(self, path: Path, *, commit: str = COMMIT, operation: str = "steady", sha: str = MANIFEST_SHA) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable, str(CLAIM), str(path), "--commit", commit,
                "--operation", operation, "--manifest-sha256", sha,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def write(self, root: Path, value: dict[str, object]) -> Path:
        path = root / "approval.json"
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def test_claims_exact_consumed_approval_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(Path(directory), approval())
            first = self.claim(path)
            self.assertEqual(first.returncode, 0, first.stderr)
            claimed = json.loads(path.read_text())
            self.assertIsInstance(claimed.get("apply_started_at"), str)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            second = self.claim(path)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("already claimed", second.stderr)

    def test_rejects_unconsumed_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(Path(directory), approval(consumed=False))
            result = self.claim(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unconsumed", result.stderr)

    def test_rejects_wrong_binding(self) -> None:
        cases = (
            (approval(commit="c" * 40), COMMIT, "steady", MANIFEST_SHA),
            (approval(operation="recovery"), COMMIT, "steady", MANIFEST_SHA),
            (approval(manifest_sha256="d" * 64), COMMIT, "steady", MANIFEST_SHA),
        )
        for index, (value, commit, operation, sha) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = self.write(Path(directory), value)
                result = self.claim(path, commit=commit, operation=operation, sha=sha)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("does not match", result.stderr)

    def test_rejects_missing_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.claim(Path(directory) / "approval.json")
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
