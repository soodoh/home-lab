#!/usr/bin/env python3
"""Tests for protected controller input validation."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
VALIDATOR = REPOSITORY / "scripts/controller/validate-protected-file.py"


class ProtectedFileTests(unittest.TestCase):
    def validate(self, path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), str(path), "--label", "test input"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_accepts_owned_mode_0600_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.yml"
            path.write_text("value: true\n")
            path.chmod(0o600)
            result = self.validate(path)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_group_or_world_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.yml"
            path.write_text("value: true\n")
            for mode in (0o640, 0o604):
                with self.subTest(mode=oct(mode)):
                    path.chmod(mode)
                    result = self.validate(path)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("owned by the controller user with mode 0600", result.stderr)

    def test_rejects_symlink_even_when_target_is_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.yml"
            target.write_text("value: true\n")
            target.chmod(0o600)
            link = root / "input.yml"
            os.symlink(target, link)
            result = self.validate(link)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("regular non-symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
