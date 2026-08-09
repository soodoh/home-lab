#!/usr/bin/env python3
"""Regression tests for deterministic Ansible check-log normalization."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
NORMALIZER = ROOT / "scripts/controller/normalize-ansible-plan.py"


class NormalizeAnsiblePlanTests(unittest.TestCase):
    def normalize(self, text: str) -> str:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as stream:
            stream.write(text)
            path = Path(stream.name)
        try:
            return subprocess.run(
                ["python3", str(NORMALIZER), str(path)],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
        finally:
            path.unlink()

    def test_normalizes_nested_template_temp_directories(self) -> None:
        first = "+++ after: /home/operator/.ansible/tmp/ansible-local-123/tmpalpha/file.j2\n"
        second = "+++ after: /home/operator/.ansible/tmp/ansible-local-456/tmpbravo/file.j2\n"
        normalized = self.normalize(first)
        self.assertEqual(normalized, self.normalize(second))
        self.assertEqual(
            normalized,
            "+++ after: /.ansible/tmp/<normalized>/<normalized>/file.j2\n",
        )


if __name__ == "__main__":
    unittest.main()
