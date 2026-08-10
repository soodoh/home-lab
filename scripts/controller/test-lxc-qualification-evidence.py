#!/usr/bin/env python3
"""Regression tests for the retained disposable LXC qualification evidence."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
VALIDATOR = REPOSITORY / "scripts/controller/validate-lxc-qualification-evidence.py"
EVIDENCE = REPOSITORY / "infrastructure/evidence/proxmox-lxc-qualification.json"


class QualificationEvidenceTests(unittest.TestCase):
    def run_validator(self, evidence: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(VALIDATOR), "--evidence-json", str(evidence)],
            cwd=REPOSITORY,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_tracked_evidence_is_valid(self) -> None:
        result = self.run_validator(EVIDENCE)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reused_run_id_is_rejected(self) -> None:
        evidence = json.loads(EVIDENCE.read_text())
        evidence["runs"][1]["run_id"] = evidence["runs"][0]["run_id"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(evidence))
            result = self.run_validator(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reuses a run ID", result.stderr)


if __name__ == "__main__":
    unittest.main()
