#!/usr/bin/env python3
"""Regression tests for pre-apply CT retirement audits."""

from pathlib import Path
import re
import unittest


RECONCILE = Path(__file__).resolve().parents[1] / "reconcile-infrastructure"


class ReconcileCtAuditTests(unittest.TestCase):
    def function_body(self, name: str) -> str:
        source = RECONCILE.read_text()
        match = re.search(rf"^{name}\(\) \{{\n(?P<body>.*?)^\}}$", source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        return match.group("body")

    def test_sensitive_ssh_audits_receive_existing_access_proof(self) -> None:
        expected = (
            'ansible_require_noop "$arch_inventory" playbooks/site.yml '
            'docker-host-production --tags "$tag" -e arch_ssh_access_proven=true'
        )
        for name in ("apply_ct_retirement", "apply_network_migration"):
            with self.subTest(name=name):
                self.assertIn(expected, self.function_body(name))


if __name__ == "__main__":
    unittest.main()
