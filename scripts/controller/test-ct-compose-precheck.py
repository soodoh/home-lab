#!/usr/bin/env python3
"""Static contract tests for the CT retirement Compose artifact precheck."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
PLAYBOOK = REPOSITORY / "ansible/playbooks/verify-active-compose-artifact.yml"
RECONCILER = REPOSITORY / "scripts/reconcile-infrastructure"


class ComposeRetirementPrecheckTests(unittest.TestCase):
    def test_playbook_is_read_only_fail_closed_and_redacted(self) -> None:
        source = PLAYBOOK.read_text()
        self.assertIn("hosts: docker_host", source)
        self.assertIn("gather_facts: false", source)
        self.assertIn('compose_current_dir }}/scripts/compose-artifact.py', source)
        self.assertIn("- /usr/bin/python", source)
        self.assertIn(
            "compose_current_dir: /srv/docker-compose/current",
            (REPOSITORY / "ansible/group_vars/docker_host.yml").read_text(),
        )
        self.assertRegex(source, re.compile(r"\n\s+- --no-git\n\s+- hash\n"))
        self.assertIn("changed_when: false", source)
        self.assertIn("check_mode: false", source)
        self.assertGreaterEqual(source.count("no_log: true"), 3)
        self.assertIn(
            "compose_retirement_active_artifact.stdout == "
            "compose_retirement_expected_artifact_sha256",
            source,
        )
        for mutating_module in ("ansible.builtin.copy:", "ansible.builtin.file:", "ansible.builtin.git:"):
            with self.subTest(module=mutating_module):
                self.assertNotIn(mutating_module, source)

    def test_precheck_is_manifest_bound_and_immediately_precedes_legacy_apply(self) -> None:
        source = RECONCILER.read_text()
        function = re.search(
            r"verify_active_compose_artifact_for_ct_retirement\(\) \{(?P<body>.*?)\n\}",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(function)
        body = function.group("body")
        self.assertIn(".compose_artifact_sha256", body)
        self.assertIn('chmod 0600 "$expected_vars" "$check_log"', body)
        self.assertIn('rm -f "$expected_vars" "$check_log"', body)
        self.assertNotIn("ansible_extra_args", body)
        self.assertIn(".changed == 0 and .unreachable == 0 and .failed == 0", body)

        retirement = re.search(
            r"apply_ct_retirement\(\) \{(?P<body>.*?)\n\}", source, re.DOTALL
        )
        self.assertIsNotNone(retirement)
        retirement_body = retirement.group("body")
        self.assertRegex(
            retirement_body,
            re.compile(
                r"verify_active_compose_artifact_for_ct_retirement\s+"
                r"apply_root proxmox-legacy"
            ),
        )


if __name__ == "__main__":
    unittest.main()
