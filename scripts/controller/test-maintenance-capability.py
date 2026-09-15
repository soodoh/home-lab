#!/usr/bin/env python3
"""Offline maintenance installer regression; no playbooks or host effects run."""
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from jinja2 import Environment, StrictUndefined, UndefinedError
import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts/controller/maintenance-capability-activation.py'
spec = importlib.util.spec_from_file_location('capability', SOURCE)
capability = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capability)
PLAY = yaml.safe_load((ROOT / 'ansible/playbooks/install-maintenance-capability.yml').read_text())[0]
TASKS = yaml.safe_load((ROOT / 'ansible/roles/maintenance_capability/tasks/main.yml').read_text())
EXPECTED = {
    'package-identity': {
        'transport': 'debian-package-apply-transport',
        'executor': 'debian-package-transaction',
        'observer': 'package-candidate-observer',
    },
    'debian-reboot': {'executor': 'debian-reboot-transaction'},
}


class MaintenanceCapabilityTests(unittest.TestCase):
    def environment(self):
        env = Environment(undefined=StrictUndefined)
        env.filters['hash'] = lambda value, algorithm: hashlib.new(algorithm, value.encode()).hexdigest()

        def lookup(plugin, path, rstrip):
            self.assertEqual(plugin, 'ansible.builtin.file')
            self.assertFalse(rstrip)
            candidate = Path(path)
            self.assertEqual(candidate.parent, ROOT / 'infrastructure/maintenance/host')
            return candidate.read_text()

        env.globals['lookup'] = lookup
        return env

    def test_remaining_source_hashes_match_installer(self):
        self.assertEqual(set(capability.SOURCES), set(EXPECTED))
        expression = PLAY['pre_tasks'][1]['ansible.builtin.set_fact']['maintenance_capability_expected_source_hashes']
        evaluate = self.environment().compile_expression(expression.strip()[2:-2].strip())
        for kind, names in EXPECTED.items():
            with self.subTest(kind=kind):
                expected = {key: hashlib.sha256((ROOT / 'infrastructure/maintenance/host' / name).read_bytes()).hexdigest()
                            for key, name in names.items()}
                self.assertEqual(capability.source_hashes(kind), expected)
                self.assertEqual(evaluate(maintenance_capability_kind=kind,
                                          maintenance_capability_source_root=str(ROOT / 'infrastructure/maintenance/host')), expected)

    def test_unsupported_kinds_rejected_before_lookup_and_roles(self):
        guard = PLAY['pre_tasks'][0]['ansible.builtin.assert']['that']
        role_guard = TASKS[0]['ansible.builtin.assert']['that']
        self.assertIn(guard[0], role_guard)
        self.assertEqual(len(guard), 1)
        evaluate = self.environment().compile_expression(guard[0])
        for kind in (*EXPECTED, 'unattended-retirement', 'unknown'):
            with self.subTest(kind=kind):
                self.assertEqual(evaluate(maintenance_capability_kind=kind), kind in EXPECTED)
        with self.assertRaises(UndefinedError):
            evaluate()  # Missing selector must fail, not select reboot implicitly.

    def test_cli_rejects_retired_kind_without_planning(self):
        with patch.object(sys, 'argv', [str(SOURCE), 'plan', 'unattended-retirement']), \
                patch.object(capability, 'save') as save, \
                patch.object(capability, 'apply') as apply, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                capability.main()
        self.assertEqual(error.exception.code, 2)
        save.assert_not_called()
        apply.assert_not_called()

    def test_shared_guards_and_installations_remain(self):
        self.assertEqual(PLAY['roles'], [
            {'role': 'lifecycle_state'},
            {'role': 'apply_lock', 'vars': {
                'apply_lock_action': 'acquire',
                'apply_lock_operation': 'maintenance-capability-{{ maintenance_capability_kind }}-{{ maintenance_capability_plan_sha256 }}'}},
            {'role': 'maintenance_capability'},
        ])
        release = PLAY['post_tasks'][0]
        self.assertEqual(release['ansible.builtin.import_role'], {'name': 'apply_lock'})
        self.assertEqual(release['vars']['apply_lock_action'], 'release')
        self.assertEqual(release['when'], 'not ansible_check_mode')
        for requirement in (
            "lifecycle_profile == 'production'", "lifecycle_contract_host == 'debian'",
            "maintenance_capability_plan_sha256 is match('^[0-9a-f]{64}$')",
            'maintenance_capability_approved_sha256 == maintenance_capability_plan_sha256',
            'maintenance_capability_source_hashes == maintenance_capability_expected_source_hashes',
        ):
            self.assertIn(requirement, TASKS[0]['ansible.builtin.assert']['that'])
        self.assertEqual(len(TASKS), 6)
        package = TASKS[3]
        self.assertEqual(package['when'], "maintenance_capability_kind == 'package-identity'")
        self.assertEqual([item['dest'] for item in package['loop']],
                         ['/usr/local/libexec/home-lab/' + name for name in EXPECTED['package-identity'].values()])
        self.assertIn("replace('@EXPECTED_PACKAGES_BASE64@', 'W10=')", package['loop'][2]['content'])
        reboot = TASKS[5]
        self.assertEqual(reboot['when'], "maintenance_capability_kind == 'debian-reboot'")
        self.assertEqual(reboot['ansible.builtin.copy']['dest'], '/usr/local/libexec/home-lab/debian-reboot-transaction')
        for task in (package, reboot):
            self.assertTrue(task['become'])
            self.assertEqual({key: task['ansible.builtin.copy'][key] for key in ('owner', 'group', 'mode')},
                             {'owner': 'root', 'group': 'root', 'mode': '0755'})


if __name__ == '__main__':
    unittest.main()
