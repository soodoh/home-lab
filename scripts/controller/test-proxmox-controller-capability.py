#!/usr/bin/env python3
"""Offline retirement boundary and surviving authority/descriptor guards."""
import ast
import json
from pathlib import Path
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ControllerCapabilityTests(unittest.TestCase):
    def test_retired_capability_and_upgrade_entrypoints_are_absent(self):
        for path in ('scripts/controller/proxmox-controller-observer-capability.py',
                     'infrastructure/proxmox-access/host/proxmox-controller-capability-transaction.py',
                     'scripts/controller/proxmox-plan-capability.py',
                     'scripts/controller/proxmox-package-observer-capability.py',
                     'scripts/controller/proxmox-deploy-capability.py',
                     'scripts/controller/proxmox-deploy-upgrade.py',
                     'scripts/controller/test-proxmox-deploy-upgrade.py',
                     'scripts/physical-console-install-proxmox-deploy-upgrade',
                     'scripts/physical-console-install-proxmox-observer-upgrade',
                     'scripts/physical-console-install-proxmox-private-preparer-upgrade'):
            self.assertFalse((ROOT / path).exists() or (ROOT / path).is_symlink(), path)

    def test_descriptor_ancestry_validation_is_identical_in_both_participants(self):
        sources = [ROOT / 'infrastructure/host-lifecycle/proxmox/controller-observer-template.py',
                   ROOT / 'infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator']
        definitions = []
        for path in sources:
            tree = ast.parse(path.read_text())
            definitions.append({n.name: ast.dump(n, include_attributes=False) for n in tree.body if isinstance(n, ast.FunctionDef)})
        for name in ('parent_fd', 'fingerprint'):
            self.assertEqual(definitions[0][name], definitions[1][name])

    def test_retained_nix_ordinary_initializing_and_terminal_paths_reject_reboot_owner(self):
        source = (ROOT / 'nix/proxmox/activator-template.py').read_text(); tree = ast.parse(source)
        selected = {'read_lock', 'require_lock', 'reconcile_initializing', 'reconcile_terminal_release',
                    'lock_matches_ownership', 'commit', 'rollback'}
        namespace = {'json': json, 'stat': __import__('stat'), 'LOCK_PATH': Path('/synthetic/apply.lock')}
        def exact(value, keys, label):
            if set(value) != keys:
                raise ValueError('legacy exact shape rejects reboot owner')
        def canonical(value):
            return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        owner = {'format': 'home-lab-proxmox-reboot-owner-v1', 'operation': 'apply-reboot',
                 'plan_sha256': 'a' * 64, 'boot_id': 'synthetic-before', 'token': 'b' * 64}
        namespace.update(exact=exact, canonical=canonical,
                         read_fixed_file=lambda *a: (canonical(owner), types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o100600)),
                         validate_common=lambda *a: None, validate_envelope_shape=lambda *a: None,
                         self_sha256=lambda: 'synthetic-legacy', completed_retry=lambda *a: None)
        def prohibited(*a):
            self.fail('legacy path reached mutation/removal for reboot record')
        namespace.update(release_fixed_lock=prohibited, save_journal=prohibited, read_manifest=prohibited)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in selected:
                exec(compile(ast.Module(body=[node], type_ignores=[]), 'retained-nix-fixture', 'exec'), namespace)
        for operation in ('commit', 'rollback'):
            namespace['read_journal'] = lambda *a: {'state': 'applying'}
            with self.assertRaisesRegex(ValueError, 'legacy exact shape'):
                namespace[operation]({'planSha256': 'c' * 64})
        for status in ('committed-release-pending', 'recovered-release-pending'):
            with self.assertRaisesRegex(ValueError, 'legacy exact shape'):
                namespace['reconcile_terminal_release']({'state': status, 'ownership': {}})
        with self.assertRaisesRegex(ValueError, 'legacy exact shape'):
            namespace['reconcile_initializing']({'state': 'initializing', 'ownership': {'activatorSha256': 'synthetic-legacy'}})
        # Current Ansible and firewall share the descriptor and this exact retained
        # pathname; no legacy source is modified to interpret the reboot format.
        ansible = (ROOT / 'ansible/roles/apply_lock/tasks/main.yml').read_text()
        self.assertIn('test ! -e "$competing_lock"', ansible)
        self.assertIn('/var/lib/home-lab/reconciliation/apply.lock', ansible)
        firewall = (ROOT / 'infrastructure/proxmox-firewall/host/proxmox-firewall-transaction.py').read_text()
        self.assertIn('MUTEX = Path("/var/lib/home-lab/reconciliation/operation.lock")', firewall)
        self.assertIn('NIX_LOCK = Path("/var/lib/home-lab/reconciliation/apply.lock")', firewall)


if __name__ == '__main__': unittest.main()
