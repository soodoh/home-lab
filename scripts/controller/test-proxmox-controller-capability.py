#!/usr/bin/env python3
"""Offline retirement boundary and surviving authority/descriptor guards."""
from pathlib import Path
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
                     'scripts/physical-console-install-proxmox-private-preparer-upgrade',
                     'infrastructure/host-lifecycle/proxmox/controller-observer-template.py',
                     'infrastructure/proxmox-access/host/proxmox-ansible-plan-transport',
                     'infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator',
                     'scripts/controller/proxmox-package-activation.py',
                     'scripts/controller/proxmox-reboot-activation.py'):
            self.assertFalse((ROOT / path).exists() or (ROOT / path).is_symlink(), path)

    def test_retained_native_paths_have_no_nix_or_legacy_activator_dependency(self):
        for raw in ('ansible/roles/proxmox_package_maintenance/tasks/main.yml',
                    'ansible/roles/proxmox_reboot/tasks/main.yml',
                    'infrastructure/host-lifecycle/proxmox/vfio-recover.py'):
            source = (ROOT / raw).read_text()
            self.assertNotIn('nix/', source)
            self.assertNotIn('proxmox-ansible-deploy-activator', source)

    def test_native_and_firewall_paths_still_refuse_retained_owners(self):
        ansible = (ROOT / 'ansible/roles/apply_lock/tasks/main.yml').read_text()
        self.assertIn('test ! -e "$competing_lock"', ansible)
        self.assertIn('/var/lib/home-lab/reconciliation/apply.lock', ansible)
        firewall = (ROOT / 'infrastructure/proxmox-firewall/host/proxmox-firewall-transaction.py').read_text()
        self.assertIn('MUTEX = Path("/var/lib/home-lab/reconciliation/operation.lock")', firewall)
        self.assertIn('NIX_LOCK = Path("/var/lib/home-lab/reconciliation/apply.lock")', firewall)
        self.assertFalse((ROOT / 'nix').exists())


if __name__ == '__main__': unittest.main()
