#!/usr/bin/env python3
"""Static fail-closed checks for package-set ownership activation."""

import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "scripts/controller/proxmox-package-ownership-activation.py"
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"


def main() -> None:
    controller = CONTROLLER.read_text()
    activator = ACTIVATOR.read_text()
    transport = TRANSPORT.read_text()
    ast.parse(controller)
    ast.parse(activator)

    for required in (
        "PROXMOX_PACKAGE_OWNERSHIP_APPLY_CONFIRMED", "apply-proxmox-package-ownership-",
        '"authorized": False', '"automatic_reboot": False', '"changed": False',
        '"consumer_parity_verified": True', '"protected_values_exported": False',
        '"current_owner": "ansible"', '"state": "transferred"', "consumer_parity()",
        'package_manifest_sha256', 'playbooks/packages-plan.yml',
    ):
        assert required in controller, required
    for required in (
        "home-lab-proxmox-package-ownership-activation-v1",
        "home-lab-proxmox-package-ownership-journal-v1",
        '"apply-package-ownership"', '"inspect-package-lifecycle"',
        "package_ownership_snapshot", "PACKAGE_OWNERSHIP_LOCK",
        '"changed": False', '"automatic_reboot": False', '"packages_mutated": False',
        '"protected_values_exported": False', '"installed_manifest_matches"',
        '"/usr/bin/dpkg-query"', '"/usr/bin/apt-get"', '"--simulate"',
        '"/usr/bin/dpkg", "--audit"', '"/usr/bin/apt-mark", "showhold"',
    ):
        assert required in activator, required
    for required in (
        "stage\\ package-ownership\\ *", "observe\\ package-lifecycle)",
        "apply\\ package-ownership\\ *", '"apply-package-ownership"',
    ):
        assert required in transport, required

    operation = activator[activator.index("def package_ownership_contract_material"):activator.index("def boot_configuration_reboot_evidence")]
    for forbidden in (
        '"update"', '"install"', '"remove"', '"purge"', '"reboot"',
        '"systemctl", "restart"', '"systemctl", "stop"',
    ):
        assert forbidden not in operation, forbidden
    assert 'save_package_journal(path, receipt, exclusive=True)' in operation
    assert re.search(r'HEX64\.fullmatch\(request\["plan_sha256"\]\)', activator)
    assert 'set(request) != {"operation", "plan_sha256"}' in activator
    print("proxmox_package_ownership_activation_tests=passed")


if __name__ == "__main__":
    main()
