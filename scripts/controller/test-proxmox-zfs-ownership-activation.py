#!/usr/bin/env python3
"""Adversarial source checks for no-mutation ZFS ownership receipts."""

from __future__ import annotations

import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "scripts/controller/proxmox-zfs-ownership-activation.py"
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"


def main() -> None:
    controller = CONTROLLER.read_text(encoding="utf-8")
    activator = ACTIVATOR.read_text(encoding="utf-8")
    transport = TRANSPORT.read_text(encoding="utf-8")
    ast.parse(controller)
    ast.parse(activator)

    for required in (
        "PROXMOX_ZFS_OWNERSHIP_APPLY_CONFIRMED", "apply-proxmox-zfs-ownership-",
        '"authorized": False', '"automatic_reboot": False', '"changed": False',
        '"consumer_parity_verified": True', '"protected_values_exported": False',
        '"current_owner": "ansible"', '"state": "transferred"', "consumer_parity()",
        '"--check"', "clean pushed HEAD", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
    ):
        assert required in controller, required
    for required in (
        "home-lab-proxmox-zfs-ownership-activation-v1", "home-lab-proxmox-zfs-ownership-journal-v1",
        '"apply-zfs-ownership"', '"inspect-storage-lifecycle"', "zfs_ownership_snapshot",
        "ZFS_OWNERSHIP_LOCK", '"changed": False', '"automatic_reboot": False',
        '"member_identities_exported": False', '"protected_values_exported": False',
        "save_package_journal(path, receipt, exclusive=True)",
    ):
        assert required in activator, required
    for required in (
        "stage\\ storage-ownership\\ *", "observe\\ storage-lifecycle)",
        "apply\\ storage-ownership\\ *", '"apply-zfs-ownership"',
    ):
        assert required in transport, required

    operation = activator[activator.index("def zfs_ownership_snapshot"):activator.index("def boot_configuration_reboot_evidence")]
    for forbidden in (
        '"/usr/sbin/zfs", "set"', '"/usr/sbin/zfs", "mount"', '"/usr/sbin/zfs", "unmount"',
        '"/usr/sbin/zpool", "import"', '"/usr/sbin/zpool", "export"', '"/usr/sbin/zpool", "scrub"',
        '"/usr/sbin/exportfs"', '"/usr/bin/systemctl", "restart"', '"/usr/bin/systemctl", "reload"',
        '"/usr/sbin/qm", "start"', '"/usr/sbin/qm", "stop"', "subprocess.Popen",
    ):
        assert forbidden not in operation, forbidden
    assert re.search(r'HEX64\.fullmatch\(request\["plan_sha256"\]\)', activator)
    assert 'set(request) != {"operation", "plan_sha256"}' in activator
    print("proxmox_zfs_ownership_activation_tests=passed")


if __name__ == "__main__":
    main()
