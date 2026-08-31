#!/usr/bin/env python3
"""Adversarial source checks for no-mutation NFS ownership receipts."""

from __future__ import annotations

import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "scripts/controller/proxmox-nfs-ownership-activation.py"
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"


def main() -> None:
    controller = CONTROLLER.read_text(encoding="utf-8")
    activator = ACTIVATOR.read_text(encoding="utf-8")
    transport = TRANSPORT.read_text(encoding="utf-8")
    ast.parse(controller)
    ast.parse(activator)

    for required in (
        "PROXMOX_NFS_OWNERSHIP_APPLY_CONFIRMED", "apply-proxmox-nfs-ownership-",
        '"authorized": False', '"automatic_reboot": False', '"changed": False',
        '"consumer_parity_verified": True', '"protected_values_exported": False',
        '"current_owner": "ansible"', '"state": "transferred"', "consumer_parity()",
        '"--check"', "clean pushed HEAD", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
    ):
        assert required in controller, required
    for required in (
        "home-lab-proxmox-nfs-ownership-activation-v1", "home-lab-proxmox-nfs-ownership-journal-v1",
        '"apply-nfs-ownership"', '"inspect-nfs-lifecycle"', "nfs_ownership_snapshot",
        "NFS_OWNERSHIP_LOCK", '"changed": False', '"automatic_reboot": False',
        '"protected_values_exported": False', 'nfs["export"]', 'nfs["client"]',
        'nfs["exports_file"]["path"]', 'nfs["options"]', 'nfs["squash_policy"]',
        '"/usr/sbin/exportfs", "-v"', '"/usr/bin/systemctl", "is-active"',
        "save_package_journal(path, receipt, exclusive=True)",
    ):
        assert required in activator, required
    for required in (
        "stage\\ nfs-ownership\\ *", "observe\\ nfs-lifecycle)",
        "apply\\ nfs-ownership\\ *", '"apply-nfs-ownership"',
    ):
        assert required in transport, required

    operation = activator[activator.index("def nfs_ownership_snapshot"):activator.index("def boot_configuration_reboot_evidence")]
    for forbidden in (
        '"/usr/sbin/zfs", "set"', '"/usr/sbin/zfs", "mount"', '"/usr/sbin/zfs", "unmount"',
        '"/usr/sbin/zpool", "import"', '"/usr/sbin/zpool", "export"', '"/usr/sbin/zpool", "scrub"',
        '"/usr/sbin/exportfs", "-r"', '"/usr/sbin/exportfs", "-u"',
        '"/usr/bin/systemctl", "restart"', '"/usr/bin/systemctl", "reload"',
        '"/usr/sbin/qm", "start"', '"/usr/sbin/qm", "stop"', "subprocess.Popen",
    ):
        assert forbidden not in operation, forbidden
    assert re.search(r'HEX64\.fullmatch\(request\["plan_sha256"\]\)', activator)
    assert 'set(request) != {"operation", "plan_sha256"}' in activator
    print("proxmox_nfs_ownership_activation_tests=passed")


if __name__ == "__main__":
    main()
