#!/usr/bin/env python3
"""Adversarial source checks for no-mutation NETWORK ownership receipts."""

from __future__ import annotations

import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "scripts/controller/proxmox-network-ownership-activation.py"
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"


def main() -> None:
    controller = CONTROLLER.read_text(encoding="utf-8")
    activator = ACTIVATOR.read_text(encoding="utf-8")
    transport = TRANSPORT.read_text(encoding="utf-8")
    ast.parse(controller)
    ast.parse(activator)

    for required in (
        "PROXMOX_NETWORK_OWNERSHIP_APPLY_CONFIRMED", "apply-proxmox-network-ownership-",
        '"authorized": False', '"automatic_reboot": False', '"changed": False',
        '"consumer_parity_verified": True', '"protected_values_exported": False',
        '"current_owner": "ansible"', '"state": "transferred"', "consumer_parity()",
        '"--check"', "clean pushed HEAD", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
    ):
        assert required in controller, required
    for required in (
        "home-lab-proxmox-network-ownership-activation-v1", "home-lab-proxmox-network-ownership-journal-v1",
        '"apply-network-ownership"', '"inspect-network-lifecycle"', "network_ownership_snapshot",
        "NETWORK_OWNERSHIP_LOCK", '"changed": False', '"automatic_reboot": False',
        '"protected_values_exported": False', '"runtime_activated": False',
        'network["bridge"]', 'network["bridge_port"]', 'network["proxmox"]["ipv4"]',
        '"/usr/sbin/ip", "-j", "address", "show"', '"/usr/sbin/ip", "-j", "route", "show"',
        '"/usr/local/libexec/home-lab/proxmox-observer", "observe"',
        "save_package_journal(path, receipt, exclusive=True)",
    ):
        assert required in activator, required
    for required in (
        "stage\\ network-ownership\\ *", "observe\\ network-lifecycle)",
        "apply\\ network-ownership\\ *", '"apply-network-ownership"',
    ):
        assert required in transport, required

    operation = activator[activator.index("def network_ownership_snapshot"):activator.index("def boot_configuration_reboot_evidence")]
    for forbidden in (
        '"/usr/sbin/ip", "address", "add"', '"/usr/sbin/ip", "address", "delete"',
        '"/usr/sbin/ip", "link", "set"', '"/usr/sbin/ip", "route", "add"',
        '"/usr/sbin/ifup"', '"/usr/sbin/ifdown"', '"/usr/sbin/ifreload"',
        '"/usr/bin/tailscale", "up"', '"/usr/bin/tailscale", "set"',
        '"/usr/bin/systemctl", "restart"', '"/usr/bin/systemctl", "reload"',
        '"/usr/sbin/qm", "start"', '"/usr/sbin/qm", "stop"', "subprocess.Popen",
    ):
        assert forbidden not in operation, forbidden
    assert re.search(r'HEX64\.fullmatch\(request\["plan_sha256"\]\)', activator)
    assert 'set(request) != {"operation", "plan_sha256"}' in activator
    print("proxmox_network_ownership_activation_tests=passed")


if __name__ == "__main__":
    main()
