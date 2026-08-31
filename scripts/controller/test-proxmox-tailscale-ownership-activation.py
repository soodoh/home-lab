#!/usr/bin/env python3
"""Adversarial source checks for no-mutation TAILSCALE ownership receipts."""

from __future__ import annotations

import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "scripts/controller/proxmox-tailscale-ownership-activation.py"
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"


def main() -> None:
    controller = CONTROLLER.read_text(encoding="utf-8")
    activator = ACTIVATOR.read_text(encoding="utf-8")
    transport = TRANSPORT.read_text(encoding="utf-8")
    ast.parse(controller)
    ast.parse(activator)

    for required in (
        "PROXMOX_TAILSCALE_OWNERSHIP_APPLY_CONFIRMED", "apply-proxmox-tailscale-ownership-",
        '"authorized": False', '"automatic_reboot": False', '"changed": False',
        '"consumer_parity_verified": True', '"protected_values_exported": False',
        '"current_owner": "ansible"', '"state": "transferred"', "consumer_parity()",
        '"--check"', "clean pushed HEAD", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
    ):
        assert required in controller, required
    for required in (
        "home-lab-proxmox-tailscale-ownership-activation-v1", "home-lab-proxmox-tailscale-ownership-journal-v1",
        '"apply-tailscale-ownership"', '"inspect-tailscale-lifecycle"', "tailscale_ownership_snapshot",
        "TAILSCALE_OWNERSHIP_LOCK", '"changed": False', '"automatic_reboot": False',
        '"protected_values_exported": False', '"state_mutated": False', '"service_restarted": False',
        'expected["hostname"]', 'expected["advertise_tag"]', 'expected["netfilter_mode"]',
        '"/usr/bin/tailscale", "status", "--json"', '"/usr/bin/tailscale", "debug", "prefs"',
        '"/usr/local/libexec/home-lab/proxmox-observer", "observe"', "network_ownership_snapshot()",
        "save_package_journal(path, receipt, exclusive=True)",
    ):
        assert required in activator, required
    for required in (
        "stage\\ tailscale-ownership\\ *", "observe\\ tailscale-lifecycle)",
        "apply\\ tailscale-ownership\\ *", '"apply-tailscale-ownership"',
    ):
        assert required in transport, required

    operation = activator[activator.index("def tailscale_ownership_snapshot"):activator.index("def boot_configuration_reboot_evidence")]
    for forbidden in (
        '"/usr/sbin/ip", "address", "add"', '"/usr/sbin/ip", "address", "delete"',
        '"/usr/sbin/ip", "link", "set"', '"/usr/sbin/ip", "route", "add"',
        '"/usr/sbin/ifup"', '"/usr/sbin/ifdown"', '"/usr/sbin/ifreload"',
        '"/usr/bin/tailscale", "up"', '"/usr/bin/tailscale", "set"',
        '"/usr/bin/tailscale", "down"', '"/usr/bin/tailscale", "logout"',
        '"/usr/bin/systemctl", "restart"', '"/usr/bin/systemctl", "reload"',
        '"/usr/sbin/qm", "start"', '"/usr/sbin/qm", "stop"', "subprocess.Popen",
    ):
        assert forbidden not in operation, forbidden
    assert "state_metadata.st_nlink" not in operation
    assert re.search(r'HEX64\.fullmatch\(request\["plan_sha256"\]\)', activator)
    assert 'set(request) != {"operation", "plan_sha256"}' in activator
    print("proxmox_tailscale_ownership_activation_tests=passed")


if __name__ == "__main__":
    main()
