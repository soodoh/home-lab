#!/usr/bin/env python3
"""Static and adversarial checks for read-only Proxmox networking parity."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
PROVIDER = ROOT / "ansible/roles/proxmox_network_lifecycle/tasks/main.yml"
CONSUMER = ROOT / "ansible/roles/proxmox_network_consumers/tasks/main.yml"
PLAYBOOK = ROOT / "ansible/playbooks/proxmox-network-plan.yml"
DOC = ROOT / "docs/proxmox-networking-tailscale-handoff.md"


def main() -> None:
    script = "const fs=require('node:fs'),y=require('js-yaml');process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1],'utf8'))));"
    contract = json.loads(subprocess.check_output(("node", "-e", script, str(CONTRACT)), cwd=ROOT, text=True))
    provider = PROVIDER.read_text(encoding="utf-8")
    consumer = CONSUMER.read_text(encoding="utf-8")
    playbook = PLAYBOOK.read_text(encoding="utf-8")
    documentation = DOC.read_text(encoding="utf-8")
    combined = provider + consumer

    pending = {"current_owner": "nix", "target_owner": "ansible", "state": "pending",
               "parity_required": True, "single_writer": True}
    transferred = {**pending, "current_owner": "ansible", "state": "transferred"}
    ready = {**pending, "state": "ready"}
    handoffs = contract["lifecycle"]["hosts"]["proxmox"]["domain_handoffs"]
    assert handoffs["network_interfaces"] == transferred
    assert handoffs["tailscale_node"] == transferred
    assert handoffs["package_set"] == transferred
    ownership = contract["network"]["ownership"]
    assert ownership["resolver_management"] == "excluded-from-this-handoff"
    assert ownership["hosts_file_management"] == "excluded-from-this-handoff"
    assert ownership["runtime_activation"] == "separately-authorized-watchdog"

    for forbidden in (
        '"/usr/sbin/ip", "address", "add"', '"/usr/sbin/ip", "address", "delete"',
        '"/usr/sbin/ip", "link", "set"', '"/usr/sbin/ip", "route", "add"',
        '"/usr/sbin/ifup"', '"/usr/sbin/ifdown"', '"/usr/sbin/ifreload"',
        '"/usr/bin/tailscale", "up"', '"/usr/bin/tailscale", "set"',
        '"/usr/bin/tailscale", "down"', '"/usr/bin/tailscale", "logout"',
        '"/usr/bin/systemctl", "restart"', '"/usr/bin/systemctl", "reload"',
        '"/usr/sbin/qm", "start"', '"/usr/sbin/qm", "stop"',
        "ansible.builtin.copy", "ansible.builtin.template", "ansible.builtin.service",
        "ansible.builtin.systemd_service", "changed_when: true", "/etc/resolv.conf", "/etc/hosts",
    ):
        assert forbidden not in combined, forbidden
    for required in (
        'changed_when: false', 'check_mode: false', 'no_log: true', '"mutation_authorized": False',
        '"protected_values_exported": False', '"peer_identities_exported": False',
        '"/usr/sbin/ip", "-j", "address", "show"', '"/usr/sbin/ip", "-j", "route", "show"',
        '"/usr/bin/tailscale", "status", "--json"', '"/usr/bin/tailscale", "debug", "prefs"',
        '"/usr/local/libexec/home-lab/proxmox-observer", "observe"',
        '"/usr/sbin/qm", "config"', 'socket.create_connection',
    ):
        assert required in combined, required
    assert contract["proxmox"]["tailscale"]["auth_key_secret_ref"] not in combined
    assert "proxmox_storage_lifecycle" in playbook
    assert "proxmox_storage_consumers" in playbook
    assert "proxmox_network_lifecycle" in playbook
    assert "proxmox_network_consumers" in playbook
    assert playbook.count("gather_facts: false") == 2
    assert "OpenTofu/controller-owned" in documentation
    assert "excluded-from-this-handoff" in documentation
    assert "separately-authorized-watchdog" in documentation
    print("proxmox_network_lifecycle_tests=passed")


if __name__ == "__main__":
    main()
