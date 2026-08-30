#!/usr/bin/env python3
"""Static and adversarial checks for read-only Proxmox storage parity."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
PROVIDER = ROOT / "ansible/roles/proxmox_storage_lifecycle/tasks/main.yml"
CONSUMER = ROOT / "ansible/roles/proxmox_storage_consumers/tasks/main.yml"
PLAYBOOK = ROOT / "ansible/playbooks/proxmox-storage-plan.yml"
DOC = ROOT / "docs/proxmox-storage-nfs-handoff.md"


def main() -> None:
    script = "const fs=require('node:fs'),y=require('js-yaml');process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1],'utf8'))));"
    contract = json.loads(subprocess.check_output(("node", "-e", script, str(CONTRACT)), cwd=ROOT, text=True))
    provider = PROVIDER.read_text(encoding="utf-8")
    consumer = CONSUMER.read_text(encoding="utf-8")
    playbook = PLAYBOOK.read_text(encoding="utf-8")
    documentation = DOC.read_text(encoding="utf-8")

    expected = {"current_owner": "nix", "target_owner": "ansible", "state": "pending",
                "parity_required": True, "single_writer": True}
    handoffs = contract["lifecycle"]["hosts"]["proxmox"]["domain_handoffs"]
    assert handoffs["zfs_dataset"] == expected
    assert handoffs["nfs_export_service"] == expected

    combined = provider + consumer
    for forbidden in (
        '"/usr/sbin/zfs", "set"', '"/usr/sbin/zfs", "mount"', '"/usr/sbin/zfs", "unmount"',
        '"/usr/sbin/zpool", "import"', '"/usr/sbin/zpool", "export"', '"/usr/sbin/zpool", "scrub"',
        '"/usr/sbin/exportfs", "-r"', '"/usr/sbin/exportfs", "-u"',
        '"/usr/bin/systemctl", "reload"', '"/usr/bin/systemctl", "restart"',
        "ansible.builtin.copy", "ansible.builtin.template", "ansible.builtin.service",
        "ansible.builtin.systemd_service", "changed_when: true",
    ):
        assert forbidden not in combined, forbidden
    for required in (
        'changed_when: false', 'check_mode: false', '"mutation_authorized": False',
        '"protected_values_exported": False', '"member_identities_exported": False',
        '"/usr/sbin/zpool", "status"', '"/usr/sbin/zfs", "get"',
        '"/usr/sbin/exportfs", "-v"', '"/usr/bin/findmnt"',
    ):
        assert required in combined, required

    for member in contract["storage"]["zfs"]["members"]:
        assert member["secret_ref"] not in combined
    assert "proxmox_storage_lifecycle" in playbook
    assert "proxmox_storage_consumers" in playbook
    assert playbook.count("gather_facts: false") == 2
    assert "Pool topology and disks should remain outside" not in documentation
    assert "audit-only prerequisites" in documentation
    assert "remains owned by OpenTofu/PVE API" in documentation
    assert "must not share one authorization" in documentation
    print("proxmox_storage_lifecycle_tests=passed")


if __name__ == "__main__":
    main()
