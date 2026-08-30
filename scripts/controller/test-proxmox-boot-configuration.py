#!/usr/bin/env python3
"""Adversarial source-boundary tests for Proxmox boot-configuration planning."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
PROJECTION = ROOT / "nix/proxmox/projection.json"
ROLE = ROOT / "ansible/roles/proxmox_boot_configuration/tasks/main.yml"
PLAYBOOK = ROOT / "ansible/playbooks/proxmox-boot-configuration-plan.yml"


def main() -> None:
    parsed = subprocess.run(
        ("node", "-e", "const fs=require('node:fs');const y=require('js-yaml');process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1],'utf8'))));", str(CONTRACT)),
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    contract = json.loads(parsed.stdout)
    projection = json.loads(PROJECTION.read_bytes())
    role = ROLE.read_text(encoding="utf-8")
    playbook = PLAYBOOK.read_text(encoding="utf-8")

    handoff = contract["lifecycle"]["hosts"]["proxmox"]["domain_handoffs"]["boot_configuration"]
    assert handoff == {
        "current_owner": "ansible",
        "target_owner": "ansible",
        "state": "transferred",
        "parity_required": True,
        "single_writer": True,
    }

    vfio = contract["proxmox"]["vfio"]
    protected_file = vfio["modprobe_file"]
    assert protected_file["kind"] == "protected-managed-file"
    assert protected_file["projectable"] is False
    assert all(item["path"] != protected_file["path"] for item in projection["managedFiles"])
    assert all(item["path"] != protected_file["path"] for item in projection["planningPolicy"]["managedFilePolicies"])

    protected_literals = [
        *vfio["device_ids"],
        contract["proxmox"]["vm"]["pci"]["gpu"]["bdf"],
        contract["proxmox"]["vm"]["pci"]["gpu_audio"]["bdf"],
        contract["proxmox"]["vm"]["pci"]["host_igpu"]["bdf"],
    ]
    for value in protected_literals:
        assert value not in role
        assert value not in playbook

    assert "no_log: true" in role
    assert "expected_modprobe_sha256" in role
    assert "expected_id_sha256" not in role
    assert "unexpected_vfio_device_count" in role
    assert "protectedHardware" in role
    assert "mutation_authorized: false" in role
    assert "changed_when: false" in role
    assert "check_mode: false" in role
    assert "'device_ids':" not in role
    assert "'soft_dependencies':" not in role
    assert "'pci': proxmox.vm.pci" not in role
    assert "'zfs': storage.zfs" not in role

    for forbidden in (
        "update-grub",
        "update-initramfs",
        "apt-get",
        "dist-upgrade",
        'systemctl", "restart',
        'systemctl", "reboot',
        "/sys/bus/pci/drivers/vfio-pci/bind",
        "/sys/bus/pci/drivers/vfio-pci/unbind",
    ):
        assert forbidden not in role

    assert "proxmox_boot_configuration" in playbook
    assert "lifecycle_state_enforce: false" in playbook
    print("proxmox_boot_configuration_tests=passed")


if __name__ == "__main__":
    main()
