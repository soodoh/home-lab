#!/usr/bin/env python3
"""Reject widening of the disposable Debian qualification boundary."""
from pathlib import Path

root = Path(__file__).resolve().parents[2]
source = (root / "infrastructure/tofu/debian-lifecycle-qualification/main.tf").read_text()

required = (
    'vm_id      = 9900',
    'reboot_after_update                  = false',
    'on_boot       = false',
    'protection    = false',
    'delete_unreferenced_disks_on_destroy = true',
    'serial       = "DEB-LIFE-ROOT-32G"',
    'input_policy  = "DROP"',
    'output_policy = "DROP"',
    'source  = "${var.controller_ipv4}/32"',
    'dest    = "192.168.0.0/16"',
    'comment = "public package sources only"',
    'package_update: false',
    'package_upgrade: false',
    'sudo: ALL=(ALL) NOPASSWD:ALL',
    'upload_mode  = "stream"',
)
for item in required:
    assert item in source, f"Debian qualification boundary omits {item}"

for forbidden in (
    "HOME-LAB-DEBIAN-64G",
    "HOME-LAB-STATE",
    "HOME-LAB-GAMES",
    "d4a19647-7879-4079-9fc9-b3e79711b449",
    "31602ce7-0054-498a-9f24-f51ca491e7b3",
    "vm_id       = 100",
    "on_boot       = true",
    "protection    = true",
    "package_upgrade: true",
    "tailscale",
    "age-keygen",
    "docker.io",
):
    assert forbidden not in source, f"Debian qualification contains forbidden production value {forbidden}"

assert source.index('dest    = "192.168.0.0/16"') < source.index('dest    = "0.0.0.0/0"')
assert source.count('resource "proxmox_virtual_environment_vm"') == 1
assert source.count("disk {") == 1
print("debian_lifecycle_qualification=verified vmid=9900 isolated=true automatic_apply=false")
