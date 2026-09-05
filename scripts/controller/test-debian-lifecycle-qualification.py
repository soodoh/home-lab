#!/usr/bin/env python3
"""Reject widening of the disposable Debian qualification boundary."""
from pathlib import Path

root = Path(__file__).resolve().parents[2]
source = (root / "infrastructure/tofu/debian-lifecycle-qualification/main.tf").read_text() + (root / "infrastructure/debian/cloud-init/qualification-user-data.tftpl").read_text()

required = (
    'vm_id    = 9900',
    'resource "proxmox_download_file" "qualification_image"',
    'checksum_algorithm = "sha512"',
    'url                = local.contract.debian.image.url',
    'checksum           = local.contract.debian.image.sha512',
    'datastore_id = var.qualification_disk_datastore_id',
    'node_name   = var.qualification_node_name',
    'bridge   = var.qualification_bridge',
    'import_from  = proxmox_download_file.qualification_image[0].id',
    'var.isolation_attestation_sha256 != ""',
    'variable "start_qualification"',
    'sha256(var.qualification_ssh_public_key) == var.qualification_ssh_public_key_sha256',
    'qualification-[a-z0-9-]+$',
    'local.contract.lifecycle.qualification_route.mode == "production-pve-disposable-vm"',
    'local.contract.lifecycle.qualification_route.production_vm_mutation_allowed == false',
    'local.contract.lifecycle.qualification_route.production_disk_attachment_allowed == false',
    'var.proxmox_endpoint == local.contract.proxmox.api_endpoint',
    'var.qualification_cloud_init_file_id == "local:snippets/home-lab-debian-lifecycle-qualification.yaml"',
    'reboot_after_update                  = false',
    'on_boot       = false',
    'started       = var.start_qualification',
    'protection    = false',
    'delete_unreferenced_disks_on_destroy = true',
    'serial       = "DEB-LIFE-ROOT-32G"',
    'input_policy  = "DROP"',
    'output_policy = "DROP"',
    'dest    = "255.255.255.255/32"',
    'sport   = "68"',
    'dport   = "67"',
    'source  = "0.0.0.0/0"',
    'sport   = "67"',
    'dport   = "68"',
    'source  = "${var.controller_ipv4}/32"',
    'dest    = "192.168.0.0/16"',
    'dest    = "100.64.0.0/10"',
    'comment = "public IPv4 egress after private and CGNAT denies"',
    'servers = ["1.1.1.1", "9.9.9.9"]',
    'package_update: false',
    'package_upgrade: false',
    'sudo: ALL=(ALL) NOPASSWD:ALL',
    'while [ "$attempt" -lt 60 ]; do',
    '/usr/bin/systemctl start systemd-resolved.service',
    '/usr/bin/resolvectl status eth0',
    '/usr/bin/resolvectl dns eth0 1.1.1.1 9.9.9.9',
    '/usr/bin/sleep 1',
    'path: /etc/systemd/network/10-cloud-init-eth0.network.d/10-public-dns.conf',
    'UseDNS=no',
    'user_data_file_id = var.qualification_cloud_init_file_id',
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
    "started       = true",
    "package_upgrade: true",
    "tailscale",
    "age-keygen",
    "docker.io",
    "local:import/home-lab-restic-recovery-",
    'resource "proxmox_virtual_environment_file"',
    "  ssh {",
):
    assert forbidden not in source, f"Debian qualification contains forbidden production value {forbidden}"

for denied in ('10.0.0.0/8', '100.64.0.0/10', '172.16.0.0/12', '192.168.0.0/16'):
    assert source.index(f'dest    = "{denied}"') < source.index('dest    = "0.0.0.0/0"')
assert source.count('resource "proxmox_virtual_environment_vm"') == 1
assert source.count("disk {") == 1
print("debian_lifecycle_qualification=verified vmid=9900 shared_hypervisor=true production_vm_mutation=false automatic_apply=false")
