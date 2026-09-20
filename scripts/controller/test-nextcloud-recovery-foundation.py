#!/usr/bin/env python3
"""Static refusal tests for the stopped-only Nextcloud recovery foundation."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOFU = ROOT / "infrastructure/tofu/nextcloud-recovery-qualification"


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AssertionError(reason)


def main() -> None:
    main_source = (TOFU / "main.tf").read_text()
    variables = (TOFU / "variables.tf").read_text()
    versions = (TOFU / "versions.tf").read_text()
    outputs = (TOFU / "outputs.tf").read_text()
    provider_lock = (TOFU / ".terraform.lock.hcl").read_text()
    combined = "\n".join((main_source, variables, versions, outputs))

    require('version = "= 0.111.1"' in versions, "provider version must remain exact")
    require('version     = "0.111.1"' in provider_lock, "provider lock must match the source pin")
    require('h1:' in provider_lock and 'zh:' in provider_lock, "provider lock must retain package hashes")
    require('backend "local" {}' in versions, "foundation must not share remote production state")
    require(re.search(r"^\s*vm_id\s*=\s*9000$", main_source, re.MULTILINE) is not None, "VMID 9000 must remain fixed")
    require(re.search(r"^\s*started\s*=\s*false$", main_source, re.MULTILINE) is not None, "provider root must never start the guest")
    require(re.search(r"^\s*on_boot\s*=\s*false$", main_source, re.MULTILINE) is not None, "guest must not start at boot")
    require(re.search(r"^\s*memory_mb\s*=\s*6144$", main_source, re.MULTILINE) is not None, "guest memory must remain 6 GiB")
    require(re.search(r"^\s*disk_size_gb\s*=\s*64$", main_source, re.MULTILINE) is not None, "recovery disk must remain 64 GiB")
    require(re.search(r'^\s*disk_datastore\s*=\s*"local-lvm"$', main_source, re.MULTILINE) is not None, "production ZFS pool must not hold the guest disk")
    require('retrieval_bridge = "vmbr0"' in main_source, "temporary bridge must remain explicit")
    require('proxmox_endpoint = "https://proxmox:8006/api2/json"' in main_source, "provider endpoint must remain exact")
    require('network_device = var.retrieval_nic_enabled ? [{' in main_source, "NIC presence must use one boolean seam")
    require('}] : []' in main_source, "NIC removal must use an explicit empty list")
    require('dynamic "network_device"' not in main_source, "zero dynamic blocks would preserve net0 instead of deleting it")
    require(re.search(r"^\s*firewall\s*=\s*true$", main_source, re.MULTILINE) is not None, "retrieval NIC must enable the PVE firewall")
    require('condition     = can(cidrhost("${var.controller_ipv4}/32", 0))' in main_source, "enabled firewall must require an exact controller IPv4")

    expected_variables = {
        "proxmox_endpoint",
        "enable_foundation",
        "retrieval_nic_enabled",
        "controller_ipv4",
        "recovery_ssh_public_key",
        "recovery_ssh_public_key_sha256",
        "isolation_attestation_sha256",
    }
    observed_variables = set(re.findall(r'^variable "([^"]+)"', variables, re.MULTILINE))
    require(observed_variables == expected_variables, f"unexpected foundation interface: {sorted(observed_variables)}")
    require('variable "start' not in variables, "root must expose no startup authority")

    expected_resources = {
        "proxmox_download_file.recovery_image",
        "proxmox_virtual_environment_file.cloud_init",
        "proxmox_virtual_environment_vm.foundation",
        "proxmox_virtual_environment_firewall_options.foundation",
        "proxmox_virtual_environment_firewall_rules.foundation",
    }
    observed_resources = {
        f"{kind}.{name}"
        for kind, name in re.findall(r'^resource "([^"]+)" "([^"]+)"', main_source, re.MULTILINE)
    }
    require(observed_resources == expected_resources, f"unexpected resources: {sorted(observed_resources)}")
    require(main_source.count('count = var.enable_foundation ? 1 : 0') == len(expected_resources), "every resource must be disabled by default")

    require('input_policy  = "DROP"' in main_source, "input policy must drop")
    require('output_policy = "DROP"' in main_source, "output policy must drop")
    deny_destinations = (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "224.0.0.0/4",
    )
    https_position = main_source.index('comment = "public HTTPS retrieval after private denies"')
    for destination in deny_destinations:
        require(main_source.index(f'dest    = "{destination}"') < https_position, f"{destination} deny must precede HTTPS")
    require(main_source.count('dport   = "53"') == 4, "DNS must be limited to two fixed resolvers over UDP/TCP")
    require(main_source.count('dport   = "443"') == 1, "only one broad public retrieval rule is allowed")
    require('dport   = "80"' not in main_source, "plaintext HTTP egress is forbidden")

    require("net.ipv6.conf.all.disable_ipv6=1" in main_source, "cloud-init must disable IPv6")
    require("package_update: false" in main_source and "package_upgrade: false" in main_source, "cloud-init package mutation is forbidden")
    require("packages:" not in main_source, "tools must arrive as pinned archives, not packages")
    for forbidden in (
        "remote-exec",
        "local-exec",
        "/mnt/storage",
        "/mnt/games",
        "tailscale",
        "proxmox_virtual_environment_vm.debian",
        "vm_id       = 100",
        "started       = true",
    ):
        require(forbidden not in combined, f"foundation contains forbidden authority: {forbidden}")

    require('retrieval_nic_enabled = var.retrieval_nic_enabled' in outputs, "output must report NIC presence")
    require('started               = false' in outputs, "output must attest stopped-only scope")
    print("nextcloud_recovery_foundation=verified stopped_only=true resources=5")


if __name__ == "__main__":
    main()
