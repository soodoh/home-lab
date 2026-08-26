#!/usr/bin/env python3
"""Accept only exact provider-0.111.1 plans for disposable recovery VM 9900."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

HEX = re.compile(r"^[0-9a-f]{64}$")
IMAGE = "proxmox_download_file.recovery_image[0]"
CLOUD_INIT = "proxmox_virtual_environment_file.recovery_cloud_init[0]"
VM = "proxmox_virtual_environment_vm.recovery[0]"
VM_BLOCK = "proxmox_virtual_environment_vm.recovery"
ALLOWED = {
    VM: "proxmox_virtual_environment_vm",
}
IMAGE_URL = "https://cloud.debian.org/images/cloud/trixie/20260810-2566/debian-13-generic-amd64-20260810-2566.qcow2"
IMAGE_SHA512 = "f6978100d8031c266d55d7815ceea7fcdeacf28e1e5834fdb9c94ac96880a054a6e6f8681c2d3b0584e0057eaf3ef7353856b85212d04134744faa9b3bb1f24f"


def fail(message: str) -> None:
    raise SystemExit(f"restic_recovery_vm_plan=failed reason={message}")


def one(values: Any, label: str) -> dict[str, Any]:
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        fail(f"{label}_differs")
    return values[0]


def absent_or_empty(value: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return all(value.get(key) in (None, [], {}, "") for key in keys)


def validate_image(value: dict[str, Any]) -> None:
    expected = {
        "checksum": IMAGE_SHA512, "checksum_algorithm": "sha512", "content_type": "import",
        "datastore_id": "local", "decompression_algorithm": None,
        "file_name": "home-lab-restic-recovery-debian-20260810-2566.qcow2",
        "node_name": "proxmox", "overwrite": True, "overwrite_unmanaged": False,
        "upload_timeout": 600, "url": IMAGE_URL, "verify": True,
    }
    if value != expected:
        fail("image_identity_differs")


def validate_cloud_init(value: dict[str, Any], expected_sha256: str) -> None:
    expected_keys = {"content_type", "datastore_id", "file_mode", "node_name", "overwrite", "source_file", "source_raw", "timeout_upload", "upload_mode"}
    if (set(value) != expected_keys or value.get("content_type") != "snippets" or value.get("datastore_id") != "local"
            or value.get("file_mode") is not None or value.get("node_name") != "proxmox" or value.get("overwrite") is not True
            or value.get("source_file") != [] or value.get("timeout_upload") != 1800 or value.get("upload_mode") != "stream"):
        fail("cloud_init_resource_identity_differs")
    source = one(value.get("source_raw"), "cloud_init_source")
    data = source.get("data")
    if (set(source) != {"data", "file_name", "resize"}
            or source.get("file_name") != "home-lab-restic-recovery-cloud-init.yaml" or source.get("resize") != 0
            or not isinstance(data, str) or hashlib.sha256(data.encode()).hexdigest() != expected_sha256):
        fail("cloud_init_content_identity_differs")


def validate_disk(value: dict[str, Any], interface: str, serial: str, size: int, imported: bool, operation: str) -> None:
    common = {
        "aio": "io_uring", "backup": False, "cache": "none", "datastore_id": "local-lvm", "discard": "on",
        "interface": interface, "iothread": True, "queues": 0, "replicate": False, "serial": serial,
        "size": size, "speed": [], "ssd": False,
    }
    if any(value.get(key) != expected for key, expected in common.items()):
        fail(f"disk_{interface}_differs")
    if operation == "create":
        expected_keys = set(common) | {"file_id", "import_from"}
        expected_import = "local:import/home-lab-restic-recovery-debian-20260810-2566.qcow2" if imported else None
        if set(value) != expected_keys or value.get("file_id") is not None or value.get("import_from") != expected_import:
            fail("create_disk_identity_differs")
    else:
        expected_keys = set(common) | {"file_format", "file_id", "import_from", "path_in_datastore"}
        file_id = value.get("file_id")
        if (set(value) != expected_keys or value.get("import_from") not in (None, "")
                or not isinstance(file_id, str) or re.fullmatch(r"local-lvm:vm-9900-disk-[0-9]+", file_id) is None
                or value.get("path_in_datastore") not in (None, "")):
            fail("destroy_disk_identity_differs")


def validate_vm(value: dict[str, Any], operation: str) -> None:
    expected_fields = {
        "acpi", "agent", "amd_sev", "audio_device", "bios", "boot_order", "cdrom", "clone", "cpu",
        "delete_unreferenced_disks_on_destroy", "description", "disk", "efi_disk", "hook_script_file_id",
        "hostpci", "initialization", "keyboard_layout", "kvm_arguments", "machine", "memory", "migrate",
        "name", "network_device", "node_name", "numa", "on_boot", "operating_system", "pool_id",
        "protection", "purge_on_destroy", "reboot", "reboot_after_update", "rng", "scsi_hardware",
        "serial_device", "smbios", "started", "startup", "stop_on_destroy", "tablet_device", "tags",
        "template", "timeout_clone", "timeout_create", "timeout_migrate", "timeout_move_disk", "timeout_reboot",
        "timeout_shutdown_vm", "timeout_start_vm", "timeout_stop_vm", "tpm_state", "usb", "virtiofs", "vm_id", "watchdog",
    }
    if set(value) != expected_fields: fail("vm_fields_differ")
    expected = {
        "acpi": True, "bios": "seabios", "boot_order": ["scsi0"], "delete_unreferenced_disks_on_destroy": True,
        "description": "Disposable isolated Proton Restic restore qualification; never production VM 100",
        "keyboard_layout": "en-us", "kvm_arguments": None, "machine": "q35", "migrate": False,
        "name": "home-lab-restic-recovery", "node_name": "proxmox", "on_boot": False, "pool_id": None,
        "protection": False, "purge_on_destroy": True, "reboot": False, "reboot_after_update": True,
        "scsi_hardware": "virtio-scsi-single", "started": True, "stop_on_destroy": True, "tablet_device": True,
        "template": False, "timeout_clone": 1800, "timeout_create": 1800, "timeout_migrate": 1800,
        "timeout_move_disk": 1800, "timeout_reboot": 1800, "timeout_shutdown_vm": 1800,
        "timeout_start_vm": 1800, "timeout_stop_vm": 300, "vm_id": 9900,
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()): fail("vm_identity_or_lifecycle_differs")
    empty = ("amd_sev", "audio_device", "cdrom", "clone", "efi_disk", "hostpci", "numa", "rng", "smbios", "startup", "tpm_state", "usb", "virtiofs", "watchdog")
    if not absent_or_empty(value, empty) or value.get("hook_script_file_id") not in (None, ""): fail("host_or_passthrough_attachment_forbidden")
    if sorted(value.get("tags") or []) != ["disposable", "qualification", "restic-recovery"]: fail("vm_tags_differ")
    agent = one(value.get("agent"), "agent"); wait_for_ip = one(agent.get("wait_for_ip"), "agent_wait_for_ip")
    if (agent != {"enabled": True, "timeout": "15m", "trim": False, "type": "virtio", "wait_for_ip": [wait_for_ip]}
            or wait_for_ip != {"disabled": False, "ipv4": True, "ipv6": False}): fail("qemu_agent_identity_differs")
    cpu = one(value.get("cpu"), "cpu"); memory = one(value.get("memory"), "memory")
    if cpu != {"affinity": None, "architecture": None, "cores": 8, "flags": None, "hotplugged": 0, "limit": 0, "numa": False, "sockets": 1, "type": "host"}: fail("compute_identity_differs")
    if memory != {"dedicated": 16384, "floating": 0, "hugepages": None, "keep_hugepages": False, "shared": 0}: fail("memory_identity_differs")
    if one(value.get("operating_system"), "operating_system") != {"type": "l26"} or one(value.get("serial_device"), "serial_device") != {"device": "socket"}: fail("guest_platform_identity_differs")
    disks = value.get("disk")
    if not isinstance(disks, list) or len(disks) != 2: fail("disk_count_differs")
    by_interface = {item.get("interface"): item for item in disks if isinstance(item, dict)}
    if set(by_interface) != {"scsi0", "scsi1"}: fail("disk_interfaces_differ")
    validate_disk(by_interface["scsi0"], "scsi0", "RESTIC-ROOT-32G", 32, True, operation)
    validate_disk(by_interface["scsi1"], "scsi1", "RESTIC-RECOVERY-128G", 128, False, operation)
    network = one(value.get("network_device"), "network")
    expected_network = {"bridge": "vmbr0", "disconnected": None, "enabled": True, "firewall": True, "model": "virtio", "mtu": 0, "queues": 0, "rate_limit": 0, "trunks": None, "vlan_id": 0}
    if operation == "destroy":
        mac = network.get("mac_address")
        if not isinstance(mac, str) or re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) is None: fail("network_mac_differs")
        expected_network["mac_address"] = mac
    if network != expected_network: fail("network_identity_differs")
    initialization = one(value.get("initialization"), "initialization")
    common_initialization = {"datastore_id": "local-lvm", "dns": [], "interface": None, "ip_config": [{"ipv4": [{"address": "dhcp", "gateway": None}], "ipv6": []}], "upgrade": False, "user_account": [], "user_data_file_id": "local:snippets/home-lab-restic-recovery-cloud-init.yaml"}
    if operation == "create":
        if initialization != common_initialization: fail("cloud_init_identity_differs")
    else:
        allowed = set(common_initialization) | {"file_format"}
        if set(initialization) != allowed or any(initialization.get(key) != val for key, val in common_initialization.items()): fail("cloud_init_identity_differs")


def sensitive_unknown(unknown: Any) -> bool:
    expected = {
        "agent": [{"wait_for_ip": [{}]}], "amd_sev": [], "audio_device": [], "boot_order": [False],
        "cdrom": [], "clone": [], "cpu": [{"units": True}],
        "disk": [
            {"file_format": True, "path_in_datastore": True, "speed": []},
            {"file_format": True, "path_in_datastore": True, "speed": []},
        ],
        "efi_disk": [], "hostpci": [], "hotplug": True, "id": True,
        "initialization": [{
            "dns": [], "file_format": True, "ip_config": [{"ipv4": [{}], "ipv6": []}],
            "meta_data_file_id": True, "network_data_file_id": True, "type": True,
            "user_account": [], "vendor_data_file_id": True,
        }],
        "ipv4_addresses": True, "ipv6_addresses": True, "mac_addresses": True,
        "memory": [{}], "network_device": [{"mac_address": True}], "network_interface_names": True,
        "numa": [], "operating_system": [{}], "rng": [], "serial_device": [{}], "smbios": [],
        "startup": [], "tags": [False, False, False], "tpm_state": [], "usb": [], "vga": True,
        "virtiofs": [], "watchdog": [],
    }
    return unknown != expected


def validate_configuration(plan: dict[str, Any]) -> None:
    resources = plan.get("configuration", {}).get("root_module", {}).get("resources", [])
    vm = [item for item in resources if item.get("address") == VM_BLOCK]
    if len(vm) != 1: fail("vm_configuration_absent")
    encoded = json.dumps(vm[0].get("expressions", {}), sort_keys=True)
    if ("home-lab-restic-recovery-cloud-init.yaml" not in encoded
            or "proxmox_virtual_environment_file" in encoded):
        fail("cloud_init_reference_differs")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    parser.add_argument("--operation", choices=("create", "destroy"), required=True)
    parser.add_argument("--expected-cloud-init-sha256", required=True)
    args = parser.parse_args()
    if HEX.fullmatch(args.expected_cloud_init_sha256) is None:
        fail("cloud_init_hash_differs")
    try:
        plan = json.loads(args.plan_json.read_text())
    except (OSError, json.JSONDecodeError):
        fail("unreadable_plan")
    if args.operation == "create":
        validate_configuration(plan)
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        fail("resource_changes_absent")
    observed: set[str] = set()
    mutated: set[str] = set()
    for change in changes:
        if not isinstance(change, dict):
            fail("resource_change_invalid")
        address = change.get("address")
        if address not in ALLOWED or change.get("type") != ALLOWED[address] or address in observed:
            fail("resource_scope_differs")
        actions = (change.get("change") or {}).get("actions")
        permitted = (["create"], ["no-op"]) if args.operation == "create" else (["delete"], ["no-op"])
        if actions not in permitted:
            fail("resource_actions_differ")
        if actions != ["no-op"]:
            mutated.add(address)
        value = change["change"].get("after" if args.operation == "create" else "before")
        if not isinstance(value, dict):
            fail("resource_value_absent")
        if args.operation == "create" and address == VM and sensitive_unknown(change["change"].get("after_unknown", {})):
            fail("security_sensitive_value_unknown")
        if address == IMAGE:
            validate_image(value)
        elif address == CLOUD_INIT:
            validate_cloud_init(value, args.expected_cloud_init_sha256)
        else:
            validate_vm(value, args.operation)
        observed.add(address)
    if args.operation == "create":
        if VM not in mutated or VM not in observed:
            fail("required_create_scope_absent")
    elif not mutated:
        fail("required_destroy_change_absent")
    print(f"restic_recovery_vm_plan=verified operation={args.operation} resources={len(observed)} changes={len(mutated)}")


if __name__ == "__main__":
    main()
