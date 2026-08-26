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
    IMAGE: "proxmox_download_file",
    CLOUD_INIT: "proxmox_virtual_environment_file",
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
    if set(value) != {"checksum", "checksum_algorithm", "content_type", "datastore_id", "file_name", "node_name", "url"}:
        fail("image_fields_differ")
    expected = {
        "content_type": "import", "datastore_id": "local", "node_name": "proxmox",
        "url": IMAGE_URL, "checksum": IMAGE_SHA512, "checksum_algorithm": "sha512",
    }
    names = {
        "home-lab-restic-recovery-debian-20260810-2566.qcow2",
        "home-lab-restic-recovery-debian-20260810-2566.qcow2.img",
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()) or value.get("file_name") not in names:
        fail("image_identity_differs")


def validate_cloud_init(value: dict[str, Any], expected_sha256: str) -> None:
    if set(value) != {"content_type", "datastore_id", "node_name", "source_raw"}:
        fail("cloud_init_resource_fields_differ")
    if value.get("content_type") != "snippets" or value.get("datastore_id") != "local" or value.get("node_name") != "proxmox":
        fail("cloud_init_resource_identity_differs")
    source = one(value.get("source_raw"), "cloud_init_source")
    if set(source) != {"data", "file_name"}:
        fail("cloud_init_source_fields_differ")
    data = source.get("data")
    if (source.get("file_name") != "home-lab-restic-recovery-cloud-init.yaml" or not isinstance(data, str)
            or hashlib.sha256(data.encode()).hexdigest() != expected_sha256):
        fail("cloud_init_content_identity_differs")


def validate_disk(value: dict[str, Any], interface: str, serial: str, size: int, imported: bool, operation: str) -> None:
    expected_keys = {
        "aio", "backup", "cache", "datastore_id", "discard", "file_id", "import_from", "interface",
        "iothread", "path_in_datastore", "queues", "replicate", "serial", "size", "speed", "ssd",
    }
    expected = {
        "aio": "io_uring", "datastore_id": "local-lvm", "interface": interface, "serial": serial, "size": size,
        "iothread": True, "backup": False, "cache": "none", "discard": "on", "queues": 0,
        "replicate": False, "speed": [], "ssd": False,
    }
    if set(value) != expected_keys or any(value.get(key) != expected_value for key, expected_value in expected.items()):
        fail(f"disk_{interface}_differs")
    import_from = value.get("import_from")
    file_id = value.get("file_id")
    if operation == "destroy":
        if import_from not in (None, "") or not isinstance(file_id, str) or re.fullmatch(r"local-lvm:vm-9900-disk-[0-9]+", file_id) is None:
            fail("destroy_disk_identity_differs")
    elif imported:
        expected_name = "home-lab-restic-recovery-debian-20260810-2566.qcow2"
        if import_from not in (None, "") or not isinstance(file_id, str) or expected_name not in file_id:
            fail("root_import_differs")
    elif import_from not in (None, "") or file_id not in (None, ""):
        fail("recovery_disk_import_differs")
    if value.get("path_in_datastore") not in (None, ""):
        fail("disk_existing_identity_forbidden")


def validate_vm(value: dict[str, Any], operation: str) -> None:
    expected_fields = {
        "agent", "boot_order", "cdrom", "clone", "cpu", "delete_unreferenced_disks_on_destroy", "disk",
        "efi_disk", "hook_script_file_id", "hostpci", "initialization", "machine", "memory", "name",
        "network_device", "node_name", "on_boot", "operating_system", "protection", "purge_on_destroy",
        "reboot_after_update", "scsi_hardware", "serial_device", "started", "stop_on_destroy", "tags",
        "tpm_state", "usb", "vm_id",
    }
    if set(value) != expected_fields:
        fail("vm_fields_differ")
    expected = {
        "vm_id": 9900, "name": "home-lab-restic-recovery", "node_name": "proxmox",
        "machine": "q35", "scsi_hardware": "virtio-scsi-single", "boot_order": ["scsi0"],
        "on_boot": False, "started": True, "protection": False,
        "stop_on_destroy": True, "purge_on_destroy": True, "reboot_after_update": True,
        "delete_unreferenced_disks_on_destroy": True,
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        fail("vm_identity_or_lifecycle_differs")
    if sorted(value.get("tags") or []) != ["disposable", "qualification", "restic-recovery"]:
        fail("vm_tags_differ")
    if not absent_or_empty(value, ("clone", "hostpci", "usb", "hook_script_file_id", "cdrom", "efi_disk", "tpm_state")):
        fail("host_or_passthrough_attachment_forbidden")
    agent = one(value.get("agent"), "agent")
    wait_for_ip = one(agent.get("wait_for_ip"), "agent_wait_for_ip")
    if (set(agent) != {"enabled", "timeout", "trim", "type", "wait_for_ip"}
            or set(wait_for_ip) != {"disabled", "ipv4", "ipv6"}
            or agent.get("enabled") is not True or agent.get("timeout") != "15m"
            or agent.get("trim") is not False or agent.get("type") != "virtio"
            or wait_for_ip.get("disabled") is not False or wait_for_ip.get("ipv4") is not True
            or wait_for_ip.get("ipv6") is not False):
        fail("qemu_agent_identity_differs")
    operating_system = one(value.get("operating_system"), "operating_system")
    serial_device = one(value.get("serial_device"), "serial_device")
    if set(operating_system) != {"type"} or set(serial_device) != {"device"} or operating_system.get("type") != "l26" or serial_device.get("device") != "socket":
        fail("guest_platform_identity_differs")
    cpu = one(value.get("cpu"), "cpu")
    memory = one(value.get("memory"), "memory")
    if (set(cpu) != {"cores", "type"} or set(memory) != {"dedicated", "floating"}
            or cpu.get("cores") != 8 or cpu.get("type") != "host"
            or memory.get("dedicated") != 16384 or memory.get("floating") != 0):
        fail("compute_identity_differs")
    disks = value.get("disk")
    if not isinstance(disks, list) or len(disks) != 2:
        fail("disk_count_differs")
    by_interface = {item.get("interface"): item for item in disks if isinstance(item, dict)}
    if set(by_interface) != {"scsi0", "scsi1"}:
        fail("disk_interfaces_differ")
    validate_disk(by_interface["scsi0"], "scsi0", "RESTIC-RECOVERY-ROOT-32G", 32, True, operation)
    validate_disk(by_interface["scsi1"], "scsi1", "RESTIC-RECOVERY-128G", 128, False, operation)
    network = one(value.get("network_device"), "network")
    network_keys = {"bridge", "firewall", "model"} if operation == "create" else {"bridge", "firewall", "mac_address", "model"}
    if (set(network) != network_keys or network.get("bridge") != "vmbr0" or network.get("model") != "virtio"
            or network.get("firewall") is not True
            or (operation == "destroy" and (not isinstance(network.get("mac_address"), str)
                or re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", network["mac_address"]) is None))):
        fail("network_identity_differs")
    initialization = one(value.get("initialization"), "initialization")
    expected_initialization = {"datastore_id", "ip_config", "upgrade", "user_account", "user_data_file_id"}
    user_data = initialization.get("user_data_file_id")
    valid_user_data = (
        isinstance(user_data, str) and "home-lab-restic-recovery-cloud-init.yaml" in user_data
    ) or (operation == "create" and user_data in (None, ""))
    if (set(initialization) != expected_initialization or initialization.get("datastore_id") != "local-lvm"
            or initialization.get("upgrade") is not False or not valid_user_data
            or initialization.get("user_account") not in (None, [], {})):
        fail("cloud_init_identity_differs")
    ip_config = one(initialization.get("ip_config"), "ip_config")
    ipv4 = one(ip_config.get("ipv4"), "ipv4")
    if set(ip_config) != {"ipv4", "ipv6"} or ip_config.get("ipv6") not in (None, []) or set(ipv4) != {"address"} or ipv4.get("address") != "dhcp":
        fail("dhcp_identity_differs")


def sensitive_unknown(unknown: Any) -> bool:
    if not isinstance(unknown, dict):
        return True
    if set(unknown) != {"boot_order", "clone", "disk", "hostpci", "initialization", "network_device", "usb"}:
        return True
    if unknown.get("boot_order") != [False] or unknown.get("clone") != [] or unknown.get("hostpci") != [] or unknown.get("usb") != []:
        return True
    disks = unknown.get("disk")
    if (not isinstance(disks, list) or len(disks) != 2
            or any(not isinstance(item, dict) or set(item) != {"file_format", "path_in_datastore", "speed"}
                   or item.get("file_format") is not True or item.get("path_in_datastore") is not True
                   or item.get("speed") != [] for item in disks)):
        return True
    networks = unknown.get("network_device")
    if networks != [{"mac_address": True}]:
        return True
    initializations = unknown.get("initialization")
    if not isinstance(initializations, list) or len(initializations) != 1 or not isinstance(initializations[0], dict):
        return True
    item = initializations[0]
    expected = {"dns", "file_format", "ip_config", "meta_data_file_id", "network_data_file_id", "type", "user_data_file_id", "vendor_data_file_id"}
    if (set(item) != expected or item.get("dns") != [] or item.get("file_format") is not True
            or item.get("meta_data_file_id") is not True or item.get("network_data_file_id") is not True
            or item.get("type") is not True or item.get("user_data_file_id") is not True
            or item.get("vendor_data_file_id") is not True
            or item.get("ip_config") != [{"ipv4": [{}], "ipv6": []}]):
        return True
    return False


def validate_configuration(plan: dict[str, Any]) -> None:
    resources = plan.get("configuration", {}).get("root_module", {}).get("resources", [])
    vm = [item for item in resources if item.get("address") == VM_BLOCK]
    if len(vm) != 1:
        fail("vm_configuration_absent")
    encoded = json.dumps(vm[0].get("expressions", {}), sort_keys=True)
    if CLOUD_INIT not in encoded or "qualification_cloud_init_user_data" not in json.dumps(plan.get("configuration", {}), sort_keys=True):
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
        if VM not in mutated or not {VM, CLOUD_INIT} <= observed or IMAGE not in observed:
            fail("required_create_scope_absent")
    elif not mutated:
        fail("required_destroy_change_absent")
    print(f"restic_recovery_vm_plan=verified operation={args.operation} resources={len(observed)} changes={len(mutated)}")


if __name__ == "__main__":
    main()
