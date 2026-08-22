#!/usr/bin/env python3
"""Reject unsafe OpenTofu plans before any apply."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any

SENSITIVE_FIELDS = {
    "vm_id",
    "vmid",
    "mac_address",
    "protection",
    "disk",
    "hostpci",
    "usb",
    "network_device",
    "path_in_datastore",
}
VM_BOOT_LIFECYCLE_FIELDS = {
    "acpi",
    "agent",
    "audio_device",
    "bios",
    "boot_order",
    "cdrom",
    "clone",
    "cpu",
    "delete_unreferenced_disks_on_destroy",
    "efi_disk",
    "hook_script_file_id",
    "initialization",
    "kvm_arguments",
    "machine",
    "memory",
    "migrate",
    "node_name",
    "numa",
    "on_boot",
    "operating_system",
    "purge_on_destroy",
    "reboot",
    "reboot_after_update",
    "rng",
    "scsi_hardware",
    "serial_device",
    "smbios",
    "started",
    "startup",
    "stop_on_destroy",
    "tablet_device",
    "template",
    "timeout_clone",
    "timeout_create",
    "timeout_migrate",
    "timeout_reboot",
    "timeout_shutdown",
    "timeout_start",
    "timeout_stop",
    "tpm_state",
    "vga",
}
STORAGE_RESOURCE_MARKERS = ("zfs", "filesystem", "disk", "mount", "storage")
NETWORK_RESOURCE_MARKERS = ("firewall", "network", "acl", "ruleset", "federated_identity")
VM_ADDRESS = "proxmox_virtual_environment_vm.debian"
VM_RESOURCE_TYPE = "proxmox_virtual_environment_vm"
VM_CUTOVER_BOOT_ORDERS = {
    "vm-cutover-forward": (["scsi0", "net0"], ["scsi3", "scsi0", "net0"]),
    "vm-cutover-reverse": (["scsi3", "scsi0", "net0"], ["scsi0", "net0"]),
}
VM_MAC_ADDRESS = "BC:24:11:89:19:5A"
VM_SMBIOS_UUID = "03061602-d590-4d23-be5c-97f9954b3053"
VM_HOSTPCI_MAPPINGS = (
    ("hostpci1", "rx-7900-xtx"),
    ("hostpci2", "rx-7900-xtx-audio"),
)
VM_USB_MAPPINGS = ("zigbee-cp210x", "zwave-cp210x", "realtek-bluetooth")
VM_KVM_ARGUMENTS = "-cpu 'host,-hypervisor,kvm=off'"
VM_STATE_DISK = {
    "aio": "io_uring",
    "backup": True,
    "cache": "none",
    "datastore_id": "local-lvm",
    "discard": "ignore",
    "file_format": "raw",
    "file_id": "local-lvm:vm-100-disk-1",
    "import_from": None,
    "interface": "scsi2",
    "iothread": True,
    "path_in_datastore": None,
    "queues": 0,
    "replicate": True,
    "serial": "QUAL-NIXOS-128G",
    "size": 128,
    "speed": [],
    "ssd": False,
}
RECOVERY_RESOURCE_TYPES = {
    "proxmox_download_file.arch_recovery_image[0]": "proxmox_download_file",
    'proxmox_hardware_mapping_pci.device["gpu"]': "proxmox_hardware_mapping_pci",
    'proxmox_hardware_mapping_pci.device["gpu_audio"]': "proxmox_hardware_mapping_pci",
    'proxmox_hardware_mapping_usb.device["bluetooth"]': "proxmox_hardware_mapping_usb",
    'proxmox_hardware_mapping_usb.device["zigbee"]': "proxmox_hardware_mapping_usb",
    'proxmox_hardware_mapping_usb.device["zwave"]': "proxmox_hardware_mapping_usb",
    "proxmox_virtual_environment_vm.debian": "proxmox_virtual_environment_vm",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    parser.add_argument(
        "--mode",
        choices=(
            "normal",
            "recovery",
            "vm-start-prerequisite",
            "vm-cutover-forward",
            "vm-cutover-reverse",
        ),
        default="normal",
    )
    parser.add_argument("--allow-change-file", type=Path)
    parser.add_argument("--recovery-expectations", type=Path)
    return parser.parse_args()


def changed_keys(before: Any, after: Any, prefix: tuple[str, ...] = ()) -> set[tuple[str, ...]]:
    if isinstance(before, dict) and isinstance(after, dict):
        result: set[tuple[str, ...]] = set()
        for key in before.keys() | after.keys():
            result |= changed_keys(before.get(key), after.get(key), prefix + (str(key),))
        return result
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        result = set()
        for index, (before_item, after_item) in enumerate(zip(before, after, strict=True)):
            result |= changed_keys(before_item, after_item, prefix + (str(index),))
        return result
    if before != after:
        return {prefix}
    return set()


def value_at_path(value: Any, path: tuple[str, ...]) -> Any:
    current = value
    for part in path:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def safe_protection_enable(before: Any, after: Any, path: tuple[str, ...]) -> bool:
    return (
        bool(path)
        and path[-1] == "protection"
        and value_at_path(before, path) is False
        and value_at_path(after, path) is True
    )


def safe_state_disk_attachment(before: Any, after: Any) -> bool:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if changed_keys(before, after) != {("disk",)}:
        return False
    before_disks = before.get("disk")
    after_disks = after.get("disk")
    if not isinstance(before_disks, list) or not isinstance(after_disks, list):
        return False
    if len(before_disks) != 2 or len(after_disks) != 3 or after_disks[:2] != before_disks:
        return False
    if [disk.get("interface") for disk in before_disks if isinstance(disk, dict)] != ["scsi0", "scsi1"]:
        return False
    candidate = after_disks[2]
    return candidate == {
        "aio": "io_uring",
        "backup": True,
        "cache": "none",
        "datastore_id": "local-lvm",
        "discard": "ignore",
        "file_format": None,
        "file_id": None,
        "import_from": None,
        "interface": "scsi2",
        "iothread": True,
        "path_in_datastore": None,
        "queues": 0,
        "replicate": True,
        "serial": "QUAL-NIXOS-128G",
        "size": 128,
        "speed": [],
        "ssd": False,
    }


def safe_custom_rom_removal(before: Any, after: Any, path: tuple[str, ...]) -> bool:
    return (
        "hostpci" in path
        and path[-1:] == ("rom_file",)
        and isinstance(value_at_path(before, path), str)
        and value_at_path(after, path) in (None, "")
    )


def safe_hardware_mapping_transition(
    before: Any,
    after: Any,
    path: tuple[str, ...],
    mapping_resources: dict[str, list[dict[str, Any]]],
) -> bool:
    if len(path) != 3 or path[0] not in {"hostpci", "usb"} or not path[1].isdigit():
        return False
    raw_field = "id" if path[0] == "hostpci" else "host"
    if path[2] not in {raw_field, "mapping"}:
        return False
    devices_before = before.get(path[0]) if isinstance(before, dict) else None
    devices_after = after.get(path[0]) if isinstance(after, dict) else None
    index = int(path[1])
    if (
        not isinstance(devices_before, list)
        or not isinstance(devices_after, list)
        or index >= len(devices_before)
        or index >= len(devices_after)
    ):
        return False
    device_before = devices_before[index]
    device_after = devices_after[index]
    if not isinstance(device_before, dict) or not isinstance(device_after, dict):
        return False
    raw_value = device_before.get(raw_field)
    mapping_name = device_after.get("mapping")
    mapping_entries = mapping_resources.get(mapping_name, []) if isinstance(mapping_name, str) else []
    mapping_matches_raw_device = any(
        entry.get("path") == raw_value or entry.get("id") == raw_value
        for entry in mapping_entries
    )
    return (
        changed_keys(device_before, device_after) == {(raw_field,), ("mapping",)}
        and isinstance(raw_value, str)
        and bool(raw_value)
        and device_before.get("mapping") in (None, "")
        and device_after.get(raw_field) in (None, "")
        and isinstance(mapping_name, str)
        and bool(mapping_name)
        and mapping_matches_raw_device
    )


def expected_subset(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and expected_subset(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(expected_subset(item, wanted) for item, wanted in zip(actual, expected, strict=True))
        )
    return actual == expected


def expected_value_is_unknown(unknown: Any, expected: Any) -> bool:
    if unknown is True:
        return True
    if isinstance(expected, dict):
        if not isinstance(unknown, dict):
            return False
        return any(
            expected_value_is_unknown(unknown.get(key), value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(unknown, list):
            return False
        return any(
            expected_value_is_unknown(item_unknown, item_expected)
            for item_unknown, item_expected in zip(unknown, expected, strict=False)
        )
    return unknown is True


def load_recovery_expectations(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        raise SystemExit("recovery mode requires --recovery-expectations")
    if (
        not path.is_file()
        or path.is_symlink()
        or stat.S_IMODE(path.stat().st_mode) != 0o600
        or path.stat().st_uid != os.getuid()
    ):
        raise SystemExit("recovery expectations must be an owner-controlled mode-0600 regular file")
    value = json.loads(path.read_text())
    resources = value.get("resources") if isinstance(value, dict) and value.get("version") == 1 else None
    if not isinstance(resources, dict) or set(resources) != set(RECOVERY_RESOURCE_TYPES):
        raise SystemExit("recovery expectations must contain the complete resource set")
    for address, expectation in resources.items():
        if (
            not isinstance(expectation, dict)
            or expectation.get("type") != RECOVERY_RESOURCE_TYPES[address]
            or not isinstance(expectation.get("expected"), dict)
            or not expectation["expected"]
        ):
            raise SystemExit("recovery expectations are invalid")
    return resources


def recovery_failure(
    address: str,
    resource_type: str,
    actions: list[str],
    change: dict[str, Any],
    expectation: dict[str, Any],
) -> str | None:
    if resource_type != expectation["type"]:
        return f"{address}: recovery resource type differs from expectations"
    if change.get("importing") is not None or actions not in (["create"], ["no-op"]):
        return f"{address}: recovery permits only exact creates or no-ops"
    if actions == ["create"] and change.get("before") is not None:
        return f"{address}: recovery create must be fresh"
    after = change.get("after")
    expected = expectation["expected"]
    if not expected_subset(after, expected):
        return f"{address}: recovery planned values differ from expectations"
    if expected_value_is_unknown(change.get("after_unknown", {}), expected):
        return f"{address}: recovery protected values must be known"
    return None


def contains_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(contains_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_unknown(item) for item in value)
    return False


def canonical_by_id_path(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("/dev/disk/by-id/"):
        return False
    path = PurePosixPath(value)
    return path.is_absolute() and ".." not in path.parts and len(path.parts) == 5 and bool(path.name)


def exact_object_list(value: Any, expected: list[dict[str, Any]]) -> bool:
    return (
        isinstance(value, list)
        and len(value) == len(expected)
        and all(isinstance(item, dict) and expected_subset(item, wanted) for item, wanted in zip(value, expected, strict=True))
    )


def vm_cutover_identity_failure(before: Any, after: Any, expected_games_disk: str) -> str | None:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return "VM cutover requires complete before and after values"
    for values in (before, after):
        required_scalars = {
            "acpi": True,
            "bios": "seabios",
            "vm_id": 100,
            "name": "arch",
            "node_name": "proxmox",
            "machine": "q35",
            "kvm_arguments": VM_KVM_ARGUMENTS,
            "scsi_hardware": "virtio-scsi-single",
            "protection": True,
            "started": True,
            "on_boot": True,
            "reboot_after_update": True,
            "stop_on_destroy": False,
            "purge_on_destroy": False,
            "delete_unreferenced_disks_on_destroy": False,
            "migrate": False,
            "numa": False,
            "template": False,
        }
        if not expected_subset(values, required_scalars):
            return "VM cutover compute, lifecycle, or destruction authority differs"
        if not exact_object_list(values.get("cpu"), [{"cores": 24, "sockets": 1, "type": "host"}]):
            return "VM cutover requires the protected CPU topology and type"
        if not exact_object_list(values.get("memory"), [{"dedicated": 65536, "floating": 0}]):
            return "VM cutover requires the protected memory topology"
        if not exact_object_list(values.get("startup"), [{"order": "2", "up_delay": "30", "down_delay": "60"}]):
            return "VM cutover requires the protected startup lifecycle"
        if not exact_object_list(values.get("agent"), [{"enabled": True, "trim": False}]):
            return "VM cutover requires the protected guest-agent settings"
        if not exact_object_list(
            values.get("network_device"),
            [{"bridge": "vmbr0", "firewall": True, "mac_address": VM_MAC_ADDRESS, "model": "virtio"}],
        ):
            return "VM cutover requires the complete protected network identity"
        if not exact_object_list(values.get("smbios"), [{"uuid": VM_SMBIOS_UUID}]):
            return "VM cutover requires the preserved VM 100 SMBIOS identity"
        if not exact_object_list(values.get("serial_device"), [{"device": "socket"}]):
            return "VM cutover requires the protected serial console"
        if not exact_object_list(values.get("operating_system"), [{"type": "l26"}]):
            return "VM cutover requires the protected operating-system type"
        if not exact_object_list(values.get("vga"), [{"type": "none"}]):
            return "VM cutover requires the protected display configuration"

        disks = values.get("disk")
        if not isinstance(disks, list) or len(disks) != 3 or not all(isinstance(disk, dict) for disk in disks):
            return "VM cutover requires three complete protected disks"
        if [disk.get("interface") for disk in disks] != ["scsi0", "scsi1", "scsi2"]:
            return "VM cutover requires the exact protected disk order"
        if not expected_subset(
            disks[0],
            {
                "aio": "io_uring",
                "backup": True,
                "cache": "none",
                "datastore_id": "local-lvm",
                "discard": "ignore",
                "file_format": "raw",
                "file_id": "local-lvm:vm-100-disk-0",
                "import_from": None,
                "interface": "scsi0",
                "iothread": True,
                "path_in_datastore": None,
                "queues": 0,
                "replicate": True,
                "serial": None,
                "size": 550,
                "speed": [],
                "ssd": False,
            },
        ):
            return "VM cutover requires the exact protected Arch root disk"
        if not expected_subset(
            disks[1],
            {
                "aio": "io_uring",
                "backup": False,
                "cache": "none",
                "datastore_id": "",
                "discard": "on",
                "file_format": "raw",
                "file_id": None,
                "import_from": None,
                "interface": "scsi1",
                "iothread": True,
                "queues": 0,
                "replicate": True,
                "serial": None,
                "size": 3726,
                "speed": [],
                "ssd": True,
            },
        ) or disks[1].get("path_in_datastore") != expected_games_disk:
            return "VM cutover requires the exact protected games disk"
        if not expected_subset(disks[2], VM_STATE_DISK):
            return "VM cutover requires the exact protected state disk"

        if not exact_object_list(
            values.get("hostpci"),
            [
                {"device": "hostpci1", "id": None, "mapping": "rx-7900-xtx", "mdev": None, "pcie": True, "rom_file": None, "rombar": True, "xvga": True},
                {"device": "hostpci2", "id": None, "mapping": "rx-7900-xtx-audio", "mdev": None, "pcie": True, "rom_file": None, "rombar": True, "xvga": False},
            ],
        ):
            return "VM cutover requires the complete protected PCI mappings and flags"
        if not exact_object_list(
            values.get("usb"),
            [
                {"host": None, "mapping": "zigbee-cp210x", "usb3": False},
                {"host": None, "mapping": "zwave-cp210x", "usb3": False},
                {"host": None, "mapping": "realtek-bluetooth", "usb3": True},
            ],
        ):
            return "VM cutover requires the complete protected USB mappings and flags"
    return None


def vm_cutover_failure(plan: dict[str, Any], mode: str, expected_games_disk: str | None = None, external_scsi3_attested: bool = False) -> str | None:
    if not external_scsi3_attested:
        return "VM cutover is disabled until externally managed scsi3 has a separate authenticated host attestation"
    expected_games_disk = expected_games_disk or os.environ.get("TF_VAR_games_disk_by_id", "")
    if not canonical_by_id_path(expected_games_disk):
        return "VM cutover requires a protected expected games-disk identity"
    for channel in ("action_invocations", "deferred_changes", "resource_drift"):
        if channel in plan and plan[channel] not in (None, []):
            return f"VM cutover forbids nonempty {channel}"
    resources = plan.get("resource_changes")
    if not isinstance(resources, list):
        return "VM cutover requires a complete resource change list"
    mutating: list[dict[str, Any]] = []
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("change"), dict):
            return "VM cutover resource changes must be complete objects"
        if resource.get("previous_address") is not None:
            return "VM cutover forbids state moves or previous addresses"
        change = resource["change"]
        actions = change.get("actions")
        if not isinstance(actions, list) or not actions:
            return "VM cutover forbids missing or empty action lists"
        if change.get("importing") is not None:
            return "VM cutover forbids imports"
        if actions == ["no-op"]:
            if (
                change.get("before") != change.get("after")
                or not isinstance(change.get("after_unknown"), dict)
                or contains_unknown(change["after_unknown"])
            ):
                return "VM cutover no-op resources must be known and drift-free"
            continue
        if actions != ["update"]:
            return "VM cutover permits only one update and plain no-ops"
        mutating.append(resource)
    if len(mutating) != 1:
        return "VM cutover requires exactly one changed resource"
    resource = mutating[0]
    change = resource["change"]
    if resource.get("address") != VM_ADDRESS or resource.get("type") != VM_RESOURCE_TYPE:
        return "VM cutover permits only an update-in-place of VM 100"

    before, after = change.get("before"), change.get("after")
    identity_failure = vm_cutover_identity_failure(before, after, expected_games_disk)
    if identity_failure:
        return identity_failure
    expected_before, expected_after = VM_CUTOVER_BOOT_ORDERS[mode]
    if before.get("boot_order") != expected_before or after.get("boot_order") != expected_after:
        return f"{mode} requires its exact boot-order transition"
    before_other = {key: value for key, value in before.items() if key != "boot_order"}
    after_other = {key: value for key, value in after.items() if key != "boot_order"}
    if before_other != after_other:
        return "VM cutover forbids changes outside the exact boot order"
    after_unknown = change.get("after_unknown")
    if not isinstance(after_unknown, dict) or contains_unknown(after_unknown):
        return "VM cutover planned values, including identity, must be completely known"
    return None


def vm_start_prerequisite_failure(plan: dict[str, Any]) -> str | None:
    changes = [
        resource
        for resource in plan.get("resource_changes", [])
        if resource.get("change", {}).get("actions", []) not in ([], ["no-op"], ["read"])
        or resource.get("change", {}).get("importing") is not None
    ]
    if len(changes) != 1:
        return "VM-start prerequisite requires exactly one changed resource"
    resource = changes[0]
    change = resource.get("change", {})
    if resource.get("address") != "proxmox_virtual_environment_vm.debian" or \
            resource.get("type") != "proxmox_virtual_environment_vm" or \
            change.get("actions") != ["update"] or change.get("importing") is not None:
        return "VM-start prerequisite permits only an update-in-place of VM 100"
    before, after = change.get("before"), change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict) or \
            before.get("vm_id") != 100 or after.get("vm_id") != 100 or \
            before.get("protection") is not True or after.get("protection") is not True or \
            before.get("started") is not False or after.get("started") is not True:
        return "VM-start prerequisite identity, protection, or power transition differs"
    computed = {("ipv4_addresses",), ("ipv6_addresses",), ("network_interface_names",)}
    allowed = {("started",), *computed}
    changed = changed_keys(before, after)
    if ("started",) not in changed or not changed <= allowed:
        return "VM-start prerequisite changes fields other than power state and computed network outputs"
    unknown = change.get("after_unknown", {})
    if value_at_path(unknown, ("started",)) is True:
        return "VM-start prerequisite power result must be known"
    if any(path in changed and value_at_path(unknown, path) is not True for path in computed):
        return "VM-start prerequisite changed network outputs must be provider-computed"
    return None


def main() -> int:
    args = parse_args()
    plan = json.loads(args.plan_json.read_text())
    if args.mode == "vm-start-prerequisite":
        failure = vm_start_prerequisite_failure(plan)
        if failure:
            print(f"DENY: {failure}", file=sys.stderr)
            return 1
        print("plan policy passed: mode=vm-start-prerequisite actions=1")
        return 0
    if args.mode in VM_CUTOVER_BOOT_ORDERS:
        if args.allow_change_file is not None or args.recovery_expectations is not None:
            raise SystemExit("VM cutover modes do not accept allowlists or recovery expectations")
        failure = vm_cutover_failure(plan, args.mode)
        if failure:
            print(f"DENY: {failure}", file=sys.stderr)
            return 1
        print(f"plan policy passed: mode={args.mode} actions=1")
        return 0
    allow = set()
    recovery_expectations = load_recovery_expectations(args.recovery_expectations) if args.mode == "recovery" else {}
    mapping_resources: dict[str, list[dict[str, Any]]] = {}
    for resource in plan.get("resource_changes", []):
        if resource.get("type") not in {"proxmox_hardware_mapping_pci", "proxmox_hardware_mapping_usb"}:
            continue
        after = resource.get("change", {}).get("after")
        if not isinstance(after, dict) or not isinstance(after.get("name"), str) or not isinstance(after.get("map"), list):
            continue
        entries = after["map"]
        if all(isinstance(entry, dict) for entry in entries):
            mapping_resources[after["name"]] = entries
    if args.mode != "recovery" and args.recovery_expectations is not None:
        raise SystemExit("--recovery-expectations is valid only in recovery mode")
    if args.allow_change_file:
        allow = {
            line.strip()
            for line in args.allow_change_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }

    failures: list[str] = []
    observed_actions = 0
    observed_recovery_addresses: set[str] = set()
    for resource in plan.get("resource_changes", []):
        address = resource.get("address", "<unknown>")
        resource_type = resource.get("type", "")
        change = resource.get("change", {})
        actions = change.get("actions", [])
        importing = change.get("importing") is not None
        if args.mode == "recovery":
            if address in recovery_expectations:
                observed_recovery_addresses.add(address)
                failure = recovery_failure(
                    address, resource_type, actions, change, recovery_expectations[address]
                )
                if failure:
                    failures.append(failure)
                if actions == ["create"]:
                    observed_actions += 1
            elif actions not in ([], ["no-op"], ["read"]) or importing:
                failures.append(f"{address}: extra recovery change is forbidden")
            continue

        if importing:
            observed_actions += 1
            if address not in allow:
                failures.append(f"{address}: import is not explicitly allowlisted")
            elif actions != ["no-op"]:
                failures.append(f"{address}: allowlisted import must be read-only")
            continue
        if actions in ([], ["no-op"], ["read"]):
            continue
        observed_actions += 1
        if address == "terraform_data.tailscale_policy[0]":
            failures.append(f"{address}: Tailscale policy mutation is forbidden in steady state")
            continue
        if resource_type in {
            "proxmox_virtual_environment_vm",
            "proxmox_virtual_environment_container",
        } and "create" in actions:
            failures.append(f"{address}: creating or recreating compute is forbidden in steady state")
            continue
        if "delete" in actions:
            failures.append(f"{address}: delete or replacement is forbidden")
            continue
        before = change.get("before")
        after = change.get("after")
        changed = changed_keys(before, after)
        candidate_attachment = (
            address == VM_ADDRESS
            and resource_type == VM_RESOURCE_TYPE
            and actions == ["update"]
            and safe_state_disk_attachment(before, after)
        )
        sensitive = sorted(
            ".".join(path)
            for path in changed
            if (
                any(part in SENSITIVE_FIELDS for part in path)
                or (
                    address == VM_ADDRESS
                    and resource_type == VM_RESOURCE_TYPE
                    and bool(path)
                    and path[0] in VM_BOOT_LIFECYCLE_FIELDS
                )
            )
            and not safe_protection_enable(before, after, path)
            and not safe_custom_rom_removal(before, after, path)
            and not safe_hardware_mapping_transition(before, after, path, mapping_resources)
            and not candidate_attachment
        )
        unknown_sensitive: list[str] = []
        if address == VM_ADDRESS and resource_type == VM_RESOURCE_TYPE:
            unknown = change.get("after_unknown", {})
            if not isinstance(unknown, dict):
                unknown_sensitive.append("after_unknown")
            else:
                unknown_sensitive.extend(
                    key
                    for key, value in unknown.items()
                    if key in VM_BOOT_LIFECYCLE_FIELDS | SENSITIVE_FIELDS and contains_unknown(value)
                )
        if sensitive:
            failures.append(f"{address}: protected field change: {', '.join(sensitive)}")
        if unknown_sensitive:
            failures.append(f"{address}: protected fields must be known: {', '.join(sorted(unknown_sensitive))}")
        if address in allow:
            continue

        lower_type = resource_type.lower()
        if any(marker in lower_type for marker in STORAGE_RESOURCE_MARKERS):
            failures.append(f"{address}: storage mutation requires an explicit reviewed allowlist")
        if any(marker in lower_type for marker in NETWORK_RESOURCE_MARKERS):
            failures.append(f"{address}: network/control-plane mutation requires an explicit reviewed allowlist")

    if args.mode == "recovery" and observed_recovery_addresses != set(recovery_expectations):
        failures.append("recovery plan must contain the complete expected resource set")

    if failures:
        for failure in sorted(set(failures)):
            print(f"DENY: {failure}", file=sys.stderr)
        return 1
    print(f"plan policy passed: mode={args.mode} actions={observed_actions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
