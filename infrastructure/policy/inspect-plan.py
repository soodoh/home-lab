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
OIDC_RESOURCE_TYPE = "aws_iam_openid_connect_provider"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    parser.add_argument(
        "--mode",
        choices=("normal", "vm-start-prerequisite"),
        default="normal",
    )
    parser.add_argument("--allow-change-file", type=Path)
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




def contains_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(contains_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_unknown(item) for item in value)
    return False




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


def resource_envelopes(plan: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Walk only plan envelopes, never values/expressions that resemble resources.

    Reject malformed containers: an unreadable envelope cannot establish that
    identity changes are absent. Missing optional containers remain legitimate.
    """
    result: list[tuple[str, dict[str, Any]]] = []

    def mapping(value: Any, location: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError(f"{location}: malformed plan object")
        return value

    def sequence(value: Any, location: str) -> list[Any]:
        if not isinstance(value, list):
            raise ValueError(f"{location}: malformed plan list")
        return value

    def resource(value: Any, location: str) -> None:
        item = mapping(value, location)
        if not isinstance(item.get("type"), str) or not item["type"]:
            raise ValueError(f"{location}: missing or malformed resource type")
        result.append((location, item))

    def module(value: Any, location: str) -> None:
        item = mapping(value, location)
        for child in sequence(item.get("resources", []), location + "/resources"):
            resource(child, location)
        for index, child in enumerate(sequence(item.get("child_modules", []), location + "/child_modules")):
            module(child, f"{location}/child_modules/{index}")
        for name, call in mapping(item.get("module_calls", {}), location + "/module_calls").items():
            module(mapping(call, location).get("module"), f"{location}/module.{name}")

    mapping(plan, "plan")
    for name in ("resource_changes", "resource_drift"):
        for item in sequence(plan.get(name, []), name):
            resource(item, name)
    for item in sequence(plan.get("deferred_changes", []), "deferred_changes"):
        resource(mapping(item, "deferred_changes").get("resource_change"), "deferred_changes")
    for name in ("planned_values", "configuration"):
        module(mapping(plan.get(name, {}), name).get("root_module", {}), name)
    prior = mapping(plan.get("prior_state", {}), "prior_state")
    module(mapping(prior.get("values", {}), "prior_state/values").get("root_module", {}), "prior_state")
    return result


def oidc_ownership_failures(envelopes: list[tuple[str, dict[str, Any]]]) -> list[str]:
    """Unconditional ownership prohibition, stronger than identity mutation denial."""
    return [
        f"{location}: {resource.get('address', '<unknown>')}: managed IAM OIDC provider ownership is forbidden"
        for location, resource in envelopes
        if resource["type"] == OIDC_RESOURCE_TYPE and resource.get("mode") != "data"
    ]


def known_identity_result(value: Any) -> bool:
    """Unknown masks may contain booleans and nested containers, not truthy guesses."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, dict):
        return all(known_identity_result(item) for item in value.values())
    if isinstance(value, list):
        return all(known_identity_result(item) for item in value)
    return False


def controller_identity_failures(
    plan: dict[str, Any], envelopes: list[tuple[str, dict[str, Any]]]
) -> list[str]:
    failures: list[str] = []
    # Absent flags support older complete plan documents; explicit uncertainty
    # cannot be used to hide identity work deferred by the plan producer.
    if ("complete" in plan and plan["complete"] is not True) or (
        "errored" in plan and plan["errored"] is not False
    ):
        failures.append("incomplete/errored plan cannot establish safe identity convergence")
    for location, resource in envelopes:
        identity = resource["type"].startswith(("aws_iam_", "aws_rolesanywhere_"))
        if identity and resource.get("mode") != "data":
            label = f"{location}: {resource.get('address', '<unknown>')}: managed IAM/Roles Anywhere"
            if not isinstance(resource.get("address"), str) or not resource["address"]:
                failures.append(f"{label} tracking address is missing or malformed")
                continue
            if resource.get("mode") != "managed":
                failures.append(f"{label} mode is missing or unrecognized")
                continue
            if location == "deferred_changes":
                failures.append(f"{label} deferred identity change is forbidden")
                continue
            if location not in {"resource_changes", "resource_drift"}:
                continue  # Retained ownership alone is permitted (unlike OIDC).
            change = resource.get("change")
            if not isinstance(change, dict):
                failures.append(f"{label} malformed identity change")
                continue
            actions = change.get("actions")
            if resource.get("previous_address") is not None:
                failures.append(f"{label} identity tracking move requires owner intervention")
            elif change.get("importing") is not None:
                failures.append(f"{label} identity import is forbidden")
            elif actions not in (["no-op"], ["read"]):
                failures.append(f"{label} identity mutation, drift, or unknown actions are forbidden")
            elif not known_identity_result(change.get("after_unknown", {})):
                failures.append(f"{label} unknown or malformed identity result")
            elif "before" not in change or not isinstance(change.get("after"), dict) or (
                actions == ["no-op"] and change.get("before") != change["after"]
            ) or (actions == ["read"] and change.get("before") is not None
                  and not isinstance(change["before"], dict)):
                failures.append(f"{label} malformed or inconsistent identity read/no-op")
        # Preserve existing data/import/protected-field admission, but never let
        # malformed change envelopes crash or fall into an empty-actions shortcut.
        if location in {"resource_changes", "resource_drift", "deferred_changes"}:
            change = resource.get("change")
            if not isinstance(change, dict) or not isinstance(change.get("actions"), list) or not all(
                isinstance(action, str) for action in change["actions"]
            ):
                failures.append(f"{location}: malformed change/actions envelope")
    return failures


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def main() -> int:
    args = parse_args()
    try:
        plan = json.loads(args.plan_json.read_text(), object_pairs_hook=reject_duplicate_keys)
        envelopes = resource_envelopes(plan)
    except (ValueError, RecursionError) as error:
        print(f"DENY: malformed plan; owner intervention required to verify identity tracking: {error}", file=sys.stderr)
        return 1
    # Both invariants precede EVERY controller mode, allowlist and import/no-op shortcut.
    ownership_failures = oidc_ownership_failures(envelopes)
    if ownership_failures:
        for failure in sorted(set(ownership_failures)):
            print(f"DENY: {failure}", file=sys.stderr)
        return 1
    identity_failures = controller_identity_failures(plan, envelopes)
    if identity_failures:
        for failure in sorted(set(identity_failures)):
            print(f"DENY: {failure}; owner intervention required: independently verify source/state/plan, "
                  "complete owner bootstrap or repair, and refresh/verify retained identity tracking before resuming", file=sys.stderr)
        return 1
    if args.mode == "vm-start-prerequisite":
        failure = vm_start_prerequisite_failure(plan)
        if failure:
            print(f"DENY: {failure}", file=sys.stderr)
            return 1
        print("plan policy passed: mode=vm-start-prerequisite actions=1")
        return 0
    allow = set()
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
    if args.allow_change_file:
        allow = {
            line.strip()
            for line in args.allow_change_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }

    failures: list[str] = []
    observed_actions = 0
    for resource in plan.get("resource_changes", []):
        address = resource.get("address", "<unknown>")
        resource_type = resource.get("type", "")
        change = resource.get("change", {})
        actions = change.get("actions", [])
        importing = change.get("importing") is not None

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
        if (
            address == "terraform_data.tailscale_policy[0]" or resource_type == "tailscale_acl"
        ) and address not in allow:
            failures.append(f"{address}: Tailscale policy mutation requires an explicit reviewed allowlist")
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


    if failures:
        for failure in sorted(set(failures)):
            print(f"DENY: {failure}", file=sys.stderr)
        return 1
    print(f"plan policy passed: mode={args.mode} actions={observed_actions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
