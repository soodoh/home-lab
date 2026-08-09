#!/usr/bin/env python3
"""Reject unsafe OpenTofu plans before any apply."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
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
STORAGE_RESOURCE_MARKERS = ("zfs", "filesystem", "disk", "mount", "storage")
NETWORK_RESOURCE_MARKERS = ("firewall", "network", "acl", "ruleset", "federated_identity")
RECOVERY_ADDRESSES = {
    "proxmox_download_file.arch_recovery_image[0]",
    'proxmox_hardware_mapping_pci.device["coral"]',
    'proxmox_hardware_mapping_pci.device["gpu"]',
    'proxmox_hardware_mapping_pci.device["gpu_audio"]',
    'proxmox_hardware_mapping_usb.device["bluetooth"]',
    'proxmox_hardware_mapping_usb.device["zigbee"]',
    'proxmox_hardware_mapping_usb.device["zwave"]',
    "proxmox_virtual_environment_vm.arch",
}
MAPPING_ADDRESSES = RECOVERY_ADDRESSES - {
    "proxmox_download_file.arch_recovery_image[0]",
    "proxmox_virtual_environment_vm.arch",
}
TAILSCALE_CONTROLLER_RETIREMENT_ADDRESSES = {
    "terraform_data.tailscale_policy[0]",
    "tailscale_federated_identity.ci_plan[0]",
    "tailscale_federated_identity.ci_apply[0]",
    "tailscale_federated_identity.provider_plan[0]",
    "tailscale_federated_identity.provider_apply[0]",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    parser.add_argument(
        "--mode",
        choices=(
            "normal",
            "adopt",
            "adopt-or-noop",
            "recovery",
            "ct-unprotect",
            "ct-delete",
            "ct-gateway-detach",
            "ct-gateway-retire",
            "network-migration",
            "disk-growth",
            "omada-gateway-reservation-retirement",
            "qualification",
            "tailscale-controller-retirement",
            "tailscale-controller-access",
        ),
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
    if before != after:
        return {prefix}
    return set()


def is_exact_ct101(value: dict[str, Any]) -> bool:
    vm_id = value.get("vm_id")
    identifier = value.get("id")
    if vm_id is None:
        return identifier == "101"
    return vm_id == 101 and identifier in {None, "101"}

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


def contains_exact(value: Any, needle: str) -> bool:
    if isinstance(value, dict):
        return any(key == needle or contains_exact(entry, needle) for key, entry in value.items())
    if isinstance(value, list):
        return any(contains_exact(entry, needle) for entry in value)
    return value == needle


def unique_index(entries: Any, expected: Any, label: str) -> int:
    if not isinstance(entries, list):
        raise ValueError(f"{label} is not a list")
    indexes = [index for index, entry in enumerate(entries) if entry == expected]
    if len(indexes) != 1:
        raise ValueError(f"{label} must occur exactly once")
    return indexes[0]


def detached_gateway_policy(active: Any) -> Any:
    if not isinstance(active, dict):
        raise ValueError("managed policy is not an object")
    policy = deepcopy(active)
    if any(contains_exact(policy, tag) for tag in ("tag:ci", "tag:ci-plan", "tag:ci-apply")):
        raise ValueError("gateway lifecycle policy contains a retired CI tag")
    expected_approvers = {
        "routes": {
            "192.168.0.100/32": ["tag:infra-router"],
            "192.168.0.123/32": ["tag:infra-router"],
        }
    }
    if policy.get("autoApprovers") != expected_approvers:
        raise ValueError("gateway route auto-approvers are missing or malformed")
    del policy["autoApprovers"]

    grants = policy.get("grants")
    if not isinstance(grants, list):
        raise ValueError("grants are missing or malformed")
    routed_grants = (
        {"src": ["autogroup:owner", "autogroup:admin"], "dst": ["192.168.0.123"], "ip": ["tcp:8006"]},
        {"src": ["autogroup:owner", "autogroup:admin"], "dst": ["192.168.0.100"], "ip": ["tcp:22"]},
    )
    for grant in routed_grants:
        del grants[unique_index(grants, grant, "routed LAN grant")]
    return policy


def local_controller_gateway_policy(detached: Any) -> Any:
    if not isinstance(detached, dict):
        raise ValueError("managed policy is not an object")
    policy = deepcopy(detached)
    ci_tags = {"tag:ci-plan", "tag:ci-apply"}
    if "autoApprovers" in policy or contains_exact(policy, "tag:ci"):
        raise ValueError("policy is not in the detached gateway stage")
    owners = policy.get("tagOwners")
    if not isinstance(owners, dict):
        raise ValueError("tag owners are missing or malformed")
    for tag in ci_tags:
        if owners.get(tag) != ["autogroup:admin"]:
            raise ValueError("CI tag owner is missing or malformed")
        del owners[tag]

    grants = policy.get("grants")
    if not isinstance(grants, list):
        raise ValueError("grants are missing or malformed")
    retained_grants = []
    for grant in grants:
        if not isinstance(grant, dict) or not isinstance(grant.get("src"), list):
            raise ValueError("grant is malformed")
        sources = grant["src"]
        if grant.get("dst") == ["tag:docker-host"] and grant.get("ip") == ["tcp:22"]:
            if not all(tag in sources for tag in ci_tags):
                raise ValueError("direct Docker grant lacks both CI tags")
            grant["src"] = ["autogroup:owner", "autogroup:admin"]
            retained_grants.append(grant)
        elif not any(source in ci_tags for source in sources):
            retained_grants.append(grant)
        elif not all(source in ci_tags for source in sources):
            raise ValueError("unexpected mixed CI grant")
    policy["grants"] = retained_grants

    ssh = policy.get("ssh")
    if not isinstance(ssh, list):
        raise ValueError("SSH policy is missing or malformed")
    retained_ssh = []
    for rule in ssh:
        if not isinstance(rule, dict) or not isinstance(rule.get("src"), list):
            raise ValueError("SSH rule is malformed")
        sources = rule["src"]
        if rule.get("dst") == ["tag:docker-host"] and rule.get("users") == ["ansible-deploy"]:
            if sources != ["autogroup:admin"]:
                raise ValueError("detached ansible-deploy SSH rule is malformed")
            rule["src"] = ["autogroup:owner", "autogroup:admin"]
            retained_ssh.append(rule)
        elif not any(source in ci_tags for source in sources):
            retained_ssh.append(rule)
        elif not all(source in ci_tags for source in sources):
            raise ValueError("unexpected mixed CI SSH rule")
    policy["ssh"] = retained_ssh

    for key in ("tests", "sshTests"):
        entries = policy.get(key)
        if not isinstance(entries, list):
            raise ValueError(f"{key} are missing or malformed")
        policy[key] = [entry for entry in entries if isinstance(entry, dict) and entry.get("src") not in ci_tags]
    if any(contains_exact(policy, tag) for tag in ci_tags):
        raise ValueError("an unreviewed CI tag occurrence remains")
    return local_controller_access_policy(policy)

def local_controller_access_policy(detached: Any) -> Any:
    if not isinstance(detached, dict):
        raise ValueError("managed policy is not an object")
    policy = deepcopy(detached)
    if any(contains_exact(policy, tag) for tag in ("tag:ci", "tag:ci-plan", "tag:ci-apply")):
        raise ValueError("local-controller policy contains a retired CI tag")
    old_rule = {
        "action": "accept",
        "src": ["autogroup:owner", "autogroup:admin", "tag:docker-host"],
        "dst": ["tag:proxmox"],
        "users": ["root"],
    }
    rules = policy.get("ssh")
    index = unique_index(rules, old_rule, "combined Proxmox SSH rule")
    rules[index:index + 1] = [
        {
            "action": "accept",
            "src": ["autogroup:owner", "autogroup:admin"],
            "dst": ["tag:proxmox"],
            "users": ["root", "tofu-plan", "tofu-apply"],
        },
        {
            "action": "accept",
            "src": ["tag:docker-host"],
            "dst": ["tag:proxmox"],
            "users": ["root"],
        },
    ]
    ssh_tests = policy.get("sshTests")
    if not isinstance(ssh_tests, list) or len(ssh_tests) != 1:
        raise ValueError("detached SSH tests are malformed")
    return policy


def retired_gateway_policy(detached: Any) -> Any:
    policy = deepcopy(detached)
    owners = policy.get("tagOwners") if isinstance(policy, dict) else None
    if not isinstance(owners, dict) or owners.get("tag:infra-router") != ["autogroup:admin"]:
        raise ValueError("infra-router tag owner is missing or malformed")
    del owners["tag:infra-router"]
    grant = {"src": ["autogroup:admin"], "dst": ["tag:infra-router"], "ip": ["*"]}
    grants = policy.get("grants")
    del grants[unique_index(grants, grant, "infra-router admin grant")]
    if contains_exact(policy, "tag:infra-router"):
        raise ValueError("an unreviewed infra-router tag occurrence remains")
    return policy


def policy_json(change: Any, side: str) -> Any:
    value = (change.get(side) or {}).get("input", {}).get("policy_json")
    if not isinstance(value, str):
        raise ValueError(f"managed policy {side} JSON is missing")
    return json.loads(value)


def safe_protection_enable(before: Any, after: Any, path: tuple[str, ...]) -> bool:
    return path and path[-1] == "protection" and value_at_path(before, path) is False and value_at_path(after, path) is True


def complete_mapping(after: Any, expected_name: str) -> bool:
    if not isinstance(after, dict) or after.get("name") != expected_name:
        return False
    mapping = after.get("map")
    return isinstance(mapping, list) and len(mapping) > 0 and all(
        isinstance(entry, dict)
        and isinstance(entry.get("id"), str)
        and bool(entry.get("id"))
        and isinstance(entry.get("node"), str)
        and bool(entry.get("node"))
        for entry in mapping
    )


def only_hardware_mappings(entries: Any, raw_field: str) -> bool:
    return isinstance(entries, list) and len(entries) > 0 and all(
        isinstance(entry, dict)
        and isinstance(entry.get("mapping"), str)
        and bool(entry.get("mapping"))
        and entry.get(raw_field) in (None, "")
        for entry in entries
    )


def main() -> int:
    args = parse_args()
    plan = json.loads(args.plan_json.read_text())
    allow = set()
    if args.allow_change_file:
        allow = {line.strip() for line in args.allow_change_file.read_text().splitlines() if line.strip() and not line.startswith("#")}

    failures: list[str] = []
    observed_actions = 0
    observed_addresses: set[str] = set()
    for resource in plan.get("resource_changes", []):
        address = resource.get("address", "<unknown>")
        resource_type = resource.get("type", "")
        change = resource.get("change", {})
        actions = change.get("actions", [])
        importing = change.get("importing") is not None
        if actions in ([], ["no-op"], ["read"]) and not importing:
            continue
        observed_actions += 1
        observed_addresses.add(address)

        if args.mode in {"adopt", "adopt-or-noop"}:
            if not importing or any(action in actions for action in ("create", "update", "delete")):
                failures.append(f"{address}: adoption permits import-only actions")
            continue


        if args.mode == "omada-gateway-reservation-retirement":
            expected_address = 'omada_dhcp_reservation.reservation["bc:24:11:fd:4c:5c"]'
            before = change.get("before") or {}
            before_mac = str(before.get("mac", "")).lower().replace("-", ":")
            valid_change = (
                address == expected_address
                and actions == ["delete"]
                and before_mac == "bc:24:11:fd:4c:5c"
                and change.get("after") is None
            )
            if not valid_change:
                failures.append(f"{address}: gateway-reservation retirement permits only the exact retired CT reservation deletion")
            continue
        if args.mode == "qualification":
            before = change.get("before")
            after = change.get("after")
            expected_name = "tofu-provider-qualification"
            valid_create = actions == ["create"] and before is None and (after or {}).get("name") == expected_name
            valid_delete = actions == ["delete"] and (before or {}).get("name") == expected_name and after is None
            if address != "omada_dhcp_reservation.qualification[0]" or not (valid_create or valid_delete):
                failures.append(f"{address}: qualification permits only creation or removal of the disposable Omada reservation")
            continue

        if args.mode == "recovery":
            recovery_addresses = RECOVERY_ADDRESSES
            if address not in recovery_addresses or actions != ["create"] or change.get("before") is not None:
                failures.append(f"{address}: recovery permits only expected fresh creates")
                continue
            after = change.get("after") or {}
            if address.startswith("proxmox_hardware_mapping_"):
                expected_name = address.split('["', 1)[1].split('"]', 1)[0]
                if not complete_mapping(after, expected_name):
                    failures.append(f"{address}: recovery requires a complete expected hardware mapping")
            elif address == "proxmox_download_file.arch_recovery_image[0]":
                if after.get("checksum_algorithm") != "sha256" or not after.get("checksum"):
                    failures.append(f"{address}: recovery image requires a SHA-256 checksum")
            elif address == "proxmox_virtual_environment_vm.arch":
                if (
                    after.get("vm_id") != 100
                    or after.get("protection") is not True
                    or not isinstance(after.get("disk"), list)
                    or len(after.get("disk")) < 2
                    or not only_hardware_mappings(after.get("hostpci"), "id")
                    or not only_hardware_mappings(after.get("usb"), "host")
                ):
                    failures.append(f"{address}: recovery requires protected VM 100 with complete disks and mappings")
            continue

        if args.mode == "network-migration":
            mapping_addresses = MAPPING_ADDRESSES
            vm_address = "proxmox_virtual_environment_vm.arch"
            if address not in mapping_addresses | {vm_address}:
                failures.append(f"{address}: hardware-mapping migration action is outside the allowlist")
                continue
            before = change.get("before") or {}
            after = change.get("after") or {}
            if address in mapping_addresses:
                expected_name = address.split('["', 1)[1].split('"]', 1)[0]
                if actions != ["create"] or change.get("before") is not None or not complete_mapping(after, expected_name):
                    failures.append(f"{address}: migration requires one complete new expected mapping")
                continue
            changed_roots = {path[0] for path in changed_keys(before, after) if path}
            if (
                actions != ["update"]
                or before.get("vm_id") != 100
                or after.get("vm_id") != 100
                or before.get("protection") is not True
                or after.get("protection") is not True
                or changed_roots != {"hostpci", "usb"}
                or not only_hardware_mappings(after.get("hostpci"), "id")
                or not only_hardware_mappings(after.get("usb"), "host")
            ):
                failures.append(f"{address}: migration permits only the complete VM 100 host-device mapping transition")
            continue

        if args.mode == "disk-growth":
            before = change.get("before") or {}
            after = change.get("after") or {}
            before_disks = before.get("disk")
            after_disks = after.get("disk")
            expected_after = deepcopy(before)
            valid_disks = (
                isinstance(before_disks, list)
                and isinstance(after_disks, list)
                and len(before_disks) == 2
                and len(after_disks) == 2
                and before_disks[0].get("interface") == "scsi0"
                and before_disks[0].get("datastore_id") == "local-lvm"
                and before_disks[0].get("size") == 400
                and after_disks[0].get("size") == 550
            )
            if valid_disks:
                expected_after["disk"] = deepcopy(before_disks)
                expected_after["disk"][0]["size"] = 550
            if (
                address != "proxmox_virtual_environment_vm.arch"
                or actions != ["update"]
                or before.get("vm_id") != 100
                or after.get("vm_id") != 100
                or before.get("protection") is not True
                or after.get("protection") is not True
                or not valid_disks
                or after != expected_after
            ):
                failures.append(f"{address}: disk-growth mode permits only VM 100 scsi0 growth from 400 to 550 GiB")
            continue

        if args.mode == "tailscale-controller-access":
            try:
                before_policy = policy_json(change, "before")
                after_policy = policy_json(change, "after")
                valid_change = (
                    address == "terraform_data.tailscale_policy[0]"
                    and actions == ["update"]
                    and after_policy == local_controller_access_policy(before_policy)
                )
            except (AttributeError, json.JSONDecodeError, TypeError, ValueError):
                valid_change = False
            if not valid_change:
                failures.append(f"{address}: local-controller access repair permits only the exact Proxmox SSH policy split")
            continue

        if args.mode == "tailscale-controller-retirement":
            if address == "terraform_data.tailscale_policy[0]":
                try:
                    before_policy = policy_json(change, "before")
                    after_policy = policy_json(change, "after")
                    valid_change = actions == ["update"] and after_policy == local_controller_gateway_policy(before_policy)
                except (AttributeError, json.JSONDecodeError, TypeError, ValueError):
                    valid_change = False
            else:
                before = change.get("before") or {}
                expected_descriptions = {
                    "tailscale_federated_identity.ci_plan[0]": "infrastructure-plan",
                    "tailscale_federated_identity.ci_apply[0]": "infrastructure-apply",
                    "tailscale_federated_identity.provider_plan[0]": "home-lab GitHub OpenTofu Tailscale plan provider",
                    "tailscale_federated_identity.provider_apply[0]": "home-lab GitHub OpenTofu Tailscale apply provider",
                }
                valid_change = (
                    address in expected_descriptions
                    and resource_type == "tailscale_federated_identity"
                    and actions == ["delete"]
                    and before.get("issuer") == "https://token.actions.githubusercontent.com"
                    and before.get("description") == expected_descriptions[address]
                    and change.get("after") is None
                )
            if not valid_change:
                failures.append(f"{address}: Tailscale controller retirement permits only the exact CI policy and identity removal")
            continue

        if args.mode in {"ct-gateway-detach", "ct-gateway-retire"}:
            try:
                before_policy = policy_json(change, "before")
                after_policy = policy_json(change, "after")
                if args.mode == "ct-gateway-detach":
                    expected_policy = detached_gateway_policy(before_policy)
                    message = "gateway detach mode permits only the exact active-to-detached policy transformation"
                else:
                    expected_policy = retired_gateway_policy(before_policy)
                    message = "gateway retire mode permits only the exact detached-to-retired policy transformation"
                valid_change = (
                    address == "terraform_data.tailscale_policy[0]"
                    and actions == ["update"]
                    and after_policy == expected_policy
                )
            except (AttributeError, json.JSONDecodeError, TypeError, ValueError):
                valid_change = False
                message = "gateway lifecycle policy is missing, malformed, or has the wrong source occurrences"
            if not valid_change:
                failures.append(f"{address}: {message}")
            continue

        if args.mode in {"ct-unprotect", "ct-delete"}:
            target = "proxmox_virtual_environment_container.tailscale_gateway[0]"
            before = change.get("before") or {}
            after = change.get("after") or {}
            if args.mode == "ct-unprotect":
                valid_change = (
                    address == target
                    and actions == ["update"]
                    and is_exact_ct101(before)
                    and is_exact_ct101(after)
                    and before.get("protection") is True
                    and after.get("protection") is False
                    and changed_keys(before, after) == {("protection",)}
                )
                message = "CT unprotect mode permits only the exact protection update for CT 101"
            else:
                valid_change = (
                    address == target
                    and actions == ["delete"]
                    and is_exact_ct101(before)
                    and before.get("protection") is False
                    and change.get("after") is None
                )
                message = "CT delete mode permits only deletion of unprotected CT 101"
            if not valid_change:
                failures.append(f"{address}: {message}")
            continue

        if address == "terraform_data.tailscale_policy[0]":
            try:
                before_policy = policy_json(change, "before")
                after_policy = policy_json(change, "after")
                rollback = before_policy == detached_gateway_policy(after_policy)
            except (AttributeError, json.JSONDecodeError, TypeError, ValueError):
                rollback = False
            if not rollback:
                failures.append(f"{address}: gateway-policy mutation requires its exact lifecycle operation")
            continue

        legacy_container = "proxmox_virtual_environment_container.tailscale_gateway[0]"
        if address == legacy_container and "create" in actions:
            failures.append(f"{address}: creating or recreating retired CT 101 is forbidden")
            continue


        if "delete" in actions:
            failures.append(f"{address}: delete or replacement is forbidden")
            continue

        if address in allow:
            continue

        before = change.get("before")
        after = change.get("after")
        changed = changed_keys(before, after)
        sensitive = sorted(
            ".".join(path)
            for path in changed
            if any(part in SENSITIVE_FIELDS for part in path)
            and not safe_protection_enable(before, after, path)
        )
        if sensitive:
            failures.append(f"{address}: protected field change: {', '.join(sensitive)}")

        lower_type = resource_type.lower()
        if any(marker in lower_type for marker in STORAGE_RESOURCE_MARKERS):
            failures.append(f"{address}: storage mutation requires an explicit reviewed allowlist")
        if args.mode != "network-migration" and any(marker in lower_type for marker in NETWORK_RESOURCE_MARKERS):
            failures.append(f"{address}: network/control-plane mutation requires network-migration mode or an allowlist")

    if args.mode == "adopt" and observed_actions == 0:
        failures.append("adoption plan contains no import actions")
    if args.mode == "recovery" and observed_addresses != RECOVERY_ADDRESSES:
        failures.append("recovery plan must contain the complete expected fresh resource set")
    if (
        args.mode == "tailscale-controller-retirement"
        and (observed_actions != 5 or observed_addresses != TAILSCALE_CONTROLLER_RETIREMENT_ADDRESSES)
    ):
        failures.append("Tailscale controller retirement plan must contain one policy update and four identity deletions")
    if args.mode == "tailscale-controller-access" and (
        observed_actions != 1 or observed_addresses != {"terraform_data.tailscale_policy[0]"}
    ):
        failures.append("local-controller access repair plan must contain exactly one policy update")
    if (
        args.mode == "network-migration"
        and observed_addresses != MAPPING_ADDRESSES | {"proxmox_virtual_environment_vm.arch"}
    ):
        failures.append("hardware migration plan must contain all mappings and the VM transition")
    if args.mode == "disk-growth" and (
        observed_actions != 1
        or observed_addresses != {"proxmox_virtual_environment_vm.arch"}
    ):
        failures.append("disk growth plan must contain exactly one VM 100 action")
    if args.mode in {"ct-gateway-detach", "ct-gateway-retire"} and (
        observed_actions != 1
        or observed_addresses != {"terraform_data.tailscale_policy[0]"}
    ):
        failures.append("gateway lifecycle plan must contain exactly one complete policy update")
    if args.mode in {"ct-unprotect", "ct-delete"} and (
        observed_actions != 1
        or observed_addresses != {"proxmox_virtual_environment_container.tailscale_gateway[0]"}
    ):
        failures.append("CT retirement plan must contain exactly one complete target action")
    if args.mode == "omada-gateway-reservation-retirement" and (
        observed_actions != 1
        or observed_addresses != {'omada_dhcp_reservation.reservation["bc:24:11:fd:4c:5c"]'}
    ):
        failures.append("Omada gateway-reservation retirement must contain exactly one target deletion")

    if failures:
        for failure in sorted(set(failures)):
            print(f"DENY: {failure}", file=sys.stderr)
        return 1
    print(f"plan policy passed: mode={args.mode} actions={observed_actions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
