#!/usr/bin/env python3
"""Build and verify the deterministic protocol-v4 Proxmox host bundle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

BUNDLE_FORMAT = "home-lab-proxmox-host-bundle-v1"
HASH_ALGORITHM = "sha256-canonical-file-tree-v1"
PROTOCOL_VERSION = 4
EXPECTED_HELPERS = ("proxmox-activator", "proxmox-observer", "proxmox-private-preparer")
ACTIVATOR_TEMPLATE_PATH = Path(__file__).with_name("activator-template.py")
OBSERVER_TEMPLATE_PATH = Path(__file__).with_name("observer-template.py")
PREPARER_TEMPLATE_PATH = Path(__file__).with_name("private-preparer-template.py")
EXPECTED_PROJECTION_KEYS = {
    "accounts", "apiIntent", "architecture", "auditAbsence", "healthExpectations", "hostNetworking",
    "kernelPolicy", "managedArtifacts", "managedFileFragments", "managedFileMetadata", "managedFiles",
    "nativeServices", "packagePolicy", "planningPolicy", "ssh", "storagePolicy", "tailscale", "version",
}
FORBIDDEN_PROJECTION_KEYS = {
    "api_endpoint", "auth_key_secret_ref", "bdf", "by_id_secret_ref", "compatibility_config_path",
    "device_ids", "filesystem_uuid", "iommu_group", "mac", "mapping", "materialization", "members",
    "pci", "pool_guid_secret_ref", "port_secret_ref", "projectable", "rom_file", "serial_secret_ref",
    "smbios_uuid", "subsystem_id", "token_escrow", "token_name", "usb", "vendor_device",
}
PVE_COMPATIBILITY_ROOT = "/" + "etc" + "/" + "pve"
FORBIDDEN_STRING_PATTERNS = (
    re.compile(re.escape(PVE_COMPATIBILITY_ROOT) + r"(?:/|$)"),
    re.compile(r"(?:^|/)(?:authorized_keys2?|ssh_host_(?:ed25519|ecdsa|rsa)_key)(?:$|/)", re.IGNORECASE),
    re.compile(r"/(?:dev/(?:disk|serial)|root/\.config/home-lab)(?:/|$)"),
    re.compile(r"(?:" + "HOMELAB" + r"_|" + "TAILSCALE" + r"_AUTH_KEY|PROXMOX_(?:PLAN|APPLY|FIREWALL)_SSH_PUBLIC_KEYS)"),
    re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\b", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{4}:[0-9a-f]{4}\b", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE),
)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require_regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise ValueError(f"{label} is missing: {path}") from error
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a regular file: {path}")


def write_file(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def canonical_tree_files(root: Path) -> list[Path]:
    try:
        root_mode = root.lstat().st_mode
    except FileNotFoundError as error:
        raise ValueError(f"bundle tree is missing: {root}") from error
    if not stat.S_ISDIR(root_mode):
        raise ValueError(f"bundle tree root must be a real directory: {root}")
    files: list[Path] = []

    def visit(directory: Path) -> None:
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda candidate: candidate.name):
                candidate = directory / entry.name
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    raise ValueError(f"bundle tree must not contain symlinks: {candidate}")
                if stat.S_ISDIR(mode):
                    visit(candidate)
                elif stat.S_ISREG(mode):
                    files.append(candidate)
                else:
                    raise ValueError(f"bundle tree contains unsupported entry: {candidate}")

    visit(root)
    return sorted(files, key=lambda candidate: candidate.relative_to(root).as_posix())


def canonical_tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for candidate in canonical_tree_files(root):
        relative = candidate.relative_to(root).as_posix().encode()
        content = candidate.read_bytes()
        executable = bool(stat.S_IMODE(candidate.lstat().st_mode) & 0o111)
        digest.update(b"file\0")
        digest.update(struct.pack(">I", len(relative)))
        digest.update(relative)
        digest.update(b"\1" if executable else b"\0")
        digest.update(struct.pack(">Q", len(content)))
        digest.update(content)
    return digest.hexdigest()


def safe_target_path(target: str) -> Path:
    candidate = Path(target)
    if not candidate.is_absolute() or ".." in candidate.parts or "\0" in target:
        raise ValueError(f"managed target path is unsafe: {target}")
    if target == PVE_COMPATIBILITY_ROOT or target.startswith(f"{PVE_COMPATIBILITY_ROOT}/"):
        raise ValueError(f"managed target enters PVE-owned state: {target}")
    relative = Path(*candidate.parts[1:])
    if not relative.parts:
        raise ValueError("managed target path must not be root")
    return relative


def validate_no_protected_data(value: Any, label: str, key: str = "") -> None:
    if isinstance(value, list):
        for item in value:
            validate_no_protected_data(item, label, key)
        return
    if isinstance(value, dict):
        for nested_key, nested in value.items():
            if nested_key in FORBIDDEN_PROJECTION_KEYS or nested_key.endswith("_secret_ref") or \
                    "compatibility" in nested_key.lower() or \
                    (nested_key != "requiresApproval" and re.search(
                        r"(?:approval|cleanup|confirmed|marker|migration)", nested_key, re.IGNORECASE
                    )):
                raise ValueError(f"{label} contains forbidden key: {nested_key}")
            validate_no_protected_data(nested, label, nested_key)
        return
    if isinstance(value, str):
        for pattern in FORBIDDEN_STRING_PATTERNS:
            if pattern.search(value):
                raise ValueError(f"{label} contains protected or PVE-owned value in {key or 'value'}")


def validate_package_manifest(manifest: Any) -> int:
    if not isinstance(manifest, dict) or set(manifest) != {"version", "architecture", "provenance", "packages"}:
        raise ValueError("package manifest shape is invalid")
    if manifest["version"] != 1 or manifest["architecture"] != "amd64":
        raise ValueError("package manifest version or architecture is invalid")
    packages = manifest["packages"]
    if not isinstance(packages, list) or not packages:
        raise ValueError("package manifest must contain packages")
    names = []
    for package in packages:
        if not isinstance(package, dict) or set(package) != {"name", "version"} or \
                not isinstance(package["name"], str) or not isinstance(package["version"], str):
            raise ValueError("package manifest record is invalid")
        names.append(package["name"])
    if len(names) != len(set(names)):
        raise ValueError("package manifest names must be unique")
    provenance = manifest["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != {"installedInventory", "solverResult"}:
        raise ValueError("package manifest provenance shape is invalid")
    inventory = provenance["installedInventory"]
    solver = provenance["solverResult"]
    if not isinstance(inventory, dict) or set(inventory) != {"format", "sha256", "installedRecords"} or \
            inventory["format"] != "dpkg-query-status-tsv-v1" or \
            not isinstance(inventory["installedRecords"], int) or isinstance(inventory["installedRecords"], bool) or \
            inventory["installedRecords"] < 1 or not re.fullmatch(r"[0-9a-f]{64}", inventory.get("sha256", "")):
        raise ValueError("installed-inventory provenance is invalid")
    if not isinstance(solver, dict) or set(solver) != {"format", "sha256", "changes"} or \
            solver["format"] != "apt-get-simulate-v1" or not re.fullmatch(r"[0-9a-f]{64}", solver.get("sha256", "")) or \
            not isinstance(solver["changes"], list):
        raise ValueError("solver provenance is invalid")
    package_count = inventory["installedRecords"]
    for change in solver["changes"]:
        if not isinstance(change, dict) or set(change) != {"action", "name", "previousVersion", "version"} or \
                change["action"] not in {"install", "remove", "upgrade"} or not isinstance(change["name"], str):
            raise ValueError("solver provenance change is invalid")
        if change["action"] == "install":
            if change["previousVersion"] is not None or not isinstance(change["version"], str):
                raise ValueError("solver install provenance is invalid")
            package_count += 1
        elif change["action"] == "remove":
            if not isinstance(change["previousVersion"], str) or change["version"] is not None:
                raise ValueError("solver removal provenance is invalid")
            package_count -= 1
        elif not isinstance(change["previousVersion"], str) or not isinstance(change["version"], str) or \
                change["previousVersion"] == change["version"]:
            raise ValueError("solver upgrade provenance is invalid")
    if package_count != len(packages):
        raise ValueError("package manifest count differs from provenance")
    validate_no_protected_data(manifest, "package manifest")
    return len(packages)


def validate_projection(projection: Any, package_count: int, package_manifest_sha256: str) -> None:
    if not isinstance(projection, dict) or set(projection) != EXPECTED_PROJECTION_KEYS:
        raise ValueError("projection top-level shape is invalid")
    if projection["version"] != 1 or projection["architecture"] != "amd64":
        raise ValueError("projection version or architecture is invalid")
    package_policy = projection.get("packagePolicy")
    if not isinstance(package_policy, dict) or package_policy.get("manifestPackageCount") != package_count or \
            package_policy.get("manifestSha256") != package_manifest_sha256:
        raise ValueError("projection package-manifest binding is invalid")
    validate_no_protected_data(projection, "projection")
    expected_lists = (
        "managedFiles", "managedFileFragments", "managedArtifacts", "managedFileMetadata", "auditAbsence",
        "nativeServices",
    )
    if any(not isinstance(projection.get(name), list) for name in expected_lists):
        raise ValueError("projection record collections are malformed")
    managed_paths = set()
    for record in projection["managedFiles"]:
        if not isinstance(record, dict) or set(record) != {"path", "owner", "group", "mode", "content"} or \
                not all(isinstance(record[field], str) for field in record):
            raise ValueError("managed-file projection record is malformed")
        safe_target_path(record["path"])
        if not re.fullmatch(r"0[0-7]{3}", record["mode"]):
            raise ValueError("managed-file projection mode is malformed")
        if record["path"] in managed_paths:
            raise ValueError("managed-file projection paths must be unique")
        managed_paths.add(record["path"])
    for collection in ("managedFileFragments", "managedArtifacts", "auditAbsence"):
        for record in projection[collection]:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                raise ValueError(f"{collection} projection record is malformed")
            safe_target_path(record["path"])
    api_intent = projection.get("apiIntent")
    if not isinstance(api_intent, dict) or set(api_intent) != {"pveAccess", "pveFirewall", "pveStorage"}:
        raise ValueError("PVE semantic API intent is malformed")
    planning = projection.get("planningPolicy")
    expected_domains = {
        "managed-files", "managed-fragments", "managed-artifacts", "packages", "services", "accounts",
        "tailscale", "pve-access", "pve-firewall", "pve-storage",
    }
    if not isinstance(planning, dict) or set(planning) != {"domains", "managedFilePolicies", "maxAgeSeconds", "servicePolicies"} or \
            planning["maxAgeSeconds"] != 1800 or not isinstance(planning["domains"], list) or \
            {item.get("domain") for item in planning["domains"] if isinstance(item, dict)} != expected_domains:
        raise ValueError("planning policy is malformed")
    policy_keys = {"automatic", "domain", "requiresApproval", "requiresReboot", "requiresWatchdog", "safetyClass"}
    safety_classes = {"guarded", "reboot-bound", "protected-session", "access-critical", "data-critical"}
    for item in planning["domains"]:
        if set(item) != policy_keys or item["safetyClass"] not in safety_classes or \
                any(not isinstance(item[key], bool) for key in ("automatic", "requiresApproval", "requiresReboot", "requiresWatchdog")):
            raise ValueError("planning policy domain classification is malformed")
        if item["domain"] == "packages" and (item["automatic"] or item["safetyClass"] != "protected-session"):
            raise ValueError("package policy must remain a nonautomatic protected session")
    service_policy_keys = {"automatic", "name", "requiresApproval", "requiresReboot", "requiresWatchdog", "safetyClass"}
    service_names = {item["name"] for item in projection["nativeServices"]}
    service_policies = planning["servicePolicies"]
    if not isinstance(service_policies, list) or len(service_policies) != len(service_names) or \
            {item.get("name") for item in service_policies if isinstance(item, dict)} != service_names:
        raise ValueError("every native service must have exactly one service policy")
    expected_service_policy = {
        "chrony.service": ("guarded", True, False),
        "nfs-server.service": ("data-critical", False, False),
        "ssh.service": ("access-critical", False, True),
        "tailscaled.service": ("access-critical", False, True),
    }
    for item in service_policies:
        if set(item) != service_policy_keys or item["name"] not in expected_service_policy or \
                any(not isinstance(item[key], bool) for key in ("automatic", "requiresApproval", "requiresReboot", "requiresWatchdog")):
            raise ValueError("service policy is malformed or incomplete")
        expected_class, expected_automatic, expected_watchdog = expected_service_policy[item["name"]]
        if (item["safetyClass"], item["automatic"], item["requiresWatchdog"]) != \
                (expected_class, expected_automatic, expected_watchdog) or not item["requiresApproval"] or item["requiresReboot"]:
            raise ValueError("service policy weakens the authoritative safety classification")
    target_keys = {"automatic", "path", "requiresApproval", "requiresReboot", "requiresWatchdog", "safetyClass"}
    managed_file_paths = {item["path"] for item in projection["managedFiles"]}
    target_policies = planning["managedFilePolicies"]
    if not isinstance(target_policies, list) or {item.get("path") for item in target_policies if isinstance(item, dict)} != managed_file_paths:
        raise ValueError("every managed file must have exactly one target policy")
    for item in target_policies:
        if set(item) != target_keys or item["safetyClass"] not in safety_classes or \
                any(not isinstance(item[key], bool) for key in ("automatic", "requiresApproval", "requiresReboot", "requiresWatchdog")):
            raise ValueError("managed-file target policy is malformed")
        access_critical = item["path"] == "/etc/network/interfaces" or "/ssh/" in item["path"] or "/sudoers.d/" in item["path"]
        if access_critical != (item["safetyClass"] == "access-critical") or \
                (access_critical and (not item["requiresApproval"] or not item["requiresWatchdog"])):
            raise ValueError("access-critical managed-file target policy is unsafe")


def observation_specification(projection: dict[str, Any]) -> dict[str, Any]:
    accounts = []
    for collection in (projection["accounts"]["service"], projection["accounts"]["human"]):
        for account in collection:
            accounts.append({
                "comment": account.get("comment", ""),
                "groups": sorted(account.get("groups", account.get("supplementaryGroups", []))),
                "home": account["home"], "name": account["name"],
                "primaryGroup": account.get("group", account["name"]), "shell": account["shell"],
            })
    pve_manager = next((item for item in projection["packagePolicy"]["critical"]
                        if item["role"] == "pve-manager"), None)
    if pve_manager is None:
        raise ValueError("projection lacks the required PVE manager identity policy")
    return {
        "accounts": sorted(accounts, key=lambda item: item["name"]),
        "auditAbsence": [{"absence": item["absence"], "target": item["path"], **(
            {"pattern": item["pattern"]} if "pattern" in item else {})} for item in projection["auditAbsence"]],
        "aptSourceNames": sorted(Path(item["path"]).name for item in projection["managedFiles"]
                                 if item["path"].startswith("/etc/apt/sources.list.d/")),
        "managedArtifacts": [{"expectedSha256": item["sha256"], "group": item["group"], "owner": item["owner"],
                              "symlinkTarget": item["symlinkTarget"], "target": item["path"]}
                             for item in projection["managedArtifacts"]],
        "managedFiles": [{"expectedSha256": sha256_bytes(item["content"].encode()), "group": item["group"],
                          "owner": item["owner"], "target": item["path"]} for item in projection["managedFiles"]],
        "managedFragments": [{"content": item["content"], "expectedSha256": sha256_bytes(item["content"].encode()),
                              "group": item["group"], "owner": item["owner"], "target": item["path"]}
                             for item in projection["managedFileFragments"]],
        "health": projection["healthExpectations"],
        "networkSnippetNames": sorted(projection["hostNetworking"]["permittedActiveSnippets"]),
        "expectedIdentity": {"architecture": projection["architecture"], "hostname": projection["hostNetworking"]["hostname"],
                             "os": "debian", "pveVersion": "pve-manager/" + pve_manager["version"]},
        "protectedAccessExpectedCount": len(accounts) + len(projection["apiIntent"]["pveAccess"]["bindings"]),
        "protectedExpectedCount": 3,
        "pveAccessRoles": projection["apiIntent"]["pveAccess"]["roles"],
        "pveFirewall": projection["apiIntent"]["pveFirewall"],
        "pveStorage": projection["apiIntent"]["pveStorage"],
        "services": sorted(item["name"] for item in projection["nativeServices"]),
        "storage": projection["storagePolicy"],
        "tailscale": {
            "acceptDns": projection["tailscale"]["acceptDns"],
            "acceptRoutes": projection["tailscale"]["acceptRoutes"],
            "advertiseRoutes": projection["tailscale"]["advertiseRoutes"],
            "advertiseTags": [projection["tailscale"]["advertiseTag"]],
            "backendState": projection["healthExpectations"]["tailscaleBackendState"],
            "hostname": projection["tailscale"]["hostname"],
            "netfilterMode": projection["tailscale"]["netfilterMode"],
            "ssh": projection["tailscale"]["ssh"],
        },
    }


def activation_specification(projection: dict[str, Any], flake_lock_sha256: str, include_bindings: bool = True) -> dict[str, Any]:
    policies = {item["domain"]: item for item in projection["planningPolicy"]["domains"]}
    file_policies = {item["path"]: item for item in projection["planningPolicy"]["managedFilePolicies"]}
    service_policies = {item["name"]: item for item in projection["planningPolicy"]["servicePolicies"]}
    catalog: dict[str, Any] = {}

    def add(domain: str, name: str, kind: str, target_type: str, desired: dict[str, Any], material: dict[str, Any], policy: dict[str, Any]) -> None:
        if not policy["automatic"] or policy["requiresWatchdog"] or policy["safetyClass"] in {"access-critical", "data-critical", "protected-session"}:
            return
        target_key = "name" if domain == "services" else "path"
        target = {target_key: name, "type": target_type}
        after = {"state": "present", **desired}
        catalog[domain + "\0" + name] = {
            "action": {"after": after, "approvalRequired": policy["requiresApproval"], "domain": domain,
                       "kind": kind, "rebootRequired": policy["requiresReboot"], "safetyClass": policy["safetyClass"],
                       "target": target, "watchdogRequired": policy["requiresWatchdog"]},
            "domain": domain, **material, "after": after,
        }

    for item in projection["managedFiles"]:
        add("managed-files", item["path"], "replace-file", "file",
            {"contentMatches": True, "groupMatches": True, "mode": item["mode"], "ownerMatches": True, "type": "file"},
            {"contentBase64": base64.b64encode(item["content"].encode()).decode(), "group": item["group"],
             "mode": item["mode"], "nativeOperation": "update-initramfs" if item["path"] in {
                 "/etc/modprobe.d/zfs.conf", "/etc/modules-load.d/home-lab-vfio.conf"} else None,
             "owner": item["owner"], "path": item["path"], "sha256": sha256_bytes(item["content"].encode())},
            file_policies[item["path"]])
    for item in projection["managedFileFragments"]:
        add("managed-fragments", item["path"], "ensure-fragment", "file-fragment",
            {"groupMatches": True, "matchCount": 1, "mode": item["mode"], "ownerMatches": True, "type": "file"},
            {"group": item["group"], "line": item["content"], "mode": item["mode"], "nativeOperation": "update-grub",
             "owner": item["owner"], "path": item["path"], "sha256": sha256_bytes(item["content"].encode())},
            policies["managed-fragments"])
    for item in projection["managedArtifacts"]:
        add("managed-artifacts", item["path"], "install-artifact", "artifact",
            {"contentMatches": True, "groupMatches": True, "mode": item["mode"], "ownerMatches": True,
             "symlinkTargetMatches": True, "type": "symlink" if item["symlinkTarget"] else "file"},
            {"group": item["group"], "mode": item["mode"], "owner": item["owner"], "path": item["path"],
             "sha256": item["sha256"], "sourceUrl": item["sourceUrl"], "symlinkTarget": item["symlinkTarget"]},
            policies["managed-artifacts"])
    for item in projection["nativeServices"]:
        add("services", item["name"], "reconcile-service", "service",
            {"active": item["state"] == "started", "enabled": item["enabled"]},
            {"active": item["state"] == "started", "enabled": item["enabled"], "name": item["name"]},
            service_policies[item["name"]])
    ordered_catalog = dict(sorted(catalog.items()))
    if not include_bindings:
        return {"catalog": ordered_catalog, "catalogOrder": list(ordered_catalog)}
    preparer = expected_helper_content("proxmox-private-preparer", projection, flake_lock_sha256)
    observer = expected_helper_content("proxmox-observer", projection, flake_lock_sha256)
    expected_bindings = {
        "activationEnvelopeSchemaSha256": sha256_file(ACTIVATOR_TEMPLATE_PATH.with_name("activation-envelope.schema.json")),
        "flakeLockSha256": flake_lock_sha256,
        "observerSha256": sha256_bytes(observer),
        "privatePreparerSha256": sha256_bytes(preparer),
        "privatePreparationRequestSchemaSha256": sha256_file(PREPARER_TEMPLATE_PATH.with_name("private-preparation-request.schema.json")),
        "packageManifestSha256": projection["packagePolicy"]["manifestSha256"],
        "planSchemaSha256": sha256_file(ACTIVATOR_TEMPLATE_PATH.with_name("plan.schema.json")),
        "privatePreconditionsSchemaSha256": sha256_file(ACTIVATOR_TEMPLATE_PATH.with_name("private-preconditions.schema.json")),
        "projectionSha256": sha256_bytes(canonical_json(projection)),
    }
    return {"catalog": ordered_catalog, "catalogOrder": list(ordered_catalog), "expectedBindings": expected_bindings,
            "protectedAccessExpectedCount": observation_specification(projection)["protectedAccessExpectedCount"],
            "protectedHardwareExpectedCount": observation_specification(projection)["protectedExpectedCount"]}


def preparation_specification(projection: dict[str, Any], flake_lock_sha256: str) -> dict[str, Any]:
    catalog = activation_specification(projection, flake_lock_sha256, False)
    pve_manager = next(item for item in projection["packagePolicy"]["critical"] if item["role"] == "pve-manager")
    return {**catalog, "hostname": projection["hostNetworking"]["hostname"],
            "node": projection["apiIntent"]["pveStorage"]["nodes"][0],
            "pool": projection["apiIntent"]["pveStorage"]["pool"],
            "pveAccessBindings": projection["apiIntent"]["pveAccess"]["bindings"],
            "pveVersion": "pve-manager/" + pve_manager["version"]}


def expected_helper_content(name: str, projection: dict[str, Any], flake_lock_sha256: str | None = None) -> bytes:
    if name not in EXPECTED_HELPERS:
        raise ValueError(f"unsupported fixed helper name: {name}")
    if flake_lock_sha256 is None:
        local_lock = ACTIVATOR_TEMPLATE_PATH.parents[1] / "flake.lock"
        if not local_lock.is_file():
            raise ValueError("fixed flake-lock binding is unavailable")
        flake_lock_sha256 = sha256_file(local_lock)
    if name == "proxmox-private-preparer":
        template = PREPARER_TEMPLATE_PATH.read_text(encoding="utf-8")
        encoded_spec = json.dumps(canonical_json(preparation_specification(projection, flake_lock_sha256)).decode().strip())
        return template.replace("'@PREPARATION_SPEC@'", encoded_spec).encode()
    if name == "proxmox-activator":
        template = ACTIVATOR_TEMPLATE_PATH.read_text(encoding="utf-8")
        encoded_spec = json.dumps(canonical_json(activation_specification(projection, flake_lock_sha256)).decode().strip())
        return template.replace("'@ACTIVATION_SPEC@'", encoded_spec).encode()
    template = OBSERVER_TEMPLATE_PATH.read_text(encoding="utf-8")
    observer_spec = observation_specification(projection)
    observer_spec["privatePreparerSha256"] = sha256_bytes(expected_helper_content("proxmox-private-preparer", projection, flake_lock_sha256))
    encoded_spec = json.dumps(canonical_json(observer_spec).decode().strip())
    return template.replace("'@OBSERVATION_SPEC@'", encoded_spec).encode()


def expected_helper_version(name: str) -> bytes:
    capabilities = {"proxmox-observer": ["observe"], "proxmox-activator": ["guarded-session"],
                    "proxmox-private-preparer": ["summary", "prepare"]}
    return canonical_json({"capabilities": capabilities[name], "helper": name,
                           "protocol": PROTOCOL_VERSION, "version": 1})


def expected_protocol() -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "milestone": "bootstrap-recovery",
        "capabilities": ["observe", "plan", "prepare", "guarded-apply", "rollback", "bootstrap-recovery"],
        "helpers": {
            "proxmox-activator": {"commands": ["version", "self-check", "session"], "mutating": True},
            "proxmox-observer": {"commands": ["version", "self-check", "observe"], "mutating": False},
            "proxmox-private-preparer": {"commands": ["summary", "prepare"], "mutating": False},
        },
        "uploadedCodeExecution": False,
    }


def directory_regular_names(directory: Path, label: str) -> set[str]:
    try:
        mode = directory.lstat().st_mode
    except FileNotFoundError as error:
        raise ValueError(f"{label} directory is missing") from error
    if not stat.S_ISDIR(mode):
        raise ValueError(f"{label} must be a real directory")
    names = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            entry_mode = entry.stat(follow_symlinks=False).st_mode
            if not stat.S_ISREG(entry_mode):
                raise ValueError(f"{label} contains a non-regular entry: {entry.name}")
            names.add(entry.name)
    return names


def build_bundle(args: argparse.Namespace) -> None:
    projection_path = Path(args.projection)
    package_manifest_path = Path(args.package_manifest)
    flake_lock_path = Path(args.flake_lock)
    output = Path(args.output)
    hash_output = Path(args.hash_output)
    for label, source in {
        "projection": projection_path, "package manifest": package_manifest_path, "flake lock": flake_lock_path,
    }.items():
        require_regular_file(source, label)

    if output.exists():
        if not stat.S_ISDIR(output.lstat().st_mode) or any(os.scandir(output)):
            raise ValueError(f"bundle output is not an empty real directory: {output}")
    else:
        output.mkdir(parents=True)

    projection_raw = projection_path.read_bytes()
    projection = json.loads(projection_raw)
    if projection_raw != canonical_json(projection):
        raise ValueError("projection must be canonical compact JSON")
    package_raw = package_manifest_path.read_bytes()
    package_manifest = json.loads(package_raw)
    package_count = validate_package_manifest(package_manifest)
    package_manifest_sha256 = sha256_bytes(package_raw)
    validate_projection(projection, package_count, package_manifest_sha256)

    projection_sha256 = sha256_bytes(projection_raw)
    flake_lock_sha256 = sha256_file(flake_lock_path)
    helper_contents = {name: expected_helper_content(name, projection, flake_lock_sha256) for name in EXPECTED_HELPERS}
    helper_hashes = {name: sha256_bytes(content) for name, content in helper_contents.items()}
    observation_schema = OBSERVER_TEMPLATE_PATH.with_name("observation.schema.json").read_bytes()
    plan_schema = OBSERVER_TEMPLATE_PATH.with_name("plan.schema.json").read_bytes()
    private_schema = OBSERVER_TEMPLATE_PATH.with_name("private-preconditions.schema.json").read_bytes()
    activation_schema = OBSERVER_TEMPLATE_PATH.with_name("activation-envelope.schema.json").read_bytes()
    preparation_schema = PREPARER_TEMPLATE_PATH.with_name("private-preparation-request.schema.json").read_bytes()
    metadata = {
        "bundleFormat": BUNDLE_FORMAT,
        "contentHashAlgorithm": HASH_ALGORITHM,
        "target": {"architecture": "amd64", "os": "linux", "requiresNix": False},
        "protocolVersion": PROTOCOL_VERSION,
        "packageCount": package_count,
        "projectionSha256": projection_sha256,
        "packageManifestSha256": package_manifest_sha256,
        "observationSchemaSha256": sha256_bytes(observation_schema),
        "planSchemaSha256": sha256_bytes(plan_schema),
        "privatePreconditionsSchemaSha256": sha256_bytes(private_schema),
        "activationEnvelopeSchemaSha256": sha256_bytes(activation_schema),
        "privatePreparationRequestSchemaSha256": sha256_bytes(preparation_schema),
        "flakeLockSha256": flake_lock_sha256,
        "helperSha256": helper_hashes,
        "helperInstall": {
            "deployment": "copy-out-of-store", "owner": "root", "group": "root", "mode": "0755",
        },
    }

    write_file(output / "policy/projection.json", projection_raw)
    write_file(output / "policy/observation.schema.json", observation_schema)
    write_file(output / "policy/plan.schema.json", plan_schema)
    write_file(output / "policy/private-preconditions.schema.json", private_schema)
    write_file(output / "policy/activation-envelope.schema.json", activation_schema)
    write_file(output / "policy/private-preparation-request.schema.json", preparation_schema)
    write_file(output / "packages/proxmox-package-manifest.json", package_raw)
    write_file(output / "metadata.json", canonical_json(metadata))
    write_file(output / "protocol.json", canonical_json(expected_protocol()))

    rendered_records = []
    for record in projection["managedFiles"]:
        relative = safe_target_path(record["path"])
        content = record["content"].encode()
        bundle_path = Path("rendered/files") / relative
        write_file(output / bundle_path, content)
        rendered_records.append({
            "targetPath": record["path"], "bundlePath": bundle_path.as_posix(), "owner": record["owner"],
            "group": record["group"], "mode": record["mode"], "contentSha256": sha256_bytes(content),
        })
    rendered_records.sort(key=lambda record: record["targetPath"])
    write_file(output / "rendered/managed-files.json", canonical_json(rendered_records))
    write_file(output / "rendered/managed-file-fragments.json", canonical_json(projection["managedFileFragments"]))
    write_file(output / "rendered/managed-artifacts.json", canonical_json(projection["managedArtifacts"]))
    write_file(output / "rendered/managed-file-metadata.json", canonical_json(projection["managedFileMetadata"]))
    write_file(output / "rendered/audit-absence.json", canonical_json(projection["auditAbsence"]))

    for name, content in helper_contents.items():
        write_file(output / "helpers" / name, content, 0o755)

    hash_output.parent.mkdir(parents=True, exist_ok=True)
    write_file(hash_output, f"{canonical_tree_sha256(output)}\n".encode())


def verify_bundle(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle)
    hash_file = Path(args.hash_file)
    require_regular_file(hash_file, "bundle hash")
    expected_hash = hash_file.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("bundle hash file is malformed")
    actual_hash = canonical_tree_sha256(bundle)
    if actual_hash != expected_hash:
        raise ValueError(f"bundle content hash mismatch: expected {expected_hash}, got {actual_hash}")

    metadata_path = bundle / "metadata.json"
    protocol_path = bundle / "protocol.json"
    projection_path = bundle / "policy/projection.json"
    package_manifest_path = bundle / "packages/proxmox-package-manifest.json"
    for label, path in {
        "metadata": metadata_path, "protocol": protocol_path, "projection": projection_path,
        "package manifest": package_manifest_path,
    }.items():
        require_regular_file(path, label)
    metadata_raw = metadata_path.read_bytes()
    metadata = json.loads(metadata_raw)
    package_raw = package_manifest_path.read_bytes()
    package_manifest = json.loads(package_raw)
    package_count = validate_package_manifest(package_manifest)
    projection_raw = projection_path.read_bytes()
    projection = json.loads(projection_raw)
    if metadata_raw != canonical_json(metadata) or projection_raw != canonical_json(projection):
        raise ValueError("bundle JSON policy or metadata is not canonical")
    validate_projection(projection, package_count, sha256_file(package_manifest_path))

    expected_metadata_keys = {
        "activationEnvelopeSchemaSha256", "bundleFormat", "contentHashAlgorithm", "flakeLockSha256", "helperInstall", "helperSha256", "packageCount",
        "observationSchemaSha256", "packageManifestSha256", "planSchemaSha256", "privatePreconditionsSchemaSha256",
        "privatePreparationRequestSchemaSha256", "projectionSha256", "protocolVersion", "target",
    }
    if not isinstance(metadata, dict) or set(metadata) != expected_metadata_keys or \
            metadata.get("bundleFormat") != BUNDLE_FORMAT or metadata.get("contentHashAlgorithm") != HASH_ALGORITHM or \
            metadata.get("protocolVersion") != PROTOCOL_VERSION:
        raise ValueError("bundle metadata structure, format, or protocol is unsupported")
    if not re.fullmatch(r"[0-9a-f]{64}", metadata.get("flakeLockSha256", "")):
        raise ValueError("bundle metadata flake-lock hash is malformed")
    if metadata.get("projectionSha256") != sha256_file(projection_path):
        raise ValueError("bundle metadata projection binding failed")
    if metadata.get("packageManifestSha256") != sha256_file(package_manifest_path) or \
            metadata.get("packageCount") != package_count:
        raise ValueError("bundle metadata package-manifest binding failed")
    observation_schema_path = bundle / "policy/observation.schema.json"
    plan_schema_path = bundle / "policy/plan.schema.json"
    private_schema_path = bundle / "policy/private-preconditions.schema.json"
    activation_schema_path = bundle / "policy/activation-envelope.schema.json"
    preparation_schema_path = bundle / "policy/private-preparation-request.schema.json"
    if metadata.get("observationSchemaSha256") != sha256_file(observation_schema_path) or \
            metadata.get("planSchemaSha256") != sha256_file(plan_schema_path) or \
            metadata.get("privatePreconditionsSchemaSha256") != sha256_file(private_schema_path) or \
            metadata.get("activationEnvelopeSchemaSha256") != sha256_file(activation_schema_path) or \
            metadata.get("privatePreparationRequestSchemaSha256") != sha256_file(preparation_schema_path) or \
            observation_schema_path.read_bytes() != OBSERVER_TEMPLATE_PATH.with_name("observation.schema.json").read_bytes() or \
            plan_schema_path.read_bytes() != OBSERVER_TEMPLATE_PATH.with_name("plan.schema.json").read_bytes() or \
            private_schema_path.read_bytes() != OBSERVER_TEMPLATE_PATH.with_name("private-preconditions.schema.json").read_bytes() or \
            activation_schema_path.read_bytes() != OBSERVER_TEMPLATE_PATH.with_name("activation-envelope.schema.json").read_bytes() or \
            preparation_schema_path.read_bytes() != PREPARER_TEMPLATE_PATH.with_name("private-preparation-request.schema.json").read_bytes():
        raise ValueError("bundle metadata schema binding failed")
    if metadata.get("target") != {"architecture": "amd64", "os": "linux", "requiresNix": False}:
        raise ValueError("bundle target metadata is invalid")
    if metadata.get("helperInstall") != {
        "deployment": "copy-out-of-store", "owner": "root", "group": "root", "mode": "0755",
    }:
        raise ValueError("bundle helper installation policy is invalid")
    helper_hashes = metadata.get("helperSha256")
    if not isinstance(helper_hashes, dict) or set(helper_hashes) != set(EXPECTED_HELPERS):
        raise ValueError("bundle helper hash key set is invalid")

    protocol_raw = protocol_path.read_bytes()
    protocol = json.loads(protocol_raw)
    if protocol != expected_protocol() or protocol_raw != canonical_json(protocol):
        raise ValueError("foundation protocol structure is invalid")
    expected_files = {
        "metadata.json", "protocol.json", "packages/proxmox-package-manifest.json",
        "policy/projection.json", "policy/observation.schema.json", "policy/plan.schema.json",
        "policy/private-preconditions.schema.json", "policy/activation-envelope.schema.json",
        "policy/private-preparation-request.schema.json", "rendered/managed-files.json",
        "rendered/managed-file-fragments.json", "rendered/managed-artifacts.json",
        "rendered/managed-file-metadata.json", "rendered/audit-absence.json",
        *("helpers/" + name for name in EXPECTED_HELPERS),
        *("rendered/files/" + safe_target_path(item["path"]).as_posix() for item in projection["managedFiles"]),
    }
    actual_files = {path.relative_to(bundle).as_posix() for path in canonical_tree_files(bundle)}
    if actual_files != expected_files:
        raise ValueError("bundle contains an unknown or missing file")
    for relative in actual_files:
        mode = stat.S_IMODE((bundle / relative).lstat().st_mode)
        expected_mode = 0o755 if relative.startswith("helpers/") else 0o644
        # Nix store materialization strips write bits and may hard-link identical files; the console installer
        # separately requires single-link root-owned 0644/0755 staging inputs before copying out of store.
        if mode not in {expected_mode, expected_mode & ~0o222}:
            raise ValueError("bundle file mode differs")
    helper_directory = bundle / "helpers"
    if directory_regular_names(helper_directory, "helper") != set(EXPECTED_HELPERS):
        raise ValueError("bundle helper directory must contain exactly the fixed helpers")
    for helper in EXPECTED_HELPERS:
        helper_path = helper_directory / helper
        expected_content = expected_helper_content(helper, projection, metadata["flakeLockSha256"])
        if helper_path.read_bytes() != expected_content:
            raise ValueError(f"helper {helper} content differs from the fixed builder template")
        if helper_hashes[helper] != sha256_bytes(expected_content):
            raise ValueError(f"helper {helper} metadata hash differs from the fixed builder template")

        if helper == "proxmox-private-preparer":
            for rejected in ("version", "self-check", "observe", "session", "unknown"):
                result = subprocess.run([sys.executable, helper_path, rejected], capture_output=True, timeout=5)
                if result.returncode != 64 or result.stdout or result.stderr != b"usage: proxmox-private-preparer <summary|prepare>\n":
                    raise ValueError("private preparer command surface differs")
            continue
        version = subprocess.run(
            [sys.executable, helper_path, "version"], capture_output=True, timeout=5,
        )
        if version.returncode != 0 or version.stdout != expected_helper_version(helper) or version.stderr != b"":
            raise ValueError(f"helper {helper} version output is unexpected")

        self_check = subprocess.run(
            [sys.executable, helper_path, "self-check"], capture_output=True, timeout=5,
        )
        capability = "observe" if helper == "proxmox-observer" else "guarded-session"
        expected_self_check = (
            f"{helper}=self-check-passed protocol={PROTOCOL_VERSION} capabilities={capability}\n".encode()
        )
        if self_check.returncode != 0 or self_check.stdout != expected_self_check or self_check.stderr != b"":
            raise ValueError(f"helper {helper} self-check output is unexpected")
        if helper == "proxmox-observer":
            observed = subprocess.run(
                [sys.executable, helper_path, "observe"], capture_output=True, timeout=30,
            )
            try:
                observation = json.loads(observed.stdout)
            except json.JSONDecodeError as error:
                raise ValueError("observer emitted malformed observation JSON") from error
            expected_observation_keys = {"domains", "format", "host", "observerSha256", "protocol"}
            if observed.returncode != 0 or observed.stderr != b"" or observed.stdout != canonical_json(observation) or \
                    set(observation) != expected_observation_keys or observation.get("protocol") != PROTOCOL_VERSION or \
                    observation.get("format") != "home-lab-proxmox-observation-v1" or \
                    observation.get("observerSha256") != sha256_bytes(expected_content):
                raise ValueError("observer canonical redacted observation is unexpected")

        commands = "version|self-check|observe" if helper == "proxmox-observer" else "version|self-check|session"
        expected_usage = f"usage: {helper} <{commands}>\n".encode()
        for rejected_command in ("plan", "apply", "verify", "bootstrap", "unknown"):
            rejected = subprocess.run(
                [sys.executable, helper_path, rejected_command], capture_output=True, timeout=5,
            )
            if rejected.returncode != 64 or rejected.stdout != b"" or rejected.stderr != expected_usage:
                raise ValueError(f"helper {helper} accepts or mishandles rejected command {rejected_command}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--projection", required=True)
    build.add_argument("--package-manifest", required=True)
    build.add_argument("--flake-lock", required=True)
    build.add_argument("--output", required=True)
    build.add_argument("--hash-output", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--hash-file", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "build":
        build_bundle(args)
    else:
        verify_bundle(args)


if __name__ == "__main__":
    main()
