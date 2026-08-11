#!/usr/bin/env python3
"""Build and verify the deterministic, inert Proxmox host foundation bundle."""

from __future__ import annotations

import argparse
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
PROTOCOL_VERSION = 1
EXPECTED_HELPERS = ("proxmox-activator", "proxmox-observer")
HELPER_NAME_TOKEN = "@HELPER_NAME@"
HELPER_TEMPLATE = '''#!/usr/bin/python3
"""Inert Proxmox helper for the controller-foundation milestone."""

import json
import sys

NAME = "@HELPER_NAME@"
PROTOCOL = 1


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"version", "self-check"}:
        print(f"usage: {NAME} <version|self-check>", file=sys.stderr)
        return 64
    if sys.argv[1] == "version":
        print(json.dumps({"capabilities": [], "helper": NAME, "protocol": PROTOCOL, "version": 1}, separators=(",", ":"), sort_keys=True))
    else:
        print(f"{NAME}=self-check-passed protocol={PROTOCOL} capabilities=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
EXPECTED_PROJECTION_KEYS = {
    "accounts", "apiIntent", "architecture", "auditAbsence", "healthExpectations", "hostNetworking",
    "kernelPolicy", "managedArtifacts", "managedFileFragments", "managedFileMetadata", "managedFiles",
    "nativeServices", "packagePolicy", "ssh", "storagePolicy", "tailscale", "version",
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
    re.compile(r"(?:" + "HOMELAB" + r"_|" + "TAILSCALE" + r"_AUTH_KEY|PROXMOX_(?:PLAN|APPLY)_SSH_PUBLIC_KEYS)"),
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
                    re.search(r"(?:approval|cleanup|confirmed|marker|migration)", nested_key, re.IGNORECASE):
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


def expected_helper_content(name: str) -> bytes:
    if name not in EXPECTED_HELPERS:
        raise ValueError(f"unsupported fixed helper name: {name}")
    return HELPER_TEMPLATE.replace(HELPER_NAME_TOKEN, name).encode()


def expected_helper_version(name: str) -> bytes:
    return canonical_json({
        "capabilities": [], "helper": name, "protocol": PROTOCOL_VERSION, "version": 1,
    })


def expected_protocol() -> dict[str, Any]:
    helper_specification = {"commands": ["version", "self-check"], "mutating": False}
    return {
        "version": PROTOCOL_VERSION,
        "milestone": "controller-foundation",
        "capabilities": [],
        "helpers": {name: dict(helper_specification) for name in EXPECTED_HELPERS},
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
    helper_contents = {name: expected_helper_content(name) for name in EXPECTED_HELPERS}
    helper_hashes = {name: sha256_bytes(content) for name, content in helper_contents.items()}
    metadata = {
        "bundleFormat": BUNDLE_FORMAT,
        "contentHashAlgorithm": HASH_ALGORITHM,
        "target": {"architecture": "amd64", "os": "linux", "requiresNix": False},
        "protocolVersion": PROTOCOL_VERSION,
        "packageCount": package_count,
        "projectionSha256": projection_sha256,
        "packageManifestSha256": package_manifest_sha256,
        "flakeLockSha256": sha256_file(flake_lock_path),
        "helperSha256": helper_hashes,
        "helperInstall": {
            "deployment": "copy-out-of-store", "owner": "root", "group": "root", "mode": "0755",
        },
    }

    write_file(output / "policy/projection.json", projection_raw)
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
    metadata = json.loads(metadata_path.read_bytes())
    package_manifest = json.loads(package_manifest_path.read_bytes())
    package_count = validate_package_manifest(package_manifest)
    projection = json.loads(projection_path.read_bytes())
    validate_projection(projection, package_count, sha256_file(package_manifest_path))

    expected_metadata_keys = {
        "bundleFormat", "contentHashAlgorithm", "flakeLockSha256", "helperInstall", "helperSha256", "packageCount",
        "packageManifestSha256", "projectionSha256", "protocolVersion", "target",
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
    helper_directory = bundle / "helpers"
    if directory_regular_names(helper_directory, "helper") != set(EXPECTED_HELPERS):
        raise ValueError("bundle helper directory must contain exactly the fixed helpers")
    for helper in EXPECTED_HELPERS:
        helper_path = helper_directory / helper
        expected_content = expected_helper_content(helper)
        if helper_path.read_bytes() != expected_content:
            raise ValueError(f"helper {helper} content differs from the fixed builder template")
        if helper_hashes[helper] != sha256_bytes(expected_content):
            raise ValueError(f"helper {helper} metadata hash differs from the fixed builder template")

        version = subprocess.run(
            [sys.executable, helper_path, "version"], capture_output=True, timeout=5,
        )
        if version.returncode != 0 or version.stdout != expected_helper_version(helper) or version.stderr != b"":
            raise ValueError(f"helper {helper} version output is unexpected")

        self_check = subprocess.run(
            [sys.executable, helper_path, "self-check"], capture_output=True, timeout=5,
        )
        expected_self_check = (
            f"{helper}=self-check-passed protocol={PROTOCOL_VERSION} capabilities=none\n".encode()
        )
        if self_check.returncode != 0 or self_check.stdout != expected_self_check or self_check.stderr != b"":
            raise ValueError(f"helper {helper} self-check output is unexpected")

        expected_usage = f"usage: {helper} <version|self-check>\n".encode()
        for rejected_command in ("plan", "apply", "verify", "unknown"):
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
