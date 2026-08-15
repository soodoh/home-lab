#!/usr/bin/env python3
"""Collect read-only, allowlisted Gate C metadata on the VM 100 Arch host."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

from argparse import ArgumentParser
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

from vm_100_gate_c import (
    ANONYMOUS_VOLUME, ANONYMOUS_VOLUME_ALLOWLIST, BACKUP_PATHS, CANDIDATE_BY_ID,
    CANDIDATE_SERIAL, CLASSIFICATIONS,
    COLLECTION_FORMAT, DESTINATION_ROOT, DISK_BYTES, DOCKER_ROOT, LEGACY_VOLUMES,
    PROJECT, RUNTIME_TMPFS_ALLOWLIST, SAFE_CONTAINER_ID, SAFE_NAME, SAFE_VOLUME_LABELS, digest,
    expected_volume_names, host_destination, project_desired_inventory,
    project_runtime_inventory, validate_candidate_inventory, validate_collection,
    volume_destination, volume_source,
)

RESERVE_BYTES = 8 * 1024 * 1024 * 1024
LIVE_COMMANDS = {
    "docker": "/usr/bin/docker", "findmnt": "/usr/bin/findmnt",
    "lsblk": "/usr/bin/lsblk", "systemctl": "/usr/bin/systemctl",
}
ARCHIVE_NAME = re.compile(r"^daily-local-backup-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.tar\.gz\.gpg$")
HASH_CHUNK_BYTES = 1024 * 1024


def run_json(command: str, argv: list[str]) -> Any:
    result = subprocess.run([command, *argv], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"command returned invalid JSON: {command}") from error


def run_json_lines(command: str, argv: list[str]) -> list[dict[str, object]]:
    result = subprocess.run([command, *argv], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    values: list[dict[str, object]] = []
    try:
        for line in result.stdout.splitlines():
            if line:
                value = json.loads(line)
                if not isinstance(value, dict): raise ValueError
                values.append(value)
    except (json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"command returned invalid JSON lines: {command}") from error
    return values


def physical_path(logical: str, fixture_root: Path | None) -> Path:
    return Path(logical) if fixture_root is None else fixture_root / logical.removeprefix("/")


def require_plain_directory(logical: str, fixture_root: Path | None) -> Path:
    path = physical_path(logical, fixture_root)
    try:
        parts = path.relative_to(fixture_root).parts if fixture_root is not None else path.parts[1:]
    except ValueError as error:
        raise SystemExit(f"fixture path escapes fixture root: {logical}") from error
    current = fixture_root if fixture_root is not None else Path("/")
    for part in parts:
        current = current / part
        if current.is_symlink(): raise SystemExit(f"copy root contains a symlink component: {logical}")
    try: path_stat = path.stat(follow_symlinks=False)
    except FileNotFoundError as error: raise SystemExit(f"required directory is missing: {logical}") from error
    if not stat.S_ISDIR(path_stat.st_mode): raise SystemExit(f"required path is not a directory: {logical}")
    return path


def mount_identity(findmnt_command: str, logical: str, physical: Path, *, include_uuid: bool = False) -> dict[str, object]:
    fields = "ID,SOURCE,FSTYPE,TARGET,UUID" if include_uuid else "ID,SOURCE,FSTYPE,TARGET"
    value = run_json(findmnt_command, ["--json", "--target", str(physical), "--output", fields])
    filesystems = value.get("filesystems") if isinstance(value, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1: raise SystemExit(f"expected exactly one mount identity for {logical}")
    mount = filesystems[0]
    try: mount_id, device, filesystem, target = int(mount["id"]), str(mount["source"]), str(mount["fstype"]), str(mount["target"])
    except (KeyError, TypeError, ValueError) as error: raise SystemExit(f"mount identity is incomplete for {logical}") from error
    if not device or not filesystem or mount_id < 1: raise SystemExit(f"mount identity is invalid for {logical}")
    if target != logical and not (logical != DESTINATION_ROOT and logical.startswith(target.rstrip("/") + "/")):
        if str(physical) != logical and str(physical).startswith(target.rstrip("/") + "/"): target = "/"
        else: raise SystemExit(f"mount target does not contain {logical}")
    result: dict[str, object] = {"device": device, "filesystem": filesystem, "mountTarget": target, "mountId": mount_id}
    if include_uuid:
        filesystem_uuid = mount.get("uuid")
        if filesystem_uuid in (None, ""): result["filesystemUuid"] = None
        elif not isinstance(filesystem_uuid, str) or not re.fullmatch(r"[A-Fa-f0-9][A-Fa-f0-9-]{0,127}", filesystem_uuid): raise SystemExit(f"filesystem UUID is invalid for {logical}")
        else: result["filesystemUuid"] = filesystem_uuid
    return result


def flatten_blockdevices(values: list[object]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict): raise SystemExit("lsblk returned a malformed device tree")
        result.append(value)
        children = value.get("children", [])
        if not isinstance(children, list): raise SystemExit("lsblk children are malformed")
        result.extend(flatten_blockdevices(children))
    return result


def verify_candidate_device(lsblk_command: str, resolved_disk: Path, mount_device: str) -> tuple[dict[str, Any], list[str]]:
    if not mount_device.startswith("/dev/") or mount_device.startswith("/dev/disk/by-id/"):
        raise SystemExit("candidate mount source must be a concrete descendant block device")
    value = run_json(lsblk_command, ["--tree", "--json", "--bytes", "--output", "PATH,SERIAL,SIZE,TYPE", str(resolved_disk)])
    roots = value.get("blockdevices") if isinstance(value, dict) else None
    if not isinstance(roots, list) or len(roots) != 1: raise SystemExit("candidate whole-disk inspection is ambiguous")
    disk = roots[0]
    if disk.get("type") != "disk" or int(disk.get("size", -1)) != DISK_BYTES or disk.get("serial") != CANDIDATE_SERIAL:
        raise SystemExit("candidate whole disk does not have the exact public identity")
    def find_chain(node: dict[str, Any], target: str, chain: list[str]) -> list[str] | None:
        path = node.get("path")
        if not isinstance(path, str) or not path.startswith("/dev/"): raise SystemExit("lsblk returned an unsafe device path")
        current = [*chain, path]
        if path == target: return current
        for child in node.get("children", []):
            found = find_chain(child, target, current)
            if found is not None: return found
        return None
    chain = find_chain(disk, mount_device, [])
    descendants = flatten_blockdevices(disk.get("children", []))
    matches = [item for item in descendants if item.get("path") == mount_device and item.get("type") in {"part", "crypt", "lvm"}]
    if len(matches) != 1 or chain is None or len(chain) < 2: raise SystemExit("candidate mount device is not a descendant filesystem/partition of the exact candidate disk")
    return disk, chain


def tree_metrics(path: Path) -> tuple[int, int, int, set[tuple[int, int]]]:
    allocated = apparent = inode_count = 0; multiply_linked: set[tuple[int, int]] = set()
    for root, directories, files in os.walk(path, followlinks=False):
        for name in [".", *directories, *files]:
            entry = Path(root) if name == "." else Path(root) / name; entry_stat = entry.lstat()
            inode_count += 1; allocated += entry_stat.st_blocks * 512; apparent += entry_stat.st_size
            if stat.S_ISREG(entry_stat.st_mode) and entry_stat.st_nlink > 1: multiply_linked.add((entry_stat.st_dev, entry_stat.st_ino))
    return allocated, apparent, inode_count, multiply_linked


def copy_metadata(*, kind: str, logical_name: str | None, engine_name: str | None, legacy: bool, source: str, destination: str, source_path: Path, source_mount: dict[str, object], destination_mount: dict[str, object], driver: str | None, options: dict[str, str], labels: dict[str, str], candidate_created_at: str | None) -> tuple[dict[str, object], set[tuple[int, int]]]:
    source_stat = source_path.stat(follow_symlinks=False); allocated, apparent, inodes, hardlinks = tree_metrics(source_path)
    return ({"kind": kind, "logicalName": logical_name, "engineName": engine_name, "legacy": legacy, "source": source, "destination": destination, "sourceMount": source_mount, "destinationMount": destination_mount, "driver": driver, "options": options, "composeLabels": labels, "candidateCreatedAt": candidate_created_at, "uid": source_stat.st_uid, "gid": source_stat.st_gid, "mode": format(stat.S_IMODE(source_stat.st_mode), "04o"), "allocatedBytes": allocated, "apparentBytes": apparent, "inodeCount": inodes, "permittedDeletionRoot": destination, "disposition": "copy"}, hardlinks)


def reject_cross_root_hardlinks(values: list[tuple[str, set[tuple[int, int]]]]) -> None:
    for index, (root, inodes) in enumerate(values):
        for other_root, other in values[index + 1:]:
            if inodes.intersection(other): raise SystemExit(f"cross-root hardlink detected between {root} and {other_root}")


def desired_mount_policy(desired: dict[str, Any]) -> dict[str, dict[tuple[str, str, bool], str]]:
    policy: dict[str, dict[tuple[str, str, bool], str]] = {}
    classified = [(path, disposition) for _, path, disposition, _ in CLASSIFICATIONS]
    for service in desired["serviceMounts"]:
        mounts: dict[tuple[str, str, bool], str] = {}
        for item in service["volumes"]:
            key = (volume_source(f"{PROJECT}_{item['source']}"), item["target"], item["readOnly"])
            if key in mounts: raise SystemExit(f"desired service has a duplicate mount: {service['service']}")
            mounts[key] = item["source"]
        for item in service["binds"]:
            source = item["source"]
            if source != "/home/docker/hass" and not any(source == root or source.startswith(root.rstrip("/") + "/") for root, _ in classified):
                raise SystemExit(f"desired bind is not explicitly classified: {source}")
            key = (source, item["target"], item["readOnly"])
            if key in mounts: raise SystemExit(f"desired service has a duplicate mount: {service['service']}")
            mounts[key] = ""
        policy[service["service"]] = mounts
    return policy


def safe_container_metadata(containers: list[dict[str, Any]], desired: dict[str, Any]) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    policy = desired_mount_policy(desired); expected_services = set(policy)
    if len(expected_services) != 41 or len(containers) != 41:
        raise SystemExit("complete Docker daemon inventory must contain exactly one container for each of 41 desired services")
    safe_containers = []; mounts = []; seen_services: set[str] = set(); seen_ids: set[str] = set(); seen_names: set[str] = set(); observed_anonymous: set[tuple[str, str, bool]] = set(); observed_tmpfs: set[tuple[str, str, bool]] = set()
    for container in containers:
        labels = (container.get("Config") or {}).get("Labels") or {}; service = labels.get("com.docker.compose.service")
        if labels.get("com.docker.compose.project") != PROJECT or not isinstance(service, str) or service not in policy: raise SystemExit("complete daemon inventory contains a nonproject or extra service container")
        if service in seen_services: raise SystemExit("complete daemon inventory contains a duplicate service container")
        identifier = str(container.get("Id") or ""); name = str(container.get("Name") or "").removeprefix("/"); running = bool((container.get("State") or {}).get("Running"))
        if not SAFE_CONTAINER_ID.fullmatch(identifier) or not SAFE_NAME.fullmatch(name) or identifier in seen_ids or name in seen_names: raise SystemExit("daemon container ID or name is invalid or duplicated")
        seen_services.add(service); seen_ids.add(identifier); seen_names.add(name)
        safe_containers.append({"id": identifier, "name": name, "service": service, "running": running})
        raw_mounts = container.get("Mounts")
        if not isinstance(raw_mounts, list): raise SystemExit("container mount metadata is unavailable")
        observed_mounts: set[tuple[str, str, bool]] = set()
        for mount in raw_mounts:
            source, destination, mount_type = mount.get("Source"), mount.get("Destination"), mount.get("Type")
            read_only = not bool(mount.get("RW", False)); key = (source, destination, read_only)
            anonymous_identity = (service, destination, read_only)
            if mount_type == "volume" and isinstance(source, str) and isinstance(destination, str) and anonymous_identity in ANONYMOUS_VOLUME_ALLOWLIST and ANONYMOUS_VOLUME.fullmatch(source):
                anonymous_name = source.removeprefix(f"{DOCKER_ROOT}/volumes/").removesuffix("/_data")
                if mount.get("Name") != anonymous_name or anonymous_identity in observed_anonymous:
                    raise SystemExit(f"anonymous volume identity is invalid or duplicated: {name}")
                observed_anonymous.add(anonymous_identity)
                mounts.append({"container": name, "service": service, "kind": "anonymous-volume", "source": source, "destination": destination, "readOnly": read_only, "logicalName": None})
                continue
            if mount_type == "tmpfs" and source == "" and isinstance(destination, str) and anonymous_identity in RUNTIME_TMPFS_ALLOWLIST:
                if anonymous_identity in observed_tmpfs:
                    raise SystemExit(f"runtime tmpfs identity is duplicated: {name}")
                observed_tmpfs.add(anonymous_identity)
                mounts.append({"container": name, "service": service, "kind": "runtime-tmpfs", "source": "", "destination": destination, "readOnly": read_only, "logicalName": None})
                continue
            if mount_type not in {"bind", "volume"} or not isinstance(source, str) or not isinstance(destination, str) or key not in policy[service]:
                raise SystemExit(f"unexpected project container mount: {name}")
            if key in observed_mounts: raise SystemExit(f"duplicate project container mount: {name}")
            observed_mounts.add(key)
            logical = policy[service][key]
            if mount_type == "volume" and (mount.get("Name") != f"{PROJECT}_{logical}" or source != volume_source(f"{PROJECT}_{logical}")):
                raise SystemExit(f"anonymous, nested, or mislabeled project volume mount: {name}")
            mounts.append({"container": name, "service": service, "kind": mount_type, "source": source, "destination": destination, "readOnly": read_only, "logicalName": logical or None})
        if observed_mounts != set(policy[service]): raise SystemExit(f"project container has missing desired mounts: {name}")
    if seen_services != expected_services: raise SystemExit("complete daemon inventory has missing or extra desired services")
    if observed_anonymous != ANONYMOUS_VOLUME_ALLOWLIST:
        raise SystemExit("complete daemon inventory has missing or extra allowlisted anonymous volumes")
    if observed_tmpfs != RUNTIME_TMPFS_ALLOWLIST:
        raise SystemExit("complete daemon inventory has missing or extra allowlisted runtime tmpfs mounts")
    safe_containers.sort(key=lambda item: (item["service"], item["name"])); mounts.sort(key=lambda item: json.dumps(item, sort_keys=True))
    running = {item["name"] for item in safe_containers if item["running"]}
    writers = [item for item in mounts if item["kind"] != "runtime-tmpfs" and item["container"] in running and not item["readOnly"]]
    return safe_containers, writers, mounts


def stream_sha256(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as archive:
        while chunk := archive.read(HASH_CHUNK_BYTES): checksum.update(chunk)
    return checksum.hexdigest()


def backup_evidence(findmnt_command: str, fixture_root: Path | None, collected_at: dt.datetime, max_age: int) -> dict[str, object]:
    replicas = []
    for logical in BACKUP_PATHS:
        directory = require_plain_directory(logical, fixture_root)
        archives = sorted((entry for entry in directory.iterdir() if entry.is_file() and not entry.is_symlink() and ARCHIVE_NAME.fullmatch(entry.name)), key=lambda entry: entry.name)
        if not archives: raise SystemExit(f"no canonical encrypted backup archive exists in {logical}")
        archive = archives[-1]; sidecar = directory / f"{archive.name}.sha256"
        if sidecar.is_symlink() or not sidecar.is_file(): raise SystemExit(f"backup checksum sidecar is missing in {logical}")
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)\n?", sidecar.read_text(encoding="ascii"))
        if match is None or match.group(2) != archive.name: raise SystemExit(f"backup sidecar name/checksum syntax differs in {logical}")
        archive_stat = archive.stat(follow_symlinks=False); mtime = dt.datetime.fromtimestamp(archive_stat.st_mtime, dt.UTC).replace(microsecond=0)
        if archive_stat.st_size < 1 or not 0 <= (collected_at - mtime).total_seconds() <= max_age: raise SystemExit(f"backup archive is stale or from the future in {logical}")
        archive_sha256 = stream_sha256(archive)
        if archive_sha256 != match.group(1): raise SystemExit(f"backup archive bytes do not match the checksum sidecar in {logical}")
        replicas.append({"path": logical, "archiveName": archive.name, "sidecarName": sidecar.name, "sha256": archive_sha256, "sizeBytes": archive_stat.st_size, "mtime": mtime.strftime("%Y-%m-%dT%H:%M:%SZ"), "mount": mount_identity(findmnt_command, logical, directory, include_uuid=True)})
    identities = {("uuid", item["mount"]["filesystemUuid"].lower()) if item["mount"]["filesystemUuid"] is not None else ("device", item["mount"]["device"]) for item in replicas}
    if len(identities) != 3 or len({(item["archiveName"], item["sha256"], item["sizeBytes"]) for item in replicas}) != 1:
        raise SystemExit("backup replicas must match and reside on three distinct underlying filesystem/device identities")
    return {"maxAgeSeconds": max_age, "replicas": replicas}


def protected_output(root: Path, name: str, data: bytes) -> None:
    if not root.is_absolute() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.json", name): raise SystemExit("output root/name is invalid")
    try: root_stat = root.stat(follow_symlinks=False)
    except FileNotFoundError as error: raise SystemExit("dedicated output root must already exist") from error
    if root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.geteuid() or stat.S_IMODE(root_stat.st_mode) & 0o077:
        raise SystemExit("output root must be an owned, non-symlink directory inaccessible to group/other")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current.is_symlink(): raise SystemExit("output root has a symlink path component")
    resolved = root.resolve(strict=True)
    forbidden = (Path(DOCKER_ROOT), Path(DESTINATION_ROOT), Path("/home/docker/hass"), *(Path(path) for path in BACKUP_PATHS))
    if any(resolved == path or path in resolved.parents or resolved in path.parents for path in forbidden): raise SystemExit("output root overlaps migration or backup data")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    directory_fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.fsync(directory_fd)
    finally: os.close(directory_fd)


def load_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict): raise SystemExit(f"{label} must be a JSON object")
    return value


def parse_args() -> object:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--desired-inventory", required=True, type=Path); parser.add_argument("--expected-desired-inventory-sha256", required=True)
    parser.add_argument("--runtime-inventory", required=True, type=Path)
    parser.add_argument("--candidate-inventory", required=True, type=Path); parser.add_argument("--expected-candidate-inventory-sha256", required=True)
    parser.add_argument("--canonical-toplevel", required=True); parser.add_argument("--output-root", required=True, type=Path); parser.add_argument("--output-name", required=True)
    parser.add_argument("--backup-max-age-seconds", required=True, type=int); parser.add_argument("--collected-at")
    parser.add_argument("--fixture-root", type=Path)
    for command in LIVE_COMMANDS: parser.add_argument(f"--{command}-command")
    return parser.parse_args()


def main() -> None:
    args = parse_args(); os.umask(0o077)
    overrides = {key: getattr(args, f"{key}_command") for key in LIVE_COMMANDS}
    if args.fixture_root is None:
        if os.geteuid() != 0: raise SystemExit("Gate C collection must run as root")
        if any(overrides.values()): raise SystemExit("live mode forbids command overrides")
        commands = LIVE_COMMANDS; fixture_root = None
    else:
        if not all(overrides.values()): raise SystemExit("fixture mode requires every explicit fixture command")
        commands = overrides; fixture_root = args.fixture_root.resolve(strict=True)
    raw_desired = load_object(args.desired_inventory, "desired inventory"); desired = project_desired_inventory(raw_desired)
    expected = expected_volume_names(desired); runtime = project_runtime_inventory(load_object(args.runtime_inventory, "runtime inventory"), expected)
    qualification = load_object(args.candidate_inventory, "candidate inventory"); validate_candidate_inventory(qualification, desired, args.canonical_toplevel)
    if digest(desired) != args.expected_desired_inventory_sha256: raise SystemExit("independently expected desired inventory digest differs")
    if digest(qualification) != args.expected_candidate_inventory_sha256: raise SystemExit("expected candidate inventory digest differs")
    info = run_json(commands["docker"], ["info", "--format", "{{json .}}"])
    if not isinstance(info, dict) or info.get("DockerRootDir") != DOCKER_ROOT: raise SystemExit("Docker root differs from /var/lib/docker")
    listed = run_json_lines(commands["docker"], ["volume", "ls", "--filter", f"label=com.docker.compose.project={PROJECT}", "--format", "{{json .}}"])
    expected_engines = sorted(f"{PROJECT}_{name}" for name in expected)
    if sorted(str(item.get("Name")) for item in listed) != expected_engines: raise SystemExit("unexpected, anonymous, or missing project volume detected")
    destination_path = require_plain_directory(DESTINATION_ROOT, fixture_root); destination_mount = mount_identity(commands["findmnt"], DESTINATION_ROOT, destination_path)
    if destination_mount["filesystem"] in {"tmpfs", "devtmpfs", "overlay"}: raise SystemExit("candidate destination is not a block filesystem")
    filesystem_stat = os.statvfs(destination_path); capacity = filesystem_stat.f_frsize * filesystem_stat.f_blocks; available = filesystem_stat.f_frsize * filesystem_stat.f_bavail
    if available <= RESERVE_BYTES: raise SystemExit("candidate free space does not exceed reserve")
    physical_by_id = physical_path(CANDIDATE_BY_ID, fixture_root)
    try: resolved_disk = physical_by_id.resolve(strict=True)
    except FileNotFoundError as error: raise SystemExit("exact candidate by-id path is missing") from error
    disk, device_ancestry = verify_candidate_device(commands["lsblk"], resolved_disk, str(destination_mount["device"]))
    qualified = {value["logicalName"]: value for value in qualification["volumes"]}; entries = []; hardlinks_by_root = []
    for logical_name in expected:
        engine = f"{PROJECT}_{logical_name}"; inspected = run_json(commands["docker"], ["volume", "inspect", engine])
        if not isinstance(inspected, list) or len(inspected) != 1: raise SystemExit(f"Docker volume inspection is ambiguous: {engine}")
        volume = inspected[0]; labels = volume.get("Labels") or {}; options = volume.get("Options") or {}
        if not isinstance(labels, dict) or not set(labels).issubset(SAFE_VOLUME_LABELS) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()) or labels.get("com.docker.compose.project") != PROJECT or labels.get("com.docker.compose.volume") != logical_name:
            raise SystemExit(f"source Docker volume labels differ: {engine}")
        source = volume_source(engine); destination = volume_destination(engine)
        if volume.get("Name") != engine or volume.get("Mountpoint") != source or volume.get("Driver") != "local" or options != {}: raise SystemExit(f"source Docker volume identity differs: {engine}")
        source_path = require_plain_directory(source, fixture_root); destination_entry_path = require_plain_directory(destination, fixture_root)
        if mount_identity(commands["findmnt"], destination, destination_entry_path) != destination_mount: raise SystemExit(f"destination root is on a nested/different mount: {destination}")
        q = qualified[logical_name]
        entry, hardlinks = copy_metadata(kind="docker-volume", logical_name=logical_name, engine_name=engine, legacy=logical_name in LEGACY_VOLUMES, source=source, destination=destination, source_path=source_path, source_mount=mount_identity(commands["findmnt"], source, source_path), destination_mount=destination_mount, driver=q["driver"], options=q["options"], labels=q["composeLabels"], candidate_created_at=q["createdAt"])
        entries.append(entry); hardlinks_by_root.append((source, hardlinks))
    hass_source = "/home/docker/hass"; hass_path = require_plain_directory(hass_source, fixture_root); hass_destination_path = require_plain_directory(host_destination(), fixture_root)
    if mount_identity(commands["findmnt"], host_destination(), hass_destination_path) != destination_mount: raise SystemExit("Home Assistant destination is on a nested/different mount")
    hass, links = copy_metadata(kind="host-path", logical_name=None, engine_name=None, legacy=False, source=hass_source, destination=host_destination(), source_path=hass_path, source_mount=mount_identity(commands["findmnt"], hass_source, hass_path), destination_mount=destination_mount, driver=None, options={}, labels={}, candidate_created_at=None)
    entries.append(hass); hardlinks_by_root.append((hass_source, links)); reject_cross_root_hardlinks(hardlinks_by_root)
    listed_ids = run_json_lines(commands["docker"], ["ps", "--all", "--format", "{{json .}}"])
    ids = [str(item.get("ID")) for item in listed_ids]
    if any(not SAFE_CONTAINER_ID.fullmatch(value) for value in ids) or len(ids) != len(set(ids)): raise SystemExit("Docker returned an invalid or duplicate container ID")
    containers = run_json(commands["docker"], ["inspect", "--", *ids]) if ids else []
    if not isinstance(containers, list) or len(containers) != len(ids): raise SystemExit("Docker container inspection is incomplete")
    inspected_ids = [str(item.get("Id") or "") for item in containers if isinstance(item, dict)]
    if any(not any(full == requested or full.startswith(requested) for full in inspected_ids) for requested in ids) or len(set(inspected_ids)) != len(ids): raise SystemExit("Docker inspected container identities differ from the requested project set")
    safe_containers, writers, mounts = safe_container_metadata(containers, desired)
    timers_raw = run_json(commands["systemctl"], ["list-timers", "--all", "--output=json"])
    if not isinstance(timers_raw, list): raise SystemExit("systemd timer metadata is invalid")
    timers = []
    for timer in timers_raw:
        if not isinstance(timer, dict) or not isinstance(timer.get("unit"), str) or not isinstance(timer.get("activates"), str) or not SAFE_NAME.fullmatch(timer["unit"]) or not SAFE_NAME.fullmatch(timer["activates"]): raise SystemExit("systemd timer names are unsafe")
        timers.append({"unit": timer["unit"], "activates": timer["activates"]})
    timers.sort(key=lambda item: item["unit"])
    timestamp = args.collected_at or dt.datetime.now(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    try: collected = dt.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError as error: raise SystemExit("collection timestamp must be canonical UTC seconds") from error
    backups = backup_evidence(commands["findmnt"], fixture_root, collected, args.backup_max_age_seconds)
    candidate = {"wholeDiskById": CANDIDATE_BY_ID, "wholeDiskDevice": device_ancestry[0], "deviceAncestry": device_ancestry, "serial": CANDIDATE_SERIAL, "sizeBytes": DISK_BYTES, "destinationRoot": DESTINATION_ROOT, "device": str(destination_mount["device"]), "filesystem": str(destination_mount["filesystem"]), "mountTarget": DESTINATION_ROOT, "mountId": int(destination_mount["mountId"]), "capacityBytes": capacity, "availableBytes": available, "reserveBytes": RESERVE_BYTES}
    collection = {"format": COLLECTION_FORMAT, "collectedAt": timestamp, "desiredInventorySha256": digest(desired), "runtimeInventorySha256": digest(runtime), "candidateInventorySha256": digest(qualification), "sourceDockerRoot": DOCKER_ROOT, "candidateQualification": qualification, "candidate": candidate, "copyEntries": entries, "backupEvidence": backups, "operationalMetadata": {"containers": safe_containers, "writers": writers, "timers": timers, "mounts": mounts}}
    validate_collection(collection, desired, runtime, expected_desired_sha256=args.expected_desired_inventory_sha256, expected_candidate_sha256=args.expected_candidate_inventory_sha256, expected_toplevel=args.canonical_toplevel)
    protected_output(args.output_root, args.output_name, json.dumps(collection, sort_keys=True, separators=(",", ":")).encode() + b"\n")


if __name__ == "__main__": main()
