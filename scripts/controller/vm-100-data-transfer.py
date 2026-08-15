#!/usr/bin/env python3
"""Execute manifest-bound VM 100 data transfer phases (precopy only)."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

from argparse import ArgumentParser
import datetime as dt
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any

from vm_100_execution import (
    SAFE_JSON_NAME, TRANSFER_LOCK_PATH, acquire_transfer_lock, bounded_error, create_run_root,
    file_metrics, load_canonical_object, open_exclusive, require_directory, require_private_root,
    root_metadata, sha256_bytes, verify_exact_checkout, write_json,
)
from vm_100_gate_c import (
    BACKUP_PATHS, CANDIDATE_BY_ID, CANDIDATE_SERIAL, DESTINATION_ROOT, DISK_BYTES,
    DOCKER_ROOT, ISOLATED_DOCKER_ARGV, digest, parse_time, validate_manifest,
)

FORMAT = "home-lab-vm-100-data-transfer-evidence-v1"
LIVE_RSYNC = "/usr/bin/rsync"
LIVE_FINDMNT = "/usr/bin/findmnt"
LIVE_LSBLK = "/usr/bin/lsblk"
LIVE_GIT = "/usr/bin/git"
LIVE_NODE = "/usr/bin/node"
LOCK_PATH = TRANSFER_LOCK_PATH
CLOSED_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CONTAINERD_ARGV_SHA256 = "22959ff226c38df99d4ecea5af7229b8c70a7649c47725ac66213116f98b3bce"


def run_json(command: str, argv: list[str]) -> Any:
    result = subprocess.run([command, *argv], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLOSED_ENV)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"command returned invalid JSON: {command}") from error


def mount_identity(findmnt: str, logical: str, physical: Path) -> dict[str, object]:
    value = run_json(findmnt, ["--json", "--target", str(physical), "--output", "ID,SOURCE,FSTYPE,TARGET"])
    filesystems = value.get("filesystems") if isinstance(value, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise SystemExit(f"mount identity is ambiguous for {logical}")
    item = filesystems[0]
    try:
        result = {"device": str(item["source"]), "filesystem": str(item["fstype"]), "mountTarget": str(item["target"]), "mountId": int(item["id"])}
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit(f"mount identity is incomplete for {logical}") from error
    if result["mountId"] < 1:
        raise SystemExit(f"mount identity is invalid for {logical}")
    return result


def _mount_items(items: list[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise SystemExit("recursive mount listing is malformed")
        result.append(item)
        children = item.get("children", [])
        if not isinstance(children, list):
            raise SystemExit("recursive mount listing is malformed")
        result.extend(_mount_items(children))
    return result


def reject_nested_mounts(findmnt: str, logical: str, physical: Path) -> None:
    value = run_json(findmnt, ["--json", "--submounts", "--target", str(physical), "--output", "ID,SOURCE,FSTYPE,TARGET"])
    filesystems = value.get("filesystems") if isinstance(value, dict) else None
    if not isinstance(filesystems, list) or not filesystems:
        raise SystemExit(f"recursive mount listing is empty for {logical}")
    roots = _mount_items(filesystems)
    physical_text = str(physical).rstrip("/") or "/"
    nested = []
    for item in roots:
        target = item.get("target")
        if not isinstance(target, str):
            raise SystemExit("recursive mount listing has no target")
        target_text = target.rstrip("/") or "/"
        if target_text != physical_text and target_text.startswith(physical_text + "/"):
            nested.append(target)
    if nested:
        raise SystemExit(f"nested mount exists below {logical}: {nested[0]}")


def verify_candidate_ancestry(lsblk: str, fixture_root: Path | None, expected: dict[str, object]) -> list[str]:
    by_id = Path(CANDIDATE_BY_ID) if fixture_root is None else fixture_root / CANDIDATE_BY_ID.removeprefix("/")
    try:
        resolved = by_id.resolve(strict=True)
    except FileNotFoundError as error:
        raise SystemExit("exact candidate by-id is missing") from error
    value = run_json(lsblk, ["--tree", "--json", "--bytes", "--output", "PATH,SERIAL,SIZE,TYPE", str(resolved)])
    devices = value.get("blockdevices") if isinstance(value, dict) else None
    if not isinstance(devices, list) or len(devices) != 1:
        raise SystemExit("candidate disk identity is ambiguous")
    root = devices[0]
    if root.get("path") != expected.get("wholeDiskDevice") or root.get("serial") != CANDIDATE_SERIAL or int(root.get("size", -1)) != DISK_BYTES or root.get("type") != "disk":
        raise SystemExit("candidate whole-disk identity changed")
    target = expected.get("device")
    def chain(node: dict[str, Any], parents: list[str]) -> list[str] | None:
        path = node.get("path")
        if not isinstance(path, str):
            raise SystemExit("candidate device ancestry is malformed")
        current = [*parents, path]
        if path == target:
            return current
        children = node.get("children", [])
        if not isinstance(children, list):
            raise SystemExit("candidate device ancestry is malformed")
        for child in children:
            if not isinstance(child, dict):
                raise SystemExit("candidate device ancestry is malformed")
            found = chain(child, current)
            if found:
                return found
        return None
    observed = chain(root, [])
    if observed != expected.get("deviceAncestry"):
        raise SystemExit("candidate device ancestry changed")
    return observed


def observe_entry(entry: dict[str, Any], commands: dict[str, str], fixture_root: Path | None, candidate: dict[str, Any], *, after: bool = False, before: dict[str, object] | None = None) -> dict[str, object]:
    source = require_directory(entry["source"], fixture_root)
    destination = require_directory(entry["destination"], fixture_root)
    reject_nested_mounts(commands["findmnt"], entry["source"], source)
    reject_nested_mounts(commands["findmnt"], entry["destination"], destination)
    source_mount = mount_identity(commands["findmnt"], entry["source"], source)
    destination_mount = mount_identity(commands["findmnt"], entry["destination"], destination)
    if source_mount != entry["sourceMount"]:
        raise SystemExit(f"source mount identity changed: {entry['source']}")
    expected_destination = {key: candidate[key] for key in ("device", "filesystem", "mountTarget", "mountId")}
    if destination_mount != entry["destinationMount"] or destination_mount != expected_destination:
        raise SystemExit(f"destination mount identity changed: {entry['destination']}")
    if entry["permittedDeletionRoot"] != entry["destination"]:
        raise SystemExit("manifest deletion root differs from destination")
    source_root, destination_root = root_metadata(source), root_metadata(destination)
    expected_source = {"uid": entry["uid"], "gid": entry["gid"], "mode": entry["mode"]}
    if any(source_root[key] != value for key, value in expected_source.items()):
        raise SystemExit(f"source root metadata changed: {entry['source']}")
    if after:
        if before is None:
            raise SystemExit("post-write observation lacks its before observation")
        old_source, old_destination = before["sourceRoot"], before["destinationRoot"]
        if not isinstance(old_source, dict) or any(source_root[key] != old_source[key] for key in ("device", "inode")):
            raise SystemExit(f"source root identity changed: {entry['source']}")
        if not isinstance(old_destination, dict) or any(destination_root[key] != old_destination[key] for key in ("device", "inode")):
            raise SystemExit(f"destination root identity changed: {entry['destination']}")
        if any(destination_root[key] != value for key, value in expected_source.items()):
            raise SystemExit(f"destination root metadata differs after rsync: {entry['destination']}")
    return {"sourceMount": source_mount, "destinationMount": destination_mount, "sourceRoot": source_root, "destinationRoot": destination_root}


def candidate_root(manifest: dict[str, Any], commands: dict[str, str], fixture_root: Path | None) -> tuple[Path, dict[str, object]]:
    candidate = manifest["candidate"]
    root = require_directory(DESTINATION_ROOT, fixture_root)
    identity = mount_identity(commands["findmnt"], DESTINATION_ROOT, root)
    expected = {key: candidate[key] for key in ("device", "filesystem", "mountTarget", "mountId")}
    if identity != expected:
        raise SystemExit("candidate root mount identity changed")
    ancestry = verify_candidate_ancestry(commands["lsblk"], fixture_root, candidate)
    filesystem = os.statvfs(root)
    capacity = filesystem.f_frsize * filesystem.f_blocks
    if capacity != candidate["capacityBytes"]:
        raise SystemExit("candidate filesystem capacity changed")
    return root, {"capacityBytes": capacity, "reserveBytes": candidate["reserveBytes"], "mount": identity, "deviceAncestry": ancestry}


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode): return "regular"
    if stat.S_ISDIR(mode): return "directory"
    if stat.S_ISLNK(mode): return "symlink"
    return "other"


def _rounded(value: int, block_size: int) -> int:
    return ((max(value, 1) + block_size - 1) // block_size) * block_size


def _open_directory_nofollow(path: Path) -> int:
    if not path.is_absolute():
        raise SystemExit("capacity traversal root must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def root_write_requirement(source: Path, destination: Path, block_size: int | None = None) -> dict[str, int]:
    """Stream source paths and compare destinations with descriptor-relative no-follow I/O."""
    required_bytes = required_inodes = 0
    open_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_root_fd = _open_directory_nofollow(source)
    try:
        destination_root_fd = _open_directory_nofollow(destination)
    except BaseException:
        os.close(source_root_fd)
        raise
    destination_vfs = os.fstatvfs(destination_root_fd)
    observed_unit = destination_vfs.f_frsize if destination_vfs.f_frsize >= 512 else destination_vfs.f_bsize
    unit = block_size or max(observed_unit, 4096)
    # Reserve one destination allocation unit for root ACL/xattr metadata even
    # when file content is unchanged.
    required_bytes += unit
    try:
        def visit(source_fd: int, destination_fd: int | None, depth: int) -> None:
            nonlocal required_bytes, required_inodes
            if depth > 1024:
                raise SystemExit("copy tree exceeds the bounded traversal depth")
            with os.scandir(source_fd) as children:
                for child in children:
                    name = child.name
                    source_value = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                    source_kind = _kind(source_value.st_mode)
                    # -A/-X can allocate ACL/xattr metadata independently of
                    # content quick-checks, so reserve one unit per source path.
                    required_bytes += unit
                    if source_kind == "regular":
                        source_file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_fd)
                        try:
                            source_value = os.fstat(source_file_fd)
                        finally:
                            os.close(source_file_fd)
                    destination_value = None
                    if destination_fd is not None:
                        try:
                            destination_value = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            destination_value = None
                    destination_kind = _kind(destination_value.st_mode) if destination_value is not None else None
                    if destination_fd is not None and destination_kind == "regular":
                        try:
                            destination_file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=destination_fd)
                            try:
                                destination_value = os.fstat(destination_file_fd)
                            finally:
                                os.close(destination_file_fd)
                        except (FileNotFoundError, OSError):
                            destination_value = None
                            destination_kind = None
                    if source_kind == "regular":
                        unchanged = destination_value is not None and destination_kind == "regular" and destination_value.st_size == source_value.st_size and destination_value.st_mtime_ns == source_value.st_mtime_ns
                        if not unchanged:
                            source_allocated = source_value.st_blocks * 512
                            required_bytes += max(_rounded(source_value.st_size, unit), source_allocated)
                            required_inodes += 1
                    elif source_kind == "symlink":
                        source_target = os.readlink(name, dir_fd=source_fd)
                        destination_target = None
                        if destination_fd is not None and destination_kind == "symlink":
                            try:
                                destination_target = os.readlink(name, dir_fd=destination_fd)
                            except OSError:
                                destination_target = None
                        if destination_kind != "symlink" or destination_target != source_target:
                            required_bytes += max(_rounded(source_value.st_size, unit), source_value.st_blocks * 512)
                            required_inodes += 1
                    elif source_kind == "directory":
                        child_destination_fd = None
                        if destination_fd is not None and destination_kind == "directory":
                            try:
                                child_destination_fd = os.open(name, open_flags, dir_fd=destination_fd)
                            except (FileNotFoundError, NotADirectoryError, OSError):
                                child_destination_fd = None
                                # Per-path metadata allocation was reserved above.
                                required_inodes += 1
                        else:
                            # Per-path metadata allocation was reserved above.
                            required_inodes += 1
                        child_source_fd = os.open(name, open_flags, dir_fd=source_fd)
                        try:
                            visit(child_source_fd, child_destination_fd, depth + 1)
                        finally:
                            os.close(child_source_fd)
                            if child_destination_fd is not None:
                                os.close(child_destination_fd)
                    elif destination_kind != source_kind:
                        # Per-path metadata allocation was reserved above.
                        required_inodes += 1
        visit(source_root_fd, destination_root_fd, 0)
    finally:
        os.close(source_root_fd)
        os.close(destination_root_fd)
    return {"requiredWriteBytes": required_bytes, "requiredInodes": required_inodes}


def build_capacity_plan(manifest: dict[str, Any], fixture_root: Path | None) -> dict[int, dict[str, int]]:
    plan: dict[int, dict[str, int]] = {}
    for index, entry in enumerate(manifest["copyEntries"]):
        plan[index] = root_write_requirement(require_directory(entry["source"], fixture_root), require_directory(entry["destination"], fixture_root))
    return plan


def refresh_capacity_plan(plan: dict[int, dict[str, int]], manifest: dict[str, Any], fixture_root: Path | None, index: int) -> None:
    entry = manifest["copyEntries"][index]
    plan[index] = root_write_requirement(require_directory(entry["source"], fixture_root), require_directory(entry["destination"], fixture_root))


def build_checked_capacity_plan(manifest: dict[str, Any], commands: dict[str, str], fixture_root: Path | None) -> dict[int, dict[str, int]]:
    plan: dict[int, dict[str, int]] = {}
    for index, entry in enumerate(manifest["copyEntries"]):
        # Each recursive traversal is immediately preceded by its own
        # mount/identity check; a global precheck followed by a later scan is
        # not sufficient.
        observe_entry(entry, commands, fixture_root, manifest["candidate"])
        plan[index] = root_write_requirement(
            require_directory(entry["source"], fixture_root),
            require_directory(entry["destination"], fixture_root),
        )
    return plan


def active_capacity_observation(manifest: dict[str, Any], commands: dict[str, str], fixture_root: Path | None, plan: dict[int, dict[str, int]], index: int) -> tuple[dict[str, object], dict[str, int]]:
    entry = manifest["copyEntries"][index]
    before = observe_entry(entry, commands, fixture_root, manifest["candidate"])
    refresh_capacity_plan(plan, manifest, fixture_root, index)
    return before, capacity_check(manifest, commands, fixture_root, plan)


def capacity_check(manifest: dict[str, Any], commands: dict[str, str], fixture_root: Path | None, plan: dict[int, dict[str, int]]) -> dict[str, int]:
    root, _ = candidate_root(manifest, commands, fixture_root)
    filesystem = os.statvfs(root)
    available_bytes = filesystem.f_frsize * filesystem.f_bavail
    available_inodes = filesystem.f_favail
    required_bytes = sum(item["requiredWriteBytes"] for item in plan.values())
    required_inodes = sum(item["requiredInodes"] for item in plan.values())
    reserve = manifest["candidate"]["reserveBytes"]
    if available_bytes < reserve + required_bytes or available_inodes < required_inodes:
        raise SystemExit("candidate byte or inode capacity is insufficient for delayed-delete writes")
    return {"availableBytes": available_bytes, "availableInodes": available_inodes, "reserveBytes": reserve, "requiredWriteBytes": required_bytes, "requiredInodes": required_inodes}


def verify_rsync(command: str, fixture: bool) -> str:
    if not fixture and command != LIVE_RSYNC:
        raise SystemExit("live mode requires fixed /usr/bin/rsync")
    value = Path(command).stat(follow_symlinks=False)
    if not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) & 0o022 or not os.access(command, os.X_OK):
        raise SystemExit("rsync executable is missing, writable, or not regular")
    result = subprocess.run([command, "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLOSED_ENV)
    first = result.stdout.splitlines()[0] if result.stdout.splitlines() else ""
    if re.fullmatch(r"rsync  version [0-9]+(?:\.[0-9]+){1,3}  protocol version [0-9]+", first) is None:
        raise SystemExit("rsync version output is unrecognized")
    return first


def verify_git(git: str, expected_commit: str) -> None:
    verify_exact_checkout(git, expected_commit, CLOSED_ENV)


def acquire_lock(path: Path) -> int:
    return acquire_transfer_lock(path)


def _fresh(collected_at: object, now: str, max_age: int, label: str) -> None:
    age = (parse_time(now, "current time") - parse_time(collected_at, label)).total_seconds()
    if age < 0 or age > max_age:
        raise SystemExit(f"{label} is stale or from the future")


def validate_external_evidence(kind: str, path: Path, expected_sha: str, manifest: dict[str, Any], args: Any, node: str) -> dict[str, object]:
    value, raw = load_canonical_object(path, kind)
    binding_names = {
        "isolated-restore": "isolatedRestoreEvidenceSha256",
        "candidate-daemon-stop": "candidateDaemonStopEvidenceSha256",
        "source-daemon-stability": "sourceDaemonStabilityEvidenceSha256",
    }
    if not SHA256.fullmatch(expected_sha) or sha256_bytes(raw) != expected_sha or manifest["bindings"][binding_names[kind]] != expected_sha:
        raise SystemExit(f"{kind} exact file SHA-256 binding differs")
    validator = Path(__file__).resolve().with_name("validate-vm-100-execution-schema.js")
    subprocess.run([node, str(validator), kind, str(path)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLOSED_ENV)
    _fresh(value.get("completedAt", value.get("collectedAt")), args.now, args.collection_max_age_seconds, kind)
    if kind == "candidate-daemon-stop":
        if value.get("result") != "passed" or value.get("failureStage") is not None or value.get("failureReason") is not None or value.get("candidateInventorySha256") != manifest["bindings"]["candidateInventorySha256"] or value.get("isolatedDockerArgvSha256") != digest(list(ISOLATED_DOCKER_ARGV)) or value.get("containerdArgvSha256") != CONTAINERD_ARGV_SHA256 or value.get("socketAbsent") is not True or value.get("runtimeFilesRemoved") is not True:
            raise SystemExit("candidate daemon stop evidence semantics differ")
        for child in ("dockerd", "containerd"):
            if not isinstance(value.get(child), dict) or value[child].get("started") is not True or value[child].get("pidGone") is not True or value[child].get("observationError") is not None:
                raise SystemExit("candidate daemon stop evidence does not prove child lifecycle and absence")
    elif kind == "source-daemon-stability":
        if value.get("result") != "passed" or value.get("failureStage") is not None or value.get("failureReason") is not None or value.get("observationError") is not None or value.get("exactEquality") is not True or value.get("beforeInventorySha256") != value.get("afterInventorySha256") or value.get("desiredInventorySha256") != manifest["bindings"]["desiredInventorySha256"] or value.get("containerCount") != 41 or value.get("runningCount") != 41 or value.get("sourceDockerRoot") != DOCKER_ROOT:
            raise SystemExit("source daemon stability evidence semantics differ")
    else:
        replicas = manifest["backupEvidence"]["replicas"]
        backup = value.get("backupArchive")
        expected_backup = {key: replicas[0][key] for key in ("archiveName", "sha256", "sizeBytes")}
        restore = value.get("restore")
        target = value.get("isolatedTarget")
        protected_roots = [DOCKER_ROOT, DESTINATION_ROOT, "/home/docker/hass", *BACKUP_PATHS]
        protected_roots.extend(entry[key] for entry in manifest["copyEntries"] for key in ("source", "destination"))
        target_path = PurePosixPath(target.get("path", "")) if isinstance(target, dict) else PurePosixPath(".")
        overlap = not target_path.is_absolute() or ".." in target_path.parts or any(target_path == PurePosixPath(root) or PurePosixPath(root) in target_path.parents or target_path in PurePosixPath(root).parents for root in protected_roots)
        if not SHA256.fullmatch(args.expected_restore_verifier_sha256) or value.get("verifierSha256") != args.expected_restore_verifier_sha256 or value.get("result") != "passed" or backup != expected_backup or not isinstance(target, dict) or target.get("independentEnvironment") is not True or target.get("productionFilesystemsMounted") is not False or target.get("emptyBefore") is not True or target.get("removedAfter") is not True or overlap or not isinstance(restore, dict) or restore.get("result") != "passed" or any(not isinstance(restore.get(key), int) or restore[key] < 1 for key in ("memberCount", "fileCount", "byteCount")):
            raise SystemExit("isolated restore evidence semantics differ")
    return value


def validate_evidence(value: dict[str, object], manifest: dict[str, Any] | None = None, expected_manifest_sha256: str | None = None) -> None:
    required = {"format", "phase", "startedAt", "completedAt", "status", "failureStage", "failureReason", "manifestSha256", "bindingsSha256", "rsyncVersion", "candidateBefore", "candidateAfter", "candidateObservationError", "entries"}
    if set(value) != required or value.get("format") != FORMAT or value.get("phase") != "precopy" or value.get("status") not in {"succeeded", "failed"}:
        raise ValueError("data transfer evidence envelope differs")
    entries = value.get("entries")
    if not isinstance(entries, list) or len(entries) > 34:
        raise ValueError("data transfer entry evidence differs")
    keys = {"index", "logicalName", "source", "destination", "writeArgvSha256", "startedAt", "completedAt", "exitCode", "stdout", "stderr", "before", "after", "observationError", "capacityBefore", "status"}
    for index, item in enumerate(entries):
        if not isinstance(item, dict) or set(item) != keys or item.get("index") != index or item.get("status") not in {"succeeded", "failed"}:
            raise ValueError("data transfer entry evidence differs")
        capacity = item.get("capacityBefore")
        if capacity is not None:
            capacity_keys = {"availableBytes", "availableInodes", "reserveBytes", "requiredWriteBytes", "requiredInodes"}
            if not isinstance(capacity, dict) or set(capacity) != capacity_keys or any(not isinstance(capacity[key], int) or capacity[key] < 0 for key in capacity_keys) or capacity["reserveBytes"] < 1 or capacity["availableBytes"] < capacity["reserveBytes"] + capacity["requiredWriteBytes"] or capacity["availableInodes"] < capacity["requiredInodes"]:
                raise ValueError("data transfer capacity evidence is incoherent")
        if item["status"] == "failed" and item.get("exitCode") == 0 and item.get("before") is not None and item.get("after") is not None and item.get("observationError") is None:
            raise ValueError("failed entry evidence is success-shaped")
    if manifest is not None:
        if expected_manifest_sha256 is not None and value["manifestSha256"] != expected_manifest_sha256:
            raise ValueError("transfer evidence manifest hash differs")
        if value["bindingsSha256"] != digest(manifest["bindings"]):
            raise ValueError("transfer evidence bindings hash differs")
        for index, item in enumerate(entries):
            expected = manifest["copyEntries"][index]
            if item["logicalName"] != expected["logicalName"] or item["source"] != expected["source"] or item["destination"] != expected["destination"] or item["writeArgvSha256"] != digest([LIVE_RSYNC, *expected["writeArgv"][1:]]):
                raise ValueError(f"transfer entry {index} does not match its manifest")
    succeeded = value["status"] == "succeeded"
    if succeeded:
        if value["failureStage"] is not None or value["failureReason"] is not None or value["candidateBefore"] is None or value["candidateAfter"] != value["candidateBefore"] or value["candidateObservationError"] is not None or len(entries) != 34:
            raise ValueError("successful transfer evidence has incomplete observations")
        if any(item["status"] != "succeeded" or item["exitCode"] != 0 or item["stdout"] is None or item["stderr"] is None or item["before"] is None or item["after"] is None or item["observationError"] is not None or item["capacityBefore"] is None for item in entries):
            raise ValueError("successful transfer evidence has a failed entry")
        if manifest is not None:
            candidate = manifest["candidate"]
            expected_candidate = {"capacityBytes": candidate["capacityBytes"], "reserveBytes": candidate["reserveBytes"], "mount": {key: candidate[key] for key in ("device", "filesystem", "mountTarget", "mountId")}, "deviceAncestry": candidate["deviceAncestry"]}
            if value["candidateBefore"] != expected_candidate or value["candidateAfter"] != expected_candidate:
                raise ValueError("transfer evidence candidate identity differs")
            for index, (item, expected) in enumerate(zip(entries, manifest["copyEntries"])):
                if item["index"] != index or item["capacityBefore"]["reserveBytes"] != candidate["reserveBytes"]:
                    raise ValueError(f"successful transfer entry {index} does not match its manifest")
                before, after = item["before"], item["after"]
                expected_source_metadata = {key: expected[key] for key in ("uid", "gid", "mode")}
                if any(before["sourceRoot"][key] != expected_source_metadata[key] or after["sourceRoot"][key] != expected_source_metadata[key] or after["destinationRoot"][key] != expected_source_metadata[key] for key in expected_source_metadata):
                    raise ValueError(f"successful transfer entry {index} has incorrect root metadata")
                if any(before[root][key] != after[root][key] for root in ("sourceRoot", "destinationRoot") for key in ("device", "inode")):
                    raise ValueError(f"successful transfer entry {index} has unstable root identity")
                if before["sourceMount"] != expected["sourceMount"] or after["sourceMount"] != expected["sourceMount"] or before["destinationMount"] != expected["destinationMount"] or after["destinationMount"] != expected["destinationMount"]:
                    raise ValueError(f"successful transfer entry {index} has incorrect mount identity")
    elif value["failureStage"] is None or value["failureReason"] is None:
        raise ValueError("failed transfer evidence lacks a bounded reason")


def timestamp() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_args() -> Any:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("precopy",))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-compose-artifact-sha256", required=True)
    parser.add_argument("--expected-canonical-toplevel", required=True)
    parser.add_argument("--expected-desired-inventory-sha256", required=True)
    parser.add_argument("--expected-candidate-inventory-sha256", required=True)
    parser.add_argument("--isolated-restore-evidence", required=True, type=Path)
    parser.add_argument("--candidate-daemon-stop-evidence", required=True, type=Path)
    parser.add_argument("--source-daemon-stability-evidence", required=True, type=Path)
    parser.add_argument("--expected-isolated-restore-evidence-sha256", required=True)
    parser.add_argument("--expected-restore-verifier-sha256", required=True)
    parser.add_argument("--expected-candidate-daemon-stop-evidence-sha256", required=True)
    parser.add_argument("--expected-source-daemon-stability-evidence-sha256", required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--collection-max-age-seconds", required=True, type=int)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--evidence-name", required=True)
    parser.add_argument("--fixture-root", type=Path)
    for name in ("rsync", "findmnt", "lsblk", "git", "node"):
        parser.add_argument(f"--{name}-command")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    os.umask(0o077)
    if args.authority != "arch":
        raise SystemExit("precopy requires independently asserted arch authority")
    overrides = {name: getattr(args, f"{name}_command") for name in ("rsync", "findmnt", "lsblk", "git", "node")}
    if args.fixture_root is None:
        if os.geteuid() != 0:
            raise SystemExit("data transfer must run as root")
        if any(overrides.values()):
            raise SystemExit("live mode forbids executable overrides")
        fixture_root = None
        commands = {"rsync": LIVE_RSYNC, "findmnt": LIVE_FINDMNT, "lsblk": LIVE_LSBLK, "git": LIVE_GIT, "node": LIVE_NODE}
        lock_path = Path(LOCK_PATH)
    else:
        if not all(overrides.values()):
            raise SystemExit("fixture mode requires every explicit executable")
        fixture_root = args.fixture_root.resolve(strict=True)
        commands = overrides
        lock_path = fixture_root / LOCK_PATH.removeprefix("/")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    manifest, raw = load_canonical_object(args.manifest, "Gate C manifest")
    preliminary_entries = manifest.get("copyEntries")
    preliminary_replicas = manifest.get("backupEvidence", {}).get("replicas", []) if isinstance(manifest.get("backupEvidence"), dict) else None
    if not isinstance(preliminary_entries, list) or any(not isinstance(entry, dict) or any(not isinstance(entry.get(key), str) for key in ("source", "destination")) for entry in preliminary_entries) or not isinstance(preliminary_replicas, list) or any(not isinstance(replica, dict) or not isinstance(replica.get("path"), str) for replica in preliminary_replicas):
        raise SystemExit("manifest roots cannot be safely derived")
    roots = [DOCKER_ROOT, "/home/docker/hass", DESTINATION_ROOT, *BACKUP_PATHS]
    roots.extend(entry[key] for entry in preliminary_entries for key in ("source", "destination"))
    roots.extend(replica["path"] for replica in preliminary_replicas)
    physical_roots = tuple(Path(value) if fixture_root is None else fixture_root / value.removeprefix("/") for value in roots)
    output_parent = require_private_root(args.output_root, physical_roots)
    if SAFE_JSON_NAME.fullmatch(args.evidence_name) is None:
        raise SystemExit("data transfer evidence name must be a safe JSON name")
    lock = acquire_transfer_lock(lock_path)
    try:
        output_root = create_run_root(output_parent, "vm-100-transfer")
    except BaseException:
        os.close(lock)
        raise
    started_at = timestamp()
    entries: list[dict[str, object]] = []
    candidate_before: dict[str, object] | None = None
    candidate_after: dict[str, object] | None = None
    candidate_error: str | None = None
    rsync_version: str | None = None
    failure: BaseException | None = None
    failure_stage: str | None = None
    interrupted = False
    try:
        try:
            failure_stage = "manifest-validation"
            if not SHA256.fullmatch(args.expected_manifest_sha256) or sha256_bytes(raw) != args.expected_manifest_sha256:
                raise SystemExit("independently expected manifest SHA-256 differs")
            schema = Path(__file__).resolve().with_name("validate-vm-100-gate-c-schema.js")
            subprocess.run([commands["node"], str(schema), str(args.manifest)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLOSED_ENV)
            validate_manifest(manifest, args.expected_commit, args.expected_compose_artifact_sha256, args.expected_canonical_toplevel, args.expected_desired_inventory_sha256, args.expected_candidate_inventory_sha256, args.now, args.collection_max_age_seconds, args.expected_isolated_restore_evidence_sha256, args.expected_candidate_daemon_stop_evidence_sha256, args.expected_source_daemon_stability_evidence_sha256)
            failure_stage = "authority-validation"
            authority = Path(__file__).resolve().with_name("check-vm-100-authority.js")
            subprocess.run([commands["node"], str(authority), "--require-ordinary-mutation"], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLOSED_ENV)
            verify_git(commands["git"], args.expected_commit)
            failure_stage = "external-evidence-validation"
            validate_external_evidence("isolated-restore", args.isolated_restore_evidence, args.expected_isolated_restore_evidence_sha256, manifest, args, commands["node"])
            validate_external_evidence("candidate-daemon-stop", args.candidate_daemon_stop_evidence, args.expected_candidate_daemon_stop_evidence_sha256, manifest, args, commands["node"])
            validate_external_evidence("source-daemon-stability", args.source_daemon_stability_evidence, args.expected_source_daemon_stability_evidence_sha256, manifest, args, commands["node"])
            rsync_version = verify_rsync(commands["rsync"], fixture_root is not None)
            failure_stage = "candidate-before-observation"
            _, candidate_before = candidate_root(manifest, commands, fixture_root)
            failure_stage = "capacity-plan"
            capacity_plan = build_checked_capacity_plan(manifest, commands, fixture_root)
            for index, entry in enumerate(manifest["copyEntries"]):
                failure_stage = f"entry-{index}-prewrite"
                item: dict[str, object] = {"index": index, "logicalName": entry["logicalName"], "source": entry["source"], "destination": entry["destination"], "writeArgvSha256": digest([LIVE_RSYNC, *entry["writeArgv"][1:]]), "startedAt": timestamp(), "completedAt": timestamp(), "exitCode": None, "stdout": None, "stderr": None, "before": None, "after": None, "observationError": None, "capacityBefore": None, "status": "failed"}
                entries.append(item)
                try:
                    before, item["capacityBefore"] = active_capacity_observation(manifest, commands, fixture_root, capacity_plan, index)
                    item["before"] = before
                except BaseException as error:
                    item["observationError"] = bounded_error(error)
                    item["completedAt"] = timestamp()
                    raise
                run_id = f"{os.getpid()}-{index:02d}-{dt.datetime.now(dt.UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
                stdout_name, stderr_name = f"precopy-{run_id}.stdout.log", f"precopy-{run_id}.stderr.log"
                failure_stage = f"entry-{index}-rsync"
                try:
                    with open_exclusive(output_root, stdout_name) as stdout, open_exclusive(output_root, stderr_name) as stderr:
                        result = subprocess.run([commands["rsync"], *entry["writeArgv"][1:]], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=CLOSED_ENV)
                        stdout.flush(); os.fsync(stdout.fileno()); stderr.flush(); os.fsync(stderr.fileno())
                    item["exitCode"] = result.returncode
                    item["stdout"], item["stderr"] = file_metrics(output_root / stdout_name), file_metrics(output_root / stderr_name)
                    if result.returncode != 0:
                        raise SystemExit(f"rsync exited {result.returncode}")
                    failure_stage = f"entry-{index}-postwrite"
                    item["after"] = observe_entry(entry, commands, fixture_root, manifest["candidate"], after=True, before=before)
                    capacity_plan[index] = {"requiredWriteBytes": 0, "requiredInodes": 0}
                    item["status"] = "succeeded"
                except BaseException as error:
                    if item["stdout"] is None and (output_root / stdout_name).exists(): item["stdout"] = file_metrics(output_root / stdout_name)
                    if item["stderr"] is None and (output_root / stderr_name).exists(): item["stderr"] = file_metrics(output_root / stderr_name)
                    if item["after"] is None and item["observationError"] is None: item["observationError"] = bounded_error(error)
                    raise
                finally:
                    item["completedAt"] = timestamp()
            failure_stage = "candidate-after-observation"
            _, candidate_after = candidate_root(manifest, commands, fixture_root)
            if candidate_after != candidate_before:
                raise SystemExit("candidate root identity changed during transfer")
            failure_stage = None
        except BaseException as error:
            failure = error
            interrupted = isinstance(error, (KeyboardInterrupt, InterruptedError))
            if failure_stage in {"candidate-before-observation", "candidate-after-observation"}:
                candidate_error = bounded_error(error)
        if candidate_before is not None and candidate_after is None:
            try:
                _, candidate_after = candidate_root(manifest, commands, fixture_root)
            except BaseException as error:
                candidate_error = bounded_error(error)
        status = "succeeded" if failure is None and len(entries) == 34 else "failed"
        if status == "failed" and candidate_before is None and candidate_error is None:
            candidate_error = bounded_error(f"candidate observation not attempted because {failure_stage or 'pre-write validation'} failed")
        evidence = {"format": FORMAT, "phase": "precopy", "startedAt": started_at, "completedAt": timestamp(), "status": status, "failureStage": None if status == "succeeded" else failure_stage, "failureReason": None if status == "succeeded" else bounded_error(failure), "manifestSha256": args.expected_manifest_sha256, "bindingsSha256": digest(manifest["bindings"]), "rsyncVersion": rsync_version, "candidateBefore": candidate_before, "candidateAfter": candidate_after, "candidateObservationError": candidate_error, "entries": entries}
        validate_evidence(evidence, manifest, args.expected_manifest_sha256)
        write_json(output_root, args.evidence_name, evidence)
    finally:
        os.close(lock)
    print(f"vm100_run_root={output_root}", file=sys.stderr if failure is not None else sys.stdout)
    print(f"vm100_transfer_evidence={output_root / args.evidence_name}", file=sys.stderr if failure is not None else sys.stdout)
    if failure is not None:
        if interrupted:
            raise failure
        raise SystemExit("precopy failed; canonical failure evidence was written") from failure


if __name__ == "__main__":
    main()
