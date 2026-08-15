#!/usr/bin/env python3
"""Qualify candidate volumes through a target-only Docker daemon on the Arch VM."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

from argparse import ArgumentParser
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

from vm_100_gate_c import (
    CANDIDATE_BY_ID, CANDIDATE_INVENTORY_FORMAT, CANDIDATE_PROFILE,
    CANDIDATE_SERIAL, DESTINATION_ROOT, DISK_BYTES, DOCKER_ROOT,
    GENERATION_LINK, ISOLATED_DOCKER_ARGV, ISOLATED_DOCKER_HOST,
    ISOLATED_DOCKER_PIDFILE, ISOLATED_DOCKER_ROOT, PROJECT, SAFE_VOLUME_LABELS,
    TOPLEVEL, digest, expected_volume_names, project_desired_inventory,
    validate_candidate_inventory, volume_destination, volume_source,
)

LIVE_DOCKER = "/usr/bin/docker"
LIVE_FINDMNT = "/usr/bin/findmnt"
LIVE_LSBLK = "/usr/bin/lsblk"


def run_json(command: str, argv: list[str]) -> Any:
    result = subprocess.run([command, *argv], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try: return json.loads(result.stdout)
    except json.JSONDecodeError as error: raise SystemExit(f"command returned invalid JSON: {command}") from error


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


def docker_json(command: str, argv: list[str]) -> Any:
    return run_json(command, ["--host", ISOLATED_DOCKER_HOST, *argv])


def docker_json_lines(command: str, argv: list[str]) -> list[dict[str, object]]:
    return run_json_lines(command, ["--host", ISOLATED_DOCKER_HOST, *argv])


def docker_text(command: str, argv: list[str]) -> str:
    result = subprocess.run([command, "--host", ISOLATED_DOCKER_HOST, *argv], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout


def require_exact_daemon_volumes(listed: list[dict[str, object]], expected_engines: list[str]) -> None:
    if sorted(str(item.get("Name")) for item in listed) != expected_engines:
        raise SystemExit("isolated candidate daemon volume listing has extra, anonymous, unlabeled, or missing volumes")


def flatten(values: list[object]) -> list[dict[str, Any]]:
    result = []
    for value in values:
        if not isinstance(value, dict) or not isinstance(value.get("children", []), list): raise SystemExit("lsblk returned malformed data")
        result.append(value); result.extend(flatten(value.get("children", [])))
    return result


def verify_candidate_device(lsblk: str, resolved_disk: Path, mount_device: str) -> list[str]:
    if not mount_device.startswith("/dev/") or mount_device.startswith("/dev/disk/by-id/"):
        raise SystemExit("candidate mount source must be a concrete descendant block device")
    tree = run_json(lsblk, ["--json", "--bytes", "--output", "PATH,SERIAL,SIZE,TYPE", str(resolved_disk)])
    roots = tree.get("blockdevices") if isinstance(tree, dict) else None
    if not isinstance(roots, list) or len(roots) != 1: raise SystemExit("candidate disk identity is ambiguous")
    disk = roots[0]
    if disk.get("type") != "disk" or disk.get("serial") != CANDIDATE_SERIAL or int(disk.get("size", -1)) != DISK_BYTES:
        raise SystemExit("candidate whole disk does not have the exact public identity")
    def find_chain(node: dict[str, Any], chain: list[str]) -> list[str] | None:
        path = node.get("path")
        if not isinstance(path, str) or not path.startswith("/dev/"): raise SystemExit("lsblk returned an unsafe device path")
        current = [*chain, path]
        if path == mount_device: return current
        for child in node.get("children", []):
            found = find_chain(child, current)
            if found is not None: return found
        return None
    chain = find_chain(disk, [])
    descendants = flatten(disk.get("children", []))
    matches = [item for item in descendants if item.get("path") == mount_device and item.get("type") in {"part", "crypt", "lvm"}]
    if len(matches) != 1 or chain is None or len(chain) < 2:
        raise SystemExit("candidate mount device is not a descendant filesystem/partition of the exact candidate disk")
    return chain


def normalize_created(value: object) -> str:
    if not isinstance(value, str) or len(value) > 64: raise SystemExit("Docker volume creation time is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None: raise ValueError
    except ValueError as error: raise SystemExit("Docker volume creation time is invalid") from error
    return parsed.astimezone(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def physical_path(logical: str, fixture_root: Path | None) -> Path:
    return Path(logical) if fixture_root is None else fixture_root / logical.removeprefix("/")


def require_directory_without_symlinks(root: Path, relative: str, label: str) -> Path:
    current = root
    try:
        root_stat = current.stat(follow_symlinks=False)
    except FileNotFoundError as error: raise SystemExit(f"{label} root is missing") from error
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode): raise SystemExit(f"{label} root is not a real directory")
    for part in Path(relative.removeprefix("/")).parts:
        current /= part
        try: value = current.stat(follow_symlinks=False)
        except FileNotFoundError as error: raise SystemExit(f"{label} is missing") from error
        if stat.S_ISLNK(value.st_mode): raise SystemExit(f"{label} has a symlink path component")
    if not stat.S_ISDIR(value.st_mode): raise SystemExit(f"{label} is not a directory")
    return current


def verify_system_profile(candidate_root: Path, canonical_toplevel: str) -> dict[str, str]:
    if TOPLEVEL.fullmatch(canonical_toplevel) is None: raise SystemExit("canonical toplevel is invalid")
    profile_parent = require_directory_without_symlinks(candidate_root, str(Path(CANDIDATE_PROFILE).parent), "candidate system profile")
    profile = profile_parent / Path(CANDIDATE_PROFILE).name
    try: profile_stat = profile.lstat()
    except FileNotFoundError as error: raise SystemExit("candidate system profile is missing") from error
    if not stat.S_ISLNK(profile_stat.st_mode): raise SystemExit("candidate system profile is not a symlink")
    profile_link_text = os.readlink(profile)
    if GENERATION_LINK.fullmatch(profile_link_text) is None:
        raise SystemExit("candidate system profile does not name a bounded generation link")
    generation_link = profile_parent / profile_link_text
    try: generation_stat = generation_link.lstat()
    except FileNotFoundError as error: raise SystemExit("candidate system generation link is missing") from error
    if not stat.S_ISLNK(generation_stat.st_mode) or os.readlink(generation_link) != canonical_toplevel:
        raise SystemExit("candidate system generation link differs from the canonical toplevel")
    require_directory_without_symlinks(candidate_root, canonical_toplevel, "candidate canonical toplevel")
    guest_generation = f"{Path(CANDIDATE_PROFILE).parent}/{profile_link_text}"
    return {
        "guestProfilePath": CANDIDATE_PROFILE,
        "hostProfilePath": f"{DESTINATION_ROOT}{CANDIDATE_PROFILE}",
        "profileLinkText": profile_link_text,
        "guestGenerationLinkPath": guest_generation,
        "hostGenerationLinkPath": f"{DESTINATION_ROOT}{guest_generation}",
        "generationLinkText": canonical_toplevel,
        "hostToplevelPath": f"{DESTINATION_ROOT}{canonical_toplevel}",
    }


def read_isolated_daemon_argv(fixture_root: Path | None) -> list[str]:
    pidfile = physical_path(ISOLATED_DOCKER_PIDFILE, fixture_root)
    protected_parent = physical_path(str(Path(ISOLATED_DOCKER_PIDFILE).parent), fixture_root)
    current = fixture_root if fixture_root is not None else Path("/")
    parts = protected_parent.relative_to(current).parts if fixture_root is not None else protected_parent.parts[1:]
    for part in parts:
        current /= part
        try: parent_stat = current.stat(follow_symlinks=False)
        except FileNotFoundError as error: raise SystemExit("isolated Docker PID directory is missing") from error
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            raise SystemExit("isolated Docker PID directory has a symlink or non-directory component")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try: descriptor = os.open(pidfile, flags)
    except FileNotFoundError as error: raise SystemExit("isolated Docker PID file is missing") from error
    try:
        pid_stat = os.fstat(descriptor)
        if not stat.S_ISREG(pid_stat.st_mode) or stat.S_IMODE(pid_stat.st_mode) & 0o022:
            raise SystemExit("isolated Docker PID file is not a protected regular file")
        pid_text = os.read(descriptor, 32).decode("ascii")
    except UnicodeDecodeError as error: raise SystemExit("isolated Docker PID file is invalid") from error
    finally: os.close(descriptor)
    if re.fullmatch(r"[1-9][0-9]{0,6}\n?", pid_text) is None:
        raise SystemExit("isolated Docker PID file is invalid")
    pid = pid_text.rstrip("\n")
    cmdline = physical_path(f"/proc/{pid}/cmdline", fixture_root)
    try: descriptor = os.open(cmdline, flags)
    except FileNotFoundError as error: raise SystemExit("isolated Docker daemon cmdline is missing") from error
    try:
        cmdline_stat = os.fstat(descriptor)
        if not stat.S_ISREG(cmdline_stat.st_mode): raise SystemExit("isolated Docker daemon cmdline is not a regular proc file")
        encoded = os.read(descriptor, 16384)
    finally: os.close(descriptor)
    try: argv = [item.decode("utf-8") for item in encoded.removesuffix(b"\0").split(b"\0")]
    except UnicodeDecodeError as error: raise SystemExit("isolated Docker daemon argv is invalid") from error
    if not encoded.endswith(b"\0") or b"\0\0" in encoded or argv != list(ISOLATED_DOCKER_ARGV):
        raise SystemExit("isolated Docker daemon argv differs from the exact safety policy")
    return argv


def protected_output(root: Path, name: str, data: bytes) -> None:
    if not root.is_absolute() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.json", name): raise SystemExit("output root/name is invalid")
    try: value = root.stat(follow_symlinks=False)
    except FileNotFoundError as error: raise SystemExit("dedicated output root must already exist") from error
    if root.is_symlink() or not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) & 0o077: raise SystemExit("output root must be owned, private, and not a symlink")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current.is_symlink(): raise SystemExit("output root has a symlink path component")
    resolved = root.resolve(strict=True)
    for protected in (Path(DOCKER_ROOT), Path(ISOLATED_DOCKER_ROOT)):
        if resolved == protected or protected in resolved.parents or resolved in protected.parents: raise SystemExit("output root overlaps Docker data")
    directory_fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.fsync(directory_fd)
    finally: os.close(directory_fd)


def parse_args() -> object:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--desired-inventory", required=True, type=Path)
    parser.add_argument("--expected-desired-inventory-sha256", required=True)
    parser.add_argument("--canonical-toplevel", required=True)
    parser.add_argument("--output-root", required=True, type=Path); parser.add_argument("--output-name", required=True)
    parser.add_argument("--collected-at"); parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--docker-command"); parser.add_argument("--findmnt-command"); parser.add_argument("--lsblk-command")
    return parser.parse_args()


def main() -> None:
    args = parse_args(); os.umask(0o077); overrides = (args.docker_command, args.findmnt_command, args.lsblk_command)
    if args.fixture_root is None:
        if os.geteuid() != 0: raise SystemExit("candidate qualification must run as root")
        if any(overrides): raise SystemExit("live mode forbids command overrides")
        docker, findmnt, lsblk = LIVE_DOCKER, LIVE_FINDMNT, LIVE_LSBLK; fixture_root = None
    else:
        if not all(overrides): raise SystemExit("fixture mode requires all explicit command paths")
        docker, findmnt, lsblk = overrides; fixture_root = args.fixture_root.resolve(strict=True)
    candidate_root = physical_path(DESTINATION_ROOT, fixture_root)
    raw = json.loads(args.desired_inventory.read_text(encoding="utf-8"))
    if not isinstance(raw, dict): raise SystemExit("desired inventory must be an object")
    desired = project_desired_inventory(raw)
    if digest(desired) != args.expected_desired_inventory_sha256: raise SystemExit("expected desired inventory digest differs")
    system_profile = verify_system_profile(candidate_root, args.canonical_toplevel)
    by_id = physical_path(CANDIDATE_BY_ID, fixture_root)
    try: resolved_disk = by_id.resolve(strict=True)
    except FileNotFoundError as error: raise SystemExit("exact candidate by-id is missing") from error
    mount = run_json(findmnt, ["--json", "--target", DESTINATION_ROOT, "--output", "SOURCE,FSTYPE,TARGET"])
    filesystems = mount.get("filesystems") if isinstance(mount, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1: raise SystemExit("candidate root mount identity is ambiguous")
    source, filesystem, target = (filesystems[0].get(key) for key in ("source", "fstype", "target"))
    if not isinstance(source, str) or not source.startswith("/dev/") or source.startswith("/dev/disk/by-id/") or not isinstance(filesystem, str) or filesystem in {"tmpfs", "devtmpfs", "overlay"} or target != DESTINATION_ROOT:
        raise SystemExit("candidate root is not the exact mounted block filesystem")
    ancestry = verify_candidate_device(lsblk, resolved_disk, source)
    info = docker_json(docker, ["info", "--format", "{{json .}}"])
    expected_info = {"DockerRootDir": ISOLATED_DOCKER_ROOT, "Containers": 0, "ContainersRunning": 0, "ContainersPaused": 0, "ContainersStopped": 0}
    if not isinstance(info, dict) or any(info.get(key) != value for key, value in expected_info.items()) or any(not isinstance(info.get(key), int) or isinstance(info.get(key), bool) for key in ("Containers", "ContainersRunning", "ContainersPaused", "ContainersStopped")):
        raise SystemExit("isolated candidate Docker root or zero-container counts differ")
    if docker_text(docker, ["ps", "--all", "--quiet"]) != "":
        raise SystemExit("isolated candidate Docker daemon contains containers")
    daemon_argv = read_isolated_daemon_argv(fixture_root)
    expected = expected_volume_names(desired); expected_engines = sorted(f"{PROJECT}_{name}" for name in expected)
    listed = docker_json_lines(docker, ["volume", "ls", "--format", "{{json .}}"])
    require_exact_daemon_volumes(listed, expected_engines)
    volumes = []
    for name in expected:
        engine = f"{PROJECT}_{name}"; inspected = docker_json(docker, ["volume", "inspect", engine])
        if not isinstance(inspected, list) or len(inspected) != 1: raise SystemExit(f"candidate volume inspection is ambiguous: {engine}")
        value = inspected[0]; labels = value.get("Labels") or {}; options = value.get("Options") or {}
        if not isinstance(labels, dict) or not set(labels).issubset(SAFE_VOLUME_LABELS) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()) or labels.get("com.docker.compose.project") != PROJECT or labels.get("com.docker.compose.volume") != name:
            raise SystemExit(f"candidate volume labels differ: {engine}")
        if value.get("Name") != engine or value.get("Driver") != "local" or options != {} or value.get("Mountpoint") != volume_destination(engine): raise SystemExit(f"candidate volume identity differs: {engine}")
        volumes.append({"logicalName": name, "engineName": engine, "driver": "local", "options": {}, "hostMountpoint": volume_destination(engine), "guestMountpoint": volume_source(engine), "composeLabels": dict(sorted(labels.items())), "createdAt": normalize_created(value.get("CreatedAt"))})
    timestamp = args.collected_at or dt.datetime.now(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    inventory = {
        "format": CANDIDATE_INVENTORY_FORMAT, "collectedAt": timestamp,
        "candidateDisk": {"wholeDiskById": CANDIDATE_BY_ID, "serial": CANDIDATE_SERIAL, "sizeBytes": DISK_BYTES},
        "candidateMount": {"device": source, "filesystem": filesystem, "target": DESTINATION_ROOT, "deviceAncestry": ancestry},
        "isolatedDockerHost": ISOLATED_DOCKER_HOST, "isolatedDockerRoot": ISOLATED_DOCKER_ROOT,
        "isolatedDockerDaemonArgv": daemon_argv,
        "systemProfile": system_profile, "canonicalProductionMigrationToplevel": args.canonical_toplevel,
        "volumes": volumes,
    }
    validate_candidate_inventory(inventory, desired, args.canonical_toplevel)
    protected_output(args.output_root, args.output_name, json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode() + b"\n")


if __name__ == "__main__": main()
