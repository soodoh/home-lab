#!/usr/bin/env python3
"""Guard VM 100 migration verification and the persistent write commit."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

AUTHORITY = "migration-in-progress"
CONFIRMATION = "commit-reviewed-vm-100-migration-writes"
STATE_DIRECTORY = Path("/var/lib/home-lab")
REQUEST_NAME = "vm-100-write-commit-request.json"
MARKER_NAME = "vm-100-write-commit.json"
BOOTED_SYSTEM = "/run/booted-system"
CURRENT_SYSTEM = "/run/current-system"
MAX_REQUEST_AGE = dt.timedelta(minutes=15)
MAX_PROTECTED_FILE_SIZE = 64 * 1024


@dataclass(frozen=True)
class MountExpectation:
    target: str
    source: str
    filesystem: str
    uuid: str | None = None


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def open_state_directory() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(STATE_DIRECTORY, flags)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"{STATE_DIRECTORY} must be a directory")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise ValueError(f"{STATE_DIRECTORY} must be root-owned by root with mode 0700")
    return descriptor


def read_protected_file(directory_fd: int, name: str, mode: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{name} must be a regular file")
        if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
            raise ValueError(f"{name} must be root-owned by root with mode {mode:04o}")
        if metadata.st_nlink != 1:
            raise ValueError(f"{name} must have exactly one link")
        if metadata.st_size > MAX_PROTECTED_FILE_SIZE:
            raise ValueError(f"{name} exceeds the protected file size limit")
        chunks: list[bytes] = []
        remaining = MAX_PROTECTED_FILE_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_PROTECTED_FILE_SIZE:
            raise ValueError(f"{name} exceeds the protected file size limit")
        return raw
    finally:
        os.close(descriptor)


def parse_canonical_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict) or raw != canonical_json(value):
        raise ValueError(f"{label} must be a canonical JSON object")
    return value


def current_system_identity(link: str) -> str:
    resolved = os.path.realpath(link)
    if not resolved.startswith("/nix/store/"):
        raise ValueError(f"{link} does not resolve into the Nix store")
    return resolved


def validate_request(directory_fd: int, expected_artifact: str) -> tuple[dict[str, object], str]:
    raw = read_protected_file(directory_fd, REQUEST_NAME, 0o600)
    request = parse_canonical_json(raw, "write-commit request")
    required = {
        "bootedSystem",
        "composeArtifactSha256",
        "confirmation",
        "createdAt",
        "currentSystem",
        "deploymentAuthority",
        "version",
    }
    if set(request) != required or request["version"] != 1:
        raise ValueError("write-commit request fields or version differ")
    if request["deploymentAuthority"] != AUTHORITY or request["composeArtifactSha256"] != expected_artifact:
        raise ValueError("write-commit request authority or Compose artifact differs")
    if request["confirmation"] != CONFIRMATION:
        raise ValueError("write-commit confirmation differs")
    if request["bootedSystem"] != current_system_identity(BOOTED_SYSTEM) or \
            request["currentSystem"] != current_system_identity(CURRENT_SYSTEM):
        raise ValueError("write-commit request is not bound to the booted and current systems")
    try:
        created = dt.datetime.fromisoformat(str(request["createdAt"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("write-commit request timestamp is invalid") from error
    now = dt.datetime.now(dt.timezone.utc)
    if created.tzinfo is None or created > now or now - created > MAX_REQUEST_AGE:
        raise ValueError("write-commit request is not fresh")
    return request, hashlib.sha256(raw).hexdigest()


def validate_marker(directory_fd: int, expected_artifact: str) -> dict[str, object]:
    marker = parse_canonical_json(read_protected_file(directory_fd, MARKER_NAME, 0o600), "write-commit marker")
    required = {
        "bootedSystem",
        "committedAt",
        "composeArtifactSha256",
        "currentSystem",
        "deploymentAuthority",
        "requestSha256",
        "version",
    }
    if set(marker) != required or marker["version"] != 1:
        raise ValueError("write-commit marker fields or version differ")
    if marker["deploymentAuthority"] != AUTHORITY or marker["composeArtifactSha256"] != expected_artifact:
        raise ValueError("write-commit marker authority or Compose artifact differs")
    if marker["bootedSystem"] != current_system_identity(BOOTED_SYSTEM) or \
            marker["currentSystem"] != current_system_identity(CURRENT_SYSTEM):
        raise ValueError("write-commit marker is not bound to the booted and current systems")
    if not isinstance(marker["requestSha256"], str) or len(marker["requestSha256"]) != 64 or \
            any(character not in "0123456789abcdef" for character in marker["requestSha256"]):
        raise ValueError("write-commit marker request digest is invalid")
    return marker


def write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        offset += os.write(descriptor, raw[offset:])


def commit(expected_artifact: str) -> None:
    directory_fd = open_state_directory()
    try:
        try:
            validate_marker(directory_fd, expected_artifact)
        except FileNotFoundError:
            pass
        else:
            print("vm_100_write_commit=already_committed")
            return
        request, request_sha256 = validate_request(directory_fd, expected_artifact)
        marker = {
            "bootedSystem": request["bootedSystem"],
            "committedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "composeArtifactSha256": expected_artifact,
            "currentSystem": request["currentSystem"],
            "deploymentAuthority": AUTHORITY,
            "requestSha256": request_sha256,
            "version": 1,
        }
        temporary = f".{MARKER_NAME}.{os.getpid()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            write_all(descriptor, canonical_json(marker))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.unlink(REQUEST_NAME, dir_fd=directory_fd)
            os.replace(temporary, MARKER_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        print(f"vm_100_write_commit=committed request_sha256={request_sha256}")
    finally:
        os.close(directory_fd)


def find_mount(expectation: MountExpectation) -> dict[str, object]:
    result = subprocess.run(
        ["findmnt", "--json", "--mountpoint", expectation.target, "--output", "TARGET,SOURCE,FSTYPE,OPTIONS,UUID"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    payload = json.loads(result.stdout)
    filesystems = payload.get("filesystems")
    if not isinstance(filesystems, list) or len(filesystems) != 1 or not isinstance(filesystems[0], dict):
        raise ValueError(f"{expectation.target} does not have one exact mount")
    mount = filesystems[0]
    if os.path.realpath(str(mount.get("target"))) != expectation.target:
        raise ValueError(f"{expectation.target} mount target differs")
    filesystem = str(mount.get("fstype") or "")
    if expectation.filesystem == "nfs" or expectation.filesystem == "nfs4":
        if filesystem != expectation.filesystem or mount.get("source") != expectation.source:
            raise ValueError(f"{expectation.target} NFS identity differs")
    elif filesystem != expectation.filesystem or mount.get("uuid") != expectation.uuid:
        raise ValueError(f"{expectation.target} filesystem identity differs")
    options = set(str(mount.get("options") or "").split(","))
    return {"options": options, "raw": mount}


def verify_mounts(expectations: tuple[MountExpectation, ...], required_option: str) -> None:
    for expectation in expectations:
        if required_option not in find_mount(expectation)["options"]:
            raise ValueError(f"{expectation.target} is missing required option {required_option}")


def unit_active(unit: str) -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0


def enable_writes(expected_artifact: str, expectations: tuple[MountExpectation, ...]) -> None:
    directory_fd = open_state_directory()
    try:
        validate_marker(directory_fd, expected_artifact)
    finally:
        os.close(directory_fd)
    states = [find_mount(expectation)["options"] for expectation in expectations]
    if all("rw" in options for options in states):
        print("vm_100_migration_writes=already_enabled")
        return
    if any("rw" in options for options in states):
        for expectation, options in zip(expectations, states, strict=True):
            if "rw" in options:
                subprocess.run(["mount", "--options", "remount,ro", expectation.target], check=True)
        verify_mounts(expectations, "ro")
    else:
        verify_mounts(expectations, "ro")
    transitioned: list[MountExpectation] = []
    try:
        for expectation in expectations:
            subprocess.run(["mount", "--options", "remount,rw", expectation.target], check=True)
            transitioned.append(expectation)
            if "rw" not in find_mount(expectation)["options"]:
                raise ValueError(f"{expectation.target} did not become writable")
    except Exception:
        for expectation in reversed(transitioned):
            subprocess.run(["mount", "--options", "remount,ro", expectation.target], check=False)
        verify_mounts(expectations, "ro")
        raise
    print("vm_100_migration_writes=enabled")


def verify_only(expected_artifact: str, expectations: tuple[MountExpectation, ...]) -> None:
    directory_fd = open_state_directory()
    try:
        try:
            validate_marker(directory_fd, expected_artifact)
        except FileNotFoundError:
            marker_exists = False
        else:
            marker_exists = True
    finally:
        os.close(directory_fd)
    if marker_exists:
        verify_mounts(expectations, "rw")
        for unit in ("vm-100-migration-write-enable.service", "docker.service", "docker.socket"):
            if not unit_active(unit):
                raise ValueError(f"{unit} is inactive after write commit")
    else:
        verify_mounts(expectations, "ro")
        for unit in ("docker.service", "docker.socket"):
            if unit_active(unit):
                raise ValueError(f"{unit} is active before write commit")
    print(f"vm_100_migration_verify=passed write_committed={str(marker_exists).lower()}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("commit", "enable-writes", "verify-marker", "verify-only"))
    parser.add_argument("--expected-artifact", required=True)
    parser.add_argument("--games-uuid", required=True)
    parser.add_argument("--games-filesystem", required=True)
    parser.add_argument("--shared-source", required=True)
    parser.add_argument("--shared-filesystem", required=True)
    args = parser.parse_args()
    if len(args.expected_artifact) != 64 or any(character not in "0123456789abcdef" for character in args.expected_artifact):
        parser.error("--expected-artifact must be a lowercase SHA-256 digest")
    expectations = (
        MountExpectation("/mnt/games", f"/dev/disk/by-uuid/{args.games_uuid}", args.games_filesystem, args.games_uuid),
        MountExpectation("/mnt/storage", args.shared_source, args.shared_filesystem),
    )
    try:
        if args.operation == "commit":
            commit(args.expected_artifact)
        elif args.operation == "enable-writes":
            enable_writes(args.expected_artifact, expectations)
        elif args.operation == "verify-marker":
            directory_fd = open_state_directory()
            try:
                validate_marker(directory_fd, args.expected_artifact)
            finally:
                os.close(directory_fd)
            print("vm_100_write_commit_marker=verified")
        else:
            verify_only(args.expected_artifact, expectations)
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"vm_100_migration_guard=failed reason={error}", file=sys.stderr)
        return 66
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
