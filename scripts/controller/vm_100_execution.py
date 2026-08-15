#!/usr/bin/env python3
"""Shared protected-I/O and observation helpers for VM 100 migration executors."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
from typing import BinaryIO

from vm_100_gate_c import canonical_bytes

SAFE_JSON_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.json$")
SAFE_LOG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.log$")
TRANSFER_LOCK_PATH = "/run/lock/vm-100-data-transfer.lock"


def require_private_root(root: Path, forbidden: tuple[Path, ...]) -> Path:
    if not root.is_absolute():
        raise SystemExit("protected output root must be absolute")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        try:
            value = current.stat(follow_symlinks=False)
        except FileNotFoundError as error:
            raise SystemExit("protected output root must already exist") from error
        if stat.S_ISLNK(value.st_mode):
            raise SystemExit("protected output root has a symlink component")
    value = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) & 0o077:
        raise SystemExit("protected output root must be an owned mode-private directory")
    resolved = root.resolve(strict=True)
    if any(resolved == item or item in resolved.parents or resolved in item.parents for item in forbidden):
        raise SystemExit("protected output root overlaps protected migration data")
    return resolved


def open_exclusive(root: Path, name: str, pattern: re.Pattern[str] = SAFE_LOG_NAME) -> BinaryIO:
    if pattern.fullmatch(name) is None:
        raise SystemExit("protected output name is invalid")
    directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    return os.fdopen(descriptor, "wb")


def write_json(root: Path, name: str, value: object) -> None:
    if SAFE_JSON_NAME.fullmatch(name) is None:
        raise SystemExit("protected JSON output name is invalid")
    encoded = canonical_bytes(value) + b"\n"
    directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def file_metrics(path: Path) -> dict[str, object]:
    checksum = hashlib.sha256()
    size = 0
    lines = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
            size += len(chunk)
            lines += chunk.count(b"\n")
    return {"sha256": checksum.hexdigest(), "bytes": size, "lines": lines}


def require_directory(logical: str, fixture_root: Path | None) -> Path:
    path = Path(logical) if fixture_root is None else fixture_root / logical.removeprefix("/")
    current = Path("/") if fixture_root is None else fixture_root
    parts = path.parts[1:] if fixture_root is None else path.relative_to(fixture_root).parts
    for part in parts:
        current /= part
        try:
            value = current.stat(follow_symlinks=False)
        except FileNotFoundError as error:
            raise SystemExit(f"required directory is missing: {logical}") from error
        if stat.S_ISLNK(value.st_mode):
            raise SystemExit(f"directory contains a symlink component: {logical}")
    if not stat.S_ISDIR(value.st_mode):
        raise SystemExit(f"required path is not a directory: {logical}")
    return path


def root_metadata(path: Path) -> dict[str, int | str]:
    value = path.stat(follow_symlinks=False)
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": format(stat.S_IMODE(value.st_mode), "04o"),
    }


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_protected_bytes(path: Path, label: str) -> bytes:
    """Read a private, owned, single-link regular file without following symlinks."""
    if not path.is_absolute():
        path = Path.cwd() / path
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        value = current.stat(follow_symlinks=False)
        if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
            raise SystemExit(f"{label} has an unsafe path component")
    parent = path.parent
    parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_descriptor)
    finally:
        os.close(parent_descriptor)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077:
            raise SystemExit(f"{label} must be an owned mode-private dedicated regular file")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            raw = source.read()
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SystemExit(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    return raw


def load_canonical_object(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = load_protected_bytes(path, label)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit(f"{label} is not JSON") from error
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be a JSON object")
    if raw != canonical_bytes(value) + b"\n":
        raise SystemExit(f"{label} is not canonical JSON")
    return value, raw


def create_run_root(parent: Path, prefix: str = "vm-100-run") -> Path:
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", prefix) is None:
        raise SystemExit("protected run prefix is invalid")
    name = f"{prefix}-{time.time_ns()}-{os.getpid()}-{secrets.token_hex(8)}"
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        child_fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            value = os.fstat(child_fd)
            if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
                raise SystemExit("protected run root is not an owned mode-0700 directory")
        finally:
            os.close(child_fd)
    finally:
        os.close(parent_fd)
    return parent / name


def verify_exact_checkout(git: str, expected_commit: str, env: dict[str, str]) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None:
        raise SystemExit("expected commit must be a full 40-hex Git object ID")
    def rev(name: str) -> str:
        return subprocess.run([git, "rev-parse", "--verify", name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env).stdout.strip()
    head = rev("HEAD")
    origin_main = rev("refs/remotes/origin/main")
    dirty = subprocess.run([git, "status", "--porcelain"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env).stdout
    if head != expected_commit or origin_main != expected_commit or dirty != "":
        raise SystemExit("HEAD, expected commit, and refs/remotes/origin/main are not the same clean checkout")


def acquire_transfer_lock(path: Path) -> int:
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        value = current.stat(follow_symlinks=False)
        if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
            raise SystemExit("transfer lock path has an unsafe component")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    value = os.fstat(descriptor)
    if not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid() or value.st_nlink != 1 or stat.S_IMODE(value.st_mode) & 0o077:
        os.close(descriptor)
        raise SystemExit("transfer lock is not a dedicated protected regular file")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise SystemExit("another VM 100 data operation holds the lock") from error
    return descriptor


def bounded_error(error: BaseException | str | None, limit: int = 512) -> str | None:
    if error is None:
        return None
    text = " ".join(str(error).split()) or type(error).__name__
    return text[:limit]
