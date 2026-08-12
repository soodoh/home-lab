#!/usr/bin/env python3
"""Shared controller-wide descriptor lock and nested ownership validation."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

FORMAT = "home-lab-controller-lock-v1"
LOCK_NAME = "controller-apply.lock"
TOKEN_ENV = "RECONCILE_CONTROLLER_LOCK_TOKEN"
FD_ENV = "RECONCILE_CONTROLLER_LOCK_FD"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_METADATA_BYTES = 4096


class LockContentionError(ValueError):
    """The controller-wide mutation lock is held by another transaction."""


@dataclass(frozen=True)
class LockHandle:
    reconcile_fd: int
    lock_fd: int
    owned: bool


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def outer_owner(commit: str, phase: str, token: str, pid: int) -> dict[str, Any]:
    if HEX40.fullmatch(commit) is None or phase not in {"steady", "recovery"} or HEX64.fullmatch(token) is None or pid <= 0:
        raise ValueError("controller lock owner inputs differ")
    return {
        "commit": commit,
        "format": FORMAT,
        "operation": "reconcile-infrastructure-apply",
        "phase": phase,
        "pid": pid,
        "tokenSha256": token_sha256(token),
    }


def _open_reconcile(repo: Path) -> int:
    root = repo / ".reconcile"
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    reconcile_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(reconcile_fd)
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
        os.close(reconcile_fd)
        raise ValueError("controller reconciliation root must be a user-owned real mode-0700 directory")
    return reconcile_fd


def _open_lock(reconcile_fd: int) -> int:
    lock_fd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=reconcile_fd)
    info = os.fstat(lock_fd)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or \
            info.st_uid != os.geteuid() or info.st_nlink != 1:
        os.close(lock_fd)
        raise ValueError("controller mutex must be a user-owned mode-0600 single-link regular file")
    return lock_fd


def _write_metadata(reconcile_fd: int, lock_fd: int, owner: dict[str, Any]) -> None:
    content = canonical(owner)
    if len(content) > MAX_METADATA_BYTES:
        raise ValueError("controller lock ownership metadata is too large")
    os.ftruncate(lock_fd, 0)
    os.lseek(lock_fd, 0, os.SEEK_SET)
    view = memoryview(content)
    while view:
        written = os.write(lock_fd, view)
        if written <= 0:
            raise OSError("short controller lock metadata write")
        view = view[written:]
    os.fsync(lock_fd)
    os.fsync(reconcile_fd)


def _read_metadata(lock_fd: int) -> dict[str, Any]:
    before = os.fstat(lock_fd)
    raw = os.pread(lock_fd, MAX_METADATA_BYTES + 1, 0)
    after = os.fstat(lock_fd)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if len(raw) > MAX_METADATA_BYTES or identity_before != identity_after:
        raise ValueError("controller lock metadata changed while reading")
    value = json.loads(raw)
    if not isinstance(value, dict) or raw != canonical(value):
        raise ValueError("controller lock metadata must be canonical JSON")
    return value


def acquire(repo: Path, owner: dict[str, Any]) -> LockHandle:
    reconcile_fd = _open_reconcile(repo)
    try:
        lock_fd = _open_lock(reconcile_fd)
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise LockContentionError("controller apply mutex is already held") from error
            _write_metadata(reconcile_fd, lock_fd, owner)
            return LockHandle(reconcile_fd, lock_fd, True)
        except Exception:
            os.close(lock_fd)
            raise
    except Exception:
        os.close(reconcile_fd)
        raise


def _validate_outer_metadata(
    metadata: dict[str, Any], token: str, expected_commit: str, expected_phase: str | None, expected_pid: int | None,
) -> None:
    if set(metadata) != {"commit", "format", "operation", "phase", "pid", "tokenSha256"} or \
            metadata.get("format") != FORMAT or metadata.get("operation") != "reconcile-infrastructure-apply" or \
            metadata.get("commit") != expected_commit or metadata.get("phase") not in {"steady", "recovery"} or \
            not isinstance(metadata.get("pid"), int) or metadata["pid"] <= 0 or \
            metadata.get("tokenSha256") != token_sha256(token):
        raise ValueError("inherited controller lock ownership metadata differs")
    if expected_phase is not None and metadata["phase"] != expected_phase:
        raise ValueError("inherited controller lock phase differs")
    if expected_pid is not None and metadata["pid"] != expected_pid:
        raise ValueError("inherited controller lock process differs")


def borrow(
    repo: Path,
    token: str,
    expected_commit: str,
    *,
    inherited_fd_text: str | None = None,
    expected_phase: str | None = None,
    expected_pid: int | None = None,
    require_inherited_fd: bool = False,
) -> LockHandle:
    if HEX64.fullmatch(token) is None or HEX40.fullmatch(expected_commit) is None:
        raise ValueError("inherited controller lock token or commit differs")
    inherited_fd: int | None = None
    inherited_info: os.stat_result | None = None
    if inherited_fd_text is not None:
        if not inherited_fd_text.isascii() or not inherited_fd_text.isdecimal():
            raise ValueError("inherited controller lock descriptor differs")
        inherited_fd = int(inherited_fd_text)
        try:
            inherited_info = os.fstat(inherited_fd)
        except OSError as error:
            if error.errno != 9:
                raise
    reconcile_fd = _open_reconcile(repo)
    try:
        lock_fd = _open_lock(reconcile_fd)
        try:
            metadata = _read_metadata(lock_fd)
            _validate_outer_metadata(metadata, token, expected_commit, expected_phase, expected_pid)
            path_info = os.fstat(lock_fd)
            inherited_verified = inherited_fd is not None and inherited_info is not None and \
                stat.S_ISREG(inherited_info.st_mode) and \
                (inherited_info.st_dev, inherited_info.st_ino) == (path_info.st_dev, path_info.st_ino)
            if inherited_verified:
                fcntl.flock(inherited_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if require_inherited_fd and not inherited_verified:
                raise ValueError("inherited controller lock descriptor is unavailable")
            if not inherited_verified:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    raise ValueError("inherited controller lock is not held")
            return LockHandle(reconcile_fd, lock_fd, False)
        except Exception:
            os.close(lock_fd)
            raise
    except Exception:
        os.close(reconcile_fd)
        raise


def acquire_or_borrow(repo: Path, owner: dict[str, Any]) -> LockHandle:
    token = os.environ.get(TOKEN_ENV)
    inherited_fd_text = os.environ.get(FD_ENV)
    if token is None:
        if inherited_fd_text is not None:
            raise ValueError("controller lock descriptor exists without ownership token")
        return acquire(repo, owner)
    expected_commit = owner.get("gitCommit")
    if not isinstance(expected_commit, str):
        raise ValueError("nested controller lock requires the exact Git commit")
    return borrow(repo, token, expected_commit, inherited_fd_text=inherited_fd_text)


def release(handle: LockHandle) -> None:
    os.close(handle.lock_fd)
    os.close(handle.reconcile_fd)
