#!/usr/bin/env python3
"""Fixed root transport for disposable Restic recovery VM 9900 operations."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

VMID = 9900
SNIPPET_DIRECTORY = Path("/var/lib/vz/snippets")
SNIPPET = SNIPPET_DIRECTORY / "home-lab-restic-recovery-cloud-init.yaml"
LOCK = Path("/run/lock/home-lab-restic-recovery-transport.lock")
PROTECTED_LOCKS = (
    Path("/var/lib/home-lab/reconciliation/apply.lock"),
    Path("/var/lib/iac-ansible-production.lock"),
    Path("/var/lib/home-lab/firewall-transaction/active.json"),
    Path("/run/lock/home-lab-pve-firewall.lock"),
)
HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_SNIPPET_BYTES = 131072


def fail(message: str, status: int = 64) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(status)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def require_root() -> None:
    if os.geteuid() != 0:
        fail("restic recovery transport requires root", 77)


def acquire_lock() -> int:
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_nlink != 1:
        os.close(descriptor); fail("restic recovery lock metadata differs", 77)
    try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor); fail("restic recovery transport is locked", 75)
    return descriptor


def require_snippet_directory() -> None:
    info = SNIPPET_DIRECTORY.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755 or info.st_uid != 0 or info.st_gid != 0:
        fail("snippet directory metadata differs", 77)


def fsync_directory() -> None:
    descriptor = os.open(SNIPPET_DIRECTORY, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def network_identity() -> None:
    status = subprocess.run(("/usr/sbin/qm", "status", str(VMID)), capture_output=True, text=True, timeout=30)
    config = subprocess.run(("/usr/sbin/qm", "config", str(VMID)), capture_output=True, text=True, timeout=30)
    if status.returncode or config.returncode or status.stderr or config.stderr: fail("VM 9900 network identity observation failed", 69)
    status_match = re.fullmatch(r"status: ([a-z]+)\n?", status.stdout)
    net_match = re.search(r"^net0: [^\n]*?(?:virtio|e1000|vmxnet3)=([0-9A-Fa-f:]{17})(?:,|$)", config.stdout, re.MULTILINE)
    if status_match is None or net_match is None: fail("VM 9900 network identity output differs", 69)
    print(canonical({"mac": net_match.group(1).upper(), "status": status_match.group(1), "vmid": VMID}))


def stage_snippet(expected: str) -> None:
    if HEX.fullmatch(expected) is None: fail("snippet digest differs")
    raw = sys.stdin.buffer.read(MAX_SNIPPET_BYTES + 1)
    if not raw or len(raw) > MAX_SNIPPET_BYTES or sha(raw) != expected: fail("snippet input differs", 65)
    if any(os.path.lexists(path) for path in PROTECTED_LOCKS): fail("protected infrastructure lock is active", 75)
    require_snippet_directory(); descriptor = acquire_lock()
    try:
        if os.path.lexists(SNIPPET):
            info = SNIPPET.lstat()
            if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and SNIPPET.read_bytes() == raw:
                print(canonical({"sha256": expected, "staged": True})); return
            fail("active recovery snippet differs", 73)
        temporary = SNIPPET_DIRECTORY / f".{SNIPPET.name}.{os.getpid()}.tmp"
        output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(output, "wb", closefd=False) as handle:
                if handle.write(raw) != len(raw): fail("snippet write was incomplete", 74)
                handle.flush(); os.fchown(output, 0, 0); os.fchmod(output, 0o600); os.fsync(output)
        finally: os.close(output)
        os.replace(temporary, SNIPPET); fsync_directory()
        if SNIPPET.read_bytes() != raw: fail("staged snippet postcondition differs", 74)
        print(canonical({"sha256": expected, "staged": True}))
    finally: os.close(descriptor)


def remove_snippet(expected: str) -> None:
    if HEX.fullmatch(expected) is None: fail("snippet digest differs")
    if any(os.path.lexists(path) for path in PROTECTED_LOCKS): fail("protected infrastructure lock is active", 75)
    require_snippet_directory(); descriptor = acquire_lock()
    try:
        if os.path.lexists(SNIPPET):
            info = SNIPPET.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or sha(SNIPPET.read_bytes()) != expected:
                fail("active recovery snippet differs", 73)
            SNIPPET.unlink(); fsync_directory()
        print(canonical({"removed": True, "sha256": expected}))
    finally: os.close(descriptor)


def main() -> None:
    require_root(); arguments = sys.argv[1:]
    if arguments == ["network-identity"]: network_identity(); return
    if len(arguments) == 2 and arguments[0] == "stage-snippet": stage_snippet(arguments[1]); return
    if len(arguments) == 2 and arguments[0] == "remove-snippet": remove_snippet(arguments[1]); return
    fail("unsupported restic recovery transport command")


if __name__ == "__main__": main()
