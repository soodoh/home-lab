#!/usr/bin/env python3
"""Fixed fresh read-only NFS canary for the Proxmox firewall transaction."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys

MOUNTPOINT = Path("/run/home-lab-proxmox-firewall-nfs-canary")
SERVER = "192.168.0.123"
NFS_PORT = 2049
SOURCE = SERVER + ":/storage/docker"
ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}


def mounted() -> bool:
    return os.path.ismount(MOUNTPOINT)


def cleanup() -> None:
    if mounted():
        result = subprocess.run(("/usr/bin/umount", "--", str(MOUNTPOINT)), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2, env=ENV)
        if result.returncode or result.stderr or mounted():
            raise RuntimeError("NFS canary unmount failed")
    if MOUNTPOINT.exists():
        MOUNTPOINT.rmdir()


def fresh_tcp() -> None:
    connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        connection.settimeout(2); connection.connect((SERVER,NFS_PORT))
    finally: connection.close()


def check() -> None:
    if MOUNTPOINT.exists() or MOUNTPOINT.is_symlink():
        raise RuntimeError("canary mountpoint already exists")
    MOUNTPOINT.mkdir(mode=0o700)
    try:
        fresh_tcp()
        result = subprocess.run(("/usr/bin/mount", "-t", "nfs4", "-o",
            "ro,nosuid,nodev,noexec,vers=4.2,timeo=5,retrans=1", SOURCE, str(MOUNTPOINT)),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2, env=ENV)
        if result.returncode or result.stderr or not mounted():
            raise RuntimeError("NFS canary mount failed")
        info = MOUNTPOINT.stat()
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("NFS canary stat failed")
        next(MOUNTPOINT.iterdir(), None)
    finally:
        cleanup()


def main() -> int:
    if os.geteuid() != 0:
        raise RuntimeError("root is required")
    def interrupted(signum: int, frame: object) -> None:
        del signum, frame
        raise InterruptedError("NFS canary interrupted")
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGHUP, interrupted)
    if sys.argv != [sys.argv[0], "check"]:
        print("usage: proxmox-firewall-nfs-canary check", file=sys.stderr)
        return 64
    check()
    print("proxmox-firewall-nfs-canary=passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        with __import__("contextlib").suppress(Exception):
            cleanup()
        print("proxmox-firewall-nfs-canary: fixed check failed", file=sys.stderr)
        raise SystemExit(1)
