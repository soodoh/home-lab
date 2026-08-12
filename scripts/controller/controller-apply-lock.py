#!/usr/bin/env python3
"""Acquire the controller transaction lock once or verify its inherited ownership."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "nix/proxmox"))
import controller_lock


def run(args: argparse.Namespace) -> int:
    if os.environ.get(controller_lock.TOKEN_ENV) is not None or os.environ.get(controller_lock.FD_ENV) is not None:
        raise ValueError("caller-supplied controller lock inheritance is forbidden")
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("controller lock runner requires a command")
    token = secrets.token_hex(32)
    owner = controller_lock.outer_owner(args.commit, args.phase, token, os.getpid())
    handle = controller_lock.acquire(Path(args.repo_root), owner)
    os.set_inheritable(handle.lock_fd, True)
    environment = dict(os.environ)
    environment[controller_lock.TOKEN_ENV] = token
    environment[controller_lock.FD_ENV] = str(handle.lock_fd)
    os.execvpe(command[0], command, environment)
    raise RuntimeError("controller lock runner exec unexpectedly returned")


def verify(args: argparse.Namespace) -> int:
    token = os.environ.get(controller_lock.TOKEN_ENV)
    inherited_fd = os.environ.get(controller_lock.FD_ENV)
    if token is None or inherited_fd is None:
        raise ValueError("controller lock inheritance is incomplete")
    handle = controller_lock.borrow(
        Path(args.repo_root),
        token,
        args.commit,
        inherited_fd_text=inherited_fd,
        expected_phase=args.phase,
        expected_pid=os.getppid(),
        require_inherited_fd=True,
    )
    controller_lock.release(handle)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="controller-apply-lock.py", allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for name in ("run", "verify"):
        operation = subparsers.add_parser(name, allow_abbrev=False)
        operation.add_argument("--repo-root", required=True)
        operation.add_argument("--commit", required=True)
        operation.add_argument("--phase", choices=("steady", "recovery"), required=True)
        if name == "run":
            operation.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.operation == "run":
        return run(args)
    return verify(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except controller_lock.LockContentionError:
        print(f"another controller apply holds {ROOT / '.reconcile/controller-apply.lock'}", file=sys.stderr)
        raise SystemExit(75)
    except (OSError, RuntimeError, ValueError):
        print("controller apply lock setup or inheritance validation failed", file=sys.stderr)
        raise SystemExit(66)
