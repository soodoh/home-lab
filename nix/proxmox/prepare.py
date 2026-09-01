#!/usr/bin/env python3
"""Controller-side fixed private-precondition preparation transport."""

import datetime as dt
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import apply as guarded_apply
import planner

PROTOCOL = 4
MAX_RESPONSE = 256 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REMOTE = "/usr/local/libexec/home-lab/proxmox-private-preparer"
SSH_PREPARE_COMMAND = planner.fixed_ssh_command("apply", "sudo -n -- " + REMOTE + " prepare")


def send(request: dict[str, Any]) -> dict[str, Any]:
    result = subprocess.run(SSH_PREPARE_COMMAND, input=planner.canonical_json(request), capture_output=True, timeout=30)
    if result.returncode or result.stderr or len(result.stdout) > MAX_RESPONSE:
        raise ValueError("bootstrap-required: fixed private preparer transport failed")
    value = json.loads(result.stdout)
    if result.stdout != planner.canonical_json(value):
        raise ValueError("fixed private preparer returned noncanonical output")
    return value


def write_exclusive(repo: Path, name: str, content: bytes) -> None:
    directory_fd = planner.open_live_output_directory(repo)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(content):
                written = os.write(fd, content[offset:])
                if written < 1:
                    raise OSError("private sidecar write made no progress")
                offset += written
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise ValueError("private sidecar output is insecure")
            os.fsync(fd)
        except Exception:
            os.close(fd)
            os.unlink(name, dir_fd=directory_fd)
            raise
        os.close(fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def prepare(args: Any, bundle_path: Path, hash_path: Path, source_root: Path) -> str:
    repo = Path(args.repo_root)
    if not repo.is_absolute() or not HEX64.fullmatch(args.plan_sha or "") or args.plan_sha != args.approve_plan_sha:
        raise ValueError("prepare requires an absolute root and identical exact plan approval hashes")
    bindings, projection, manifest, metadata = planner.bundle_inputs(bundle_path, hash_path, repo, source_root)
    if projection["nixMutationFrozen"] is True:
        raise ValueError("Nix protected preparation is frozen by lifecycle policy")
    plan_path = repo / ".reconcile" / "plans" / f"{args.plan_sha}.json"
    plan = guarded_apply.load_secure_canonical(plan_path, "plan", planner.MAX_OBSERVATION_BYTES)
    planner.validate_plan(plan, projection, manifest)
    if plan["planSha256"] != args.plan_sha or plan["bindings"] != bindings or plan["status"] != "ready" or \
            plan["mode"] != "steady" or plan["applyEligible"] is not True or plan["blockers"]:
        raise ValueError("prepare requires the exact ready steady eligible unblocked plan")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if now > planner.parse_time(plan["freshness"]["validUntil"]):
        raise ValueError("reviewed plan is expired")
    requires_watchdog = any(action["watchdogRequired"] for action in plan["actions"])
    if not args.confirm_no_concurrent_mutation or (requires_watchdog and not (
            args.confirm_console and args.confirm_lan_rollback and args.confirm_backups)):
        raise ValueError("required preparation confirmation is absent")
    if not requires_watchdog and any((args.confirm_console, args.confirm_lan_rollback, args.confirm_backups)):
        raise ValueError("conditional watchdog confirmations are not accepted for this plan")
    sidecar_name = f"{args.plan_sha}.private.json"
    directory_fd = planner.open_live_output_directory(repo)
    try:
        try:
            os.stat(sidecar_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("private sidecar already exists")
    finally:
        os.close(directory_fd)
    request = {"format": "home-lab-proxmox-private-preparation-request-v1",
               "operatorGates": {"backupsConfirmed": bool(args.confirm_backups),
                                 "consoleConfirmed": bool(args.confirm_console),
                                 "lanRollbackConfirmed": bool(args.confirm_lan_rollback),
                                 "noConcurrentMutationConfirmed": True},
               "plan": plan, "protocol": PROTOCOL, "requestedAt": planner.format_time(now)}
    response = send(request)
    validation_now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    guarded_apply.validate_private(response, plan, metadata, validation_now)
    raw = planner.canonical_json(response)
    write_exclusive(repo, sidecar_name, raw)
    return f"status=prepared planSha256={args.plan_sha} sidecar=created"
