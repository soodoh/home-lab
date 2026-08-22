#!/usr/bin/env python3
"""Authorize only the reviewed Arch-to-Debian OpenTofu state address move."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

EXPECTED_ROOTS = {"aws-foundation", "proxmox-legacy", "proxmox", "omada", "tailscale"}
OLD_ADDRESS = "proxmox_virtual_environment_vm.arch"
NEW_ADDRESS = "proxmox_virtual_environment_vm.debian"


def fail(message: str) -> None:
    raise ValueError(message)


def read_json(path: Path) -> object:
    if not path.is_file() or path.is_symlink():
        fail(f"required regular file is missing: {path}")
    return json.loads(path.read_text())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.strip()


def verify(repo: Path, plan_dir: Path) -> None:
    repo = repo.resolve()
    plan_dir = plan_dir.resolve()
    commit = git(repo, "rev-parse", "HEAD")
    expected_dir = (repo / ".reconcile" / "plans" / commit / "steady").resolve()
    if plan_dir != expected_dir:
        fail("state-only move plan directory is not the exact HEAD steady-plan directory")
    if git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("state-only move requires a clean working tree")

    manifest_path = plan_dir / "manifest.json"
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        fail("saved-plan manifest must be an object")
    if manifest.get("version") != 5 or manifest.get("commit") != commit:
        fail("saved-plan manifest version or commit differs")
    if manifest.get("phase") != "steady" or manifest.get("stage") != "converge":
        fail("state-only move requires the steady converge stage")

    plans = manifest.get("plans")
    if not isinstance(plans, list) or {item.get("root") for item in plans if isinstance(item, dict)} != EXPECTED_ROOTS:
        fail("saved-plan roots differ")
    changed = {item.get("root") for item in plans if isinstance(item, dict) and item.get("changed") is True}
    if changed != {"proxmox"}:
        fail("only the Proxmox root may contain the state move")

    proxmox_plan: Path | None = None
    for item in plans:
        if not isinstance(item, dict):
            fail("saved-plan entry must be an object")
        file = item.get("file")
        expected_sha = item.get("sha256")
        if not isinstance(file, str) or not isinstance(expected_sha, str):
            fail("saved-plan filename or digest is invalid")
        path = plan_dir / file
        if sha256(path) != expected_sha:
            fail(f"saved-plan digest differs: {file}")
        if item.get("root") == "proxmox":
            proxmox_plan = path

    host_plan = manifest.get("proxmox_host_plan")
    if not isinstance(host_plan, dict) or host_plan.get("actions") != 0 or host_plan.get("status") != "ready":
        fail("Proxmox host plan is not an exact zero-action ready plan")
    if proxmox_plan is None:
        fail("Proxmox plan is missing")

    plan = json.loads(subprocess.run(
        ["tofu", f"-chdir={repo / 'infrastructure/tofu/proxmox'}", "show", "-json", str(proxmox_plan)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout)
    changes = plan.get("resource_changes")
    if not isinstance(changes, list) or not changes:
        fail("Proxmox plan has no resource records")
    moved = []
    for change in changes:
        if not isinstance(change, dict) or change.get("change", {}).get("actions") != ["no-op"]:
            fail("state-only plan contains an infrastructure action")
        previous = change.get("previous_address")
        if previous is not None:
            moved.append((previous, change.get("address")))
        values = change.get("change", {})
        if values.get("before") != values.get("after"):
            fail("state-only plan changes resource values")
    if moved != [(OLD_ADDRESS, NEW_ADDRESS)]:
        fail("state-only plan does not contain the exact Arch-to-Debian address move")

    output_changes = plan.get("output_changes", {})
    if not isinstance(output_changes, dict) or any(
        not isinstance(value, dict) or value.get("actions") != ["no-op"] or value.get("before") != value.get("after")
        for value in output_changes.values()
    ):
        fail("state-only plan changes outputs")

    note = json.loads(git(repo, "notes", "--ref=refs/notes/debian-qualification", "show", commit))
    if note.get("commit") != commit or note.get("manifestSha256") != sha256(manifest_path):
        fail("state-only plan note is not bound to the exact commit and manifest")
    if note.get("allActionsZero") is not True or note.get("proxmoxHostActions") != 0:
        fail("state-only plan note does not attest zero actions")
    if note.get("stateOnlyMoves") != [{"from": OLD_ADDRESS, "to": NEW_ADDRESS}]:
        fail("state-only plan note does not attest the exact address move")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--plan-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.repo_root, args.plan_dir)
    except (json.JSONDecodeError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"debian_state_only_move=refused reason={error}", file=sys.stderr)
        return 1
    print("debian_state_only_move=authorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
