#!/usr/bin/env python3
"""Build and apply one no-mutation Proxmox boot ownership receipt."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-boot-ownership-activations"
LOCK = ROOT / ".local/locks/proxmox-boot-ownership.lock"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "UpdateHostKeys=no", "ansible-deploy@proxmox")
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
SCHEMA = ROOT / "infrastructure/contract/schema.json"
INVENTORY = ROOT / "ansible/inventory/production.yml"
ROLE = ROOT / "ansible/roles/proxmox_boot_configuration/tasks/main.yml"
PLAYBOOK = ROOT / "ansible/playbooks/proxmox-boot-configuration-plan.yml"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def git(*arguments: str) -> str:
    return subprocess.check_output(("git", *arguments), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("boot ownership activation requires clean pushed HEAD")
    return commit


def transferred_contract() -> None:
    script = "const fs=require('node:fs'),{load}=require('js-yaml');const v=load(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(JSON.stringify(v.lifecycle.hosts.proxmox.domain_handoffs.boot_configuration));"
    result = subprocess.run(("node", "-e", script, str(CONTRACT)), cwd=ROOT, capture_output=True, text=True, timeout=30)
    expected = {"current_owner": "ansible", "target_owner": "ansible", "state": "transferred",
                "parity_required": True, "single_writer": True}
    if result.returncode or result.stderr or json.loads(result.stdout) != expected:
        raise SystemExit("boot ownership is not transferred to Ansible")


def observe() -> dict:
    result = subprocess.run((*SSH, "observe boot-configuration"), capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("boot ownership observation failed")
    value = json.loads(result.stdout)
    if value.get("format") != "home-lab-proxmox-protected-boot-observation-v1" or \
            value.get("source", {}).get("sha256") != value.get("expected_source_sha256") or \
            value.get("unexpected_vfio_device_count") != 0 or \
            value.get("expected_vfio_devices_bound") != value.get("expected_vfio_device_count"):
        raise SystemExit("boot ownership parity is incomplete")
    return value


def write_private(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def build() -> tuple[Path, str]:
    commit = clean_pushed_commit()
    transferred_contract()
    before = observe()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    value = {
        "activator_sha256": file_sha(ACTIVATOR),
        "authorized": False,
        "automatic_reboot": False,
        "before": before,
        "changed": False,
        "commit": commit,
        "contract_schema_sha256": file_sha(SCHEMA),
        "contract_sha256": file_sha(CONTRACT),
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
        "format": "home-lab-proxmox-boot-ownership-activation-v1",
        "host_key_fingerprint": FINGERPRINT,
        "inventory_sha256": file_sha(INVENTORY),
        "playbook_sha256": file_sha(PLAYBOOK),
        "protected_values_exported": False,
        "role_sha256": file_sha(ROLE),
        "transport_sha256": file_sha(TRANSPORT),
    }
    raw = canonical(value)
    digest = sha(raw)
    path = OUTPUT / f"{digest}.json"
    write_private(path, raw)
    return path, digest


def load(path: Path) -> tuple[dict, bytes, str]:
    metadata = path.lstat()
    raw = path.read_bytes()
    value = json.loads(raw)
    digest = sha(raw)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.getuid() or \
            stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or path.parent != OUTPUT or \
            path.name != f"{digest}.json" or raw != canonical(value):
        raise SystemExit("boot ownership activation metadata differs")
    return value, raw, digest


def controller_lock() -> int:
    LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(LOCK.parent, 0o700)
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    import fcntl
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise SystemExit("boot ownership controller lock is active") from error
    return descriptor


def apply(path: Path) -> None:
    value, raw, digest = load(path)
    expected = f"apply-proxmox-boot-ownership-{digest}"
    if os.environ.get("PROXMOX_BOOT_OWNERSHIP_APPLY_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    if value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != file_sha(CONTRACT) or \
            value.get("contract_schema_sha256") != file_sha(SCHEMA) or value.get("inventory_sha256") != file_sha(INVENTORY) or \
            value.get("role_sha256") != file_sha(ROLE) or value.get("playbook_sha256") != file_sha(PLAYBOOK) or \
            value.get("transport_sha256") != file_sha(TRANSPORT) or value.get("activator_sha256") != file_sha(ACTIVATOR) or \
            datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("boot ownership activation binding or freshness differs")
    transferred_contract()
    if observe() != value.get("before"):
        raise SystemExit("boot ownership observation changed after planning")
    descriptor = controller_lock()
    try:
        staged = subprocess.run((*SSH, f"stage boot-ownership {digest}"), input=raw, capture_output=True, timeout=120)
        if staged.returncode or staged.stderr or json.loads(staged.stdout) != {"staged": True}:
            raise SystemExit("boot ownership staging failed")
        result = subprocess.run((*SSH, f"apply boot-ownership {digest}"), capture_output=True, timeout=300)
    finally:
        os.close(descriptor)
    if result.returncode or result.stderr:
        raise SystemExit("boot ownership activation failed")
    output = json.loads(result.stdout)
    if output.get("boot_ownership_transaction") not in {"committed", "already-committed"} or \
            output.get("changed") is not False or output.get("plan_sha256") != digest:
        raise SystemExit("boot ownership activation result differs")
    print(json.dumps(output, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("build")
    applied = commands.add_parser("apply")
    applied.add_argument("activation", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "build":
        path, digest = build()
        print(json.dumps({"activation_sha256": digest, "authorized": False, "path": str(path)}, sort_keys=True))
    else:
        apply(arguments.activation.resolve())


if __name__ == "__main__":
    main()
