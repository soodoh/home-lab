#!/usr/bin/env python3
"""Build and apply one no-mutation Proxmox package-set ownership receipt."""

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
OUTPUT = ROOT / ".local/proxmox-package-ownership-activations"
LOCK = ROOT / ".local/locks/proxmox-package-ownership.lock"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "UpdateHostKeys=no", "ansible-deploy@proxmox")
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
SCHEMA = ROOT / "infrastructure/contract/schema.json"
INVENTORY = ROOT / "ansible/inventory/production.yml"
ROLE = ROOT / "ansible/roles/package_lifecycle/tasks/main.yml"
CONSUMER_ROLE = ROOT / "ansible/roles/package_lifecycle/defaults/main.yml"
PLAYBOOK = ROOT / "ansible/playbooks/packages-plan.yml"
MANIFEST = ROOT / "nix/proxmox/package-manifest.json"


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
        raise SystemExit("PACKAGE ownership activation requires clean pushed HEAD")
    return commit


def transferred_contract() -> None:
    script = "const fs=require('node:fs'),{load}=require('js-yaml');const v=load(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(JSON.stringify(v.lifecycle.hosts.proxmox.domain_handoffs.package_set));"
    result = subprocess.run(("node", "-e", script, str(CONTRACT)), cwd=ROOT, capture_output=True, text=True, timeout=30)
    expected = {"current_owner": "ansible", "target_owner": "ansible", "state": "transferred",
                "parity_required": True, "single_writer": True}
    if result.returncode or result.stderr or json.loads(result.stdout) != expected:
        raise SystemExit("Package-set ownership is not transferred to Ansible")


def observe() -> dict:
    result = subprocess.run((*SSH, "observe package-lifecycle"), capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("PACKAGE ownership observation failed")
    value = json.loads(result.stdout)
    if value.get("format") != "home-lab-proxmox-package-ownership-observation-v1" or \
            value.get("parity_complete") is not True or value.get("protected_values_exported") is not False or \
            value.get("active_lifecycle_locks"):
        raise SystemExit("PACKAGE ownership parity is incomplete")
    return value


def consumer_parity() -> None:
    result = subprocess.run(("ansible-playbook", "-i", "inventory/production.yml", "playbooks/packages-plan.yml",
                             "--check"), cwd=ROOT / "ansible", capture_output=True, text=True, timeout=600)
    output = result.stdout
    if result.returncode or result.stderr or \
            "docker-host-production" not in output or "proxmox-host-production" not in output or \
            output.count("changed=0") < 2 or "failed=0" not in output:
        raise SystemExit("package consumer parity check failed")


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
    consumer_parity()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    value = {
        "activator_sha256": file_sha(ACTIVATOR), "authorized": False, "automatic_reboot": False,
        "before": before, "changed": False, "commit": commit, "consumer_parity_verified": True,
        "consumer_role_sha256": file_sha(CONSUMER_ROLE), "contract_schema_sha256": file_sha(SCHEMA),
        "contract_sha256": file_sha(CONTRACT), "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
        "format": "home-lab-proxmox-package-ownership-activation-v1", "host_key_fingerprint": FINGERPRINT,
        "inventory_sha256": file_sha(INVENTORY), "package_manifest_sha256": file_sha(MANIFEST),
        "playbook_sha256": file_sha(PLAYBOOK), "protected_values_exported": False,
        "role_sha256": file_sha(ROLE), "transport_sha256": file_sha(TRANSPORT),
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
        raise SystemExit("PACKAGE ownership activation metadata differs")
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
        raise SystemExit("PACKAGE ownership controller lock is active") from error
    return descriptor


def apply(path: Path) -> None:
    value, raw, digest = load(path)
    expected = f"apply-proxmox-package-ownership-{digest}"
    if os.environ.get("PROXMOX_PACKAGE_OWNERSHIP_APPLY_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    bindings = {"commit": clean_pushed_commit(), "contract_sha256": file_sha(CONTRACT),
                "contract_schema_sha256": file_sha(SCHEMA), "inventory_sha256": file_sha(INVENTORY),
                "package_manifest_sha256": file_sha(MANIFEST), "role_sha256": file_sha(ROLE),
                "consumer_role_sha256": file_sha(CONSUMER_ROLE), "playbook_sha256": file_sha(PLAYBOOK),
                "transport_sha256": file_sha(TRANSPORT), "activator_sha256": file_sha(ACTIVATOR)}
    if any(value.get(key) != expected_value for key, expected_value in bindings.items()) or \
            datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("PACKAGE ownership activation binding or freshness differs")
    transferred_contract()
    consumer_parity()
    if observe() != value.get("before"):
        raise SystemExit("PACKAGE ownership observation changed after planning")
    descriptor = controller_lock()
    try:
        staged = subprocess.run((*SSH, f"stage package-ownership {digest}"), input=raw, capture_output=True, timeout=120)
        if staged.returncode or staged.stderr or json.loads(staged.stdout) != {"staged": True}:
            raise SystemExit("PACKAGE ownership staging failed")
        result = subprocess.run((*SSH, f"apply package-ownership {digest}"), capture_output=True, timeout=300)
    finally:
        os.close(descriptor)
    if result.returncode or result.stderr:
        raise SystemExit("PACKAGE ownership activation failed")
    output = json.loads(result.stdout)
    if output.get("package_ownership_transaction") not in {"committed", "already-committed"} or \
            output.get("changed") is not False or output.get("plan_sha256") != digest:
        raise SystemExit("PACKAGE ownership activation result differs")
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
