#!/usr/bin/env python3
"""Build, apply, and recover one protected Proxmox VFIO source cleanup."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from protected_execution import acquire_transfer_lock


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-boot-configuration-activations"
LOCK = ROOT / ".local/locks/proxmox-boot-configuration.lock"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "UpdateHostKeys=no", "ansible-deploy@proxmox")
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
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
        raise SystemExit("protected boot activation requires clean pushed HEAD")
    return commit


def observe() -> dict:
    result = subprocess.run((*SSH, "observe boot-configuration"), capture_output=True, timeout=120)
    if result.returncode or result.stderr or len(result.stdout) > 65536:
        raise SystemExit("fixed protected boot observation failed")
    value = json.loads(result.stdout)
    required = {"commit", "contract_sha256", "expected_source_sha256", "expected_vfio_device_count",
                "expected_vfio_devices_bound", "format", "initramfs", "source",
                "unexpected_vfio_device_count", "version"}
    if not isinstance(value, dict) or set(value) != required or \
            value.get("format") != "home-lab-proxmox-protected-boot-observation-v1" or value.get("version") != 1 or \
            not isinstance(value.get("source"), dict) or not isinstance(value.get("initramfs"), list) or \
            len(value["initramfs"]) != 2 or value.get("expected_vfio_device_count") != 2 or \
            value.get("expected_vfio_devices_bound") != 2 or value.get("unexpected_vfio_device_count") != 1:
        raise SystemExit("protected boot observation shape or retirement residue differs")
    source = value["source"]
    if source.get("path") != "/etc/modprobe.d/home-lab-vfio.conf" or source.get("uid") != 0 or \
            source.get("gid") != 0 or source.get("mode") != "0644" or source.get("nlink") != 1 or \
            source.get("sha256") == value.get("expected_source_sha256"):
        raise SystemExit("protected boot source is not the exact actionable residue")
    if {item.get("role") for item in value["initramfs"]} != {"current", "fallback"} or \
            any(item.get("uid") != 0 or item.get("gid") != 0 or item.get("mode") != "0644" or
                item.get("nlink") != 1 for item in value["initramfs"]):
        raise SystemExit("retained initramfs observation differs")
    return value


def write_activation(value: dict) -> tuple[Path, str]:
    raw = canonical(value); digest = sha(raw)
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    target = OUTPUT / f"{digest}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return target, digest


def build() -> tuple[Path, str]:
    commit = clean_pushed_commit(); before = observe(); now = datetime.now(timezone.utc).replace(microsecond=0)
    contract = ROOT / "infrastructure/contract/home-lab.yml"
    if before["commit"] != commit or before["contract_sha256"] != file_sha(contract):
        raise SystemExit("protected boot host checkout binding differs")
    activation = {
        "activator_sha256": file_sha(ACTIVATOR),
        "authorized": False,
        "automatic_reboot": False,
        "before": before,
        "commit": commit,
        "contract_schema_sha256": file_sha(ROOT / "infrastructure/contract/schema.json"),
        "contract_sha256": file_sha(contract),
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "domain": "boot-configuration",
        "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
        "format": "home-lab-proxmox-protected-boot-activation-v1",
        "host": "proxmox",
        "host_key_fingerprint": FINGERPRINT,
        "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml"),
        "playbook_sha256": file_sha(PLAYBOOK),
        "protected_values_exported": False,
        "rebuild_initramfs": True,
        "reboot_required": True,
        "role_sha256": file_sha(ROLE),
        "transport_sha256": file_sha(TRANSPORT),
    }
    return write_activation(activation)


def load_activation(path: Path, allow_expired: bool = False) -> tuple[dict, bytes, str]:
    metadata = path.lstat(); raw = path.read_bytes(); digest = sha(raw)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.getuid() or \
            metadata.st_nlink != 1 or metadata.st_size > 65536 or path.name != f"{digest}.json":
        raise SystemExit("protected boot activation metadata differs")
    value = json.loads(raw)
    if raw != canonical(value) or value.get("format") != "home-lab-proxmox-protected-boot-activation-v1" or \
            value.get("authorized") is not False or value.get("automatic_reboot") is not False or \
            value.get("protected_values_exported") is not False or value.get("rebuild_initramfs") is not True or \
            value.get("reboot_required") is not True:
        raise SystemExit("protected boot activation is not canonical and inert")
    commit = clean_pushed_commit()
    bindings = {
        "activator_sha256": file_sha(ACTIVATOR), "commit": commit,
        "contract_schema_sha256": file_sha(ROOT / "infrastructure/contract/schema.json"),
        "contract_sha256": file_sha(ROOT / "infrastructure/contract/home-lab.yml"),
        "host_key_fingerprint": FINGERPRINT,
        "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml"),
        "playbook_sha256": file_sha(PLAYBOOK), "role_sha256": file_sha(ROLE),
        "transport_sha256": file_sha(TRANSPORT),
    }
    if any(value.get(name) != expected for name, expected in bindings.items()):
        raise SystemExit("protected boot activation source binding differs")
    if not allow_expired and datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("protected boot activation expired")
    return value, raw, digest


def stage(raw: bytes, digest: str) -> None:
    inspected = subprocess.run((*SSH, f"inspect boot-configuration {digest}"), capture_output=True, timeout=60)
    if inspected.returncode == 0 and inspected.stdout == b'{"present":true}\n' and not inspected.stderr:
        return
    if inspected.returncode != 66:
        raise SystemExit("protected boot activation remote inspection failed")
    staged = subprocess.run((*SSH, f"stage boot-configuration {digest}"), input=raw, capture_output=True, timeout=120)
    if staged.returncode or staged.stderr or staged.stdout != b'{"staged":true}\n':
        raise SystemExit("protected boot activation remote staging failed")


def controller_lock() -> int:
    LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(LOCK.parent, 0o700)
    return acquire_transfer_lock(LOCK)


def apply(path: Path) -> None:
    value, raw, digest = load_activation(path)
    expected = f"apply-proxmox-boot-configuration-{digest}"
    if os.environ.get("PROXMOX_BOOT_CONFIGURATION_APPLY_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock = controller_lock()
    try:
        if observe() != value["before"]:
            raise SystemExit("protected boot activation evidence changed")
        stage(raw, digest)
        result = subprocess.run((*SSH, f"apply boot-configuration {digest}"), capture_output=True, timeout=1800)
    finally:
        os.close(lock)
    if result.returncode or result.stderr:
        raise SystemExit("protected boot apply failed; inspect the retained root-only journal before recovery")
    output = json.loads(result.stdout)
    expected_output = {"boot_configuration_transaction": "committed", "changed": True,
                       "plan_sha256": digest, "rebooted": False}
    if output != expected_output:
        raise SystemExit("protected boot activation receipt differs")
    print(json.dumps(output, sort_keys=True))


def recover(path: Path) -> None:
    _, _, digest = load_activation(path, allow_expired=True)
    expected = f"recover-proxmox-boot-configuration-{digest}"
    if os.environ.get("PROXMOX_BOOT_CONFIGURATION_RECOVER_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock = controller_lock()
    try:
        result = subprocess.run((*SSH, f"recover boot-configuration {digest}"), capture_output=True, timeout=900)
    finally:
        os.close(lock)
    if result.returncode or result.stderr:
        raise SystemExit("protected boot recovery failed; inspect the retained root-only journal")
    output = json.loads(result.stdout)
    if output.get("plan_sha256") != digest or output.get("boot_configuration_transaction") not in {"committed", "rolled-back"} or \
            output.get("rebooted") is not False:
        raise SystemExit("protected boot recovery receipt differs")
    print(json.dumps(output, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("build")
    applied = commands.add_parser("apply"); applied.add_argument("activation", type=Path)
    recovered = commands.add_parser("recover"); recovered.add_argument("activation", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        path, digest = build(); print(json.dumps({"activation_sha256": digest, "authorized": False, "path": str(path)}, sort_keys=True))
    elif args.command == "apply":
        apply(args.activation.resolve())
    else:
        recover(args.activation.resolve())


if __name__ == "__main__":
    main()
