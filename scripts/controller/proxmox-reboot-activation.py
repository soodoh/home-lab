#!/usr/bin/env python3
"""Build and execute one exact, separately authorized Proxmox reboot activation."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from protected_execution import acquire_transfer_lock

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-reboot-activations"
LOCK = ROOT / ".local/locks/proxmox-reboot.lock"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "ansible-deploy@proxmox")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("reboot activation requires clean pushed HEAD")
    return commit


def load_private(path: Path, label: str) -> tuple[dict, bytes]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 1024 * 1024:
        raise SystemExit(f"{label} metadata differs")
    raw = path.read_bytes(); value = json.loads(raw)
    if raw != canonical(value):
        raise SystemExit(f"{label} is not canonical")
    return value, raw


def build(maintenance_path: Path, backup_path: Path, access_path: Path) -> tuple[Path, str]:
    commit = clean_pushed_commit(); maintenance, maintenance_raw = load_private(maintenance_path, "maintenance plan")
    backup, backup_raw = load_private(backup_path, "backup attestation"); access, access_raw = load_private(access_path, "access evidence")
    bindings = maintenance.get("bindings", {}); evidence = maintenance.get("evidence", {})
    if maintenance.get("format") != "home-lab-host-maintenance-plan-v1" or maintenance.get("kind") != "reboot" or maintenance.get("host") != "proxmox" or maintenance.get("authorized") is not False or maintenance.get("actionable") is not True or maintenance.get("blockers") != ["saved-reviewed-plan-required", "separate-reboot-authorization-required"]:
        raise SystemExit("maintenance plan is not actionable reboot evidence")
    if bindings.get("git_commit") != commit or bindings.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or bindings.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml") or bindings.get("host_key_fingerprint") != FINGERPRINT:
        raise SystemExit("maintenance plan source binding differs")
    material = {key: item for key, item in maintenance.items() if key != "plan_sha256"}
    if sha(canonical(material)) != maintenance.get("plan_sha256") or sha(canonical(evidence)) != maintenance.get("evidence_sha256") or datetime.now(timezone.utc) > datetime.fromisoformat(maintenance["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("maintenance plan hash or freshness differs")
    if backup.get("format") != "home-lab-proxmox-reboot-backup-attestation-v1" or backup.get("commit") != commit or backup.get("authorized") is not False or backup.get("automatic_reboot") is not False or backup.get("evidence", {}).get("pending_records") != 0 or backup.get("evidence", {}).get("proton_copy_records", 0) < 1 or backup.get("evidence", {}).get("age_seconds", 86401) > 86400 or any(backup.get("evidence", {}).get(name, {}).get("result") != "success" for name in ("local_service", "proton_service")):
        raise SystemExit("backup attestation differs")
    proofs = access.get("proofs", {})
    if access.get("format") != "home-lab-proxmox-access-evidence-v1" or access.get("commit") != commit or proofs.get("console", {}).get("attested") is not True or proofs.get("plan_observer", {}).get("positive") is not True or proofs.get("deploy_transport", {}).get("positive") is not True or proofs.get("human_session", {}).get("positive") is not True:
        raise SystemExit("access and console evidence is incomplete")
    expected = {"boot_id": evidence["boot_id"], "current_kernel": evidence["current_kernel"], "target_kernel": evidence["target_kernel"]}
    activation = {"format": "home-lab-proxmox-reboot-activation-v1", "commit": commit,
                  "contract_sha256": bindings["contract_sha256"], "inventory_sha256": bindings["inventory_sha256"],
                  "host_key_fingerprint": FINGERPRINT, "created_at": maintenance["created_at"], "expires_at": maintenance["expires_at"],
                  "maintenance_plan_sha256": maintenance["plan_sha256"], "backup_attestation_sha256": sha(backup_raw),
                  "access_evidence_sha256": sha(access_raw), "console_attested": True,
                  "expected": expected, "evidence": {"boot_id": evidence["boot_id"], "current_kernel": evidence["current_kernel"],
                  "target_kernel": evidence["target_kernel"], "reboot_indicated": evidence["reboot_indicated"],
                  "health": evidence["health"], "evidence_sha256": evidence["evidence_sha256"]},
                  "automatic_reboot": False, "authorized": False}
    raw = canonical(activation); digest = sha(raw); OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    target = OUTPUT / f"{digest}.json"; fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return target, digest


def validate_activation(path: Path, allow_expired: bool = False) -> tuple[dict, bytes, str]:
    value, raw = load_private(path, "reboot activation"); digest = sha(raw)
    if path.name != f"{digest}.json" or value.get("format") != "home-lab-proxmox-reboot-activation-v1" or value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or value.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml") or value.get("host_key_fingerprint") != FINGERPRINT or value.get("automatic_reboot") is not False or value.get("authorized") is not False:
        raise SystemExit("reboot activation source binding differs")
    if not allow_expired and datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("reboot activation expired")
    return value, raw, digest


def stage(raw: bytes, digest: str) -> None:
    inspected = subprocess.run((*SSH, f"inspect reboot {digest}"), capture_output=True, timeout=60)
    if inspected.returncode == 0 and inspected.stdout == b'{"present":true}\n' and not inspected.stderr:
        return
    if inspected.returncode != 66:
        raise SystemExit("reboot activation remote inspection failed")
    staged = subprocess.run((*SSH, f"stage reboot {digest}"), input=raw, capture_output=True, timeout=120)
    if staged.returncode or staged.stderr or staged.stdout != b'{"staged":true}\n':
        raise SystemExit("reboot activation remote staging failed")


def prepare(path: Path) -> None:
    value, raw, digest = validate_activation(path); expected = f"prepare-proxmox-reboot-{digest}"
    if os.environ.get("PROXMOX_REBOOT_PREPARE_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock = acquire_transfer_lock(LOCK)
    try:
        stage(raw, digest); result = subprocess.run((*SSH, f"prepare reboot {digest}"), capture_output=True, timeout=600)
    finally:
        os.close(lock)
    if result.returncode or result.stderr:
        raise SystemExit("reboot preparation failed")
    output = json.loads(result.stdout)
    if output.get("reboot_transaction") not in {"prepared", "already-prepared"} or output.get("plan_sha256") != digest:
        raise SystemExit("reboot preparation result differs")
    receipt = {"format": "home-lab-proxmox-reboot-preparation-v1", "activation_sha256": digest, "commit": value["commit"],
               "prepared_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "result": output,
               "automatic_reboot": False}
    receipt_raw = canonical(receipt); receipt_digest = sha(receipt_raw); target = OUTPUT / f"prepared-{receipt_digest}.json"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(receipt_raw); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"activation_sha256": digest, "preparation_sha256": receipt_digest, "receipt": str(target)}, sort_keys=True))


def apply(path: Path, receipt_path: Path) -> None:
    value, raw, digest = validate_activation(path); receipt, _ = load_private(receipt_path, "reboot preparation receipt")
    if receipt.get("format") != "home-lab-proxmox-reboot-preparation-v1" or receipt.get("activation_sha256") != digest or receipt.get("commit") != value["commit"] or receipt.get("automatic_reboot") is not False:
        raise SystemExit("reboot preparation receipt binding differs")
    expected = f"apply-proxmox-reboot-{digest}"
    if os.environ.get("PROXMOX_REBOOT_APPLY_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock = acquire_transfer_lock(LOCK)
    try:
        result = subprocess.run((*SSH, f"apply reboot {digest}"), capture_output=True, timeout=120)
        if result.returncode not in {0, 255}:
            raise SystemExit("reboot initiation failed")
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            time.sleep(10)
            verified = subprocess.run((*SSH, f"verify reboot {digest}"), capture_output=True, timeout=60)
            if verified.returncode != 0:
                continue
            output = json.loads(verified.stdout)
            if not verified.stderr and output.get("reboot_transaction") in {"committed", "already-committed"} and output.get("plan_sha256") == digest and output.get("current_kernel") == value["expected"]["target_kernel"]:
                print(json.dumps(output, sort_keys=True)); return
        raise SystemExit("reboot verification timed out; use physical console and inspect the root-only journal")
    finally:
        os.close(lock)


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    built = commands.add_parser("build"); built.add_argument("maintenance_plan", type=Path); built.add_argument("backup_attestation", type=Path); built.add_argument("access_receipt", type=Path)
    prepared = commands.add_parser("prepare"); prepared.add_argument("activation", type=Path)
    applied = commands.add_parser("apply"); applied.add_argument("activation", type=Path); applied.add_argument("preparation_receipt", type=Path); args = parser.parse_args()
    if args.command == "build":
        path, digest = build(args.maintenance_plan.resolve(), args.backup_attestation.resolve(), args.access_receipt.resolve()); print(json.dumps({"authorized": False, "activation_sha256": digest, "path": str(path)}, sort_keys=True))
    elif args.command == "prepare": prepare(args.activation.resolve())
    else: apply(args.activation.resolve(), args.preparation_receipt.resolve())


if __name__ == "__main__": main()
