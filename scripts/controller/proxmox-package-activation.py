#!/usr/bin/env python3
"""Build, prepare, and apply exact saved Proxmox package activations."""

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
OUTPUT = ROOT / ".local/proxmox-package-activations"
LOCK = ROOT / ".local/proxmox-package-activation.lock"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes", "ansible-deploy@proxmox")


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
        raise SystemExit("package activation requires clean pushed HEAD")
    return commit


def load_private(path: Path, label: str) -> tuple[dict, bytes]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or raw != canonical(value):
        raise SystemExit(f"{label} metadata or canonical content differs")
    return value, raw


def build(maintenance_path: Path, access_receipt_path: Path) -> tuple[Path, str]:
    commit = clean_pushed_commit(); maintenance, raw = load_private(maintenance_path, "maintenance plan")
    access_receipt, access_raw = load_private(access_receipt_path, "access evidence receipt")
    if maintenance_path.name != f"{maintenance.get('plan_sha256')}.json" or maintenance.get("format") != "home-lab-host-maintenance-plan-v1" or maintenance.get("kind") != "package" or maintenance.get("host") != "proxmox" or maintenance.get("authorized") is not False or maintenance.get("actionable") is not True or maintenance.get("bindings", {}).get("git_commit") != commit:
        raise SystemExit("maintenance package plan is not exact, current, and actionable")
    if datetime.now(timezone.utc) > datetime.fromisoformat(maintenance["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("maintenance package plan expired")
    proposal = maintenance["evidence"]
    if proposal.get("holds") != [] or proposal.get("change_counts", {}).get("remove") or proposal.get("change_counts", {}).get("downgrade") or not proposal.get("changes"):
        raise SystemExit("maintenance package proposal is unsafe")
    proofs = access_receipt.get("proofs", {})
    if access_receipt.get("format") != "home-lab-proxmox-access-evidence-v1" or access_receipt.get("commit") != commit or proofs.get("console", {}).get("attested") is not True or proofs.get("plan_observer", {}).get("positive") is not True or proofs.get("deploy_transport", {}).get("positive") is not True or proofs.get("human_session", {}).get("positive") is not True:
        raise SystemExit("current access and console evidence is incomplete")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    activation = {"format": "home-lab-proxmox-package-activation-v1", "commit": commit,
                  "contract_sha256": file_sha(ROOT / "infrastructure/contract/home-lab.yml"),
                  "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml"),
                  "host_key_fingerprint": FINGERPRINT, "created_at": now.isoformat().replace("+00:00", "Z"),
                  "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
                  "maintenance_plan_sha256": maintenance["plan_sha256"], "proposal": proposal,
                  "access_evidence_sha256": sha(access_raw), "console_attested": True,
                  "automatic_reboot": False, "authorized": False}
    activation_raw = canonical(activation); digest = sha(activation_raw); OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    target = OUTPUT / f"{digest}.json"; fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(activation_raw); handle.flush(); os.fsync(handle.fileno())
    return target, digest


def validate_activation(path: Path) -> tuple[dict, bytes, str]:
    value, raw = load_private(path, "package activation"); digest = sha(raw)
    if path.name != f"{digest}.json" or value.get("format") != "home-lab-proxmox-package-activation-v1" or value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or value.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml") or value.get("host_key_fingerprint") != FINGERPRINT or value.get("automatic_reboot") is not False or value.get("authorized") is not False:
        raise SystemExit("package activation source binding differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("package activation expired")
    return value, raw, digest


def stage(raw: bytes, digest: str) -> None:
    inspected = subprocess.run((*SSH, f"inspect package {digest}"), capture_output=True, timeout=60)
    if inspected.returncode == 0 and inspected.stdout == b'{"present":true}\n' and not inspected.stderr:
        return
    if inspected.returncode != 66:
        raise SystemExit("package activation remote inspection failed")
    staged = subprocess.run((*SSH, f"stage package {digest}"), input=raw, capture_output=True, timeout=120)
    if staged.returncode or staged.stderr or staged.stdout != b'{"staged":true}\n':
        raise SystemExit("package activation remote staging failed")


def prepare(path: Path) -> None:
    value, raw, digest = validate_activation(path)
    expected = f"prepare-proxmox-package-{digest}"
    if os.environ.get("PROXMOX_PACKAGE_PREPARE_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock = acquire_transfer_lock(LOCK)
    try:
        stage(raw, digest)
        result = subprocess.run((*SSH, f"prepare package {digest}"), capture_output=True, timeout=2100)
    finally:
        os.close(lock)
    if result.returncode or result.stderr:
        raise SystemExit("package preparation failed")
    output = json.loads(result.stdout)
    if output.get("package_transaction") not in {"prepared", "already-prepared"} or output.get("plan_sha256") != digest:
        raise SystemExit("package preparation result differs")
    receipt = {"format": "home-lab-proxmox-package-preparation-v1", "activation_sha256": digest, "commit": value["commit"],
               "prepared_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
               "result": output, "automatic_reboot": False}
    receipt_raw = canonical(receipt); receipt_digest = sha(receipt_raw); target = OUTPUT / f"prepared-{receipt_digest}.json"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(receipt_raw); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"activation_sha256": digest, "preparation_sha256": receipt_digest, "receipt": str(target)}, sort_keys=True))


def apply(path: Path, receipt_path: Path) -> None:
    value, raw, digest = validate_activation(path); receipt, _ = load_private(receipt_path, "package preparation receipt")
    if receipt.get("format") != "home-lab-proxmox-package-preparation-v1" or receipt.get("activation_sha256") != digest or receipt.get("commit") != value["commit"] or receipt.get("automatic_reboot") is not False:
        raise SystemExit("package preparation receipt binding differs")
    expected = f"apply-proxmox-package-{digest}"
    if os.environ.get("PROXMOX_PACKAGE_APPLY_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    lock = acquire_transfer_lock(LOCK)
    try:
        stage(raw, digest)
        result = subprocess.run((*SSH, f"apply package {digest}"), capture_output=True, timeout=3900)
    finally:
        os.close(lock)
    if result.returncode or result.stderr:
        raise SystemExit("package apply failed; inspect the retained root-only journal before recovery")
    output = json.loads(result.stdout)
    if output.get("package_transaction") not in {"committed", "already-committed"} or output.get("plan_sha256") != digest or output.get("automatic_reboot") is not False:
        raise SystemExit("package apply result differs")
    print(json.dumps(output, sort_keys=True))


def main() -> None:
    parser=argparse.ArgumentParser(); commands=parser.add_subparsers(dest="command",required=True); built=commands.add_parser("build"); built.add_argument("maintenance_plan",type=Path); built.add_argument("access_receipt",type=Path); prepared=commands.add_parser("prepare"); prepared.add_argument("activation",type=Path); applied=commands.add_parser("apply"); applied.add_argument("activation",type=Path); applied.add_argument("preparation_receipt",type=Path); args=parser.parse_args()
    if args.command == "build":
        path,digest=build(args.maintenance_plan.resolve(), args.access_receipt.resolve()); print(json.dumps({"authorized":False,"activation_sha256":digest,"path":str(path)},sort_keys=True))
    elif args.command == "prepare": prepare(args.activation.resolve())
    else: apply(args.activation.resolve(), args.preparation_receipt.resolve())


if __name__ == "__main__": main()
