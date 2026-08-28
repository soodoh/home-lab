#!/usr/bin/env python3
"""Create and authorize an immutable, no-host-mutation timezone ownership handoff."""

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
PLAN_DIR = ROOT / ".local/proxmox-timezone-handoff"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "ansible-plan@proxmox", "observe")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("timezone handoff requires clean pushed HEAD")
    return commit


def observe() -> dict:
    result = subprocess.run(SSH, capture_output=True, timeout=60)
    if result.returncode or result.stderr or len(result.stdout) > 1024 * 1024:
        raise SystemExit("fixed timezone observation failed")
    value = json.loads(result.stdout)
    domain = value.get("domains", {}).get("timezone")
    expected = {"records": [{"name": "system", "timezone": "America/Los_Angeles"}], "status": "complete", "unexpectedCount": 0}
    if domain != expected or value.get("format") != "home-lab-proxmox-observation-v1" or value.get("protocol") != 4:
        raise SystemExit("fixed observer does not prove exact timezone parity")
    return {"observer_sha256": value.get("observerSha256"), "timezone": domain}


def source_proof() -> dict:
    projection = (ROOT / "scripts/controller/proxmox-nix-projection.js").read_text()
    planner = (ROOT / "nix/proxmox/planner.py").read_text()
    activator = (ROOT / "nix/proxmox/activator-template.py").read_text()
    contract = (ROOT / "infrastructure/contract/home-lab.yml").read_text()
    proof = {
        "contract_transferred": "current_owner: ansible\n          target_owner: ansible\n          state: transferred" in contract,
        "nix_planning_domain_absent": "- { domain: timezone," not in contract,
        "projection_mutation_absent": "\n    timezone: systemTimezone" not in projection,
        "planner_action_absent": '"timezone": "set-timezone"' not in planner,
        "planner_desired_absent": '"timezone": [{"name": "system"' not in planner,
        "activator_mutation_absent": "set_timezone(" not in activator and 'item["domain"] == "timezone"' not in activator,
        "ansible_gate_present": "base_timezone_mutation_authorized" in (ROOT / "ansible/roles/base/tasks/main.yml").read_text(),
    }
    if not all(proof.values()):
        raise SystemExit("timezone ownership source exclusion proof failed")
    return proof


def make_plan() -> tuple[dict, str, Path]:
    commit = clean_pushed_commit()
    evidence = observe()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    plan = {
        "format": "home-lab-proxmox-timezone-handoff-v1",
        "commit": commit,
        "contract_sha256": file_sha(ROOT / "infrastructure/contract/home-lab.yml"),
        "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml"),
        "host_key_fingerprint": FINGERPRINT,
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
        "live_evidence": evidence,
        "live_evidence_sha256": sha(canonical(evidence)),
        "source_exclusion": source_proof(),
        "action": {
            "domain": "timezone", "from_owner": "nix", "to_owner": "ansible",
            "expected_timezone": "America/Los_Angeles", "host_mutation": False,
            "install_audit_only_nix_bundle": True, "activate_ansible_owner_gate": True,
        },
        "authorized": False,
    }
    raw = canonical(plan); digest = sha(raw)
    PLAN_DIR.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(PLAN_DIR, 0o700)
    path = PLAN_DIR / f"{digest}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return plan, digest, path


def load_plan(path: Path) -> tuple[dict, bytes, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise SystemExit("timezone handoff plan metadata differs")
    raw = path.read_bytes(); digest = sha(raw)
    if path.name != f"{digest}.json": raise SystemExit("timezone handoff plan filename hash differs")
    plan = json.loads(raw)
    if canonical(plan) != raw or plan.get("format") != "home-lab-proxmox-timezone-handoff-v1" or plan.get("authorized") is not False:
        raise SystemExit("timezone handoff plan is not canonical or inert")
    return plan, raw, digest


def authorize(path: Path) -> None:
    plan, _, digest = load_plan(path)
    if plan.get("commit") != clean_pushed_commit() or plan.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or plan.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml") or plan.get("host_key_fingerprint") != FINGERPRINT or plan.get("source_exclusion") != source_proof():
        raise SystemExit("timezone handoff plan source binding differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("timezone handoff plan expired")
    current = observe()
    if sha(canonical(current)) != plan.get("live_evidence_sha256"):
        raise SystemExit("timezone handoff live evidence changed")
    expected = f"authorize-proxmox-timezone-handoff-{digest}"
    if os.environ.get("PROXMOX_TIMEZONE_HANDOFF_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    receipt = {"format": "home-lab-proxmox-timezone-handoff-authorization-v1", "plan_sha256": digest,
               "commit": plan["commit"], "authorized_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}
    receipt_path = PLAN_DIR / f"{digest}.authorized.json"
    fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(canonical(receipt)); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"authorization": "recorded", "plan_sha256": digest, "receipt": str(receipt_path)}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True); commands.add_parser("plan"); auth = commands.add_parser("authorize"); auth.add_argument("plan", type=Path); args = parser.parse_args()
    if args.command == "plan":
        _, digest, path = make_plan(); print(json.dumps({"authorized": False, "path": str(path), "plan_sha256": digest}, sort_keys=True))
    else:
        authorize(args.plan.resolve())


if __name__ == "__main__": main()
