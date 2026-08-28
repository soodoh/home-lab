#!/usr/bin/env python3
"""Authorize installation of the fixed saved-plan Proxmox deploy capability."""

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
PLAN_DIR = ROOT / ".local/proxmox-deploy-capability"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
TRANSPORT = "/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport"
ACTIVATOR = "/usr/local/libexec/home-lab/proxmox-ansible-deploy-activator"
RULE = f"ansible-deploy ALL=(root) NOPASSWD: {ACTIVATOR}"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "proxmox@proxmox", "sudo -n -- /usr/bin/python3 -")


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
        raise SystemExit("deploy capability requires clean pushed HEAD")
    return commit


def observe() -> dict:
    program = r'''
import grp,json,os,pwd,subprocess
name="ansible-deploy"; value=pwd.getpwnam(name); status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True); fields=status.stdout.split()
paths=("/home/ansible-deploy/.ssh/authorized_keys","/home/ansible-deploy/.ssh/authorized_keys2","/etc/sudoers.d/ansible-deploy","/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport","/usr/local/libexec/home-lab/proxmox-ansible-deploy-activator")
locks=[p for p in ("/var/lib/home-lab/reconciliation/apply.lock","/var/lib/iac-ansible-production.lock","/var/lib/home-lab/firewall-transaction/active.json") if os.path.lexists(p)]
print(json.dumps({"account":{"groups":sorted(grp.getgrgid(g).gr_name for g in os.getgrouplist(name,value.pw_gid)),"home":value.pw_dir,"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {"L","LK"},"shell":value.pw_shell},"paths":{p:os.path.lexists(p) for p in paths},"locks":locks},sort_keys=True,separators=(",",":")))
'''
    result = subprocess.run(SSH, input=program, text=True, capture_output=True, timeout=60)
    if result.returncode or result.stderr:
        raise SystemExit("deploy capability observation failed")
    return json.loads(result.stdout)


def validate_inert(value: dict) -> None:
    if value.get("account") != {"groups": ["ansible-deploy"], "home": "/home/ansible-deploy", "password_locked": True, "shell": "/usr/sbin/nologin"} or value.get("locks") != [] or any(value.get("paths", {}).values()):
        raise SystemExit("ansible-deploy is not in the exact inert state")


def source_proof() -> dict:
    contract = (ROOT / "infrastructure/contract/home-lab.yml").read_text()
    transport = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
    activator = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
    proof = {"transport_sha256": file_sha(transport), "activator_sha256": file_sha(activator),
             "contract_shell": f"shell: {TRANSPORT}" in contract, "contract_sudo_rule": f'rule: "{RULE}"' in contract,
             "no_generic_sudo": "NOPASSWD: ALL" not in transport.read_text() + activator.read_text()}
    if proof["contract_shell"] is not True or proof["contract_sudo_rule"] is not True or proof["no_generic_sudo"] is not True:
        raise SystemExit("deploy capability source proof failed")
    return proof


def save_plan() -> tuple[Path, str]:
    commit = clean_pushed_commit(); evidence = observe(); validate_inert(evidence); now = datetime.now(timezone.utc).replace(microsecond=0)
    plan = {"format": "home-lab-proxmox-deploy-capability-v1", "commit": commit,
            "contract_sha256": file_sha(ROOT / "infrastructure/contract/home-lab.yml"),
            "inventory_sha256": file_sha(ROOT / "ansible/inventory/production.yml"), "host_key_fingerprint": FINGERPRINT,
            "created_at": now.isoformat().replace("+00:00", "Z"), "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
            "observation": evidence, "observation_sha256": sha(canonical(evidence)), "source_proof": source_proof(),
            "action": {"account": "ansible-deploy", "shell": TRANSPORT, "sudo_rule": RULE,
                       "capability": "saved-lifecycle-marker-plans-only", "authorized_keys": "absent"}, "authorized": False}
    raw = canonical(plan); digest = sha(raw); PLAN_DIR.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(PLAN_DIR, 0o700)
    path = PLAN_DIR / f"{digest}.json"; fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return path, digest


def authorize(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1: raise SystemExit("deploy capability plan metadata differs")
    raw = path.read_bytes(); digest = sha(raw); plan = json.loads(raw)
    if path.name != f"{digest}.json" or raw != canonical(plan) or plan.get("authorized") is not False or plan.get("commit") != clean_pushed_commit() or plan.get("contract_sha256") != file_sha(ROOT / "infrastructure/contract/home-lab.yml") or plan.get("inventory_sha256") != file_sha(ROOT / "ansible/inventory/production.yml") or plan.get("source_proof") != source_proof():
        raise SystemExit("deploy capability plan binding differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")): raise SystemExit("deploy capability plan expired")
    current = observe(); validate_inert(current)
    if sha(canonical(current)) != plan.get("observation_sha256"): raise SystemExit("deploy capability observation changed")
    expected = f"authorize-proxmox-deploy-capability-{digest}"
    if os.environ.get("PROXMOX_DEPLOY_CAPABILITY_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
    receipt = {"format": "home-lab-proxmox-deploy-capability-authorization-v1", "plan_sha256": digest, "commit": plan["commit"], "authorized_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}
    receipt_path = PLAN_DIR / f"{digest}.authorized.json"; fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(canonical(receipt)); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"authorization": "recorded", "plan_sha256": digest, "receipt": str(receipt_path)}, sort_keys=True))


def main() -> None:
    parser=argparse.ArgumentParser(); commands=parser.add_subparsers(dest="command",required=True); commands.add_parser("plan"); auth=commands.add_parser("authorize"); auth.add_argument("plan",type=Path); args=parser.parse_args()
    if args.command == "plan":
        path,digest=save_plan(); print(json.dumps({"authorized":False,"path":str(path),"plan_sha256":digest},sort_keys=True))
    else: authorize(args.plan.resolve())


if __name__ == "__main__": main()
