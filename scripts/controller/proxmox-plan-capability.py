#!/usr/bin/env python3
"""Guard the fixed observer capability handoff for the inert ansible-plan account."""

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
PLANS = ROOT / ".local/access-plan-capability"
TARGET = "proxmox@proxmox"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
TRANSPORT = "/usr/local/libexec/home-lab/proxmox-ansible-plan-transport"
OBSERVER = "/usr/local/libexec/home-lab/proxmox-observer"
PACKAGE_OBSERVER = "/usr/local/libexec/home-lab/proxmox-package-candidate-observer"
RULE = f"ansible-plan ALL=(root) NOPASSWD: {OBSERVER} observe, {PACKAGE_OBSERVER} observe proxmox"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_hash(path: Path) -> str:
    return digest(path.read_bytes())


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_commit() -> str:
    head = git("rev-parse", "HEAD")
    if head != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("plan capability requires clean pushed HEAD")
    return head


def observe() -> dict:
    program = r'''
import grp, hashlib, json, os, pwd, stat, subprocess
name="ansible-plan"; account=pwd.getpwnam(name)
groups=sorted(grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name,account.pw_gid))
status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True,check=False); fields=status.stdout.split()
def meta(path):
 try: value=os.lstat(path)
 except FileNotFoundError: return {"exists":False}
 result={"exists":True,"uid":value.st_uid,"gid":value.st_gid,"mode":format(stat.S_IMODE(value.st_mode),"04o"),"regular":stat.S_ISREG(value.st_mode),"symlink":stat.S_ISLNK(value.st_mode)}
 if result["regular"] and value.st_size<1048576: result["sha256"]=hashlib.sha256(open(path,"rb").read()).hexdigest()
 return result
paths={path:meta(path) for path in ("/home/ansible-plan/.ssh/authorized_keys","/home/ansible-plan/.ssh/authorized_keys2","/etc/sudoers.d/ansible-plan","/usr/local/libexec/home-lab/proxmox-ansible-plan-transport","/usr/local/libexec/home-lab/proxmox-observer","/usr/local/libexec/home-lab/proxmox-package-candidate-observer")}
locks=[p for p in ("/var/lib/home-lab/reconciliation/apply.lock","/var/lib/iac-ansible-production.lock","/var/lib/home-lab/firewall-transaction/active.json") if os.path.lexists(p)]
print(json.dumps({"account":{"exists":True,"home":account.pw_dir,"shell":account.pw_shell,"groups":groups,"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {"L","LK"}},"paths":paths,"locks":locks},sort_keys=True,separators=(",",":")))
'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise SystemExit("plan capability observation failed")
    return json.loads(result.stdout)


def validate_staged(value: dict) -> None:
    account = value.get("account", {})
    if value.get("locks") != [] or account != {"exists": True, "home": "/home/ansible-plan", "shell": "/usr/sbin/nologin", "groups": ["ansible-plan"], "password_locked": True}:
        raise SystemExit("ansible-plan is not in the exact inert staged state")
    paths = value.get("paths", {})
    for path in ("/home/ansible-plan/.ssh/authorized_keys", "/home/ansible-plan/.ssh/authorized_keys2", "/etc/sudoers.d/ansible-plan"):
        if paths.get(path) != {"exists": False}:
            raise SystemExit("ansible-plan conventional access or sudo already exists")
    source_hash = file_hash(ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-plan-transport")
    transport = paths.get(TRANSPORT, {})
    observer = paths.get(OBSERVER, {})
    package_observer = paths.get(PACKAGE_OBSERVER, {})
    if transport.get("sha256") != source_hash or transport.get("uid") != 0 or transport.get("gid") != 0 or transport.get("mode") != "0755" or not transport.get("regular") or transport.get("symlink"):
        raise SystemExit("installed plan transport differs")
    if not isinstance(observer.get("sha256"), str) or observer.get("uid") != 0 or observer.get("gid") != 0 or observer.get("mode") != "0755" or not observer.get("regular") or observer.get("symlink"):
        raise SystemExit("installed observer differs")
    if not isinstance(package_observer.get("sha256"), str) or package_observer.get("uid") != 0 or package_observer.get("gid") != 0 or package_observer.get("mode") != "0755" or not package_observer.get("regular") or package_observer.get("symlink"):
        raise SystemExit("installed package observer differs; use the exact package observer capability upgrade first")


def make_plan(observation: dict, commit: str, now: datetime) -> dict:
    validate_staged(observation)
    return {"format": "home-lab-proxmox-plan-capability-v1", "commit": commit,
            "contract_sha256": file_hash(ROOT / "infrastructure/contract/home-lab.yml"),
            "inventory_sha256": file_hash(ROOT / "ansible/inventory/production.yml"),
            "host_key_fingerprint": FINGERPRINT, "created_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(seconds=1800)).isoformat().replace("+00:00", "Z"),
            "observation_sha256": digest(canonical(observation)),
            "action": {"account": "ansible-plan", "shell": TRANSPORT, "sudo_rule": RULE,
                       "authorized_keys": "absent", "groups": ["ansible-plan"]}, "authorized": False}


def save(plan: dict) -> tuple[Path, str]:
    raw = canonical(plan); sha = digest(raw); PLANS.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(PLANS, 0o700)
    path = PLANS / f"{sha}.json"; fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    return path, sha


def apply(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise SystemExit("plan capability artifact metadata differs")
    raw = path.read_bytes(); sha = digest(raw)
    if path.name != f"{sha}.json": raise SystemExit("plan capability hash differs")
    plan = json.loads(raw)
    if canonical(plan) != raw or plan.get("commit") != clean_commit() or plan.get("contract_sha256") != file_hash(ROOT / "infrastructure/contract/home-lab.yml") or plan.get("inventory_sha256") != file_hash(ROOT / "ansible/inventory/production.yml") or plan.get("host_key_fingerprint") != FINGERPRINT or plan.get("authorized") is not False:
        raise SystemExit("plan capability source binding differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("plan capability expired")
    expected = f"enable-proxmox-plan-capability-{sha}"
    if os.environ.get("PROXMOX_PLAN_CAPABILITY_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    current = observe(); validate_staged(current)
    if digest(canonical(current)) != plan.get("observation_sha256"): raise SystemExit("plan capability observation changed")
    remote = f'''set -euo pipefail
[[ ! -e /var/lib/home-lab/reconciliation/apply.lock && ! -e /var/lib/iac-ansible-production.lock && ! -e /var/lib/home-lab/firewall-transaction/active.json ]]
[[ $(getent passwd ansible-plan | cut -d: -f7) == /usr/sbin/nologin ]]
[[ ! -e /etc/sudoers.d/ansible-plan && ! -e /home/ansible-plan/.ssh/authorized_keys && ! -e /home/ansible-plan/.ssh/authorized_keys2 ]]
tmp=$(mktemp /etc/sudoers.d/.ansible-plan.XXXXXX); trap 'rm -f "$tmp"; usermod --shell /usr/sbin/nologin ansible-plan >/dev/null 2>&1 || true; rm -f /etc/sudoers.d/ansible-plan' ERR
printf '%s\\n' '{RULE}' >"$tmp"; chown root:root "$tmp"; chmod 0440 "$tmp"; /usr/sbin/visudo --check --file="$tmp" >/dev/null
install -o root -g root -m 0440 "$tmp" /etc/sudoers.d/ansible-plan; rm -f "$tmp"; usermod --shell {TRANSPORT} ansible-plan
'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /bin/bash -s"), input=remote, text=True, timeout=120)
    if result.returncode: raise SystemExit("plan capability transaction failed")
    print(json.dumps({"plan_capability": "enabled", "plan_sha256": sha}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True); commands.add_parser("plan"); enabled = commands.add_parser("apply"); enabled.add_argument("plan", type=Path); args = parser.parse_args()
    if args.command == "plan":
        plan = make_plan(observe(), clean_commit(), datetime.now(timezone.utc)); path, sha = save(plan); print(json.dumps({"path": str(path), "plan_sha256": sha, "authorized": False}, sort_keys=True))
    else: apply(args.plan.resolve())


if __name__ == "__main__": main()
