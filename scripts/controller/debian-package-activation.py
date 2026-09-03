#!/usr/bin/env python3
"""Prepare/apply one exact Debian package final lock through its dedicated identity."""
import argparse, hashlib, json, os, stat, subprocess
from datetime import datetime, timezone
from pathlib import Path
from protected_execution import acquire_transfer_lock

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / ".local/locks/debian-package.lock"
TARGET = "ansible-package-apply@docker-host"

def canonical(value): return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(*args): return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()
def clean_commit():
    commit=git("rev-parse","HEAD")
    if commit != git("rev-parse","origin/main") or git("status","--porcelain=v1","--untracked-files=all"):
        raise SystemExit("Debian package activation requires clean pushed HEAD")
    return commit

def protected_read(path):
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid() or before.st_size > 262144:
        raise SystemExit("package lock metadata differs")
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        after=os.fstat(descriptor); raw=os.read(descriptor,262145)
    finally: os.close(descriptor)
    if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size) or len(raw)>262144:
        raise SystemExit("package lock changed during read")
    return raw

def known_host_fingerprint():
    value=os.environ.get("HOME_LAB_DEBIAN_PRODUCTION_KNOWN_HOSTS",""); path=Path(value)
    if not value or not path.is_absolute(): raise SystemExit("dedicated Debian known-hosts path required")
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
        raise SystemExit("dedicated Debian known-hosts metadata differs")
    result=subprocess.run(("ssh-keygen","-lf",str(path)),capture_output=True,text=True)
    lines=[line for line in result.stdout.splitlines() if line]
    if result.returncode or result.stderr or len(lines)!=1 or len(lines[0].split())<2 or not lines[0].split()[1].startswith("SHA256:"):
        raise SystemExit("dedicated Debian host key identity differs")
    return lines[0].split()[1]

def load(path):
    raw=protected_read(path); value=json.loads(raw); digest=sha(raw)
    if raw != canonical(value) or path.name != f"{digest}.json":
        raise SystemExit("package lock canonical content or filename differs")
    material=dict(value); material.pop("final_sha256",None); bindings=value.get("bindings",{})
    if (value.get("format") != "home-lab-package-transaction-final-v1" or value.get("host") != "debian" or
        value.get("base_commit") != clean_commit() or value.get("authorized") is not False or value.get("automatic_apply") is not False or
        value.get("automatic_reboot") is not False or value.get("actionable") is not True or
        value.get("blockers") != ["separate-exact-authorization-required"] or value.get("final_sha256") != sha(canonical(material)) or
        bindings.get("contract_sha256") != sha((ROOT/"infrastructure/contract/home-lab.yml").read_bytes()) or
        bindings.get("inventory_sha256") != sha((ROOT/"ansible/inventory/production.yml").read_bytes()) or
        bindings.get("host_key_fingerprint") != known_host_fingerprint() or
        bindings.get("changes_sha256") != sha(canonical(value.get("transaction",{}).get("changes",[]))) or
        datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z","+00:00"))):
        raise SystemExit("package lock authority, hash, current bindings, or freshness differs")
    return value,raw,digest

def ssh_args():
    known=os.environ["HOME_LAB_DEBIAN_PRODUCTION_KNOWN_HOSTS"]
    known_host_fingerprint()
    return ("ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={known}","-o","UpdateHostKeys=no","-o","IdentitiesOnly=yes","-o","RequestTTY=no","-o","ClearAllForwardings=yes",TARGET)

def invoke(operation,path):
    value,raw,digest=load(path); expected=f"{operation}-debian-package-{digest}"
    if os.environ.get(f"DEBIAN_PACKAGE_{operation.upper()}_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    LOCK.parent.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(LOCK.parent,0o700); lock=acquire_transfer_lock(LOCK)
    try:
        inspected=subprocess.run((*ssh_args(),f"inspect package {digest}"),capture_output=True,timeout=60)
        if inspected.returncode or inspected.stderr: raise SystemExit("package inspection failed")
        inspection=json.loads(inspected.stdout)
        if inspection != {"present":True}:
            if inspection != {"present":False}: raise SystemExit("package inspection result differs")
            staged=subprocess.run((*ssh_args(),f"stage package {digest}"),input=raw,capture_output=True,timeout=120)
            if staged.returncode or staged.stderr or staged.stdout != b'{"staged":true}\n': raise SystemExit("package staging failed")
        result=subprocess.run((*ssh_args(),f"{operation} package {digest}"),capture_output=True,timeout=3900)
    finally: os.close(lock)
    if result.returncode or result.stderr: raise SystemExit("dedicated package transaction failed; inspect retained journal")
    output=json.loads(result.stdout)
    if output.get("plan_sha256",digest) != digest or output.get("automatic_reboot") is not False:
        raise SystemExit("dedicated package result differs")
    if operation == "apply":
        audit=subprocess.run(("ansible-playbook","-i",str(ROOT/"ansible/inventory/production.yml"),"--limit","docker_host",str(ROOT/"ansible/playbooks/audit.yml")),cwd=ROOT)
        if audit.returncode: raise SystemExit("post-package production audit failed; retain journal for manual recovery")
    print(json.dumps(output,sort_keys=True))

def main():
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="operation",required=True)
    for name in ("prepare","apply","recover"): sub.add_parser(name).add_argument("lock",type=Path)
    args=parser.parse_args(); invoke(args.operation,args.lock.resolve())
if __name__ == "__main__": main()
