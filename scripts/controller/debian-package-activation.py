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

def load(path):
    info=path.lstat(); raw=path.read_bytes(); value=json.loads(raw)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or raw != canonical(value):
        raise SystemExit("package lock metadata or canonical content differs")
    material=dict(value); material.pop("final_sha256",None)
    if (value.get("format") != "home-lab-package-transaction-final-v1" or value.get("host") != "debian" or
        value.get("base_commit") != clean_commit() or value.get("authorized") is not False or value.get("automatic_apply") is not False or
        value.get("automatic_reboot") is not False or value.get("actionable") is not True or
        value.get("blockers") != ["separate-exact-authorization-required"] or value.get("final_sha256") != sha(canonical(material)) or
        datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z","+00:00"))):
        raise SystemExit("package lock authority, hash, commit, or freshness differs")
    return value,raw,sha(raw)

def ssh_args():
    known=os.environ.get("HOME_LAB_DEBIAN_PRODUCTION_KNOWN_HOSTS","")
    if not known or not Path(known).is_absolute(): raise SystemExit("dedicated Debian known-hosts path required")
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
