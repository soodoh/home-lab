#!/usr/bin/env python3
"""Build separate, unauthorized retirement plans for legacy Proxmox tofu SSH identities."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-tofu-identity-retirement"
TARGET = "proxmox@proxmox"
SSH = (
    "ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
    "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
    "-o", "RequestTTY=no",
)
HOST_KEY_FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
IDENTITIES = ("tofu-plan", "tofu-apply")
HOST_ASSETS = {
    "tofu-plan": (
        "/home/tofu-plan", "/home/tofu-plan/.ssh",
        "/home/tofu-plan/.ssh/authorized_keys", "/etc/sudoers.d/tofu-plan",
    ),
    "tofu-apply": (
        "/home/tofu-apply", "/home/tofu-apply/.ssh",
        "/home/tofu-apply/.ssh/authorized_keys", "/etc/sudoers.d/tofu-apply",
        "/usr/local/libexec/home-lab/proxmox-apply-transport",
    ),
}
RETAINED_HOST_ASSETS = (
    "/root/.config/home-lab/proxmox-plan-token.env",
    "/root/.config/home-lab/proxmox-apply-token.env",
    "/root/.ssh/authorized_keys",
    "/home/firewall-apply/.ssh/authorized_keys",
    "/etc/sudoers.d/firewall-apply",
    "/usr/local/libexec/home-lab/proxmox-firewall-transport",
    "/usr/local/libexec/home-lab/proxmox-private-preparer",
    "/usr/local/libexec/home-lab/proxmox-activator",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("tofu identity retirement planning requires clean pushed HEAD")
    return commit


def access_state(contract_raw: bytes) -> str:
    text = contract_raw.decode()
    section = text.split("      access_cutover:\n", 1)
    if len(section) != 2:
        raise SystemExit("access cutover policy is unavailable")
    match = re.search(r"^        state: (pending|ready|complete)$", section[1].split("      domain_handoffs:\n", 1)[0], re.MULTILINE)
    if not match:
        raise SystemExit("access cutover state is unavailable")
    return match.group(1)


def local_metadata(path: Path) -> dict:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"exists": False}
    value = {
        "exists": True, "uid": info.st_uid, "gid": info.st_gid,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"), "nlink": info.st_nlink,
        "regular": stat.S_ISREG(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode),
        "size": info.st_size,
    }
    if value["regular"]:
        value["sha256"] = sha(path.read_bytes())
    return value


def observe_host() -> dict:
    request = {"identities": list(IDENTITIES), "paths": sorted({*RETAINED_HOST_ASSETS, *sum(HOST_ASSETS.values(), ())})}
    program = r'''
import grp,hashlib,json,os,pwd,stat,subprocess,sys
request=json.load(sys.stdin)
def metadata(path):
 try: info=os.lstat(path)
 except FileNotFoundError: return {"exists":False}
 value={"exists":True,"uid":info.st_uid,"gid":info.st_gid,"mode":format(stat.S_IMODE(info.st_mode),"04o"),"nlink":info.st_nlink,"regular":stat.S_ISREG(info.st_mode),"directory":stat.S_ISDIR(info.st_mode),"symlink":stat.S_ISLNK(info.st_mode),"size":info.st_size}
 if value["regular"]:
  with open(path,"rb") as handle: value["sha256"]=hashlib.sha256(handle.read()).hexdigest()
 if value["directory"]:
  records=[]
  for root,dirs,files in os.walk(path,topdown=True,followlinks=False):
   dirs.sort(); files.sort()
   for name in dirs+files:
    item=os.path.join(root,name); item_info=os.lstat(item); record={"path":os.path.relpath(item,path),"uid":item_info.st_uid,"gid":item_info.st_gid,"mode":format(stat.S_IMODE(item_info.st_mode),"04o"),"regular":stat.S_ISREG(item_info.st_mode),"directory":stat.S_ISDIR(item_info.st_mode),"symlink":stat.S_ISLNK(item_info.st_mode),"size":item_info.st_size}
    if record["regular"]:
     with open(item,"rb") as handle: record["sha256"]=hashlib.sha256(handle.read()).hexdigest()
    records.append(record)
  value["tree_sha256"]=hashlib.sha256((json.dumps(records,sort_keys=True,separators=(",",":"))+"\n").encode()).hexdigest(); value["tree_entries"]=len(records)
 return value
def account(name):
 try: item=pwd.getpwnam(name)
 except KeyError: return {"exists":False}
 status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True); fields=status.stdout.split()
 pids=subprocess.run(["/usr/bin/pgrep","-u",name],capture_output=True,text=True)
 return {"exists":True,"uid":item.pw_uid,"gid":item.pw_gid,"home":item.pw_dir,"shell":item.pw_shell,"gecos":item.pw_gecos,"groups":sorted(grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name,item.pw_gid)),"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {"L","LK"},"active_pids":sorted(int(value) for value in pids.stdout.split())}
def group(name):
 try: item=grp.getgrnam(name)
 except KeyError: return {"exists":False}
 return {"exists":True,"gid":item.gr_gid,"members":sorted(item.gr_mem)}
locks=[path for path in ("/var/lib/iac-ansible-production.lock","/var/lock/home-lab-compose.lock","/run/lock/home-lab-restic-backup.lock","/run/lock/home-lab-apt.lock","/run/lock/home-lab-pve-firewall.lock") if os.path.lexists(path)]
print(json.dumps({"accounts":{name:account(name) for name in request["identities"]},"groups":{name:group(name) for name in request["identities"]},"locks":locks,"paths":{path:metadata(path) for path in request["paths"]}},sort_keys=True,separators=(",",":")))
'''
    command = (*SSH, TARGET, "sudo -n -- /usr/bin/python3 -")
    request_arg = json.dumps(request, sort_keys=True, separators=(",", ":"))
    wrapped = program.replace("request=json.load(sys.stdin)", f"request=json.loads({request_arg!r})")
    result = subprocess.run(command, input=wrapped, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("tofu identity retirement host observation failed closed")
    value = json.loads(result.stdout)
    if value.get("locks") != []:
        raise SystemExit("a protected lifecycle lock is active")
    return value


def build_plans(commit: str, contract_raw: bytes, observation: dict, controller: dict, now: datetime) -> list[dict]:
    state = access_state(contract_raw)
    created = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    expires = (now + timedelta(minutes=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    common = {
        "format": "home-lab-proxmox-tofu-identity-retirement-plan-v1", "commit": commit,
        "contract_sha256": sha(contract_raw), "host_key_fingerprint": HOST_KEY_FINGERPRINT,
        "created_at": created, "expires_at": expires, "access_cutover_state": state,
        "authorized": False,
        "explicit_exclusions": {
            "pve_api_identities": ["root@pam!tofu-plan", "root@pam!tofu-apply"],
            "protected_token_escrows": ["/root/.config/home-lab/proxmox-plan-token.env", "/root/.config/home-lab/proxmox-apply-token.env"],
            "root_authorized_keys": "/root/.ssh/authorized_keys", "firewall_recovery": True,
            "openssh_policy": True, "unrelated_accounts_and_groups": True,
        },
        "retained_host_assets_before": {path: observation["paths"][path] for path in RETAINED_HOST_ASSETS},
    }
    plans = []
    for sequence, identity in enumerate(IDENTITIES, 1):
        blockers = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
        if state != "ready": blockers.insert(0, "access-cutover-state-not-ready")
        if observation["accounts"][identity].get("active_pids"):
            blockers.insert(0, "identity-has-active-processes")
        plans.append({**common, "sequence": sequence, "kind": f"host-{identity}-retirement", "scope": "proxmox-host",
                      "before": {"account": observation["accounts"][identity], "group": observation["groups"][identity],
                                 "assets": {path: observation["paths"][path] for path in HOST_ASSETS[identity]}},
                      "after": {"account": {"exists": False}, "group": {"exists": False},
                                "assets": {path: {"exists": False} for path in HOST_ASSETS[identity]}},
                      "blockers": blockers})
    for sequence, identity in enumerate(IDENTITIES, 3):
        paths = controller[identity]
        plans.append({**common, "sequence": sequence, "kind": f"controller-{identity}-credential-retirement", "scope": "controller",
                      "before": {path: local_metadata(Path(path)) for path in paths},
                      "after": {path: {"exists": False} for path in paths},
                      "blockers": [f"host-{identity}-retirement-receipt-required", "controller-recovery-attestation-required", "separate-authorization-required"]})
    return plans


def save_plans(plans: list[dict]) -> tuple[Path, str]:
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    references = []
    for plan in plans:
        raw = canonical(plan); digest = sha(raw)
        target = OUTPUT / f"{plan['sequence']}-{plan['kind']}-{digest}.json"
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        references.append({"sequence": plan["sequence"], "kind": plan["kind"], "plan_sha256": digest,
                           "path": str(target), "blockers": plan["blockers"]})
    manifest = {"format": "home-lab-proxmox-tofu-identity-retirement-manifest-v1", "commit": plans[0]["commit"],
                "created_at": plans[0]["created_at"], "expires_at": plans[0]["expires_at"],
                "plans": references, "authorized": False}
    raw = canonical(manifest); digest = sha(raw); target = OUTPUT / f"manifest-{digest}.json"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    directory = os.open(OUTPUT, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return target, digest


def plan() -> None:
    commit = clean_pushed_commit(); contract_raw = (ROOT / "infrastructure/contract/home-lab.yml").read_bytes()
    observation = observe_host()
    controller = {name: [str(Path.home() / f".ssh/home-lab-proxmox-{name.removeprefix('tofu-')}"),
                         str(Path.home() / f".ssh/home-lab-proxmox-{name.removeprefix('tofu-')}.pub")] for name in IDENTITIES}
    plans = build_plans(commit, contract_raw, observation, controller, datetime.now(timezone.utc))
    target, digest = save_plans(plans)
    print(json.dumps({"authorized": False, "manifest_sha256": digest, "path": str(target),
                      "plans": [{"kind": item["kind"], "blockers": item["blockers"]} for item in plans]}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("command", choices=("plan",)); args = parser.parse_args()
    if args.command == "plan": plan()


if __name__ == "__main__":
    main()
