#!/usr/bin/env python3
"""Build an exact, unauthorized plan for removing stale root supplementary groups."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-root-group-retirement"
TARGET = "proxmox@proxmox"
SSH = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
       "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "-o", "RequestTTY=no")
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
TARGET_GROUP = "apex"
RETAINED = (
    "/root/.ssh/authorized_keys", "/root/.config/home-lab/proxmox-plan-token.env",
    "/root/.config/home-lab/proxmox-apply-token.env", "/home/firewall-apply/.ssh/authorized_keys",
    "/etc/sudoers.d/firewall-apply", "/usr/local/libexec/home-lab/proxmox-firewall-transport",
    "/usr/local/libexec/home-lab/proxmox-private-preparer", "/usr/local/libexec/home-lab/proxmox-activator",
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/60-home-lab.conf",
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
        raise SystemExit("root group retirement planning requires clean pushed HEAD")
    return commit


def access_policy(raw: bytes) -> tuple[str, list[str]]:
    text = raw.decode(); section = text.split("      access_cutover:\n", 1)
    if len(section) != 2:
        raise SystemExit("access cutover policy is unavailable")
    body = section[1].split("      domain_handoffs:\n", 1)[0]
    state_match = re.search(r"^        state: (pending|ready|complete)$", body, re.MULTILINE)
    groups_match = re.search(r"^        retire_root_supplementary_groups:\n((?:          - [^\n]+\n)+)", body, re.MULTILINE)
    groups = re.findall(r"^          - ([^\n]+)$", groups_match.group(1), re.MULTILINE) if groups_match else []
    if state_match is None or groups != [TARGET_GROUP]:
        raise SystemExit("root supplementary-group retirement policy differs")
    return state_match.group(1), groups


def observe() -> dict:
    paths = sorted(RETAINED)
    program = f'''import grp,hashlib,json,os,pwd,stat,subprocess\npaths={paths!r}\ndef meta(path):\n try:s=os.lstat(path)\n except FileNotFoundError:return {{"exists":False}}\n value={{"exists":True,"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"regular":stat.S_ISREG(s.st_mode),"symlink":stat.S_ISLNK(s.st_mode),"nlink":s.st_nlink,"size":s.st_size}}\n if value["regular"]:value["sha256"]=hashlib.sha256(open(path,"rb").read()).hexdigest()\n return value\nroot=pwd.getpwnam("root");apex=grp.getgrnam("apex")\nrecords={{}}\nfor path in ("/etc/group","/etc/gshadow"):\n lines=[line for line in open(path).read().splitlines() if line.split(":",1)[0]=="apex"]\n records[path]={{"count":len(lines),"sha256":hashlib.sha256((lines[0]+"\\n").encode()).hexdigest() if len(lines)==1 else None}}\nlocks=[]\nfor path in ("/var/lib/iac-ansible-production.lock","/var/lock/home-lab-compose.lock","/run/lock/home-lab-restic-backup.lock","/run/lock/home-lab-apt.lock","/run/lock/home-lab-pve-firewall.lock"):\n if os.path.lexists(path):locks.append(path)\ntokens=json.loads(subprocess.run(["/usr/sbin/pveum","user","token","list","root@pam","--output-format","json"],capture_output=True,text=True,check=True).stdout)\nprint(json.dumps({{"apex":{{"exists":True,"gid":apex.gr_gid,"members":sorted(apex.gr_mem)}},"database_records":records,"locks":locks,"paths":{{path:meta(path) for path in paths}},"pve_tokens":sorted([{{"tokenid":item["tokenid"],"privsep":item["privsep"]}} for item in tokens],key=lambda item:item["tokenid"]),"root":{{"exists":True,"gid":root.pw_gid,"home":root.pw_dir,"shell":root.pw_shell,"groups":sorted(grp.getgrgid(gid).gr_name for gid in os.getgrouplist("root",root.pw_gid))}}}},sort_keys=True,separators=(",",":")))\n'''
    result = subprocess.run((*SSH, TARGET, "sudo -n -- /usr/bin/python3 -"), input=program, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr:
        raise SystemExit("root group retirement observation failed")
    value = json.loads(result.stdout)
    if value.get("locks") != []:
        raise SystemExit("a protected lifecycle lock is active")
    return value


def build_plan(commit: str, contract_raw: bytes, observation: dict, now: datetime) -> dict:
    state, groups = access_policy(contract_raw)
    blockers = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
    if state != "ready": blockers.insert(0, "access-cutover-state-not-ready")
    before = {"root_groups": observation["root"]["groups"], "apex": observation["apex"],
              "database_records": observation["database_records"]}
    if before != {"root_groups": ["apex", "root"], "apex": {"exists": True, "gid": 1000, "members": ["root"]},
                  "database_records": before["database_records"]} or any(item.get("count") != 1 or not item.get("sha256") for item in before["database_records"].values()):
        blockers.insert(0, "root-apex-membership-differs")
    created = now.replace(microsecond=0); expires = created + timedelta(minutes=30)
    return {"format": "home-lab-proxmox-root-group-retirement-plan-v1", "commit": commit,
            "contract_sha256": sha(contract_raw), "inventory_sha256": sha((ROOT / "ansible/inventory/production.yml").read_bytes()),
            "host_key_fingerprint": FINGERPRINT, "created_at": created.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"), "access_cutover_state": state,
            "target_group": groups[0], "before": before,
            "after": {"root_groups": ["root"], "apex": {"exists": True, "gid": 1000, "members": []}},
            "retained_assets_before": {path: observation["paths"][path] for path in RETAINED},
            "retained_pve_tokens": observation["pve_tokens"],
            "explicit_exclusions": {"delete_apex_group": False, "delete_root_account": False, "root_authorized_keys": True,
                                    "openssh_policy": True, "pve_api_tokens": ["tofu-plan", "tofu-apply"],
                                    "firewall_recovery": True, "tofu_ssh_identities": "already-retired"},
            "blockers": blockers, "authorized": False}


def plan() -> None:
    contract_raw = (ROOT / "infrastructure/contract/home-lab.yml").read_bytes()
    value = build_plan(clean_pushed_commit(), contract_raw, observe(), datetime.now(timezone.utc))
    raw = canonical(value); digest = sha(raw); OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    target = OUTPUT / f"root-apex-{digest}.json"; descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"authorized": False, "blockers": value["blockers"], "path": str(target), "plan_sha256": digest}, sort_keys=True))


if __name__ == "__main__":
    plan()
