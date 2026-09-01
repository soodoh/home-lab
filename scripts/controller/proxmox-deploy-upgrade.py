#!/usr/bin/env python3
"""Authorize a fixed deploy helper upgrade without changing account privileges."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / ".local/proxmox-deploy-upgrade"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
TRANSPORT = "/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport"
ACTIVATOR = "/usr/local/libexec/home-lab/proxmox-ansible-deploy-activator"
OBSERVER = "/usr/local/libexec/home-lab/proxmox-observer"
PREPARER = "/usr/local/libexec/home-lab/proxmox-private-preparer"
FIREWALL_TRANSACTION = "/usr/local/libexec/home-lab/proxmox-firewall-transaction"
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
    commit=git("rev-parse","HEAD")
    if commit!=git("rev-parse","origin/main") or git("status","--porcelain=v1","--untracked-files=all"):
        raise SystemExit("deploy upgrade requires clean pushed HEAD")
    return commit


def observe() -> dict:
    program=f'''import grp,hashlib,json,os,pwd,stat,subprocess\nname="ansible-deploy"; account=pwd.getpwnam(name); status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True); fields=status.stdout.split()\ndef meta(path):\n s=os.lstat(path); return {{"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"regular":stat.S_ISREG(s.st_mode),"symlink":stat.S_ISLNK(s.st_mode),"nlink":s.st_nlink,"sha256":hashlib.sha256(open(path,"rb").read()).hexdigest()}}\nprint(json.dumps({{"account":{{"groups":sorted(grp.getgrgid(g).gr_name for g in os.getgrouplist(name,account.pw_gid)),"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {{"L","LK"}},"shell":account.pw_shell}},"authorized_keys_absent":not os.path.lexists("/home/ansible-deploy/.ssh/authorized_keys") and not os.path.lexists("/home/ansible-deploy/.ssh/authorized_keys2"),"helpers":{{{TRANSPORT!r}:meta({TRANSPORT!r}),{ACTIVATOR!r}:meta({ACTIVATOR!r}),{OBSERVER!r}:meta({OBSERVER!r}),{PREPARER!r}:meta({PREPARER!r}),{FIREWALL_TRANSACTION!r}:meta({FIREWALL_TRANSACTION!r})}},"sudo_rule":open("/etc/sudoers.d/ansible-deploy").read(),"locks":[p for p in ("/var/lib/home-lab/reconciliation/apply.lock","/var/lib/iac-ansible-production.lock","/var/lib/home-lab/firewall-transaction/active.json") if os.path.lexists(p)]}},sort_keys=True,separators=(",",":")))\n'''
    result=subprocess.run(SSH,input=program,text=True,capture_output=True,timeout=60)
    if result.returncode or result.stderr: raise SystemExit("deploy upgrade observation failed")
    value=json.loads(result.stdout)
    if value.get("account")!={"groups":["ansible-deploy"],"password_locked":True,"shell":TRANSPORT} or value.get("authorized_keys_absent") is not True or value.get("sudo_rule")!=RULE+"\n" or value.get("locks")!=[]:
        raise SystemExit("deploy capability differs before upgrade")
    for metadata in value["helpers"].values():
        if metadata.get("uid")!=0 or metadata.get("gid")!=0 or metadata.get("mode")!="0755" or metadata.get("regular") is not True or metadata.get("symlink") is not False or metadata.get("nlink")!=1:
            raise SystemExit("installed deploy helper metadata differs")
    return value


def source_bytes() -> dict[str, bytes]:
    spec=importlib.util.spec_from_file_location("proxmox_bundle",ROOT/"nix/proxmox/bundle.py");module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    projection=json.loads((ROOT/"nix/proxmox/projection.json").read_bytes())
    return {TRANSPORT:(ROOT/"infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport").read_bytes(),
            ACTIVATOR:(ROOT/"infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator").read_bytes(),
            OBSERVER:module.expected_helper_content("proxmox-observer",projection),
            PREPARER:module.expected_helper_content("proxmox-private-preparer",projection),
            FIREWALL_TRANSACTION:(ROOT/"infrastructure/proxmox-firewall/host/proxmox-firewall-transaction.py").read_bytes()}


def source_hashes() -> dict:
    return {path:sha(raw) for path,raw in source_bytes().items()}


def plan() -> tuple[Path,str]:
    commit=clean_pushed_commit(); before=observe(); after=source_hashes()
    if {path:item["sha256"] for path,item in before["helpers"].items()}==after: raise SystemExit("reviewed helpers already match")
    now=datetime.now(timezone.utc).replace(microsecond=0)
    value={"format":"home-lab-proxmox-deploy-upgrade-v1","commit":commit,"contract_sha256":file_sha(ROOT/"infrastructure/contract/home-lab.yml"),"inventory_sha256":file_sha(ROOT/"ansible/inventory/production.yml"),"host_key_fingerprint":FINGERPRINT,"created_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now+timedelta(seconds=1800)).isoformat().replace("+00:00","Z"),"before":before,"after_sha256":after,"preserve":{"account_shell":TRANSPORT,"sudo_rule":RULE,"authorized_keys":"absent"},"capability":"saved-actions-and-read-only-compatibility-only","authorized":False}
    raw=canonical(value);digest=sha(raw);OUTPUT.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(OUTPUT,0o700);path=OUTPUT/f"{digest}.json";fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return path,digest


def authorize(path: Path) -> None:
    info=path.lstat();raw=path.read_bytes();value=json.loads(raw);digest=sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.getuid() or info.st_nlink!=1 or path.name!=f"{digest}.json" or raw!=canonical(value):raise SystemExit("deploy upgrade plan metadata differs")
    if value.get("commit")!=clean_pushed_commit() or value.get("contract_sha256")!=file_sha(ROOT/"infrastructure/contract/home-lab.yml") or value.get("inventory_sha256")!=file_sha(ROOT/"ansible/inventory/production.yml") or value.get("host_key_fingerprint")!=FINGERPRINT or value.get("after_sha256")!=source_hashes() or datetime.now(timezone.utc)>datetime.fromisoformat(value["expires_at"].replace("Z","+00:00")):raise SystemExit("deploy upgrade binding or freshness differs")
    if observe()!=value.get("before"):raise SystemExit("deploy helpers changed after planning")
    expected=f"authorize-proxmox-deploy-upgrade-{digest}"
    if os.environ.get("PROXMOX_DEPLOY_UPGRADE_CONFIRMED")!=expected:raise SystemExit(f"exact confirmation required: {expected}")
    receipt={"format":"home-lab-proxmox-deploy-upgrade-authorization-v1","plan_sha256":digest,"commit":value["commit"],"authorized_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")};receipt_raw=canonical(receipt);receipt_digest=sha(receipt_raw);target=OUTPUT/f"authorized-{receipt_digest}.json";fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as handle:handle.write(receipt_raw);handle.flush();os.fsync(handle.fileno())
    print(json.dumps({"authorization_sha256":receipt_digest,"path":str(target),"plan_sha256":digest},sort_keys=True))


def apply_upgrade(plan_path: Path, authorization_path: Path) -> None:
    info=plan_path.lstat();plan_raw=plan_path.read_bytes();value=json.loads(plan_raw);digest=sha(plan_raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.getuid() or info.st_nlink!=1 or plan_path.name!=f"{digest}.json" or plan_raw!=canonical(value):raise SystemExit("deploy upgrade plan metadata differs")
    auth_info=authorization_path.lstat();auth_raw=authorization_path.read_bytes();auth_value=json.loads(auth_raw);auth_digest=sha(auth_raw)
    if not stat.S_ISREG(auth_info.st_mode) or stat.S_IMODE(auth_info.st_mode)!=0o600 or auth_info.st_uid!=os.getuid() or auth_info.st_nlink!=1 or authorization_path.name!=f"authorized-{auth_digest}.json" or auth_raw!=canonical(auth_value):raise SystemExit("deploy upgrade authorization metadata differs")
    if value.get("commit")!=clean_pushed_commit() or value.get("contract_sha256")!=file_sha(ROOT/"infrastructure/contract/home-lab.yml") or value.get("inventory_sha256")!=file_sha(ROOT/"ansible/inventory/production.yml") or value.get("host_key_fingerprint")!=FINGERPRINT or value.get("after_sha256")!=source_hashes() or datetime.now(timezone.utc)>datetime.fromisoformat(value["expires_at"].replace("Z","+00:00")):raise SystemExit("deploy upgrade apply binding or freshness differs")
    expected_auth={"format":"home-lab-proxmox-deploy-upgrade-authorization-v1","plan_sha256":digest,"commit":value["commit"],"authorized_at":auth_value.get("authorized_at")}
    if auth_value!=expected_auth:raise SystemExit("deploy upgrade authorization binding differs")
    current=observe()
    if current!=value.get("before"):raise SystemExit("deploy helpers changed after authorization")
    expected=f"apply-proxmox-deploy-upgrade-{digest}-{auth_digest}"
    if os.environ.get("PROXMOX_DEPLOY_UPGRADE_CONFIRMED")!=expected:raise SystemExit(f"exact confirmation required: {expected}")
    contents=source_bytes();changed={path:contents[path] for path,new_hash in value["after_sha256"].items() if value["before"]["helpers"][path]["sha256"]!=new_hash}
    if not changed:raise SystemExit("deploy upgrade has no changed helpers")
    payload={"plan_sha256":digest,"before":value["before"]["helpers"],"after_sha256":value["after_sha256"],"changed":{path:raw.hex() for path,raw in changed.items()}}
    program=f'''\nimport hashlib,json,os,stat\npayload={payload!r}\ndef canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\\n").encode()\ndef meta(path):\n s=os.lstat(path);return {{"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"regular":stat.S_ISREG(s.st_mode),"symlink":stat.S_ISLNK(s.st_mode),"nlink":s.st_nlink,"sha256":hashlib.sha256(open(path,"rb").read()).hexdigest()}}\ndef private(path,raw):\n fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,"wb") as handle: handle.write(raw);handle.flush();os.fsync(handle.fileno())\nlocks=[p for p in ("/var/lib/home-lab/reconciliation/apply.lock","/var/lib/iac-ansible-production.lock","/var/lib/home-lab/firewall-transaction/active.json","/var/lock/home-lab-compose.lock","/run/lock/home-lab-restic-backup.lock") if os.path.lexists(p)]\nif locks or {{path:meta(path) for path in payload["before"]}}!=payload["before"]: raise SystemExit(64)\nparent="/var/lib/home-lab";info=os.lstat(parent)\nif not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=0: raise SystemExit(64)\nroot=os.path.join(parent,"deploy-upgrade");journal=os.path.join(root,payload["plan_sha256"])\nfor path in (root,journal):\n try: os.mkdir(path,0o700)\n except FileExistsError:\n  if path!=root: raise\n info=os.lstat(path)\n if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=0: raise SystemExit(64)\nbackup={{path:open(path,"rb").read().hex() for path in payload["changed"]}}\nprivate(os.path.join(journal,"rollback.json"),canonical({{"format":"home-lab-proxmox-deploy-upgrade-rollback-v1","plan_sha256":payload["plan_sha256"],"files":backup}}))\nfor path in (journal,root):\n fd=os.open(path,os.O_RDONLY);os.fsync(fd);os.close(fd)\ntry:\n for path,raw_hex in payload["changed"].items():\n  directory=os.path.dirname(path);temporary=os.path.join(directory,f".{{os.path.basename(path)}}.deploy-upgrade-{{os.getpid()}}")\n  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)\n  with os.fdopen(fd,"wb") as handle: os.fchown(handle.fileno(),0,0);os.fchmod(handle.fileno(),0o755);handle.write(bytes.fromhex(raw_hex));handle.flush();os.fsync(handle.fileno())\n  os.replace(temporary,path);directory_fd=os.open(directory,os.O_RDONLY);os.fsync(directory_fd);os.close(directory_fd)\n if {{path:meta(path)["sha256"] for path in payload["after_sha256"]}}!=payload["after_sha256"]: raise RuntimeError("postcondition")\nexcept Exception:\n for path,raw_hex in backup.items():\n  directory=os.path.dirname(path);temporary=os.path.join(directory,f".{{os.path.basename(path)}}.deploy-rollback-{{os.getpid()}}")\n  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)\n  with os.fdopen(fd,"wb") as handle: os.fchown(handle.fileno(),0,0);os.fchmod(handle.fileno(),0o755);handle.write(bytes.fromhex(raw_hex));handle.flush();os.fsync(handle.fileno())\n  os.replace(temporary,path);directory_fd=os.open(directory,os.O_RDONLY);os.fsync(directory_fd);os.close(directory_fd)\n raise\nreceipt={{"format":"home-lab-proxmox-deploy-upgrade-receipt-v1","plan_sha256":payload["plan_sha256"],"changed":sorted(payload["changed"]),"status":"committed"}}\nprivate(os.path.join(journal,"receipt.json"),canonical(receipt));directory_fd=os.open(journal,os.O_RDONLY);os.fsync(directory_fd);os.close(directory_fd)\nprint(json.dumps(receipt,sort_keys=True,separators=(",",":")))\n'''
    result=subprocess.run(SSH,input=program,text=True,capture_output=True,timeout=120)
    if result.returncode or result.stderr:raise SystemExit("deploy upgrade transaction failed")
    receipt=json.loads(result.stdout)
    if receipt!={"format":"home-lab-proxmox-deploy-upgrade-receipt-v1","plan_sha256":digest,"changed":sorted(changed),"status":"committed"}:raise SystemExit("deploy upgrade receipt differs")
    after=observe()
    if {path:item["sha256"] for path,item in after["helpers"].items()}!=value["after_sha256"]:raise SystemExit("deploy upgrade post-observation differs")
    print(json.dumps({"changed":sorted(changed),"plan_sha256":digest,"status":"committed"},sort_keys=True))


def main() -> None:
    parser=argparse.ArgumentParser();commands=parser.add_subparsers(dest="command",required=True);commands.add_parser("plan");auth=commands.add_parser("authorize");auth.add_argument("plan",type=Path);apply_parser=commands.add_parser("apply");apply_parser.add_argument("plan",type=Path);apply_parser.add_argument("authorization",type=Path);args=parser.parse_args()
    if args.command=="plan":
        path,digest=plan();print(json.dumps({"authorized":False,"path":str(path),"plan_sha256":digest},sort_keys=True))
    elif args.command=="authorize":authorize(args.plan.resolve())
    else:apply_upgrade(args.plan.resolve(),args.authorization.resolve())


if __name__=="__main__":main()
