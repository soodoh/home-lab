#!/usr/bin/env python3
"""Guarded installer for the fixed ansible-deploy Restic recovery capability."""
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
OUTPUT = ROOT / ".local/proxmox-restic-recovery-capability"
TRANSPORT = "/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport"
HELPER = "/usr/local/libexec/home-lab/proxmox-restic-recovery-transport"
SUDOERS = "/etc/sudoers.d/ansible-deploy"
ACTIVATOR = "/usr/local/libexec/home-lab/proxmox-ansible-deploy-activator"
RULE = f"ansible-deploy ALL=(root) NOPASSWD: {ACTIVATOR}, {HELPER}\n"
LEGACY_RULE = f"ansible-deploy ALL=(root) NOPASSWD: {ACTIVATOR}\n"
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
SSH_BASE = ("ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes")
HUMAN = (*SSH_BASE, "proxmox@proxmox", "sudo -n -- /usr/bin/python3 -")
DEPLOY = (*SSH_BASE, "ansible-deploy@proxmox")
TARGETS = {TRANSPORT: 0o755, HELPER: 0o755, SUDOERS: 0o440}
RESTORE_ORDER = (SUDOERS, HELPER, TRANSPORT)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("Restic recovery capability requires clean pushed HEAD")
    return commit


def sources() -> dict[str, bytes]:
    return {
        TRANSPORT: (ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport").read_bytes(),
        HELPER: (ROOT / "infrastructure/proxmox-access/host/proxmox-restic-recovery-transport.py").read_bytes(),
        SUDOERS: RULE.encode(),
    }


def observe_candidates() -> list[dict]:
    program = r'''import json,os,stat
root="/var/lib/home-lab/restic-recovery-capability";items=[]
if os.path.isdir(root) and not os.path.islink(root):
 for name in sorted(os.listdir(root)):
  path=os.path.join(root,name,"state.json")
  if not os.path.isfile(path) or os.path.islink(path):continue
  info=os.lstat(path)
  if stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=0 or info.st_nlink!=1:raise SystemExit(65)
  value=json.load(open(path))
  if value.get("status") in {"preparing","candidate","rolling-back","committed"}:items.append(value)
print(json.dumps(items,sort_keys=True,separators=(",",":")))
'''
    result = subprocess.run(HUMAN, input=program, text=True, capture_output=True, timeout=60)
    if result.returncode or result.stderr: raise SystemExit("Restic recovery candidate observation failed")
    return json.loads(result.stdout)

def observe() -> dict:
    program = f'''import grp,hashlib,json,os,pwd,stat,subprocess\npaths={sorted(TARGETS)!r}\ndef meta(path):\n try:s=os.lstat(path)\n except FileNotFoundError:return {{"exists":False}}\n raw=open(path,"rb").read() if stat.S_ISREG(s.st_mode) else b"";value={{"exists":True,"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"regular":stat.S_ISREG(s.st_mode),"symlink":stat.S_ISLNK(s.st_mode),"nlink":s.st_nlink,"sha256":hashlib.sha256(raw).hexdigest() if stat.S_ISREG(s.st_mode) else None,"raw_hex":raw.hex() if stat.S_ISREG(s.st_mode) else None}}\n return value\nname="ansible-deploy";account=pwd.getpwnam(name);status=subprocess.run(["/usr/bin/passwd","--status",name],capture_output=True,text=True);fields=status.stdout.split()\nprint(json.dumps({{"account":{{"groups":sorted(grp.getgrgid(g).gr_name for g in os.getgrouplist(name,account.pw_gid)),"password_locked":status.returncode==0 and len(fields)>1 and fields[1] in {{"L","LK"}},"shell":account.pw_shell}},"authorized_keys_absent":not os.path.lexists("/home/ansible-deploy/.ssh/authorized_keys") and not os.path.lexists("/home/ansible-deploy/.ssh/authorized_keys2"),"paths":{{p:meta(p) for p in paths}},"locks":[p for p in ("/var/lib/home-lab/reconciliation/apply.lock","/var/lib/iac-ansible-production.lock","/var/lib/home-lab/firewall-transaction/active.json","/var/lock/home-lab-compose.lock","/run/lock/home-lab-restic-backup.lock") if os.path.lexists(p)]}},sort_keys=True,separators=(",",":")))\n'''
    result = subprocess.run(HUMAN, input=program, text=True, capture_output=True, timeout=60)
    if result.returncode or result.stderr: raise SystemExit("Restic recovery capability observation failed")
    value = json.loads(result.stdout)
    if value["account"] != {"groups": ["ansible-deploy"], "password_locked": True, "shell": TRANSPORT} or value["authorized_keys_absent"] is not True or value["locks"] != []:
        raise SystemExit("ansible-deploy boundary differs")
    for path, metadata in value["paths"].items():
        if metadata.get("exists") is True and (metadata.get("uid") != 0 or metadata.get("gid") != 0 or metadata.get("regular") is not True or metadata.get("symlink") is not False or metadata.get("nlink") != 1 or metadata.get("mode") != format(TARGETS[path], "04o")):
            raise SystemExit("installed Restic recovery capability metadata differs")
    if value["paths"][HELPER].get("exists") is False and value["paths"][SUDOERS].get("sha256") != sha(LEGACY_RULE.encode()):
        raise SystemExit("legacy Restic recovery capability boundary differs")
    value["candidates"] = observe_candidates()
    return value


def write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def plan() -> tuple[Path, str]:
    commit = clean_pushed_commit(); before = observe(); expected = {path: sha(raw) for path, raw in sources().items()}; matching = all(before["paths"][path].get("sha256") == expected[path] for path in TARGETS)
    transactions = before["candidates"]
    if len(transactions) > 1: raise SystemExit("Restic recovery capability transaction set differs")
    transaction_state = transactions[0] if transactions else None
    if transaction_state and transaction_state.get("after_sha256") != expected: raise SystemExit("Restic recovery capability transaction source differs")
    if transaction_state and transaction_state.get("status") in {"candidate", "committed"} and not matching: raise SystemExit("Restic recovery capability committed files differ")
    if transaction_state and transaction_state.get("status") in {"preparing", "rolling-back"}:
        payload = transaction_state.get("payload", {}); allowed = True
        for path in TARGETS:
            current = before["paths"][path]; old = payload.get("before_meta", {}).get(path); new_hash = expected[path]
            if current != old and current.get("sha256") != new_hash: allowed = False
        if not allowed: raise SystemExit("Restic recovery capability interrupted state differs")
    if transaction_state and transaction_state.get("status") == "committed" and matching:
        local_receipts = [json.loads(path.read_bytes()) for path in OUTPUT.glob("receipt-*.json")]
        if any(item.get("candidate_plan_sha256") == transaction_state.get("plan_sha256") for item in local_receipts): raise SystemExit("Restic recovery capability already matches")
    if matching and transaction_state is None: raise SystemExit("Restic recovery capability already matches")
    now = datetime.now(timezone.utc).replace(microsecond=0); value = {"format": "home-lab-proxmox-restic-recovery-capability-plan-v1", "commit": commit, "contract_sha256": sha((ROOT / "infrastructure/contract/home-lab.yml").read_bytes()), "inventory_sha256": sha((ROOT / "ansible/inventory/production.yml").read_bytes()), "host_key_fingerprint": FINGERPRINT, "created_at": now.isoformat().replace("+00:00", "Z"), "expires_at": (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"), "before": before, "after_sha256": expected, "modes": {path: format(mode, "04o") for path, mode in TARGETS.items()}, "resume_candidate": transaction_state["plan_sha256"] if transaction_state else None, "resume_status": transaction_state["status"] if transaction_state else None, "preserve": {"account": "ansible-deploy", "authorized_keys": "absent", "generic_shell": False}, "authorized": False}
    raw = canonical(value); digest = sha(raw); OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700); path = OUTPUT / f"{digest}.json"; write_exclusive(path, raw); return path, digest


def load_plan(path: Path) -> tuple[dict, bytes, str]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw); digest = sha(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or path.name != f"{digest}.json" or raw != canonical(value): raise SystemExit("capability plan metadata differs")
    if value.get("commit") != clean_pushed_commit() or value.get("contract_sha256") != sha((ROOT / "infrastructure/contract/home-lab.yml").read_bytes()) or value.get("inventory_sha256") != sha((ROOT / "ansible/inventory/production.yml").read_bytes()) or value.get("host_key_fingerprint") != FINGERPRINT or value.get("after_sha256") != {path: sha(raw) for path, raw in sources().items()} or datetime.now(timezone.utc) > datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")): raise SystemExit("capability plan binding or freshness differs")
    return value, raw, digest


def authorize(path: Path) -> None:
    value, _, digest = load_plan(path)
    if observe() != value["before"]: raise SystemExit("capability changed after planning")
    expected = f"authorize-proxmox-restic-recovery-capability-{digest}"
    if os.environ.get("PROXMOX_RESTIC_RECOVERY_CAPABILITY_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
    receipt = {"format": "home-lab-proxmox-restic-recovery-capability-authorization-v1", "plan_sha256": digest, "commit": value["commit"], "authorized_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}; raw = canonical(receipt); receipt_digest = sha(raw); target = OUTPUT / f"authorized-{receipt_digest}.json"; write_exclusive(target, raw); print(json.dumps({"authorization_sha256": receipt_digest, "path": str(target), "plan_sha256": digest}, sort_keys=True))


def remote_transaction(payload: dict, rollback: bool = False) -> dict:
    del rollback
    program = r'''import hashlib,json,os,stat
payload=json.loads(PAYLOAD)
def meta(path):
 try:s=os.lstat(path)
 except FileNotFoundError:return {"exists":False}
 raw=open(path,"rb").read();return {"exists":True,"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"regular":stat.S_ISREG(s.st_mode),"symlink":stat.S_ISLNK(s.st_mode),"nlink":s.st_nlink,"sha256":hashlib.sha256(raw).hexdigest(),"raw_hex":raw.hex()}
def put(path,raw,mode):
 directory=os.path.dirname(path);temporary=os.path.join(directory,f".{os.path.basename(path)}.{os.getpid()}.tmp");fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,"wb") as handle:os.fchown(handle.fileno(),0,0);os.fchmod(handle.fileno(),mode);handle.write(raw);handle.flush();os.fsync(handle.fileno())
 os.replace(temporary,path);d=os.open(directory,os.O_RDONLY);os.fsync(d);os.close(d)
base="/var/lib/home-lab";root=os.path.join(base,"restic-recovery-capability");journal=os.path.join(root,payload["plan_sha256"]);state_path=os.path.join(journal,"state.json")
def set_state(status):
 value={"status":status,"plan_sha256":payload["plan_sha256"],"after_sha256":{path:item["sha256"] for path,item in payload["after"].items()},"payload":payload};raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode();temporary=state_path+f".{os.getpid()}.tmp";fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
 os.replace(temporary,state_path);d=os.open(journal,os.O_RDONLY);os.fsync(d);os.close(d)
def restore():
 for path in payload["restore_order"]:
  item=payload["before"][path]
  current=meta(path);before=payload["before_meta"][path];after=payload["after"][path]
  if current!=before and current.get("sha256")!=after["sha256"]:raise SystemExit(66)
  if item["exists"]:put(path,bytes.fromhex(item["raw_hex"]),int(item["mode"],8))
  elif os.path.lexists(path):os.unlink(path)
if payload["rollback"]:
 if not os.path.isfile(state_path):raise SystemExit(67)
 set_state("rolling-back");restore();set_state("rolled-back");print(json.dumps({"status":"rolled-back"},sort_keys=True,separators=(",",":")));raise SystemExit
if os.path.isdir(journal):
 state=json.load(open(state_path))
 if state.get("status")!="preparing" or state.get("payload")!=payload:raise SystemExit(68)
else:
 for path in (root,journal):
  try:os.mkdir(path,0o700)
  except FileExistsError:
   if path==journal:raise
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=0:raise SystemExit(64)
 fd=os.open(os.path.join(journal,"rollback.json"),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"w") as handle:json.dump(payload["before"],handle,sort_keys=True,separators=(",",":"));handle.flush();os.fsync(handle.fileno())
 set_state("preparing")
for path in payload["before"]:
 current=meta(path);before=payload["before_meta"][path];after=payload["after"][path]
 if current!=before and current.get("sha256")!=after["sha256"]:raise SystemExit(64)
try:
 for path,item in payload["after"].items():
  if meta(path).get("sha256")!=item["sha256"]:put(path,bytes.fromhex(item["raw_hex"]),int(item["mode"],8))
 if {path:meta(path)["sha256"] for path in payload["after"]}!={path:item["sha256"] for path,item in payload["after"].items()}:raise RuntimeError("postcondition")
except Exception:
 set_state("rolling-back");restore();set_state("rolled-back");raise
set_state("candidate");print(json.dumps({"status":"candidate"},sort_keys=True,separators=(",",":")))
'''
    combined = program.replace("PAYLOAD", repr(json.dumps(payload, sort_keys=True, separators=(",", ":"))))
    result = subprocess.run(HUMAN, input=combined, text=True, capture_output=True, timeout=120)
    if result.returncode or result.stderr: raise SystemExit("Restic recovery capability host transaction failed")
    return json.loads(result.stdout)


def cleanup_canary_snippet(expected: str) -> None:
    program = f'''import hashlib,os,stat\npath="/var/lib/vz/snippets/home-lab-restic-recovery-cloud-init.yaml"\nif os.path.lexists(path):\n s=os.lstat(path);raw=open(path,"rb").read() if stat.S_ISREG(s.st_mode) else b""\n if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or hashlib.sha256(raw).hexdigest()!={expected!r}:raise SystemExit(65)\n os.unlink(path);directory=os.open(os.path.dirname(path),os.O_RDONLY);os.fsync(directory);os.close(directory)\n'''
    result = subprocess.run(HUMAN, input=program, text=True, capture_output=True, timeout=60)
    if result.returncode or result.stderr: raise SystemExit("capability canary cleanup failed")


def commit_candidate(candidate_digest: str, receipt_plan_digest: str) -> None:
    program = f'''import hashlib,json,os,stat\njournal={str(Path('/var/lib/home-lab/restic-recovery-capability') / candidate_digest)!r};state_path=os.path.join(journal,"state.json");value=json.load(open(state_path))\nif value.get("status")!="candidate" or value.get("plan_sha256")!={candidate_digest!r}:raise SystemExit(64)\nfor path,expected in value["after_sha256"].items():\n s=os.lstat(path);raw=open(path,"rb").read()\n if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit(65)\nvalue["status"]="committed";value["receipt_plan_sha256"]={receipt_plan_digest!r};temporary=state_path+f".{{os.getpid()}}.tmp";raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\\n").encode();fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nwith os.fdopen(fd,"wb") as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())\nos.replace(temporary,state_path);directory=os.open(journal,os.O_RDONLY);os.fsync(directory);os.close(directory)\n'''
    result = subprocess.run(HUMAN, input=program, text=True, capture_output=True, timeout=60)
    if result.returncode or result.stderr: raise SystemExit("capability candidate commit failed")


def apply(plan_path: Path, authorization_path: Path) -> None:
    value, _, digest = load_plan(plan_path); auth_info = authorization_path.lstat(); auth_raw = authorization_path.read_bytes(); auth = json.loads(auth_raw); auth_digest = sha(auth_raw)
    if not stat.S_ISREG(auth_info.st_mode) or stat.S_IMODE(auth_info.st_mode) != 0o600 or auth_info.st_uid != os.getuid() or auth_info.st_nlink != 1 or authorization_path.name != f"authorized-{auth_digest}.json" or auth_raw != canonical(auth) or auth != {"format": "home-lab-proxmox-restic-recovery-capability-authorization-v1", "plan_sha256": digest, "commit": value["commit"], "authorized_at": auth.get("authorized_at")}: raise SystemExit("capability authorization differs")
    before = observe()
    if before != value["before"]: raise SystemExit("capability changed after authorization")
    expected = f"apply-proxmox-restic-recovery-capability-{digest}-{auth_digest}"
    if os.environ.get("PROXMOX_RESTIC_RECOVERY_CAPABILITY_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
    source = sources(); resume_digest = value.get("resume_candidate"); resume_status = value.get("resume_status"); already_committed = resume_status == "committed"
    if resume_digest:
        transactions = [item for item in before["candidates"] if item.get("plan_sha256") == resume_digest]
        if len(transactions) != 1: raise SystemExit("capability resume transaction differs")
        payload = transactions[0]["payload"]
        if resume_status == "rolling-back":
            payload["rollback"] = True; remote_transaction(payload, rollback=True); restored = observe(); backup = {path: {"exists": item.get("exists") is True, "mode": item.get("mode"), "raw_hex": item.get("raw_hex") or ""} for path, item in restored["paths"].items()}; payload = {"rollback": False, "plan_sha256": digest, "before": backup, "before_meta": restored["paths"], "restore_order": list(RESTORE_ORDER), "after": {path: {"raw_hex": raw.hex(), "mode": format(TARGETS[path], "04o"), "sha256": sha(raw)} for path, raw in source.items()}}; resume_status = None; already_committed = False
            if remote_transaction(payload) != {"status": "candidate"}: raise SystemExit("capability rollback resume differs")
        elif resume_status == "preparing":
            if remote_transaction(payload) != {"status": "candidate"}: raise SystemExit("capability preparing resume differs")
    else:
        backup = {path: {"exists": item.get("exists") is True, "mode": item.get("mode"), "raw_hex": item.get("raw_hex") or ""} for path, item in before["paths"].items()}; payload = {"rollback": False, "plan_sha256": digest, "before": backup, "before_meta": before["paths"], "restore_order": list(RESTORE_ORDER), "after": {path: {"raw_hex": raw.hex(), "mode": format(TARGETS[path], "04o"), "sha256": sha(raw)} for path, raw in source.items()}}
        try:
            if remote_transaction(payload) != {"status": "candidate"}: raise RuntimeError("capability candidate receipt differs")
        except Exception:
            payload["rollback"] = True; remote_transaction(payload, rollback=True); raise
    candidate_digest = payload["plan_sha256"]
    test_raw = b"#cloud-config\nhostname: home-lab-capability-canary\n"; test_digest = sha(test_raw)
    try:
        staged = subprocess.run((*DEPLOY, f"restic-recovery stage-snippet {test_digest}"), input=test_raw, capture_output=True, timeout=60)
        removed = subprocess.run((*DEPLOY, f"restic-recovery remove-snippet {test_digest}"), capture_output=True, timeout=60)
        rejected = subprocess.run((*DEPLOY, "restic-recovery stage-snippet invalid;id"), capture_output=True, timeout=60)
        if staged.returncode or json.loads(staged.stdout) != {"sha256": test_digest, "staged": True} or removed.returncode or json.loads(removed.stdout) != {"removed": True, "sha256": test_digest} or rejected.returncode != 64: raise RuntimeError("capability canary differs")
    except Exception:
        cleanup_canary_snippet(test_digest)
        if not already_committed: payload["rollback"] = True; remote_transaction(payload, rollback=True)
        raise
    after = observe()
    if any(after["paths"][path].get("sha256") != sha(source[path]) for path in TARGETS):
        cleanup_canary_snippet(test_digest)
        if not already_committed: payload["rollback"] = True; remote_transaction(payload, rollback=True)
        raise SystemExit("capability post-observation differs")
    if not already_committed: commit_candidate(candidate_digest, digest)
    final = observe(); active = [item for item in final["candidates"] if item.get("status") != "committed"]
    if active or any(final["paths"][path].get("sha256") != sha(source[path]) for path in TARGETS): raise SystemExit("capability committed observation differs")
    receipt = {"format": "home-lab-proxmox-restic-recovery-capability-receipt-v1", "plan_sha256": digest, "candidate_plan_sha256": candidate_digest, "status": "committed", "snippet_transport_canary": True, "guest_interfaces_canary": "required-during-live-vm-9900-qualification"}; receipt_raw = canonical(receipt); receipt_digest = sha(receipt_raw); write_exclusive(OUTPUT / f"receipt-{receipt_digest}.json", receipt_raw)
    print(json.dumps({**receipt, "receipt_sha256": receipt_digest}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True); commands.add_parser("plan"); auth = commands.add_parser("authorize"); auth.add_argument("plan", type=Path); apply_parser = commands.add_parser("apply"); apply_parser.add_argument("plan", type=Path); apply_parser.add_argument("authorization", type=Path); args = parser.parse_args()
    if args.command == "plan": path, digest = plan(); print(json.dumps({"authorized": False, "path": str(path), "plan_sha256": digest}, sort_keys=True))
    elif args.command == "authorize": authorize(args.plan.resolve())
    else: apply(args.plan.resolve(), args.authorization.resolve())


if __name__ == "__main__": main()
