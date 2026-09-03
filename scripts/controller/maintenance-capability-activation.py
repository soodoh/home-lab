#!/usr/bin/env python3
"""Save and consume one exact Debian maintenance capability plan."""
import argparse, datetime as dt, hashlib, json, os, stat, subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock
ROOT=Path(__file__).resolve().parents[2]; OUTPUT=ROOT/".local/maintenance-capabilities"; LOCK=ROOT/".local/locks/maintenance-capability.lock"
SOURCES={
 "package-identity":["infrastructure/maintenance/host/debian-package-apply-transport","infrastructure/maintenance/host/debian-package-transaction","infrastructure/maintenance/host/package-candidate-observer"],
 "unattended-retirement":["infrastructure/maintenance/host/unattended-retirement-observer","infrastructure/maintenance/host/unattended-retirement-transaction"],
 "debian-reboot":["infrastructure/maintenance/host/debian-reboot-transaction"],
}
def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(*args): return subprocess.check_output(("git",*args),cwd=ROOT,text=True).strip()
def commit():
 c=git("rev-parse","HEAD")
 if c!=git("rev-parse","origin/main") or git("status","--porcelain=v1","--untracked-files=all"): raise SystemExit("capability plan requires clean pushed HEAD")
 return c
def source_hashes(kind):
 names={"package-identity":["transport","executor","observer"],"unattended-retirement":["observer","executor"],"debian-reboot":["executor"]}[kind]
 return {name:sha((ROOT/path).read_bytes()) for name,path in zip(names,SOURCES[kind])}
def save(kind):
 now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0); material={"format":"home-lab-maintenance-capability-plan-v1","kind":kind,"host":"debian","commit":commit(),"contract_sha256":sha((ROOT/"infrastructure/contract/home-lab.yml").read_bytes()),"inventory_sha256":sha((ROOT/"ansible/inventory/production.yml").read_bytes()),"source_hashes":source_hashes(kind),"created_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now+dt.timedelta(minutes=30)).isoformat().replace("+00:00","Z"),"authorized":False,"automatic_apply":False}
 raw=canonical(material); digest=sha(raw); OUTPUT.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(OUTPUT,0o700); path=OUTPUT/f"{digest}.json"; fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
 print(json.dumps({"authorized":False,"path":str(path),"plan_sha256":digest},sort_keys=True))
def load(path):
 info=path.lstat(); raw=path.read_bytes(); value=json.loads(raw); digest=sha(raw)
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.getuid() or path.name!=f"{digest}.json" or raw!=canonical(value): raise SystemExit("capability plan metadata or canonical hash differs")
 kind=value.get("kind")
 if kind not in SOURCES or value.get("format")!="home-lab-maintenance-capability-plan-v1" or value.get("authorized") is not False or value.get("automatic_apply") is not False or value.get("commit")!=commit() or value.get("source_hashes")!=source_hashes(kind) or value.get("contract_sha256")!=sha((ROOT/"infrastructure/contract/home-lab.yml").read_bytes()) or value.get("inventory_sha256")!=sha((ROOT/"ansible/inventory/production.yml").read_bytes()) or dt.datetime.now(dt.timezone.utc)>dt.datetime.fromisoformat(value["expires_at"].replace("Z","+00:00")): raise SystemExit("capability plan binding or freshness differs")
 return value,digest
def apply(path):
 value,digest=load(path); expected=f"apply-{value['kind']}-capability-{digest}"
 if os.environ.get("MAINTENANCE_CAPABILITY_CONFIRMED")!=expected: raise SystemExit(f"exact confirmation required: {expected}")
 extras=json.dumps({"maintenance_capability_kind":value["kind"],"maintenance_capability_plan_sha256":digest,"maintenance_capability_approved_sha256":digest,"maintenance_capability_source_hashes":value["source_hashes"]},separators=(",",":"))
 command=("ansible-playbook","-i",str(ROOT/"ansible/inventory/production.yml"),"--limit","docker_host",str(ROOT/"ansible/playbooks/install-maintenance-capability.yml"),"--extra-vars",extras)
 checked=subprocess.run((*command,"--check"),cwd=ROOT)
 if checked.returncode: raise SystemExit("immediate capability check failed")
 LOCK.parent.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(LOCK.parent,0o700); lock=acquire_transfer_lock(LOCK)
 try: result=subprocess.run(command,cwd=ROOT)
 finally: os.close(lock)
 if result.returncode: raise SystemExit("capability apply failed; retained host lock may require inspection")
 print(json.dumps({"capability":"installed","kind":value["kind"],"plan_sha256":digest},sort_keys=True))
def main():
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="command",required=True); planned=sub.add_parser("plan"); planned.add_argument("kind",choices=sorted(SOURCES)); applied=sub.add_parser("apply"); applied.add_argument("plan",type=Path); args=p.parse_args(); save(args.kind) if args.command=="plan" else apply(args.plan.resolve())
if __name__=="__main__": main()
