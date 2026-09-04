#!/usr/bin/env python3
"""Guarded additive VM9900 disk-inspection ACL for the existing plan token."""
import argparse,datetime as dt,fcntl,hashlib,json,os,re,stat,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; OUT=ROOT/".local/proxmox-vm9900-plan-acl"; os.umask(0o077)
def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(v): return hashlib.sha256(v).hexdigest()
def commit():
 head=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(); origin=subprocess.check_output(["git","rev-parse","origin/main"],text=True).strip(); dirty=subprocess.check_output(["git","status","--porcelain"],text=True)
 if head!=origin or dirty: raise SystemExit("clean pushed commit required")
 return head
def ssh():
 known=os.environ.get("HOME_LAB_PROXMOX_PRODUCTION_KNOWN_HOSTS","")
 if not known: raise SystemExit("dedicated known-hosts required")
 return ["ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no","-o",f"UserKnownHostsFile={known}","-o","IdentitiesOnly=yes","-o","IdentityFile=none","-o","PreferredAuthentications=none","-o","PubkeyAuthentication=no","-o","PasswordAuthentication=no","-o","KbdInteractiveAuthentication=no","-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no","-o","RequestTTY=no","proxmox@proxmox"]
def observer_program(): return '''import json,subprocess\nrows=json.loads(subprocess.run(["/usr/bin/pvesh","get","/access/acl","--output-format","json"],check=True,capture_output=True,text=True).stdout)\nselected=sorted(({"path":r.get("path"),"propagate":int(r.get("propagate",0)),"roleid":r.get("roleid"),"ugid":r.get("ugid")} for r in rows if r.get("ugid")=="root@pam!tofu-plan"),key=lambda r:(r["path"],r["roleid"]))\nprint(json.dumps({"records":selected},sort_keys=True,separators=(",",":")))\n'''
def observe():
 result=subprocess.run([*ssh(),"sudo -n -- /usr/bin/python3 -"],input=observer_program(),text=True,capture_output=True,timeout=60)
 if result.returncode or result.stderr: raise SystemExit("ACL observation failed")
 return json.loads(result.stdout)
def expected(before_include_9900):
 rows=[{"path":"/","propagate":1,"roleid":"HomeLabTofuPlan","ugid":"root@pam!tofu-plan"},{"path":"/vms/100","propagate":1,"roleid":"HomeLabTofuPlanDiskInspect","ugid":"root@pam!tofu-plan"}]
 if before_include_9900: rows.append({"path":"/vms/9900","propagate":1,"roleid":"HomeLabTofuPlanDiskInspect","ugid":"root@pam!tofu-plan"})
 return {"records":sorted(rows,key=lambda r:(r["path"],r["roleid"]))}
def plan():
 before=observe()
 if before!=expected(False): raise SystemExit("unexpected plan-token ACL baseline")
 now=dt.datetime.now(dt.timezone.utc); value={"authorized":False,"automatic_apply":False,"before_sha256":sha(canonical(before)),"commit":commit(),"created_at":now.isoformat().replace("+00:00","Z"),"desired":expected(True),"expires_at":(now+dt.timedelta(minutes=20)).isoformat().replace("+00:00","Z"),"format":"home-lab-proxmox-vm9900-plan-acl-v1","operation":"add-vm9900-plan-disk-inspection","version":1}; raw=canonical(value); digest=sha(raw); OUT.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(OUT,0o700); fd=os.open(OUT/f"{digest}.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as out: out.write(raw); out.flush(); os.fsync(out.fileno())
 print(json.dumps({"authorized":False,"path":str(OUT/f'{digest}.json'),"plan_sha256":digest},sort_keys=True))
def load(path):
 info=path.lstat(); raw=path.read_bytes(); value=json.loads(raw); digest=sha(raw)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or raw!=canonical(value) or path.name!=f"{digest}.json": raise SystemExit("unsafe ACL plan")
 if value.get("commit")!=commit() or value.get("authorized") is not False or value.get("automatic_apply") is not False or value.get("desired")!=expected(True) or dt.datetime.now(dt.timezone.utc)>dt.datetime.fromisoformat(value["expires_at"].replace("Z","+00:00")): raise SystemExit("ACL plan binding failed")
 return value,raw,digest
def apply(path):
 value,raw,digest=load(path); confirmation=f"add-vm9900-plan-acl-{digest}"
 if os.environ.get("PROXMOX_VM9900_PLAN_ACL_CONFIRMED")!=confirmation: raise SystemExit(f"exact confirmation required: {confirmation}")
 if sha(canonical(observe()))!=value["before_sha256"]: raise SystemExit("ACL precondition changed")
 program=f'''import fcntl,hashlib,json,os,subprocess\nrequest=json.loads({raw.decode()!r}); lock=os.open("/var/lib/home-lab/reconciliation/operation.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)\ndef current():\n rows=json.loads(subprocess.run(["/usr/bin/pvesh","get","/access/acl","--output-format","json"],check=True,capture_output=True,text=True).stdout); return {{"records":sorted(({{"path":r.get("path"),"propagate":int(r.get("propagate",0)),"roleid":r.get("roleid"),"ugid":r.get("ugid")}} for r in rows if r.get("ugid")=="root@pam!tofu-plan"),key=lambda r:(r["path"],r["roleid"]))}}\ndef enc(v): return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\\n").encode()\nif hashlib.sha256(enc(current())).hexdigest()!=request["before_sha256"]: raise SystemExit("ACL precondition changed")\nsubprocess.run(["/usr/sbin/pveum","acl","modify","/vms/9900","--tokens","root@pam!tofu-plan","--roles","HomeLabTofuPlanDiskInspect","--propagate","1"],check=True,capture_output=True)\nafter=current()\nif after!=request["desired"]: raise SystemExit("ACL postcondition failed")\nprint(json.dumps({{"after":after,"changed":True}},sort_keys=True,separators=(",",":")))\n'''
 OUT.mkdir(mode=0o700,parents=True,exist_ok=True); lock_fd=os.open(OUT/"controller.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB); result=subprocess.run([*ssh(),"sudo -n -- /usr/bin/python3 -"],input=program,text=True,capture_output=True,timeout=90)
 finally: os.close(lock_fd)
 if result.returncode or result.stderr: raise SystemExit("ACL apply failed")
 receipt=json.loads(result.stdout)
 if receipt!={"after":expected(True),"changed":True}: raise SystemExit("ACL receipt mismatch")
 print(json.dumps({"changed":True,"plan_sha256":digest},sort_keys=True))
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True); sub.add_parser("plan"); a=sub.add_parser("apply"); a.add_argument("plan",type=Path); args=parser.parse_args(); plan() if args.command=="plan" else apply(args.plan.resolve())
if __name__=="__main__": main()
