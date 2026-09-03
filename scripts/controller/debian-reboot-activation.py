#!/usr/bin/env python3
"""Build and execute one exact Debian reboot activation; never retry a reboot."""
import argparse, datetime as dt, hashlib, json, os, shlex, stat, subprocess, time
from pathlib import Path
from protected_execution import acquire_transfer_lock
ROOT=Path(__file__).resolve().parents[2]; OUTPUT=ROOT/".local/debian-reboot-activations"; LOCK=ROOT/".local/locks/debian-reboot.lock"; EXECUTOR=ROOT/"infrastructure/maintenance/host/debian-reboot-transaction"
def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(*args): return subprocess.check_output(("git",*args),cwd=ROOT,text=True).strip()
def commit():
 c=git("rev-parse","HEAD")
 if c!=git("rev-parse","origin/main") or git("status","--porcelain=v1","--untracked-files=all"): raise SystemExit("Debian reboot activation requires clean pushed HEAD")
 return c
def private(path):
 info=path.lstat(); raw=path.read_bytes(); value=json.loads(raw)
 if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_uid!=os.getuid() or raw!=canonical(value): raise SystemExit("reboot artifact metadata differs")
 return value,raw
def ssh():
 known=os.environ.get("HOME_LAB_DEBIAN_PRODUCTION_KNOWN_HOSTS","")
 if not known or not Path(known).is_absolute(): raise SystemExit("dedicated Debian known-hosts path required")
 return ("ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={known}","-o","UpdateHostKeys=no","-o","IdentitiesOnly=yes","-o","RequestTTY=no","-o","ClearAllForwardings=yes","ansible-deploy@docker-host")
def build(path):
 maintenance,raw=private(path); evidence=maintenance.get("evidence",{}); bindings=maintenance.get("bindings",{}); current=commit()
 plan_material=dict(maintenance); plan_material.pop("plan_sha256",None)
 if maintenance.get("format")!="home-lab-host-maintenance-plan-v1" or maintenance.get("kind")!="reboot" or maintenance.get("host")!="debian" or maintenance.get("authorized") is not False or maintenance.get("actionable") is not True or maintenance.get("blockers")!=["saved-reviewed-plan-required","separate-reboot-authorization-required"] or maintenance.get("plan_sha256")!=sha(canonical(plan_material)) or bindings.get("git_commit")!=current or evidence.get("reboot_indicated") is not True or evidence.get("evidence_sha256")!=maintenance.get("evidence_sha256") or dt.datetime.now(dt.timezone.utc)>dt.datetime.fromisoformat(maintenance["expires_at"].replace("Z","+00:00")): raise SystemExit("maintenance reboot plan is not current and actionable")
 policy=__import__("yaml").safe_load((ROOT/"infrastructure/contract/home-lab.yml").read_text())["lifecycle"]["maintenance"]["reboot_plan"]
 material={"format":"home-lab-debian-reboot-activation-v1","host":"debian","commit":current,"created_at":maintenance["created_at"],"expires_at":maintenance["expires_at"],"maintenance_plan_sha256":maintenance["plan_sha256"],"expected":{"boot_id":evidence["boot_id"],"current_kernel":evidence["current_kernel"],"target_kernel":evidence["target_kernel"]},"evidence_sha256":evidence["evidence_sha256"],"pending_package_transaction_sha256":evidence["pending_package_transaction_sha256"],"inactive_backup_units":policy["inactive_backup_units"],"conflict_locks":policy["conflict_locks"],"workload_order":policy["workload_order"]["debian"],"postchecks":policy["postchecks"]["debian"],"executor_sha256":sha(EXECUTOR.read_bytes()),"automatic_reboot":False,"authorized":False}
 material["activation_sha256"]=sha(canonical(material)); raw=canonical(material); digest=sha(raw); OUTPUT.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(OUTPUT,0o700); target=OUTPUT/f"{digest}.json"; fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
 print(json.dumps({"authorized":False,"path":str(target),"activation_sha256":digest},sort_keys=True))
def load(path,allow_expired=False):
 value,raw=private(path); digest=sha(raw); material=dict(value); inner=material.pop("activation_sha256",None)
 if path.name!=f"{digest}.json" or value.get("format")!="home-lab-debian-reboot-activation-v1" or value.get("commit")!=commit() or value.get("authorized") is not False or value.get("automatic_reboot") is not False or value.get("executor_sha256")!=sha(EXECUTOR.read_bytes()) or inner!=sha(canonical(material)) or (not allow_expired and dt.datetime.now(dt.timezone.utc)>dt.datetime.fromisoformat(value["expires_at"].replace("Z","+00:00"))): raise SystemExit("reboot activation binding differs")
 return value,raw,digest
def stage(raw,digest):
 program='''import json,os,sys\nraw=sys.stdin.buffer.read(65537); digest=%r\nif len(raw)>65536 or __import__("hashlib").sha256(raw).hexdigest()!=digest: raise SystemExit(65)\nroot="/var/lib/home-lab/debian-reboot/plans"; os.makedirs(root,mode=0o700,exist_ok=True); os.chmod(root,0o700); path=root+"/"+digest+".json"\nif os.path.exists(path):\n existing=open(path,"rb").read()\n if existing!=raw: raise SystemExit(65)\nelse:\n fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.write(fd,raw); os.fchmod(fd,0o600); os.fchown(fd,0,0); os.fsync(fd); os.close(fd)\nprint('{"staged":true}')\n''' % digest
 result=subprocess.run((*ssh(),"sudo -n -- /usr/bin/python3 -c "+shlex.quote(program)),input=raw,capture_output=True,timeout=120)
 if result.returncode or result.stderr or result.stdout!=b'{"staged":true}\n': raise SystemExit("reboot activation staging failed")
def remote(operation,digest,timeout=600):
 result=subprocess.run((*ssh(),f"sudo -n -- /usr/local/libexec/home-lab/debian-reboot-transaction {operation} {digest}"),capture_output=True,timeout=timeout)
 if result.returncode or result.stderr: raise SystemExit(f"reboot {operation} failed; inspect retained journal manually")
 return json.loads(result.stdout)
def prepare(path):
 value,raw,digest=load(path); expected=f"prepare-debian-reboot-{digest}"
 if os.environ.get("DEBIAN_REBOOT_PREPARE_CONFIRMED")!=expected: raise SystemExit(f"exact confirmation required: {expected}")
 stage(raw,digest); print(json.dumps(remote("prepare",digest),sort_keys=True))
def apply(path):
 value,raw,digest=load(path); expected=f"apply-debian-reboot-{digest}"
 if os.environ.get("DEBIAN_REBOOT_APPLY_CONFIRMED")!=expected: raise SystemExit(f"exact confirmation required: {expected}")
 LOCK.parent.mkdir(parents=True,exist_ok=True,mode=0o700); lock=acquire_transfer_lock(LOCK)
 try:
  started=subprocess.run((*ssh(),f"sudo -n -- /usr/local/libexec/home-lab/debian-reboot-transaction apply {digest}"),capture_output=True,timeout=120)
  if started.returncode not in {0,255}: raise SystemExit("reboot initiation failed; do not retry automatically")
  deadline=time.monotonic()+900; verified=None
  while time.monotonic()<deadline:
   time.sleep(10)
   try: verified=remote("verify",digest,90); break
   except (SystemExit,subprocess.TimeoutExpired): continue
  if verified is None: raise SystemExit("postboot verification timed out; do not retry reboot")
  audit=subprocess.run(("ansible-playbook","-i",str(ROOT/"ansible/inventory/production.yml"),"--limit","docker_host",str(ROOT/"ansible/playbooks/audit.yml")),cwd=ROOT)
  if audit.returncode: raise SystemExit("postboot production audit failed; journal remains for manual recovery")
  committed=remote("commit",digest); print(json.dumps(committed,sort_keys=True))
 finally: os.close(lock)
def main():
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="command",required=True); x=sub.add_parser("build"); x.add_argument("maintenance_plan",type=Path); x=sub.add_parser("prepare"); x.add_argument("activation",type=Path); x=sub.add_parser("apply"); x.add_argument("activation",type=Path); args=p.parse_args(); build(args.maintenance_plan.resolve()) if args.command=="build" else prepare(args.activation.resolve()) if args.command=="prepare" else apply(args.activation.resolve())
if __name__=="__main__": main()
