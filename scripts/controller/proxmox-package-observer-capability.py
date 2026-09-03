#!/usr/bin/env python3
"""Plan/install the generated Proxmox package observer as an exact capability upgrade."""
import argparse, base64, datetime as dt, hashlib, json, os, shlex, stat, subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock
ROOT=Path(__file__).resolve().parents[2]; OUTPUT=ROOT/".local/proxmox-package-observer-capability"; CONTROLLER_LOCK=ROOT/".local/locks/proxmox-package-observer-capability.lock"
def ssh():
 known=os.environ.get("HOME_LAB_PROXMOX_PRODUCTION_KNOWN_HOSTS",""); path=Path(known)
 if not known or not path.is_absolute(): raise SystemExit("dedicated Proxmox known-hosts path required")
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600: raise SystemExit("dedicated Proxmox known-hosts metadata differs")
 identity=subprocess.run(("ssh-keygen","-lf",known),capture_output=True,text=True); lines=[line for line in identity.stdout.splitlines() if line]
 if identity.returncode or identity.stderr or len(lines)!=1 or lines[0].split()[1]!="SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ": raise SystemExit("dedicated Proxmox host key identity differs")
 return ("ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={known}","-o","UpdateHostKeys=no","-o","IdentitiesOnly=yes","-o","RequestTTY=no","-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no","proxmox@proxmox")
TRANSPORT="/usr/local/libexec/home-lab/proxmox-ansible-plan-transport"; OBSERVER="/usr/local/libexec/home-lab/proxmox-package-candidate-observer"; SUDO="/etc/sudoers.d/ansible-plan"
RULE="ansible-plan ALL=(root) NOPASSWD: /usr/local/libexec/home-lab/proxmox-observer observe, /usr/local/libexec/home-lab/proxmox-package-candidate-observer observe proxmox\n"
def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(*args): return subprocess.check_output(("git",*args),cwd=ROOT,text=True).strip()
def commit():
 c=git("rev-parse","HEAD")
 if c!=git("rev-parse","origin/main") or git("status","--porcelain=v1","--untracked-files=all"): raise SystemExit("package observer capability requires clean pushed HEAD")
 return c
def regular(path,mode):
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=mode: raise SystemExit(f"artifact metadata differs: {path}")
 return path.read_bytes()
def desired(artifact):
 manifest=regular(artifact/"manifest.json",0o644); value=json.loads(manifest); package=regular(artifact/"proxmox-package-candidate-observer",0o755); transport=regular(ROOT/"infrastructure/proxmox-access/host/proxmox-ansible-plan-transport",0o755)
 if value.get("package_observer_sha256")!=sha(package): raise SystemExit("generated package observer manifest differs")
 return {TRANSPORT:{"sha256":sha(transport),"mode":"0755"},OBSERVER:{"sha256":sha(package),"mode":"0755"},SUDO:{"sha256":sha(RULE.encode()),"mode":"0440"}},transport,package
def observe():
 program='''import hashlib,json,os,stat\npaths={}\nfor p in %r:\n try:\n  before=os.lstat(p)\n  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>1048576: paths[p]={"exists":True,"uid":before.st_uid,"gid":before.st_gid,"mode":format(stat.S_IMODE(before.st_mode),"04o"),"nlink":before.st_nlink,"regular":False}; continue\n  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW); after=os.fstat(fd); raw=os.read(fd,1048577); os.close(fd)\n  if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size) or len(raw)>1048576: raise RuntimeError("artifact changed during observation")\n  paths[p]={"exists":True,"uid":after.st_uid,"gid":after.st_gid,"mode":format(stat.S_IMODE(after.st_mode),"04o"),"nlink":after.st_nlink,"regular":True,"sha256":hashlib.sha256(raw).hexdigest()}\n except FileNotFoundError: paths[p]={"exists":False}\nlocks=[p for p in ("/var/lib/iac-ansible-production.lock","/var/lib/home-lab/reconciliation/owner.lock","/var/lib/home-lab/reconciliation/nix.lock","/var/lib/home-lab/reconciliation/operation.lock","/var/lib/home-lab/firewall-transaction/active.json") if os.path.lexists(p)]\nprint(json.dumps({"paths":paths,"locks":locks},sort_keys=True,separators=(",",":")))\n''' % ((TRANSPORT,OBSERVER,SUDO),)
 result=subprocess.run((*ssh(),"sudo -n -- /usr/bin/python3 -"),input=program,text=True,capture_output=True,timeout=60)
 if result.returncode or result.stderr: raise SystemExit("package observer capability observation failed")
 return json.loads(result.stdout)
def validate_current(current):
 if current.get("locks"): raise SystemExit("active production lock blocks capability transaction")
 for path,mode in ((TRANSPORT,"0755"),(SUDO,"0440")):
  meta=current.get("paths",{}).get(path,{})
  if meta.get("exists") is not True or meta.get("regular") is not True or meta.get("uid")!=0 or meta.get("gid")!=0 or meta.get("nlink")!=1 or meta.get("mode")!=mode: raise SystemExit("existing package observer capability metadata differs")
 package=current.get("paths",{}).get(OBSERVER,{})
 if package.get("exists") is not False and (package.get("regular") is not True or package.get("uid")!=0 or package.get("gid")!=0 or package.get("nlink")!=1 or package.get("mode")!="0755"): raise SystemExit("existing package observer metadata differs")
def plan(artifact):
 wanted,_,_=desired(artifact); current=observe(); validate_current(current)
 now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0); value={"format":"home-lab-proxmox-package-observer-capability-v1","commit":commit(),"contract_sha256":sha((ROOT/"infrastructure/contract/home-lab.yml").read_bytes()),"inventory_sha256":sha((ROOT/"ansible/inventory/proxmox-production.yml").read_bytes()),"created_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now+dt.timedelta(minutes=30)).isoformat().replace("+00:00","Z"),"before":current,"before_sha256":sha(canonical(current)),"desired":wanted,"authorized":False,"automatic_apply":False}
 raw=canonical(value); digest=sha(raw); OUTPUT.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(OUTPUT,0o700); path=OUTPUT/f"{digest}.json"; fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
 print(json.dumps({"authorized":False,"path":str(path),"plan_sha256":digest},sort_keys=True))
def apply(path,artifact):
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>262144: raise SystemExit("package observer capability plan metadata differs")
 descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try: after=os.fstat(descriptor); raw=os.read(descriptor,262145)
 finally: os.close(descriptor)
 if (info.st_dev,info.st_ino,info.st_size)!=(after.st_dev,after.st_ino,after.st_size) or len(raw)>262144: raise SystemExit("package observer capability plan changed during read")
 value=json.loads(raw); digest=sha(raw); wanted,transport,package=desired(artifact)
 if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or path.name!=f"{digest}.json" or raw!=canonical(value) or value.get("format")!="home-lab-proxmox-package-observer-capability-v1" or value.get("commit")!=commit() or value.get("contract_sha256")!=sha((ROOT/"infrastructure/contract/home-lab.yml").read_bytes()) or value.get("inventory_sha256")!=sha((ROOT/"ansible/inventory/proxmox-production.yml").read_bytes()) or value.get("authorized") is not False or value.get("automatic_apply") is not False or value.get("desired")!=wanted or dt.datetime.now(dt.timezone.utc)>dt.datetime.fromisoformat(value["expires_at"].replace("Z","+00:00")): raise SystemExit("package observer capability plan differs or expired")
 expected=f"apply-proxmox-package-observer-capability-{digest}"
 if os.environ.get("PROXMOX_PACKAGE_OBSERVER_CAPABILITY_CONFIRMED")!=expected: raise SystemExit(f"exact confirmation required: {expected}")
 current=observe(); validate_current(current)
 if sha(canonical(current))!=value.get("before_sha256"): raise SystemExit("package observer capability live state changed")
 payload={"plan_sha256":digest,"files":{TRANSPORT:base64.b64encode(transport).decode(),OBSERVER:base64.b64encode(package).decode(),SUDO:base64.b64encode(RULE.encode()).decode()},"hashes":wanted}
 installer='''import base64,hashlib,json,os,stat,sys\np=json.load(sys.stdin); backups={}; temps={}; lock="/var/lib/iac-ansible-production.lock"\nos.mkdir(lock,0o700); owner=lock+"/owner"; lockfd=os.open(owner,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.write(lockfd,("controller=proxmox\\noperation=package-observer-capability-%s\\n"%p["plan_sha256"]).encode()); os.fchown(lockfd,0,0); os.fchmod(lockfd,0o600); os.fsync(lockfd); os.close(lockfd)\ndef syncdirs():\n for directory in {os.path.dirname(x) for x in p["files"]}: fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)\ndef release():\n os.unlink(owner); os.rmdir(lock); fd=os.open("/var/lib",os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)\ntry:\n for path,text in p["files"].items():\n  raw=base64.b64decode(text,validate=True); expected=p["hashes"][path]\n  if hashlib.sha256(raw).hexdigest()!=expected["sha256"]: raise RuntimeError("payload hash")\n  if os.path.exists(path):\n   before=os.lstat(path)\n   if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: raise RuntimeError("existing artifact metadata")\n   source=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); old=os.read(source,1048577); after=os.fstat(source); os.close(source)\n   if len(old)>1048576 or (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size): raise RuntimeError("existing artifact changed")\n   backups[path]=(old,stat.S_IMODE(after.st_mode),after.st_uid,after.st_gid)\n  else: backups[path]=None\n  tmp=path+"."+p["plan_sha256"]+".tmp"; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,int(expected["mode"],8)); os.write(fd,raw); os.fchmod(fd,int(expected["mode"],8)); os.fchown(fd,0,0); os.fsync(fd); os.close(fd); temps[path]=tmp\n if os.system("/usr/sbin/visudo --check --file="+temps["/etc/sudoers.d/ansible-plan"]+" >/dev/null")!=0: raise RuntimeError("sudo")\n for path,tmp in temps.items(): os.replace(tmp,path)\n syncdirs()\nexcept Exception:\n for tmp in temps.values():\n  if os.path.exists(tmp): os.unlink(tmp)\n for path,prior in backups.items():\n  if prior is None:\n   if os.path.exists(path): os.unlink(path)\n  else:\n   raw,mode,uid,gid=prior; tmp=path+"."+p["plan_sha256"]+".rollback"; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode); os.write(fd,raw); os.fchmod(fd,mode); os.fchown(fd,uid,gid); os.fsync(fd); os.close(fd); os.replace(tmp,path)\n syncdirs(); release(); raise\nrelease(); print('{"installed":true}')\n'''
 CONTROLLER_LOCK.parent.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(CONTROLLER_LOCK.parent,0o700); controller_lock=acquire_transfer_lock(CONTROLLER_LOCK)
 try: result=subprocess.run((*ssh(),"sudo -n -- /usr/bin/python3 -c "+shlex.quote(installer)),input=json.dumps(payload,separators=(",",":")),text=True,capture_output=True,timeout=120)
 finally: os.close(controller_lock)
 if result.returncode or result.stderr or result.stdout!='{"installed":true}\n': raise SystemExit("package observer capability install failed or rolled back; retained host lock requires inspection after interruption")
 after=observe()
 for name,expected_meta in wanted.items():
  meta=after["paths"].get(name,{});
  if any((meta.get("sha256")!=expected_meta["sha256"],meta.get("mode")!=expected_meta["mode"],meta.get("uid")!=0,meta.get("gid")!=0,meta.get("nlink")!=1,meta.get("regular") is not True)): raise SystemExit("installed package observer capability differs")
 print(json.dumps({"installed":True,"plan_sha256":digest},sort_keys=True))
def main():
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="command",required=True); a=sub.add_parser("plan"); a.add_argument("artifact",type=Path); a=sub.add_parser("apply"); a.add_argument("plan",type=Path); a.add_argument("artifact",type=Path); args=p.parse_args(); plan(args.artifact.resolve()) if args.command=="plan" else apply(args.plan.resolve(),args.artifact.resolve())
if __name__=="__main__": main()
