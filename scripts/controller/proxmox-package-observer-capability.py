#!/usr/bin/env python3
"""Plan/install the generated Proxmox package observer as an exact capability upgrade."""
import argparse, base64, datetime as dt, hashlib, json, os, shlex, stat, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; OUTPUT=ROOT/".local/proxmox-package-observer-capability"
def ssh():
 known=os.environ.get("HOME_LAB_PROXMOX_PRODUCTION_KNOWN_HOSTS","")
 if not known or not Path(known).is_absolute(): raise SystemExit("dedicated Proxmox known-hosts path required")
 return ("ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={known}","-o","UpdateHostKeys=no","-o","IdentitiesOnly=yes","-o","RequestTTY=no","proxmox@proxmox")
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
 program='''import hashlib,json,os,stat\npaths={}\nfor p in %r:\n try:\n  s=os.lstat(p); raw=open(p,"rb").read(); paths[p]={"exists":True,"uid":s.st_uid,"gid":s.st_gid,"mode":format(stat.S_IMODE(s.st_mode),"04o"),"nlink":s.st_nlink,"regular":stat.S_ISREG(s.st_mode),"sha256":hashlib.sha256(raw).hexdigest()}\n except FileNotFoundError: paths[p]={"exists":False}\nlocks=[p for p in ("/var/lib/iac-ansible-production.lock","/var/lib/home-lab/reconciliation/owner.lock","/var/lib/home-lab/reconciliation/nix.lock","/var/lib/home-lab/reconciliation/operation.lock","/var/lib/home-lab/firewall-transaction/active.json") if os.path.lexists(p)]\nprint(json.dumps({"paths":paths,"locks":locks},sort_keys=True,separators=(",",":")))\n''' % ((TRANSPORT,OBSERVER,SUDO),)
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
 info=path.lstat(); raw=path.read_bytes(); value=json.loads(raw); digest=sha(raw); wanted,transport,package=desired(artifact)
 if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or path.name!=f"{digest}.json" or raw!=canonical(value) or value.get("format")!="home-lab-proxmox-package-observer-capability-v1" or value.get("commit")!=commit() or value.get("contract_sha256")!=sha((ROOT/"infrastructure/contract/home-lab.yml").read_bytes()) or value.get("inventory_sha256")!=sha((ROOT/"ansible/inventory/proxmox-production.yml").read_bytes()) or value.get("authorized") is not False or value.get("automatic_apply") is not False or value.get("desired")!=wanted or dt.datetime.now(dt.timezone.utc)>dt.datetime.fromisoformat(value["expires_at"].replace("Z","+00:00")): raise SystemExit("package observer capability plan differs or expired")
 expected=f"apply-proxmox-package-observer-capability-{digest}"
 if os.environ.get("PROXMOX_PACKAGE_OBSERVER_CAPABILITY_CONFIRMED")!=expected: raise SystemExit(f"exact confirmation required: {expected}")
 current=observe(); validate_current(current)
 if sha(canonical(current))!=value.get("before_sha256"): raise SystemExit("package observer capability live state changed")
 payload={"plan_sha256":digest,"files":{TRANSPORT:base64.b64encode(transport).decode(),OBSERVER:base64.b64encode(package).decode(),SUDO:base64.b64encode(RULE.encode()).decode()},"hashes":wanted}
 installer='''import base64,hashlib,json,os,stat,sys\np=json.load(sys.stdin); backups={}; temps={}\ntry:\n for path,text in p["files"].items():\n  raw=base64.b64decode(text,validate=True); expected=p["hashes"][path];\n  if hashlib.sha256(raw).hexdigest()!=expected["sha256"]: raise RuntimeError("payload hash")\n  backups[path]=open(path,"rb").read() if os.path.exists(path) else None\n  tmp=path+"."+p["plan_sha256"]+".tmp"; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,int(expected["mode"],8)); os.write(fd,raw); os.fchmod(fd,int(expected["mode"],8)); os.fchown(fd,0,0); os.fsync(fd); os.close(fd); temps[path]=tmp\n if "/etc/sudoers.d/ansible-plan" in p["files"] and os.system("/usr/sbin/visudo --check --file="+temps["/etc/sudoers.d/ansible-plan"]+" >/dev/null")!=0: raise RuntimeError("sudo")\n for path,tmp in temps.items(): os.replace(tmp,path)\n for directory in {os.path.dirname(x) for x in p["files"]}: fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY); os.fsync(fd); os.close(fd)\nexcept Exception:\n for path,raw in backups.items():\n  if raw is None: os.unlink(path) if os.path.exists(path) else None\n  else: open(path,"wb").write(raw)\n raise\nprint('{"installed":true}')\n'''
 result=subprocess.run((*ssh(),"sudo -n -- /usr/bin/python3 -c "+shlex.quote(installer)),input=json.dumps(payload,separators=(",",":")),text=True,capture_output=True,timeout=120)
 if result.returncode or result.stderr or result.stdout!='{"installed":true}\n': raise SystemExit("package observer capability install failed or rolled back")
 after=observe()
 for name,expected_meta in wanted.items():
  meta=after["paths"].get(name,{});
  if any((meta.get("sha256")!=expected_meta["sha256"],meta.get("mode")!=expected_meta["mode"],meta.get("uid")!=0,meta.get("gid")!=0,meta.get("nlink")!=1,meta.get("regular") is not True)): raise SystemExit("installed package observer capability differs")
 print(json.dumps({"installed":True,"plan_sha256":digest},sort_keys=True))
def main():
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="command",required=True); a=sub.add_parser("plan"); a.add_argument("artifact",type=Path); a=sub.add_parser("apply"); a.add_argument("plan",type=Path); a.add_argument("artifact",type=Path); args=p.parse_args(); plan(args.artifact.resolve()) if args.command=="plan" else apply(args.plan.resolve(),args.artifact.resolve())
if __name__=="__main__": main()
