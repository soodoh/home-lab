#!/usr/bin/env python3
"""Guard VM9900 APT metadata refresh and exact qemu-guest-agent installation."""
import argparse,datetime as dt,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_canonical_object,require_private_root,verify_exact_checkout,write_json
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"scripts/controller/debian-qualification-guest-repair.py"; spec=importlib.util.spec_from_file_location("guest_repair",SOURCE); guest=importlib.util.module_from_spec(spec); spec.loader.exec_module(guest)
CONFIRM={"refresh":"REFRESH_VM9900_DEBIAN_METADATA","install":"INSTALL_VM9900_EXACT_QEMU_GUEST_AGENT"}
FILES={"/etc/apt/sources.list":b"# See /etc/apt/sources.list.d/debian.sources\n","/etc/apt/sources.list.d/debian.sources":b"Types: deb deb-src\nURIs: mirror+file:///etc/apt/mirrors/debian.list\nSuites: trixie trixie-updates trixie-backports\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb deb-src\nURIs: mirror+file:///etc/apt/mirrors/debian-security.list\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n","/etc/apt/mirrors/debian.list":b"https://deb.debian.org/debian\n","/etc/apt/mirrors/debian-security.list":b"https://deb.debian.org/debian-security\n"}
def fail(reason): raise SystemExit(f"debian_qualification_package=failed reason={reason}")
def sha(raw): return hashlib.sha256(raw).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc)
def parse_time(value):
 try: parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
 except Exception: fail("plan-time")
 if parsed.tzinfo is None:return fail("plan-time")
 return parsed
def revision(expected=None):
 commit=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip();verify_exact_checkout("git",expected or commit,os.environ.copy());return commit
def prerequisite(args):
 restart_sha,host_sha=guest.receipts(args); dns,dns_raw=load_canonical_object(args.dns_receipt,"VM9900 DNS receipt")
 if dns.get("format")!="home-lab-debian-qualification-guest-repair-receipt-v1" or dns.get("target")!=guest.TARGET or dns.get("content_sha256")!=sha(guest.CONTENT) or dns.get("machine_id_sha256") is None:fail("dns-receipt")
 return restart_sha,host_sha,sha(dns_raw),dns["machine_id_sha256"]
def observation_program():
 expected={path:sha(raw) for path,raw in FILES.items()}
 return f'''import hashlib,json,os,stat,subprocess\nexpected={expected!r}\ndef sha(x):return hashlib.sha256(x).hexdigest()\ndef canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"))\ndef inspect(path):\n s=os.lstat(path)\n if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o644:raise SystemExit(64)\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);raw=os.read(fd,65537);opened=os.fstat(fd);os.close(fd);current=os.lstat(path)\n if len(raw)>65536 or (opened.st_dev,opened.st_ino)!=(current.st_dev,current.st_ino) or sha(raw)!=expected[path]:raise SystemExit(64)\n return sha(raw)\nresult=subprocess.run(["/usr/bin/dpkg-query","-W","-f=${{binary:Package}}=${{Version}}\\n"],capture_output=True,text=True)\nif result.returncode:raise SystemExit(64)\npackages=sorted(line for line in result.stdout.splitlines() if line)\nqga=[line for line in packages if line.startswith("qemu-guest-agent=")]\nvalue={{"format":"home-lab-debian-qualification-package-observation-v1","hostname":os.uname().nodename,"machine_id_sha256":sha(open("/etc/machine-id","rb").read()),"packages":packages,"qga":qga,"sources":{{path:inspect(path) for path in sorted(expected)}},"version":1}}\nprint(canonical(value))\n'''
def simulate_code():
 return '''\ndef simulate():\n result=subprocess.run(["/usr/bin/apt-get","--simulate","--no-install-recommends","install","qemu-guest-agent"],capture_output=True,text=True,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"})\n if result.returncode:raise RuntimeError("apt simulation")\n actions=[]\n for line in result.stdout.splitlines():\n  match=re.match(r"^Inst ([A-Za-z0-9][A-Za-z0-9+.-]*(?::[A-Za-z0-9]+)?) \\((\\S+)",line)\n  if match:actions.append(match.group(1)+"="+match.group(2))\n if not actions or not any(item.startswith("qemu-guest-agent=") for item in actions):raise RuntimeError("missing qga action")\n return sorted(actions)\n'''
def refresh_program(before,plan_sha):
 return observation_program().rsplit('print(canonical(value))',1)[0]+f'''before={before!r}\nif value!=before:raise SystemExit(65)\nimport fcntl,re\nfd=os.open("/run/lock/home-lab-debian-qualification-package.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);s=os.fstat(fd)\nif not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:raise SystemExit(64)\nfcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\nupdate=subprocess.run(["/usr/bin/apt-get","update"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env={{"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","DEBIAN_FRONTEND":"noninteractive"}})\nif update.returncode:raise RuntimeError("apt metadata refresh")\nexec({simulate_code()!r})\nactions=simulate()\nafter_result=subprocess.run(["/usr/bin/dpkg-query","-W","-f=${{binary:Package}}=${{Version}}\\n"],capture_output=True,text=True);after=sorted(line for line in after_result.stdout.splitlines() if line)\nif after!=before["packages"]:raise RuntimeError("package mutation during refresh")\nprint(canonical({{"actions":actions,"before_packages_sha256":sha(("\\n".join(after)+"\\n").encode()),"format":"home-lab-debian-qualification-package-refresh-receipt-v1","machine_id_sha256":before["machine_id_sha256"],"plan_sha256":{plan_sha!r},"sources":before["sources"],"version":1}}))\nos.close(fd)\n'''
def install_program(before,actions,plan_sha):
 return observation_program().rsplit('print(canonical(value))',1)[0]+f'''before={before!r};approved={actions!r}\nif value!=before or value["qga"]:raise SystemExit(65)\nimport fcntl,re\nfd=os.open("/run/lock/home-lab-debian-qualification-package.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);s=os.fstat(fd)\nif not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:raise SystemExit(64)\nfcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexec({simulate_code()!r})\nif simulate()!=approved:raise RuntimeError("candidate drift")\ncommand=["/usr/bin/apt-get","-y","--no-install-recommends","--no-upgrade","install",*approved]\nresult=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env={{"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","DEBIAN_FRONTEND":"noninteractive"}})\nif result.returncode:raise RuntimeError("exact package install")\nif subprocess.run(["/usr/bin/systemctl","enable","--now","qemu-guest-agent.service"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE).returncode:raise RuntimeError("qga activation")\nafter_result=subprocess.run(["/usr/bin/dpkg-query","-W","-f=${{binary:Package}}=${{Version}}\\n"],capture_output=True,text=True);after=sorted(line for line in after_result.stdout.splitlines() if line);added=sorted(set(after)-set(before["packages"]));removed=sorted(set(before["packages"])-set(after))\nif added!=approved or removed or subprocess.run(["/usr/bin/systemctl","is-active","--quiet","qemu-guest-agent.service"]).returncode:raise RuntimeError("package postcondition")\nprint(canonical({{"actions":approved,"format":"home-lab-debian-qualification-package-install-receipt-v1","machine_id_sha256":before["machine_id_sha256"],"plan_sha256":{plan_sha!r},"qga_active":True,"version":1}}))\nos.close(fd)\n'''
def validate_common(args):guest.validate_inputs(args);return require_private_root(args.output_dir,())
def make_plan(args,operation):
 output=validate_common(args);lock=acquire_transfer_lock(output/"guest-repair.lock")
 try:
  restart_sha,host_sha,dns_sha,machine=prerequisite(args);before=guest.remote(args,observation_program());created=now()
  if before.get("hostname")!="debian-lifecycle-qualification" or before.get("machine_id_sha256")!=machine or before.get("qga")!=[]:fail("package-precondition")
  value={"actions":[],"authorized":False,"automatic_apply":False,"before_sha256":sha(canonical_bytes(before)+b"\n"),"commit":revision(),"created_at":created.isoformat().replace("+00:00","Z"),"dns_receipt_sha256":dns_sha,"expires_at":(created+dt.timedelta(hours=4)).isoformat().replace("+00:00","Z"),"format":"home-lab-debian-qualification-package-plan-v1","host_key_receipt_sha256":host_sha,"machine_id_sha256":machine,"operation":operation,"restart_receipt_sha256":restart_sha,"version":1}
  if operation=="install":
   refresh,refresh_raw=load_canonical_object(args.refresh_receipt,"package refresh receipt");value["refresh_receipt_sha256"]=sha(refresh_raw);value["actions"]=refresh.get("actions",[])
   if refresh.get("format")!="home-lab-debian-qualification-package-refresh-receipt-v1" or refresh.get("machine_id_sha256")!=machine or not value["actions"]:fail("refresh-receipt")
  raw=canonical_bytes(value)+b"\n";digest=sha(raw);write_json(output,f"{digest}.{operation}-plan.json",value);print(json.dumps({"actions":value["actions"],"authorized":False,"plan":str(output/f'{digest}.{operation}-plan.json'),"plan_sha256":digest},sort_keys=True))
 finally:os.close(lock)
def apply(args,operation):
 if args.approve_plan_sha!=args.plan_sha or args.confirm!=CONFIRM[operation]:fail("exact-authorization-required")
 output=validate_common(args);value,raw=load_canonical_object(args.plan,"package plan")
 if sha(raw)!=args.plan_sha or value.get("operation")!=operation or value.get("format")!="home-lab-debian-qualification-package-plan-v1" or value.get("authorized") is not False or value.get("automatic_apply") is not False:fail("plan-binding")
 restart_sha,host_sha,dns_sha,machine=prerequisite(args);revision(value.get("commit"));created=parse_time(value.get("created_at",""));expires=parse_time(value.get("expires_at",""))
 if value.get("restart_receipt_sha256")!=restart_sha or value.get("host_key_receipt_sha256")!=host_sha or value.get("dns_receipt_sha256")!=dns_sha or value.get("machine_id_sha256")!=machine or created>now()+dt.timedelta(seconds=5) or created<now()-dt.timedelta(hours=4) or expires<=now() or expires-created>dt.timedelta(hours=4):fail("plan-binding")
 before=guest.remote(args,observation_program());
 if sha(canonical_bytes(before)+b"\n")!=value.get("before_sha256"):fail("precondition-drift")
 if operation=="install":
  refresh,refresh_raw=load_canonical_object(args.refresh_receipt,"package refresh receipt")
  if value.get("refresh_receipt_sha256")!=sha(refresh_raw) or value.get("actions")!=refresh.get("actions"):fail("refresh-binding")
 program=refresh_program(before,args.plan_sha) if operation=="refresh" else install_program(before,value["actions"],args.plan_sha);lock=acquire_transfer_lock(output/"guest-repair.lock")
 try:receipt=guest.remote(args,program,timeout=600)
 finally:os.close(lock)
 expected_format=f"home-lab-debian-qualification-package-{operation}-receipt-v1"
 if receipt.get("format")!=expected_format or receipt.get("plan_sha256")!=args.plan_sha or receipt.get("machine_id_sha256")!=machine or receipt.get("version")!=1 or (receipt.get("actions")!=value["actions"] if operation=="install" else not receipt.get("actions")):fail("receipt-binding")
 write_json(output,f"{args.plan_sha}.{operation}-receipt.json",receipt);print(json.dumps({"actions":receipt["actions"],"receipt":str(output/f'{args.plan_sha}.{operation}-receipt.json')},sort_keys=True))
def main():
 parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest="command",required=True)
 for command in ("plan-refresh","apply-refresh","plan-install","apply-install"):
  item=sub.add_parser(command)
  for option in ("guest-known-hosts","guest-private-key","restart-receipt","host-key-receipt","dns-receipt","output-dir"):item.add_argument("--"+option,type=Path,required=True)
  if command.endswith("install"):item.add_argument("--refresh-receipt",type=Path,required=True)
  if command.startswith("apply-"):item.add_argument("--plan",type=Path,required=True);item.add_argument("--plan-sha",required=True);item.add_argument("--approve-plan-sha",required=True);item.add_argument("--confirm",required=True)
 args=parser.parse_args();[setattr(args,key,value.resolve()) for key,value in vars(args).items() if isinstance(value,Path)];operation=args.command.split("-",1)[1];apply(args,operation) if args.command.startswith("apply-") else make_plan(args,operation)
if __name__=="__main__":main()
