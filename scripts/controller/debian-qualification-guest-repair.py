#!/usr/bin/env python3
"""Guard an exact VM9900 public-DNS bootstrap repair over disk-verified SSH."""
import argparse,datetime as dt,hashlib,json,os,re,stat,subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,verify_exact_checkout,write_json
ROOT=Path(__file__).resolve().parents[2]; CONFIRM="REPAIR_VM9900_PUBLIC_DNS"; TARGET="/etc/systemd/network/10-cloud-init-eth0.network.d/10-public-dns.conf"; CONTENT=b"[DHCPv4]\nUseDNS=no\n[Network]\nDNS=1.1.1.1\nDNS=9.9.9.9\n"
def fail(reason): raise SystemExit(f"debian_qualification_guest_repair=failed reason={reason}")
def sha(raw): return hashlib.sha256(raw).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc)
def protected(path,label): return load_protected_bytes(path,label)
def ssh_args(args):
 return ["ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no","-o",f"UserKnownHostsFile={args.guest_known_hosts}","-o","HostKeyAlgorithms=ssh-ed25519","-o","IdentityAgent=none","-o","IdentitiesOnly=yes","-o",f"IdentityFile={args.guest_private_key}","-o","PreferredAuthentications=publickey","-o","PubkeyAuthentication=yes","-o","PasswordAuthentication=no","-o","KbdInteractiveAuthentication=no","-o","GSSAPIAuthentication=no","-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no","-o","RequestTTY=no","-o","ConnectTimeout=10","ansible-deploy@192.168.0.53","sudo -n -- /usr/bin/python3 -"]
def remote(args,program,timeout=90):
 result=subprocess.run(ssh_args(args),input=program.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 if result.returncode or result.stderr: fail("strict-ssh-transaction")
 try: value=json.loads(result.stdout)
 except json.JSONDecodeError: fail("remote-json")
 if result.stdout!=canonical_bytes(value)+b"\n": fail("remote-canonical")
 return value
def observation_program():
 return f'''import hashlib,json,os,stat,subprocess\np={TARGET!r}\ndef sha(x): return hashlib.sha256(x).hexdigest()\ndef canonical(x): return json.dumps(x,sort_keys=True,separators=(",",":"))\ndef file():\n try:\n  s=os.lstat(p)\n  if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_nlink!=1 or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=0o644 or s.st_size>4096: raise SystemExit(64)\n  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW); raw=os.read(fd,4097); opened=os.fstat(fd);os.close(fd);current=os.lstat(p)\n  if len(raw)>4096 or (opened.st_dev,opened.st_ino)!=(current.st_dev,current.st_ino): raise SystemExit(64)\n  return {{"exists":True,"sha256":sha(raw),"size":len(raw)}}\n except FileNotFoundError:return {{"exists":False}}\ndns=subprocess.run(["/usr/bin/resolvectl","dns","eth0"],capture_output=True,text=True)\npkg=subprocess.run(["/usr/bin/dpkg-query","-W","-f=${{db:Status-Status}} ${{Version}}","qemu-guest-agent"],capture_output=True,text=True)\nvalue={{"dns":dns.stdout.strip(),"dns_rc":dns.returncode,"file":file(),"format":"home-lab-debian-qualification-guest-observation-v1","hostname":os.uname().nodename,"machine_id_sha256":sha(open("/etc/machine-id","rb").read()),"qga":pkg.stdout.strip() if pkg.returncode==0 else "absent","version":1}}\nprint(canonical(value))\n'''
def receipts(args):
 restart,restart_raw=load_canonical_object(args.restart_receipt,"VM9900 restart receipt"); host,host_raw=load_canonical_object(args.host_key_receipt,"VM9900 host-key receipt")
 if restart.get("format")!="home-lab-debian-qualification-restart-receipt-v1" or restart.get("vm_started") is not True or restart.get("vmid")!=9900 or host.get("format")!="home-lab-debian-qualification-host-key-receipt-v1" or host.get("guest_ipv4")!="192.168.0.53" or host.get("vmid")!=9900 or restart.get("host_key_receipt_sha256")!=sha(host_raw): fail("lifecycle-receipt")
 return sha(restart_raw),sha(host_raw)
def revision(expected=None):
 commit=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip(); verify_exact_checkout("git",expected or commit,os.environ.copy()); return commit
def validate_inputs(args):
 for path,label in ((args.guest_known_hosts,"guest known-hosts"),(args.guest_private_key,"guest private key")):
  info=path.lstat()
  if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600: fail(label+" metadata")
 protected(args.guest_known_hosts,"guest known-hosts"); protected(args.guest_private_key,"guest private key")
def plan(args):
 validate_inputs(args); output=require_private_root(args.output_dir,()); lock=acquire_transfer_lock(output/"guest-repair.lock")
 try:
  restart_sha,host_sha=receipts(args); before=remote(args,observation_program()); created=now()
  if before.get("format")!="home-lab-debian-qualification-guest-observation-v1" or before.get("hostname")!="debian-lifecycle-qualification" or before.get("version")!=1: fail("guest-identity")
  value={"authorized":False,"automatic_apply":False,"before_sha256":sha(canonical_bytes(before)+b"\n"),"commit":revision(),"content_sha256":sha(CONTENT),"created_at":created.isoformat().replace("+00:00","Z"),"expires_at":(created+dt.timedelta(hours=4)).isoformat().replace("+00:00","Z"),"format":"home-lab-debian-qualification-guest-repair-plan-v1","guest_ipv4":"192.168.0.53","host_key_receipt_sha256":host_sha,"machine_id_sha256":before["machine_id_sha256"],"operation":"repair-public-dns","restart_receipt_sha256":restart_sha,"target":TARGET,"version":1}
  raw=canonical_bytes(value)+b"\n"; digest=sha(raw); write_json(output,f"{digest}.guest-repair-plan.json",value); print(json.dumps({"actionable":True,"authorized":False,"plan":str(output/f'{digest}.guest-repair-plan.json'),"plan_sha256":digest},sort_keys=True))
 finally: os.close(lock)
def apply_program(plan,before):
 return f'''import fcntl,hashlib,json,os,socket,stat,subprocess,tempfile\nplan={plan!r};before={before!r};content={CONTENT!r};target={TARGET!r}\ndef sha(x): return hashlib.sha256(x).hexdigest()\ndef canonical(x): return json.dumps(x,sort_keys=True,separators=(",",":"))\ndef file():\n try:\n  s=os.lstat(target)\n  if not stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_nlink!=1 or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=0o644 or s.st_size>4096: raise RuntimeError("unsafe target")\n  fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW);raw=os.read(fd,4097);os.close(fd);return {{"exists":True,"sha256":sha(raw),"size":len(raw)}}\n except FileNotFoundError:return {{"exists":False}}\ndef observe():\n dns=subprocess.run(["/usr/bin/resolvectl","dns","eth0"],capture_output=True,text=True);pkg=subprocess.run(["/usr/bin/dpkg-query","-W","-f=${{db:Status-Status}} ${{Version}}","qemu-guest-agent"],capture_output=True,text=True)\n return {{"dns":dns.stdout.strip(),"dns_rc":dns.returncode,"file":file(),"format":"home-lab-debian-qualification-guest-observation-v1","hostname":os.uname().nodename,"machine_id_sha256":sha(open("/etc/machine-id","rb").read()),"qga":pkg.stdout.strip() if pkg.returncode==0 else "absent","version":1}}\nlock_path="/run/lock/home-lab-debian-qualification-guest-repair.lock";fd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);s=os.fstat(fd)\nif not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600: raise SystemExit(64)\nfcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\nif observe()!=before: raise SystemExit(65)\ndirectory=os.path.dirname(target);created_directory=False;changed=False\ntry:\n if not os.path.exists(directory): os.mkdir(directory,0o755);created_directory=True\n parent=os.lstat(directory)\n if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode) or parent.st_uid!=0 or parent.st_gid!=0 or stat.S_IMODE(parent.st_mode)!=0o755: raise RuntimeError("unsafe directory")\n current=file()\n if current.get("exists") and current.get("sha256")!=sha(content): raise RuntimeError("different existing DNS policy")\n if not current.get("exists"):\n  tmpfd,tmp=tempfile.mkstemp(prefix=".qualification-dns-",dir=directory)\n  with os.fdopen(tmpfd,"wb") as out: os.fchmod(out.fileno(),0o644);out.write(content);out.flush();os.fsync(out.fileno())\n  os.link(tmp,target,follow_symlinks=False);os.unlink(tmp);d=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d);changed=True\n for command in (["/usr/bin/resolvectl","dns","eth0","1.1.1.1","9.9.9.9"],["/usr/bin/resolvectl","domain","eth0","~."]):\n  if subprocess.run(command).returncode: raise RuntimeError("resolvectl")\n socket.getaddrinfo("deb.debian.org",443,type=socket.SOCK_STREAM)\n if subprocess.run(["/usr/bin/curl","-fsSI","--max-time","15","https://deb.debian.org/"],stdout=subprocess.DEVNULL).returncode: raise RuntimeError("public egress")\n after=observe()\n if after["file"]!={{"exists":True,"sha256":sha(content),"size":len(content)}} or "1.1.1.1" not in after["dns"] or "9.9.9.9" not in after["dns"]: raise RuntimeError("postcondition")\n print(canonical({{"changed":changed,"content_sha256":sha(content),"format":"home-lab-debian-qualification-guest-repair-receipt-v1","machine_id_sha256":after["machine_id_sha256"],"plan_sha256":plan["plan_sha256"],"target":target,"version":1}}))\nexcept Exception:\n if changed:\n  os.unlink(target);d=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)\n if created_directory:\n  try:os.rmdir(directory)\n  except OSError:pass\n subprocess.run(["/usr/bin/resolvectl","revert","eth0"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n raise\nfinally:os.close(fd)\n'''
def parse_time(value):
 try: parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
 except Exception: fail("plan-time")
 if parsed.tzinfo is None: fail("plan-time")
 return parsed
def apply(args):
 if args.approve_plan_sha!=args.plan_sha or args.confirm!=CONFIRM: fail("exact-authorization-required")
 validate_inputs(args); output=require_private_root(args.output_dir,()); value,raw=load_canonical_object(args.plan,"guest repair plan")
 if sha(raw)!=args.plan_sha: fail("plan-sha")
 restart_sha,host_sha=receipts(args); revision(value.get("commit")); required={"authorized","automatic_apply","before_sha256","commit","content_sha256","created_at","expires_at","format","guest_ipv4","host_key_receipt_sha256","machine_id_sha256","operation","restart_receipt_sha256","target","version"}; created=parse_time(value.get("created_at","")); expires=parse_time(value.get("expires_at",""))
 if set(value)!=required or value.get("format")!="home-lab-debian-qualification-guest-repair-plan-v1" or value.get("operation")!="repair-public-dns" or value.get("guest_ipv4")!="192.168.0.53" or value.get("target")!=TARGET or value.get("content_sha256")!=sha(CONTENT) or value.get("restart_receipt_sha256")!=restart_sha or value.get("host_key_receipt_sha256")!=host_sha or value.get("version")!=1 or value.get("authorized") is not False or value.get("automatic_apply") is not False or created>now()+dt.timedelta(seconds=5) or created<now()-dt.timedelta(hours=4) or expires<=now() or expires-created>dt.timedelta(hours=4): fail("plan-binding")
 before=remote(args,observation_program()); before_raw=canonical_bytes(before)+b"\n"
 if sha(before_raw)!=value["before_sha256"] or before.get("machine_id_sha256")!=value["machine_id_sha256"]: fail("precondition-drift")
 lock=acquire_transfer_lock(output/"guest-repair.lock")
 try:
  payload=dict(value);payload["plan_sha256"]=args.plan_sha; receipt=remote(args,apply_program(payload,before),timeout=180)
 finally: os.close(lock)
 expected={"content_sha256":value["content_sha256"],"format":"home-lab-debian-qualification-guest-repair-receipt-v1","machine_id_sha256":value["machine_id_sha256"],"plan_sha256":args.plan_sha,"target":TARGET,"version":1}
 if set(receipt)!=set(expected)|{"changed"} or any(receipt.get(key)!=item for key,item in expected.items()) or not isinstance(receipt.get("changed"),bool): fail("receipt-binding")
 write_json(output,f"{args.plan_sha}.guest-repair-receipt.json",receipt); print(json.dumps({"changed":receipt["changed"],"receipt":str(output/f'{args.plan_sha}.guest-repair-receipt.json')},sort_keys=True))
def main():
 parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest="command",required=True)
 for name in ("plan","apply"):
  item=sub.add_parser(name)
  for option in ("guest-known-hosts","guest-private-key","restart-receipt","host-key-receipt","output-dir"): item.add_argument("--"+option,type=Path,required=True)
  if name=="apply": item.add_argument("--plan",type=Path,required=True);item.add_argument("--plan-sha",required=True);item.add_argument("--approve-plan-sha",required=True);item.add_argument("--confirm",required=True)
 args=parser.parse_args()
 for key,value in vars(args).items():
  if isinstance(value,Path):setattr(args,key,value.resolve())
 apply(args) if args.command=="apply" else plan(args)
if __name__=="__main__":main()
