#!/usr/bin/env python3
"""Plan/apply the exact cloud-init snippet on an admitted isolated PVE target."""
import argparse,base64,datetime as dt,hashlib,json,os,re,subprocess,sys
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,verify_exact_checkout,write_json
ROOT=Path(__file__).resolve().parents[2]; TEMPLATE=ROOT/"infrastructure/debian/cloud-init/qualification-user-data.tftpl"; VALIDATOR=ROOT/"scripts/controller/validate-disposable-pve-target.js"; CONFIRM="PRODUCTION_PVE_VM9900_SNIPPET_CONFIRMED"
def sha(raw): return hashlib.sha256(raw).hexdigest()
def validate_target(admission,known_hosts):
 result=subprocess.run(["node",str(VALIDATOR),"--evidence",str(admission),"--known-hosts",str(known_hosts)],text=True,capture_output=True)
 if result.returncode or result.stderr: raise SystemExit("disposable PVE admission validation failed")
 try: value=json.loads(result.stdout)
 except json.JSONDecodeError as error: raise SystemExit("admission validator returned invalid JSON") from error
 if value.get("admitted") is not True or value.get("snippet_content_enabled") is not True or value.get("ssh_authentication")!="tailscale-policy": raise SystemExit("PVE snippet content or SSH route is not admitted")
 return value
def ssh_args(target,known_hosts,command):
 return ["ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no","-o",f"UserKnownHostsFile={known_hosts}","-o","IdentitiesOnly=yes","-o","IdentityAgent=none","-o","IdentityFile=none","-o","PreferredAuthentications=none","-o","PubkeyAuthentication=no","-o","PasswordAuthentication=no","-o","KbdInteractiveAuthentication=no","-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no","-o","RequestTTY=no","-o","ConnectTimeout=10",f'{target["ssh_username"]}@{target["ssh_address"]}',command]
def remote(target,known_hosts,command,data=None):
 result=subprocess.run(ssh_args(target,known_hosts,command),input=data,capture_output=True,timeout=90)
 if result.returncode or result.stderr: raise SystemExit("isolated PVE snippet transport failed")
 try: value=json.loads(result.stdout)
 except json.JSONDecodeError as error: raise SystemExit("snippet transport returned invalid JSON") from error
 if result.stdout!=canonical_bytes(value)+b"\n": raise SystemExit("snippet transport returned non-canonical JSON")
 return value
def render(public_key):
 script='const fs=require("fs"),yaml=require("js-yaml");const c=yaml.load(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(JSON.stringify({timezone:c.system_timezone,locale:c.debian.locale}))'
 result=subprocess.run(["node","-e",script,str(ROOT/"infrastructure/contract/home-lab.yml")],cwd=ROOT,text=True,capture_output=True)
 if result.returncode or result.stderr: raise SystemExit("qualification contract projection failed")
 values={**json.loads(result.stdout),"qualification_ssh_public_key":public_key}; text=TEMPLATE.read_text()
 for key,value in values.items(): text=text.replace("${"+key+"}",value)
 if "${" in text or not text.startswith("#cloud-config\n"): raise SystemExit("qualification cloud-init template rendering failed")
 return text.encode()
def guest_key(path,target):
 raw=load_protected_bytes(path,"guest qualification public key")
 try: line=raw.decode("ascii").removesuffix("\n")
 except UnicodeDecodeError as error: raise SystemExit("guest qualification public key is not ASCII") from error
 if raw!=line.encode()+b"\n" or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2} qualification-[a-z0-9-]+",line) is None: raise SystemExit("guest qualification public key is not canonical")
 if sha(line.encode())!=target["guest_ssh_public_key_sha256"]: raise SystemExit("guest qualification public key identity mismatch")
 return line
def clean_commit():
 env=os.environ.copy(); commit=subprocess.run(["git","rev-parse","HEAD"],text=True,capture_output=True,check=True).stdout.strip(); verify_exact_checkout("git",commit,env); return commit
def plan(args):
 target=validate_target(args.admission,args.known_hosts); public=guest_key(args.guest_public_key,target); commit=clean_commit(); before=remote(target,args.known_hosts,"observe")
 content=render(public); operation="replace-snippet" if before.get("snippet",{}).get("exists") is True and (before["snippet"].get("sha256")!=sha(content) or before["snippet"].get("size")!=len(content)) else "create-snippet"; now=dt.datetime.now(dt.timezone.utc); expires=now+dt.timedelta(minutes=10)
 value={"admission_sha256":target["isolation_attestation_sha256"],"authorized":False,"automatic_apply":False,"before_sha256":sha(canonical_bytes(before)+b"\n"),"commit":commit,"content_b64":base64.b64encode(content).decode(),"created_at":now.isoformat().replace("+00:00","Z"),"expires_at":expires.isoformat().replace("+00:00","Z"),"file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml","format":"home-lab-debian-qualification-snippet-plan-v1","guest_ssh_public_key_sha256":target["guest_ssh_public_key_sha256"],"known_hosts_sha256":sha(load_protected_bytes(args.known_hosts,"qualification known-hosts")),"mode":"0600","node_name":target["node_name"],"operation":operation,"sha256":sha(content),"size":len(content),"target_id":target["target_id"],"version":1}
 raw=canonical_bytes(value)+b"\n"; digest=sha(raw); output=require_private_root(args.output_dir,()); write_json(output,f"{digest}.json",value); print(json.dumps({"authorized":False,"path":str(output/f'{digest}.json'),"plan_sha256":digest},sort_keys=True))
def apply(args):
 if args.approve_plan_sha!=args.plan_sha or args.confirm!=CONFIRM: raise SystemExit("exact snippet approval and confirmation are required")
 value,raw=load_canonical_object(args.plan,"snippet plan"); digest=sha(raw)
 if digest!=args.plan_sha: raise SystemExit("snippet plan digest mismatch")
 target=validate_target(args.admission,args.known_hosts); public=guest_key(args.guest_public_key,target); verify_exact_checkout("git",value.get("commit",""),os.environ.copy())
 expected_content=render(public)
 if value.get("admission_sha256")!=target["isolation_attestation_sha256"] or value.get("target_id")!=target["target_id"] or value.get("node_name")!=target["node_name"] or value.get("file_id")!="local:snippets/home-lab-debian-lifecycle-qualification.yaml" or value.get("guest_ssh_public_key_sha256")!=sha(public.encode()) or value.get("known_hosts_sha256")!=sha(load_protected_bytes(args.known_hosts,"qualification known-hosts")) or value.get("content_b64")!=base64.b64encode(expected_content).decode() or value.get("sha256")!=sha(expected_content) or value.get("size")!=len(expected_content): raise SystemExit("snippet plan binding mismatch")
 current=remote(target,args.known_hosts,"observe")
 expected_operation="replace-snippet" if current.get("snippet",{}).get("exists") is True and (current["snippet"].get("sha256")!=sha(expected_content) or current["snippet"].get("size")!=len(expected_content)) else "create-snippet"
 if value.get("operation")!=expected_operation or value.get("before_sha256")!=sha(canonical_bytes(current)+b"\n"): raise SystemExit("snippet precondition drift")
 lock=args.output_dir/"snippet-apply.lock"; descriptor=acquire_transfer_lock(lock)
 try: receipt=remote(target,args.known_hosts,f"apply {digest} {digest}",raw)
 finally: os.close(descriptor)
 expected={"admission_sha256":value["admission_sha256"],"commit":value["commit"],"file_id":value["file_id"],"guest_ssh_public_key_sha256":value["guest_ssh_public_key_sha256"],"known_hosts_sha256":value["known_hosts_sha256"],"mode":"0600","node_name":value["node_name"],"plan_sha256":digest,"sha256":value["sha256"],"size":value["size"],"target_id":value["target_id"],"version":1}
 if any(receipt.get(key)!=item for key,item in expected.items()) or receipt.get("format")!="home-lab-debian-qualification-snippet-receipt-v1" or not isinstance(receipt.get("changed"),bool): raise SystemExit("snippet receipt mismatch")
 write_json(require_private_root(args.output_dir,()),f"{digest}.receipt.json",receipt); print(json.dumps({"changed":receipt["changed"],"receipt":str(args.output_dir/f'{digest}.receipt.json')},sort_keys=True))
def observe_receipt(args):
 target=validate_target(args.admission,args.known_hosts); public=guest_key(args.guest_public_key,target); commit=clean_commit(); content=render(public); current=remote(target,args.known_hosts,"observe"); snippet=current.get("snippet",{}); expected_sha=sha(content)
 if current.get("file_id")!="local:snippets/home-lab-debian-lifecycle-qualification.yaml" or snippet.get("exists") is not True or snippet.get("sha256")!=expected_sha or snippet.get("size")!=len(content) or snippet.get("mode")!="0600" or snippet.get("uid")!=0 or snippet.get("gid")!=0 or snippet.get("nlink")!=1: raise SystemExit("server-side snippet postcondition mismatch")
 value={"admission_sha256":target["isolation_attestation_sha256"],"commit":commit,"file_id":current["file_id"],"format":"home-lab-debian-qualification-snippet-observation-receipt-v1","guest_ssh_public_key_sha256":sha(public.encode()),"known_hosts_sha256":sha(load_protected_bytes(args.known_hosts,"qualification known-hosts")),"mode":"0600","node_name":target["node_name"],"observation_sha256":sha(canonical_bytes(current)+b"\n"),"sha256":expected_sha,"size":len(content),"target_id":target["target_id"],"version":1}; raw=canonical_bytes(value)+b"\n"; digest=sha(raw); output=require_private_root(args.output_dir,()); write_json(output,f"{digest}.observation-receipt.json",value); print(json.dumps({"receipt":str(output/f'{digest}.observation-receipt.json'),"receipt_sha256":digest},sort_keys=True))
def verify(args):
 target=validate_target(args.admission,args.known_hosts); public=guest_key(args.guest_public_key,target); receipt,receipt_raw=load_canonical_object(args.receipt,"snippet receipt"); content=render(public); current=remote(target,args.known_hosts,"observe"); observation=receipt.get("format")=="home-lab-debian-qualification-snippet-observation-receipt-v1"
 base={"admission_sha256":target["isolation_attestation_sha256"],"file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml","guest_ssh_public_key_sha256":sha(public.encode()),"known_hosts_sha256":sha(load_protected_bytes(args.known_hosts,"qualification known-hosts")),"mode":"0600","node_name":target["node_name"],"sha256":sha(content),"size":len(content),"target_id":target["target_id"],"version":1}
 required=set(base)|{"commit","format"}|({"observation_sha256"} if observation else {"changed","plan_sha256"}); expected={**base,"format":"home-lab-debian-qualification-snippet-observation-receipt-v1" if observation else "home-lab-debian-qualification-snippet-receipt-v1"}
 if set(receipt)!=required or any(receipt.get(key)!=value for key,value in expected.items()) or re.fullmatch(r"[0-9a-f]{40}",receipt.get("commit","") or "") is None: raise SystemExit("snippet receipt binding mismatch")
 if observation:
  if receipt.get("observation_sha256")!=sha(canonical_bytes(current)+b"\n"): raise SystemExit("snippet observation receipt drift")
 elif not isinstance(receipt.get("changed"),bool) or re.fullmatch(r"[0-9a-f]{64}",receipt.get("plan_sha256","") or "") is None: raise SystemExit("snippet receipt binding mismatch")
 snippet=current.get("snippet",{})
 if current.get("file_id")!=base["file_id"] or snippet.get("exists") is not True or snippet.get("sha256")!=base["sha256"] or snippet.get("size")!=base["size"] or snippet.get("mode")!="0600" or snippet.get("uid")!=0 or snippet.get("gid")!=0 or snippet.get("nlink")!=1: raise SystemExit("server-side snippet postcondition mismatch")
 output={**target,"snippet_file_id":base["file_id"],"snippet_receipt_sha256":sha(receipt_raw),"snippet_sha256":base["sha256"],"snippet_size":base["size"]}
 print(json.dumps(output,sort_keys=True,separators=(",",":")))
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
 for name in ("plan","apply","verify","observe-receipt"):
  item=sub.add_parser(name); item.add_argument("--admission",type=Path,required=True); item.add_argument("--known-hosts",type=Path,required=True); item.add_argument("--guest-public-key",type=Path,required=True)
  if name in ("plan","apply","observe-receipt"): item.add_argument("--output-dir",type=Path,required=True)
  if name=="apply": item.add_argument("--plan",type=Path,required=True); item.add_argument("--plan-sha",required=True); item.add_argument("--approve-plan-sha",required=True); item.add_argument("--confirm",required=True)
  if name=="verify": item.add_argument("--receipt",type=Path,required=True)
 args=parser.parse_args()
 for attr in ("admission","known_hosts","guest_public_key","output_dir","plan","receipt"):
  value=getattr(args,attr,None)
  if value is not None: setattr(args,attr,value.resolve())
 if args.command=="apply": apply(args)
 elif args.command=="verify": verify(args)
 elif args.command=="observe-receipt": observe_receipt(args)
 else: plan(args)
if __name__=="__main__": main()
