#!/usr/bin/env python3
"""Plan/apply the exact cloud-init snippet on an admitted isolated PVE target."""
import argparse,base64,datetime as dt,hashlib,json,os,re,subprocess,sys
from pathlib import Path
import yaml
from protected_execution import acquire_transfer_lock,canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,verify_exact_checkout,write_json
ROOT=Path(__file__).resolve().parents[2]; TEMPLATE=ROOT/"infrastructure/debian/cloud-init/qualification-user-data.tftpl"; VALIDATOR=ROOT/"scripts/controller/validate-disposable-pve-target.js"; CONFIRM="DEBIAN_QUALIFICATION_SNIPPET_CONFIRMED"
def sha(raw): return hashlib.sha256(raw).hexdigest()
def validate_target(admission,known_hosts):
 result=subprocess.run(["node",str(VALIDATOR),"--evidence",str(admission),"--known-hosts",str(known_hosts)],text=True,capture_output=True)
 if result.returncode or result.stderr: raise SystemExit("disposable PVE admission validation failed")
 try: return json.loads(result.stdout)
 except json.JSONDecodeError as error: raise SystemExit("admission validator returned invalid JSON") from error
def verify_agent(expected):
 if not os.environ.get("SSH_AUTH_SOCK"): raise SystemExit("dedicated qualification SSH agent is required")
 result=subprocess.run(["ssh-add","-L"],text=True,capture_output=True)
 lines=[line for line in result.stdout.splitlines() if line.strip()]
 if result.returncode or len(lines)!=1: raise SystemExit("qualification SSH agent must contain exactly one key")
 fields=lines[0].split()
 if len(fields)<2 or sha(f"{fields[0]} {fields[1]}".encode())!=expected: raise SystemExit("qualification SSH agent identity mismatch")
def ssh_args(target,known_hosts,command):
 return ["ssh","-F","/dev/null","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","UpdateHostKeys=no","-o",f"UserKnownHostsFile={known_hosts}","-o","IdentitiesOnly=yes","-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no","-o","RequestTTY=no","-o","ConnectTimeout=10",f'{target["ssh_username"]}@{target["ssh_address"]}',command]
def remote(target,known_hosts,command,data=None):
 result=subprocess.run(ssh_args(target,known_hosts,command),input=data,capture_output=True,timeout=90)
 if result.returncode or result.stderr: raise SystemExit("isolated PVE snippet transport failed")
 try: value=json.loads(result.stdout)
 except json.JSONDecodeError as error: raise SystemExit("snippet transport returned invalid JSON") from error
 if result.stdout!=canonical_bytes(value)+b"\n": raise SystemExit("snippet transport returned non-canonical JSON")
 return value
def render(public_key):
 contract=yaml.safe_load((ROOT/"infrastructure/contract/home-lab.yml").read_text()); text=TEMPLATE.read_text()
 values={"timezone":contract["system_timezone"],"locale":contract["debian"]["locale"],"qualification_ssh_public_key":public_key}
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
 target=validate_target(args.admission,args.known_hosts); verify_agent(target["ssh_agent_public_key_sha256"]); public=guest_key(args.guest_public_key,target); commit=clean_commit(); before=remote(target,args.known_hosts,"observe")
 content=render(public); now=dt.datetime.now(dt.timezone.utc); expires=now+dt.timedelta(minutes=10)
 value={"admission_sha256":target["isolation_attestation_sha256"],"authorized":False,"automatic_apply":False,"before_sha256":sha(canonical_bytes(before)+b"\n"),"commit":commit,"content_b64":base64.b64encode(content).decode(),"created_at":now.isoformat().replace("+00:00","Z"),"expires_at":expires.isoformat().replace("+00:00","Z"),"file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml","format":"home-lab-debian-qualification-snippet-plan-v1","guest_ssh_public_key_sha256":target["guest_ssh_public_key_sha256"],"known_hosts_sha256":sha(load_protected_bytes(args.known_hosts,"qualification known-hosts")),"mode":"0600","node_name":target["node_name"],"operation":"create-snippet","sha256":sha(content),"size":len(content),"target_id":target["target_id"],"version":1}
 raw=canonical_bytes(value)+b"\n"; digest=sha(raw); output=require_private_root(args.output_dir,()); write_json(output,f"{digest}.json",value); print(json.dumps({"authorized":False,"path":str(output/f'{digest}.json'),"plan_sha256":digest},sort_keys=True))
def apply(args):
 if args.approve_plan_sha!=args.plan_sha or args.confirm!=CONFIRM: raise SystemExit("exact snippet approval and confirmation are required")
 value,raw=load_canonical_object(args.plan,"snippet plan"); digest=sha(raw)
 if digest!=args.plan_sha: raise SystemExit("snippet plan digest mismatch")
 target=validate_target(args.admission,args.known_hosts); verify_agent(target["ssh_agent_public_key_sha256"]); public=guest_key(args.guest_public_key,target); verify_exact_checkout("git",value.get("commit",""),os.environ.copy())
 expected_content=render(public)
 if value.get("admission_sha256")!=target["isolation_attestation_sha256"] or value.get("target_id")!=target["target_id"] or value.get("node_name")!=target["node_name"] or value.get("file_id")!="local:snippets/home-lab-debian-lifecycle-qualification.yaml" or value.get("guest_ssh_public_key_sha256")!=sha(public.encode()) or value.get("known_hosts_sha256")!=sha(load_protected_bytes(args.known_hosts,"qualification known-hosts")) or value.get("content_b64")!=base64.b64encode(expected_content).decode() or value.get("sha256")!=sha(expected_content) or value.get("size")!=len(expected_content): raise SystemExit("snippet plan binding mismatch")
 current=remote(target,args.known_hosts,"observe")
 if value.get("before_sha256")!=sha(canonical_bytes(current)+b"\n"): raise SystemExit("snippet precondition drift")
 lock=args.output_dir/"snippet-apply.lock"; descriptor=acquire_transfer_lock(lock)
 try: receipt=remote(target,args.known_hosts,f"apply {digest} {digest}",raw)
 finally: os.close(descriptor)
 expected={"admission_sha256":value["admission_sha256"],"commit":value["commit"],"file_id":value["file_id"],"mode":"0600","node_name":value["node_name"],"plan_sha256":digest,"sha256":value["sha256"],"size":value["size"],"target_id":value["target_id"],"version":1}
 if any(receipt.get(key)!=item for key,item in expected.items()) or receipt.get("format")!="home-lab-debian-qualification-snippet-receipt-v1" or not isinstance(receipt.get("changed"),bool): raise SystemExit("snippet receipt mismatch")
 write_json(require_private_root(args.output_dir,()),f"{digest}.receipt.json",receipt); print(json.dumps({"changed":receipt["changed"],"receipt":str(args.output_dir/f'{digest}.receipt.json')},sort_keys=True))
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
 for name in ("plan","apply"):
  item=sub.add_parser(name); item.add_argument("--admission",type=Path,required=True); item.add_argument("--known-hosts",type=Path,required=True); item.add_argument("--guest-public-key",type=Path,required=True); item.add_argument("--output-dir",type=Path,required=True)
  if name=="apply": item.add_argument("--plan",type=Path,required=True); item.add_argument("--plan-sha",required=True); item.add_argument("--approve-plan-sha",required=True); item.add_argument("--confirm",required=True)
 args=parser.parse_args();
 for attr in ("admission","known_hosts","guest_public_key","output_dir"):
  value=getattr(args,attr); setattr(args,attr,value.resolve())
 if args.command=="apply": args.plan=args.plan.resolve(); apply(args)
 else: plan(args)
if __name__=="__main__": main()
