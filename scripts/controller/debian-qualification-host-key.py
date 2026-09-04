#!/usr/bin/env python3
"""Plan/apply read-only VM9900 host-key extraction after an exact stopped receipt."""
import argparse,datetime as dt,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,verify_exact_checkout,write_json
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"scripts/controller/debian-qualification-snippet.py"; spec=importlib.util.spec_from_file_location("qualification_snippet",SOURCE); snippet=importlib.util.module_from_spec(spec); spec.loader.exec_module(snippet)
CONFIRM="EXTRACT_VM9900_HOST_KEY_READ_ONLY"
def fail(reason): raise SystemExit(f"debian_qualification_host_key=failed reason={reason}")
def sha(raw): return hashlib.sha256(raw).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc)
def stopped(path,target,state):
 value,raw=load_canonical_object(path,"VM9900 stopped receipt"); required={"admission_sha256","commit","format","operation","plan_sha256","prior_receipt_sha256","resources","snippet_receipt_sha256","snippet_sha256","state_sha256","target_id","version","vm_started","vmid"}
 if set(value)!=required or value.get("format")!="home-lab-debian-qualification-stop-receipt-v1" or value.get("operation")!="stop" or value.get("target_id")!=target["target_id"] or value.get("vmid")!=9900 or value.get("vm_started") is not False or value.get("state_sha256")!=sha(load_protected_bytes(state,"qualification state")) or value.get("resources")!=["proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"]: fail("stopped-receipt")
 for key in ("admission_sha256","plan_sha256","prior_receipt_sha256","snippet_receipt_sha256","snippet_sha256","state_sha256"):
  if re.fullmatch(r"[0-9a-f]{64}",value.get(key,"") or "") is None: fail("stopped-receipt")
 return value,sha(raw)
def revision(expected=None):
 commit=subprocess.run(["git","rev-parse","HEAD"],text=True,capture_output=True,check=True).stdout.strip(); verify_exact_checkout("git",expected or commit,os.environ.copy()); return commit
def parse_time(value):
 try: result=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
 except Exception: fail("plan-time")
 if result.tzinfo is None: fail("plan-time")
 return result
def plan(args):
 output=require_private_root(args.output_dir,()); lock=acquire_transfer_lock(output/"lifecycle.lock")
 try:
  target=snippet.validate_target(args.admission,args.known_hosts); state=output/"state.tfstate"; receipt,receipt_sha=stopped(args.stopped_receipt,target,state); created=now()
  value={"admission_sha256":target["isolation_attestation_sha256"],"authorized":False,"automatic_apply":False,"commit":revision(),"created_at":created.isoformat().replace("+00:00","Z"),"disk_volume":"local-lvm:vm-9900-disk-0","expires_at":(created+dt.timedelta(hours=4)).isoformat().replace("+00:00","Z"),"format":"home-lab-debian-qualification-host-key-plan-v1","guest_ipv4":"192.168.0.53","node_name":target["node_name"],"operation":"extract-host-key-read-only","state_sha256":receipt["state_sha256"],"stopped_receipt_sha256":receipt_sha,"target_id":target["target_id"],"version":1,"vmid":9900}
  raw=canonical_bytes(value)+b"\n"; digest=sha(raw); write_json(output,f"{digest}.host-key-plan.json",value); print(json.dumps({"actionable":True,"authorized":False,"plan":str(output/f'{digest}.host-key-plan.json'),"plan_sha256":digest},sort_keys=True))
 finally: os.close(lock)
def apply(args):
 if args.approve_plan_sha!=args.plan_sha or args.confirm!=CONFIRM: fail("exact-authorization-required")
 output=require_private_root(args.output_dir,()); value,raw=load_canonical_object(args.plan,"host-key plan")
 if sha(raw)!=args.plan_sha: fail("plan-sha")
 target=snippet.validate_target(args.admission,args.known_hosts); state=output/"state.tfstate"; stopped_receipt,receipt_sha=stopped(args.stopped_receipt,target,state); revision(value.get("commit"))
 required={"admission_sha256","authorized","automatic_apply","commit","created_at","disk_volume","expires_at","format","guest_ipv4","node_name","operation","state_sha256","stopped_receipt_sha256","target_id","version","vmid"}; created=parse_time(value.get("created_at","")); expires=parse_time(value.get("expires_at",""))
 if set(value)!=required or value.get("format")!="home-lab-debian-qualification-host-key-plan-v1" or value.get("operation")!="extract-host-key-read-only" or value.get("target_id")!=target["target_id"] or value.get("node_name")!=target["node_name"] or value.get("disk_volume")!="local-lvm:vm-9900-disk-0" or value.get("guest_ipv4")!="192.168.0.53" or value.get("state_sha256")!=stopped_receipt["state_sha256"] or value.get("stopped_receipt_sha256")!=receipt_sha or value.get("version")!=1 or value.get("vmid")!=9900 or value.get("authorized") is not False or value.get("automatic_apply") is not False or created>now()+dt.timedelta(seconds=5) or created<now()-dt.timedelta(hours=4) or expires<=now() or expires-created>dt.timedelta(hours=4): fail("plan-binding")
 lock=acquire_transfer_lock(output/"lifecycle.lock")
 try:
  if sha(load_protected_bytes(state,"qualification state"))!=value["state_sha256"]: fail("state-drift")
  receipt=snippet.remote(target,args.known_hosts,f"host-key {args.plan_sha} {args.plan_sha}",raw)
 finally: os.close(lock)
 expected={"disk_volume":value["disk_volume"],"format":"home-lab-debian-qualification-host-key-receipt-v1","guest_ipv4":value["guest_ipv4"],"plan_sha256":args.plan_sha,"state_sha256":value["state_sha256"],"stopped_receipt_sha256":receipt_sha,"target_id":value["target_id"],"version":1,"vmid":9900}
 if any(receipt.get(key)!=item for key,item in expected.items()) or set(receipt)!=set(expected)|{"fingerprint","public_key","sha256"} or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}",receipt.get("public_key","") or "") is None or re.fullmatch(r"SHA256:[A-Za-z0-9+/]+",receipt.get("fingerprint","") or "") is None or receipt.get("sha256")!=sha((receipt["public_key"]+"\n").encode()): fail("receipt-binding")
 write_json(output,f"{args.plan_sha}.host-key-receipt.json",receipt); known=output/"vm9900_known_hosts"; line=f"{value['guest_ipv4']} {receipt['public_key']}\n".encode(); fd=os.open(known,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  if os.write(fd,line)!=len(line): fail("known-host-short-write")
  os.fsync(fd)
 finally: os.close(fd)
 directory=os.open(output,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(directory); os.close(directory)
 print(json.dumps({"fingerprint":receipt["fingerprint"],"known_hosts":str(known),"receipt":str(output/f'{args.plan_sha}.host-key-receipt.json')},sort_keys=True))
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
 for name in ("plan","apply"):
  item=sub.add_parser(name); item.add_argument("--admission",type=Path,required=True); item.add_argument("--known-hosts",type=Path,required=True); item.add_argument("--stopped-receipt",type=Path,required=True); item.add_argument("--output-dir",type=Path,required=True)
  if name=="apply": item.add_argument("--plan",type=Path,required=True); item.add_argument("--plan-sha",required=True); item.add_argument("--approve-plan-sha",required=True); item.add_argument("--confirm",required=True)
 args=parser.parse_args()
 for key,value in vars(args).items():
  if isinstance(value,Path): setattr(args,key,value.resolve())
 apply(args) if args.command=="apply" else plan(args)
if __name__=="__main__": main()
