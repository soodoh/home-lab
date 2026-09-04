#!/usr/bin/env python3
"""Produce Debian lifecycle authority receipts from actual OpenTofu and recovery bytes."""
import argparse,hashlib,json,os,re,stat,subprocess,tempfile
from pathlib import Path
from protected_execution import canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,verify_exact_checkout,write_json
ROOT=Path(__file__).resolve().parents[2]; HEX64=re.compile(r"^[0-9a-f]{64}$"); RECIPIENT=re.compile(r"^age1[023456789acdefghjklmnpqrstuvwxyz]{20,100}$")
def fail(reason): raise SystemExit(f"debian_lifecycle_authority_receipt=failed reason={reason}")
def sha(raw): return hashlib.sha256(raw).hexdigest()
def commit(expected=None):
 value=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip();verify_exact_checkout("git",expected or value,os.environ.copy());return value
def protected(path,label): return load_protected_bytes(path,label)
def resources(module):
 result=[]
 if not isinstance(module,dict): return result
 result.extend(module.get("resources",[]) or [])
 for child in module.get("child_modules",[]) or []: result.extend(resources(child))
 return result
def vm_values(document,address,plan=False):
 if plan:
  changed=[item for item in document.get("resource_changes",[]) if item.get("change",{}).get("actions")!=["no-op"]]
  if len(changed)!=1 or changed[0].get("address")!=address or changed[0].get("change",{}).get("actions")!=["update"]: fail("OpenTofu disk plan actions differ")
  change=changed[0]["change"]
  if (change.get("after_unknown") or {}).get("disk"): fail("OpenTofu disk result is unknown")
  return change.get("before") or {},change.get("after") or {}
 root=((document.get("values") or {}).get("root_module") or {}); matches=[item.get("values",{}) for item in resources(root) if item.get("address")==address]
 if len(matches)!=1: fail("OpenTofu state VM identity differs")
 return matches[0]
def verify_devices(values,devices,vmid):
 if values.get("vm_id")!=vmid: fail("OpenTofu VMID differs")
 disks=values.get("disk",[]) or []
 for expected in devices:
  matches=[item for item in disks if item.get("serial")==expected["serial"]]
  if len(matches)!=1: fail("OpenTofu disk serial differs")
  size=matches[0].get("size"); size_bytes=int(size)*1073741824 if isinstance(size,(int,float)) else None
  if size_bytes!=expected["size_bytes"]: fail("OpenTofu disk size differs")
def opentofu(args):
 request,_=load_canonical_object(args.request,"OpenTofu disk receipt request"); required={"devices","format","kind","resource_address","vmid"}
 if set(request)!=required or request.get("format")!="home-lab-opentofu-debian-disk-receipt-request-v1" or request.get("kind") not in ("storage-attachment","state-disk") or request.get("vmid")!=100 or not isinstance(request.get("devices"),list) or not request["devices"]: fail("OpenTofu receipt request differs")
 for item in request["devices"]:
  if set(item)!={"path","serial","size_bytes","uuid","fstype","surviving"} or not item["path"].startswith("/dev/disk/by-id/") or not isinstance(item["size_bytes"],int) or item["size_bytes"]<=0: fail("OpenTofu requested device differs")
 plan_raw=protected(args.saved_plan,"OpenTofu saved plan"); state_raw=protected(args.state_json,"OpenTofu state JSON")
 shown=subprocess.run(["tofu","show","-json",str(args.saved_plan)],cwd=ROOT,text=True,capture_output=True)
 if shown.returncode or shown.stderr: fail("OpenTofu saved plan inspection failed")
 try: plan=json.loads(shown.stdout); state=json.loads(state_raw)
 except json.JSONDecodeError: fail("OpenTofu plan or state JSON differs")
 before_values,plan_values=vm_values(plan,request["resource_address"],True); state_values=vm_values(state,request["resource_address"])
 verify_devices(plan_values,request["devices"],100); verify_devices(state_values,request["devices"],100)
 requested={item["serial"] for item in request["devices"]}; before_disks=before_values.get("disk",[]) or []; after_disks=plan_values.get("disk",[]) or []
 if requested & {item.get("serial") for item in before_disks} or len(after_disks)!=len(before_disks)+len(requested) or any(item not in after_disks for item in before_disks): fail("OpenTofu requested disk delta differs")
 stable_keys=(set(before_values)|set(plan_values))-{"disk","ipv4_addresses","ipv6_addresses","mac_addresses","network_interface_names"}
 if any(before_values.get(key)!=plan_values.get(key) for key in stable_keys): fail("OpenTofu plan contains unrelated VM change")
 relevant=("vm_id","node_name","name","disk","started","on_boot","protection")
 if any(plan_values.get(key)!=state_values.get(key) for key in relevant): fail("OpenTofu planned VM result differs from current state")
 common={"authority":"opentofu","commit":commit(),"plan_sha256":sha(plan_raw),"producer_sha256":producer_sha(),"state_sha256":sha(state_raw),"status":"applied","target":"debian","version":1,"vmid":100}
 if request["kind"]=="storage-attachment": value={**common,"devices":request["devices"],"format":"home-lab-opentofu-storage-attachment-receipt-v1"}
 else:
  if len(request["devices"])!=1: fail("state-disk receipt requires one disk")
  device=request["devices"][0]; value={**common,"blank_required":True,"disk":{key:device[key] for key in ("path","serial","size_bytes")},"format":"home-lab-opentofu-state-disk-receipt-v1"}
 output=require_private_root(args.output,()); raw=canonical_bytes(value)+b"\n"; digest=sha(raw); write_json(output,f"{digest}.json",value); print(json.dumps({"path":str(output/f'{digest}.json'),"receipt_sha256":digest},sort_keys=True))
def age(args):
 identity=protected(args.identity,"age recovery identity"); bundle=protected(args.recovery_bundle,"encrypted recovery bundle")
 recipient_check=subprocess.run([args.age_keygen,"-y",str(args.identity)],text=True,capture_output=True)
 if recipient_check.returncode or recipient_check.stderr or recipient_check.stdout.strip()!=args.recipient or RECIPIENT.fullmatch(args.recipient) is None: fail("age recovery recipient differs")
 with tempfile.TemporaryFile() as plaintext:
  decrypted=subprocess.run([args.age,"--decrypt","--identity",str(args.identity),str(args.recovery_bundle)],stdout=plaintext,stderr=subprocess.PIPE)
  if decrypted.returncode or decrypted.stderr: fail("recovery bundle full-read decryption failed")
  plaintext.seek(0); digest=hashlib.sha256()
  while True:
   chunk=plaintext.read(1048576)
   if not chunk: break
   digest.update(chunk)
 value={"bundle_plaintext_sha256":digest.hexdigest(),"commit":commit(),"format":"home-lab-age-recovery-receipt-v1","identity_sha256":sha(identity),"path":"/etc/sops/age/keys.txt","producer_sha256":producer_sha(),"recipient":args.recipient,"recovery_bundle_sha256":sha(bundle),"status":"verified","target":"debian","version":1}; output=require_private_root(args.output,()); raw=canonical_bytes(value)+b"\n"; receipt_sha=sha(raw); write_json(output,f"{receipt_sha}.json",value); print(json.dumps({"path":str(output/f'{receipt_sha}.json'),"receipt_sha256":receipt_sha},sort_keys=True))
def producer_sha(): return sha(Path(__file__).read_bytes())
def publish(output,value):
 directory=require_private_root(output,()); raw=canonical_bytes(value)+b"\n"; digest=sha(raw); write_json(directory,f"{digest}.json",value); print(json.dumps({"path":str(directory/f'{digest}.json'),"receipt_sha256":digest},sort_keys=True))
def restic_snapshot(args):
 if HEX64.fullmatch(args.repository_id or "") is None or HEX64.fullmatch(args.snapshot_id or "") is None: fail("Restic snapshot identity differs")
 config=subprocess.run([args.restic,"-r",args.repository,"cat","config"],text=True,capture_output=True); snapshots=subprocess.run([args.restic,"-r",args.repository,"snapshots","--json",args.snapshot_id],text=True,capture_output=True); checked=subprocess.run([args.restic,"-r",args.repository,"check","--read-data"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 try: config_value=json.loads(config.stdout); snapshot_values=json.loads(snapshots.stdout)
 except json.JSONDecodeError: fail("Restic repository observation differs")
 if config.returncode or snapshots.returncode or checked.returncode or config_value.get("id")!=args.repository_id or len(snapshot_values)!=1 or snapshot_values[0].get("id")!=args.snapshot_id: fail("Restic full-read snapshot verification failed")
 publish(args.output,{"format":"home-lab-restic-recovery-snapshot-v1","producer_sha256":producer_sha(),"repository_id":args.repository_id,"snapshot_id":args.snapshot_id,"status":"verified","target":"debian","version":1})
def tree_digest(root):
 records=[]
 for directory,names,files in os.walk(root,topdown=True,followlinks=False):
  names.sort(); files.sort()
  for name in names+files:
   path=Path(directory)/name; metadata=os.lstat(path); relative=str(path.relative_to(root)); mode=format(stat.S_IMODE(metadata.st_mode),"04o")
   if stat.S_ISLNK(metadata.st_mode): records.append({"gid":metadata.st_gid,"mode":mode,"path":relative,"target":os.readlink(path),"type":"symlink","uid":metadata.st_uid})
   elif stat.S_ISDIR(metadata.st_mode): records.append({"gid":metadata.st_gid,"mode":mode,"path":relative,"type":"directory","uid":metadata.st_uid})
   elif stat.S_ISREG(metadata.st_mode):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); digest=hashlib.sha256(); size=0
    try:
     while True:
      chunk=os.read(fd,1048576)
      if not chunk: break
      digest.update(chunk); size+=len(chunk)
    finally: os.close(fd)
    records.append({"gid":metadata.st_gid,"mode":mode,"path":relative,"sha256":digest.hexdigest(),"size":size,"type":"file","uid":metadata.st_uid})
   else: fail("unsupported restored tree entry")
 return sha(canonical_bytes(records)+b"\n")
def restic_restore(args):
 snapshot,snapshot_raw=load_canonical_object(args.snapshot_manifest,"Restic snapshot manifest"); required={"format","producer_sha256","repository_id","snapshot_id","status","target","version"}
 if set(snapshot)!=required or snapshot.get("producer_sha256")!=producer_sha() or snapshot.get("format")!="home-lab-restic-recovery-snapshot-v1" or snapshot.get("status")!="verified" or snapshot.get("target")!="debian" or snapshot.get("version")!=1: fail("fixed Restic snapshot manifest differs")
 staging=require_private_root(args.staging_root,())
 if any(staging.iterdir()): fail("Restic staging root must be empty")
 restored=subprocess.run([args.restic,"-r",args.repository,"restore",snapshot["snapshot_id"],"--target",str(staging),"--verify"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 if restored.returncode: fail("fixed Restic restore failed")
 publish(args.output,{"format":"home-lab-restic-restore-verification-v1","producer_sha256":producer_sha(),"snapshot_manifest_sha256":sha(snapshot_raw),"status":"verified","target":"debian","tree_sha256":tree_digest(staging),"version":1})
def restic_receipt(args):
 snapshot,snapshot_raw=load_canonical_object(args.snapshot_manifest,"Restic snapshot manifest"); restore,restore_raw=load_canonical_object(args.restore_manifest,"Restic restore manifest")
 snapshot_required={"format","producer_sha256","repository_id","snapshot_id","status","target","version"}; restore_required={"format","producer_sha256","snapshot_manifest_sha256","status","target","tree_sha256","version"}
 if set(snapshot)!=snapshot_required or snapshot.get("producer_sha256")!=producer_sha() or snapshot.get("format")!="home-lab-restic-recovery-snapshot-v1" or snapshot.get("status")!="verified" or snapshot.get("target")!="debian" or snapshot.get("version")!=1 or HEX64.fullmatch(snapshot.get("repository_id","") or "") is None or HEX64.fullmatch(snapshot.get("snapshot_id","") or "") is None: fail("Restic snapshot manifest differs")
 if set(restore)!=restore_required or restore.get("producer_sha256")!=producer_sha() or restore.get("format")!="home-lab-restic-restore-verification-v1" or restore.get("snapshot_manifest_sha256")!=sha(snapshot_raw) or restore.get("status")!="verified" or restore.get("target")!="debian" or restore.get("version")!=1 or HEX64.fullmatch(restore.get("tree_sha256","") or "") is None: fail("Restic restore manifest differs")
 value={"commit":commit(),"format":"home-lab-restic-recovery-activation-receipt-v1","producer_sha256":producer_sha(),"repository_id":snapshot["repository_id"],"restore_manifest_sha256":sha(restore_raw),"snapshot_id":snapshot["snapshot_id"],"snapshot_manifest_sha256":sha(snapshot_raw),"status":"verified","target":"debian","tree_sha256":restore["tree_sha256"],"version":1}; output=require_private_root(args.output,()); raw=canonical_bytes(value)+b"\n"; digest=sha(raw); write_json(output,f"{digest}.json",value); print(json.dumps({"path":str(output/f'{digest}.json'),"receipt_sha256":digest},sort_keys=True))
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True); tofu=sub.add_parser("opentofu"); tofu.add_argument("request",type=Path); tofu.add_argument("saved_plan",type=Path); tofu.add_argument("state_json",type=Path); tofu.add_argument("output",type=Path); recovery=sub.add_parser("age"); recovery.add_argument("identity",type=Path); recovery.add_argument("recovery_bundle",type=Path); recovery.add_argument("recipient"); recovery.add_argument("output",type=Path); recovery.add_argument("--age",default="age"); recovery.add_argument("--age-keygen",default="age-keygen"); snapshot_parser=sub.add_parser("restic-snapshot"); snapshot_parser.add_argument("repository"); snapshot_parser.add_argument("repository_id"); snapshot_parser.add_argument("snapshot_id"); snapshot_parser.add_argument("output",type=Path); snapshot_parser.add_argument("--restic",default="restic"); restore_parser=sub.add_parser("restic-restore"); restore_parser.add_argument("repository"); restore_parser.add_argument("snapshot_manifest",type=Path); restore_parser.add_argument("staging_root",type=Path); restore_parser.add_argument("output",type=Path); restore_parser.add_argument("--restic",default="restic"); restic_parser=sub.add_parser("restic"); restic_parser.add_argument("snapshot_manifest",type=Path); restic_parser.add_argument("restore_manifest",type=Path); restic_parser.add_argument("output",type=Path)
 args=parser.parse_args()
 for key,value in vars(args).items():
  if isinstance(value,Path): setattr(args,key,value.resolve())
 if args.command=="opentofu": opentofu(args)
 elif args.command=="age": age(args)
 elif args.command=="restic-snapshot": restic_snapshot(args)
 elif args.command=="restic-restore": restic_restore(args)
 else: restic_receipt(args)
if __name__=="__main__": main()
