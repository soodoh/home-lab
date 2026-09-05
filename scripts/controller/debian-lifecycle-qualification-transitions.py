#!/usr/bin/env python3
"""Separate saved-plan start and destroy transitions for disposable VM 9900."""
import argparse,datetime as dt,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,write_json
ROOT=Path(__file__).resolve().parents[2]; source=ROOT/"scripts/controller/debian-lifecycle-qualification.py"; spec=importlib.util.spec_from_file_location("debian_qualification_foundation",source); common=importlib.util.module_from_spec(spec); spec.loader.exec_module(common)
snippet_source=ROOT/"scripts/controller/debian-qualification-snippet.py"; snippet_spec=importlib.util.spec_from_file_location("debian_qualification_snippet",snippet_source); snippet_module=importlib.util.module_from_spec(snippet_spec); snippet_spec.loader.exec_module(snippet_module)
os.umask(0o077)
CONFIRM={"start":"START_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900","repair-network":"REPAIR_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900_DHCP","stop":"STOP_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900_FOR_OFFLINE_INSPECTION","restart":"RESTART_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900_AFTER_HOSTKEY","destroy":"DESTROY_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900"}
def fail(reason): raise SystemExit(f"debian_qualification_transition=failed reason={reason}")
def sha(raw): return hashlib.sha256(raw).hexdigest()
def parse_time(value):
 try: parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
 except Exception: fail("manifest-time")
 if parsed.tzinfo is None: fail("manifest-time")
 return parsed
def admission_lineage(args,value,operation,target):
 if value.get("admission_sha256")==target["isolation_attestation_sha256"]: return True
 if operation!="restart": return False
 raw=load_protected_bytes(args.prior_admission,"prior qualification admission")
 if sha(raw)!=value.get("admission_sha256"): fail("prior-admission-digest")
 prior_target=common.run_json(["node",str(common.ADMISSION),"--evidence",str(args.prior_admission),"--known-hosts",str(args.known_hosts),"--allow-expired-safe-stop"])
 fields=("api_ca_sha256","apply_principal","bridge","controller_ipv4","disk_datastore_id","endpoint","guest_ssh_public_key_sha256","image_datastore_id","node_name","plan_principal","snippet_datastore_id","snippet_directory","ssh_address","ssh_authentication","ssh_username","target_id")
 if prior_target.get("admission_mode")!="expired-safe-stop" or prior_target.get("isolation_attestation_sha256")!=value.get("admission_sha256") or any(prior_target.get(key)!=target.get(key) for key in fields): fail("prior-admission-lineage")
 return True
def prior(args,operation,target):
 value,raw=load_canonical_object(args.prior_receipt,"qualification prior receipt")
 if operation=="start": expected_format="home-lab-debian-qualification-foundation-receipt-v1"; expected_operation="create-stopped-foundation"; expected_started=False; prior_identity=False
 elif operation=="repair-network": expected_format="home-lab-debian-qualification-start-receipt-v1"; expected_operation="start"; expected_started=True; prior_identity=True
 elif operation=="stop":
  direct=value.get("format")=="home-lab-debian-qualification-start-receipt-v1" and value.get("operation")=="start"
  expected_format="home-lab-debian-qualification-start-receipt-v1" if direct else "home-lab-debian-qualification-repair-network-receipt-v1"; expected_operation="start" if direct else "repair-network"; expected_started=True; prior_identity=True
 elif operation=="restart": expected_format="home-lab-debian-qualification-stop-receipt-v1"; expected_operation="stop"; expected_started=False; prior_identity=True
 else: expected_format="home-lab-debian-qualification-restart-receipt-v1"; expected_operation="restart"; expected_started=True; prior_identity=True
 required={"admission_sha256","commit","format","operation","plan_sha256","resources","snippet_receipt_sha256","state_sha256","target_id","version","vm_started","vmid"} | ({"prior_receipt_sha256"} if prior_identity else set()) | ({"snippet_sha256"} if operation in ("stop","restart","destroy") else set()) | ({"host_key_receipt_sha256"} if operation=="destroy" else set())
 identities=("admission_sha256","plan_sha256","snippet_receipt_sha256","state_sha256")+(("prior_receipt_sha256",) if prior_identity else ())+(("snippet_sha256",) if operation in ("stop","restart","destroy") else ())+(("host_key_receipt_sha256",) if operation=="destroy" else ())
 expected_resources=["proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"]
 admission_ok=admission_lineage(args,value,operation,target)
 if set(value)!=required or value.get("format")!=expected_format or value.get("operation")!=expected_operation or value.get("version")!=1 or re.fullmatch(r"[0-9a-f]{40}",value.get("commit","") or "") is None or any(re.fullmatch(r"[0-9a-f]{64}",value.get(key,"") or "") is None for key in identities) or value.get("resources")!=expected_resources or not admission_ok or value.get("target_id")!=target["target_id"] or value.get("vmid")!=9900 or value.get("vm_started") is not expected_started: fail("prior-receipt")
 return value,sha(raw)
def historical_stop_target(args):
 target=common.run_json(["node",str(common.ADMISSION),"--evidence",str(args.admission),"--known-hosts",str(args.known_hosts),"--allow-expired-safe-stop"])
 if target.get("admitted") is not True or target.get("admission_mode")!="expired-safe-stop" or target.get("snippet_content_enabled") is not True: fail("historical-admission")
 return target
def historical_stop_snippet(args,target):
 public=common.guest_key(args.guest_public_key,target); receipt,raw=load_canonical_object(args.snippet_receipt,"historical snippet receipt"); content=snippet_module.render(public); current=snippet_module.remote(target,args.known_hosts,"observe")
 required={"admission_sha256","changed","commit","file_id","format","guest_ssh_public_key_sha256","known_hosts_sha256","mode","node_name","plan_sha256","sha256","size","target_id","version"}; expected={"admission_sha256":target["isolation_attestation_sha256"],"file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml","format":"home-lab-debian-qualification-snippet-receipt-v1","guest_ssh_public_key_sha256":sha(public.encode()),"known_hosts_sha256":sha(load_protected_bytes(args.known_hosts,"qualification known-hosts")),"mode":"0600","node_name":target["node_name"],"sha256":sha(content),"size":len(content),"target_id":target["target_id"],"version":1}; observed=current.get("snippet",{})
 if set(receipt)!=required or any(receipt.get(key)!=item for key,item in expected.items()) or not isinstance(receipt.get("changed"),bool) or re.fullmatch(r"[0-9a-f]{40}",receipt.get("commit","") or "") is None or re.fullmatch(r"[0-9a-f]{64}",receipt.get("plan_sha256","") or "") is None or current.get("file_id")!=expected["file_id"] or observed.get("exists") is not True or observed.get("sha256")!=expected["sha256"] or observed.get("size")!=expected["size"] or observed.get("mode")!="0600" or observed.get("uid")!=0 or observed.get("gid")!=0 or observed.get("nlink")!=1: fail("historical-snippet")
 return {**target,"snippet_file_id":expected["file_id"],"snippet_receipt_sha256":sha(raw),"snippet_sha256":expected["sha256"],"snippet_size":expected["size"]}
def target_with_snippet(args,operation):
 if operation=="stop":
  target=historical_stop_target(args); return historical_stop_snippet(args,target)
 return common.snippet(args)
def host_key(args,operation,target,prior_sha,state_sha):
 if operation!="restart": return None
 value,raw=load_canonical_object(args.host_key_receipt,"qualification host-key receipt"); required={"disk_volume","fingerprint","format","guest_ipv4","plan_sha256","public_key","sha256","state_sha256","stopped_receipt_sha256","target_id","version","vmid"}
 if set(value)!=required or value.get("format")!="home-lab-debian-qualification-host-key-receipt-v1" or value.get("disk_volume")!="local-lvm:vm-9900-disk-0" or value.get("guest_ipv4")!="192.168.0.53" or value.get("state_sha256")!=state_sha or value.get("stopped_receipt_sha256")!=prior_sha or value.get("target_id")!=target["target_id"] or value.get("version")!=1 or value.get("vmid")!=9900 or re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}",value.get("public_key","") or "") is None or re.fullmatch(r"SHA256:[A-Za-z0-9+/]+",value.get("fingerprint","") or "") is None or value.get("sha256")!=sha((value.get("public_key","")+"\n").encode()): fail("host-key-receipt")
 for key in ("plan_sha256","sha256","state_sha256","stopped_receipt_sha256"):
  if re.fullmatch(r"[0-9a-f]{64}",value.get(key,"") or "") is None: fail("host-key-receipt")
 return sha(raw)
def changed(value): return {item.get("address"):item.get("change",{}) for item in value.get("resource_changes",[]) if item.get("change",{}).get("actions")!=["no-op"]}
def unknown_true(value,path=()):
 if value is True: return [path]
 if isinstance(value,dict): return [item for key,child in value.items() for item in unknown_true(child,path+(key,))]
 if isinstance(value,list): return [item for index,child in enumerate(value) for item in unknown_true(child,path+(index,))]
 return []
def inspect(value,operation,target):
 changes=changed(value); vm_address="proxmox_virtual_environment_vm.qualification[0]"
 if operation in ("start","stop","restart"):
  if set(changes)!={vm_address} or changes[vm_address].get("actions")!=["update"]: fail(f"{operation}-actions")
  before=changes[vm_address].get("before",{}); after=changes[vm_address].get("after",{}); unknown=changes[vm_address].get("after_unknown",{}) or {}; computed={"ipv4_addresses","ipv6_addresses","mac_addresses","network_interface_names"}
  desired=operation!="stop"; before_stable={key:item for key,item in before.items() if key not in computed}; after_stable={key:item for key,item in after.items() if key not in computed}; before_stable["started"]=desired
  if any(path[0] not in computed for path in unknown_true(unknown)) or before.get("vm_id")!=9900 or before.get("started") is desired or after.get("vm_id")!=9900 or after.get("started") is not desired or after.get("on_boot") is not False or after.get("node_name")!=target["node_name"] or before_stable!=after_stable: fail(f"{operation}-vm")
  return [vm_address]
 if operation=="repair-network":
  rules_address="proxmox_virtual_environment_firewall_rules.qualification[0]"
  if set(changes)!={rules_address} or changes[rules_address].get("actions")!=["update"]: fail("repair-network-actions")
  before=changes[rules_address].get("before",{}); after=changes[rules_address].get("after",{})
  def tuples(item): return [tuple(row.get(key) or None for key in ("type","action","dest","source","proto","dport","sport")) for row in item.get("rule",[])]
  expected_rules=common.expected_firewall_rules(target)
  if before.get("node_name")!=target["node_name"] or before.get("vm_id")!=9900 or after.get("node_name")!=target["node_name"] or after.get("vm_id")!=9900 or tuples(before)!=expected_rules[2:] or tuples(after)!=expected_rules: fail("repair-network-rules")
  return [rules_address]
 expected={"proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_vm.qualification[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]"}; image_address="proxmox_download_file.qualification_image[0]"; options_address="proxmox_virtual_environment_firewall_options.qualification[0]"; rules_address="proxmox_virtual_environment_firewall_rules.qualification[0]"
 if set(changes)!=expected or any(item.get("actions")!=["delete"] for item in changes.values()): fail("destroy-actions")
 vm_before=changes[vm_address].get("before",{}); image_before=changes[image_address].get("before",{}); options_before=changes[options_address].get("before",{}); rules_before=changes[rules_address].get("before",{}); image=common.contract_image()
 if vm_before.get("vm_id")!=9900 or vm_before.get("node_name")!=target["node_name"] or len(vm_before.get("disk",[]))!=1 or vm_before["disk"][0].get("datastore_id")!=target["disk_datastore_id"] or image_before.get("node_name")!=target["node_name"] or image_before.get("datastore_id")!=target["image_datastore_id"] or image_before.get("url")!=image["url"] or image_before.get("checksum")!=image["sha512"] or options_before.get("node_name")!=target["node_name"] or options_before.get("vm_id")!=9900 or rules_before.get("node_name")!=target["node_name"] or rules_before.get("vm_id")!=9900: fail("destroy-actions")
 return sorted(expected)
def publish(output,run,binary,shown,manifest):
 plan_sha=sha(binary.read_bytes()); json_sha=sha(shown.read_bytes()); manifest["plan_sha256"]=plan_sha; manifest["plan_json_sha256"]=json_sha; os.chmod(binary,0o600); os.chmod(shown,0o600)
 final_binary=output/f"{plan_sha}.tfplan"; final_json=output/f"{plan_sha}.plan.json"; os.link(binary,final_binary,follow_symlinks=False); os.unlink(binary); os.link(shown,final_json,follow_symlinks=False); os.unlink(shown)
 descriptor=os.open(output,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)); os.fsync(descriptor); os.close(descriptor); authorization=sha(canonical_bytes(manifest)+b"\n"); write_json(output,f"{authorization}.manifest.json",manifest)
 print(json.dumps({"actionable":True,"authorization_sha256":authorization,"authorized":False,"manifest":str(output/f'{authorization}.manifest.json'),"plan_sha256":plan_sha},sort_keys=True))
def plan(args,operation):
 output=require_private_root(args.output_dir,()); target=target_with_snippet(args,operation); prior_receipt,prior_sha=prior(args,operation,target); key=common.guest_key(args.guest_public_key,target); commit=common.revision(); credentials=common.credential("plan",target); controller,run,env,state,host=common.locked_setup(output,credentials,target,args); state_before=common.state_sha(state)
 try:
  if state_before!=prior_receipt["state_sha256"]: fail("state-drift")
  host_key_sha=host_key(args,operation,target,prior_sha,state_before)
  fresh=target_with_snippet(args,operation)
  if fresh.get("snippet_receipt_sha256")!=target.get("snippet_receipt_sha256"): fail("snippet-drift")
  start_value="false" if operation=="stop" else "true"; binary=run/f"{operation}.tfplan"; shown=run/f"{operation}.json"; command=["tofu",f"-chdir={common.TF_ROOT}","plan","-input=false","-lock=true",*common.variables(target,key),f"-var=start_qualification={start_value}"]
  if operation=="destroy": command.append("-destroy")
  command.extend(["-out",str(binary)]); common.run_locked(command,env,host,f"tofu-{operation}-plan")
  with shown.open("wb") as stream: result=subprocess.run(["tofu",f"-chdir={common.TF_ROOT}","show","-json",str(binary)],env=env,stdout=stream,stderr=subprocess.PIPE)
  if result.returncode: fail("tofu-show")
  resources=inspect(json.loads(shown.read_text()),operation,target); created=common.now(); ttl=dt.timedelta(hours=4) if operation in ("repair-network","stop","restart") else dt.timedelta(minutes=30); manifest={"actionable":True,"admission_sha256":target["isolation_attestation_sha256"],"api_ca_sha256":target["api_ca_sha256"],"apply_principal":target["apply_principal"],"authorized":False,"automatic_apply":False,"commit":commit,"created_at":created.isoformat().replace("+00:00","Z"),"endpoint":target["endpoint"],"expires_at":(created+ttl).isoformat().replace("+00:00","Z"),"format":"home-lab-debian-qualification-transition-plan-v1","node_name":target["node_name"],"operation":operation,"plan_json_sha256":"","plan_principal":target["plan_principal"],"plan_sha256":"","prior_receipt_sha256":prior_sha,"resources":resources,"snippet_receipt_sha256":target["snippet_receipt_sha256"],"snippet_sha256":target["snippet_sha256"],"state_sha256":state_before,"target_id":target["target_id"],"version":1,"vmid":9900}; manifest.update({"host_key_receipt_sha256":host_key_sha} if operation=="restart" else {}); publish(output,run,binary,shown,manifest)
 finally: common.release_target(host); os.close(controller); shutil.rmtree(run,ignore_errors=True)
def manifest(args,operation,target,prior_sha,snippet_sha,host_key_sha):
 value,raw=load_canonical_object(args.manifest,"qualification transition manifest"); required={"actionable","admission_sha256","api_ca_sha256","apply_principal","authorized","automatic_apply","commit","created_at","endpoint","expires_at","format","node_name","operation","plan_json_sha256","plan_principal","plan_sha256","prior_receipt_sha256","resources","snippet_receipt_sha256","snippet_sha256","state_sha256","target_id","version","vmid"} | ({"host_key_receipt_sha256"} if operation=="restart" else set()); created=parse_time(value.get("created_at","")); expires=parse_time(value.get("expires_at","")); identities=("admission_sha256","api_ca_sha256","plan_json_sha256","plan_sha256","prior_receipt_sha256","snippet_receipt_sha256","snippet_sha256","state_sha256")+(("host_key_receipt_sha256",) if operation=="restart" else ())
 expected_resources=["proxmox_virtual_environment_vm.qualification[0]"] if operation in ("start","stop","restart") else (["proxmox_virtual_environment_firewall_rules.qualification[0]"] if operation=="repair-network" else ["proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"])
 ttl=dt.timedelta(hours=4) if operation in ("repair-network","stop","restart") else dt.timedelta(minutes=30)
 if set(value)!=required or sha(raw)!=args.authorization_sha or any(re.fullmatch(r"[0-9a-f]{64}",value.get(key,"") or "") is None for key in identities) or value.get("format")!="home-lab-debian-qualification-transition-plan-v1" or value.get("operation")!=operation or value.get("plan_sha256")!=args.plan_sha or value.get("prior_receipt_sha256")!=prior_sha or value.get("snippet_receipt_sha256")!=target["snippet_receipt_sha256"] or value.get("snippet_sha256")!=snippet_sha or (operation=="restart" and value.get("host_key_receipt_sha256")!=host_key_sha) or value.get("resources")!=expected_resources or value.get("target_id")!=target["target_id"] or value.get("endpoint")!=target["endpoint"] or value.get("node_name")!=target["node_name"] or value.get("api_ca_sha256")!=target["api_ca_sha256"] or value.get("plan_principal")!=target["plan_principal"] or value.get("apply_principal")!=target["apply_principal"] or value.get("version")!=1 or value.get("vmid")!=9900 or value.get("actionable") is not True or value.get("authorized") is not False or value.get("automatic_apply") is not False or created>common.now()+dt.timedelta(seconds=5) or created<common.now()-ttl or expires<=common.now() or expires-created>ttl: fail("manifest-binding")
 return value
def apply(args,operation):
 if re.fullmatch(r"[0-9a-f]{64}",args.plan_sha or "") is None or re.fullmatch(r"[0-9a-f]{64}",args.authorization_sha or "") is None or args.approve_plan_sha!=args.plan_sha or args.approve_authorization_sha!=args.authorization_sha or args.confirm!=CONFIRM[operation]: fail("exact-authorization-required")
 output=require_private_root(args.output_dir,()); target=target_with_snippet(args,operation); prior_receipt,prior_sha=prior(args,operation,target); host_key_sha=host_key(args,operation,target,prior_sha,prior_receipt["state_sha256"]); value=manifest(args,operation,target,prior_sha,target["snippet_sha256"],host_key_sha); common.revision(value["commit"]); binary=output/f"{args.plan_sha}.tfplan"; shown=output/f"{args.plan_sha}.plan.json"
 if sha(load_protected_bytes(binary,"transition saved plan"))!=args.plan_sha or sha(load_protected_bytes(shown,"transition plan JSON"))!=value["plan_json_sha256"]: fail("saved-plan-binding")
 inspect(json.loads(load_protected_bytes(shown,"transition plan JSON")),operation,target); credentials=common.credential("apply",target); controller,run,env,state,host=common.locked_setup(output,credentials,target,args)
 try:
  if common.state_sha(state)!=value["state_sha256"]: fail("state-drift")
  fresh=target_with_snippet(args,operation)
  if fresh.get("snippet_receipt_sha256")!=target.get("snippet_receipt_sha256") or fresh.get("snippet_receipt_sha256")!=value.get("snippet_receipt_sha256") or fresh.get("snippet_sha256")!=target.get("snippet_sha256") or fresh.get("snippet_sha256")!=value.get("snippet_sha256"): fail("snippet-drift")
  common.run_locked(["tofu",f"-chdir={common.TF_ROOT}","apply","-input=false","-lock=true","-auto-approve",str(binary)],env,host,f"tofu-{operation}-apply-no-retry")
  post=common.run_json(["tofu",f"-chdir={common.TF_ROOT}","show","-json"],env); resources=((post.get("values") or {}).get("root_module") or {}).get("resources",[]); vm=next((item.get("values",{}) for item in resources if item.get("address")=="proxmox_virtual_environment_vm.qualification[0]"),None)
  expected_addresses={"proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_vm.qualification[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]"}
  expected_started=operation not in ("stop","destroy")
  if operation!="destroy" and ({item.get("address") for item in resources}!=expected_addresses or vm is None or vm.get("vm_id")!=9900 or vm.get("started") is not expected_started or vm.get("on_boot") is not False): fail(f"{operation}-postcondition")
  if operation=="destroy" and resources: fail("destroy-postcondition")
  receipt={"admission_sha256":target["isolation_attestation_sha256"],"commit":value["commit"],"format":f"home-lab-debian-qualification-{operation}-receipt-v1","operation":operation,"plan_sha256":args.plan_sha,"prior_receipt_sha256":prior_sha,"resources":sorted(expected_addresses),"snippet_receipt_sha256":target["snippet_receipt_sha256"],"snippet_sha256":target["snippet_sha256"],"state_sha256":common.state_sha(state),"target_id":target["target_id"],"version":1,"vm_started":expected_started,"vmid":9900}; receipt.update({"host_key_receipt_sha256":host_key_sha} if operation=="restart" else {}); write_json(output,f"{args.plan_sha}.receipt.json",receipt); print(json.dumps({"receipt":str(output/f'{args.plan_sha}.receipt.json'),"vm_started":receipt["vm_started"]},sort_keys=True))
 finally: common.release_target(host); os.close(controller); shutil.rmtree(run,ignore_errors=True)
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
 for command in ("plan-start","apply-start","plan-repair-network","apply-repair-network","plan-stop","apply-stop","plan-restart","apply-restart","plan-destroy","apply-destroy"):
  item=sub.add_parser(command)
  for option in ("admission","known-hosts","guest-public-key","snippet-receipt","prior-receipt","output-dir"): item.add_argument("--"+option,type=Path,required=True)
  if command in ("plan-restart","apply-restart"):
   item.add_argument("--host-key-receipt",type=Path,required=True); item.add_argument("--prior-admission",type=Path,required=True)
  if command.startswith("apply-"):
   item.add_argument("--manifest",type=Path,required=True); item.add_argument("--plan-sha",required=True); item.add_argument("--approve-plan-sha",required=True); item.add_argument("--authorization-sha",required=True); item.add_argument("--approve-authorization-sha",required=True); item.add_argument("--confirm",required=True)
 args=parser.parse_args()
 for key,value in vars(args).items():
  if isinstance(value,Path): setattr(args,key,value.resolve())
 operation=args.command.split("-",1)[1]
 apply(args,operation) if args.command.startswith("apply-") else plan(args,operation)
if __name__=="__main__": main()
