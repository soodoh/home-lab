#!/usr/bin/env python3
"""Plan/apply a one-shot stop after an authorized restart changed state but failed before receipt publication."""
import argparse,datetime as dt,hashlib,importlib.util,json,os,re,shutil,subprocess,tempfile
from pathlib import Path
from protected_execution import canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,write_json
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"scripts/controller/debian-lifecycle-qualification-transitions.py"; spec=importlib.util.spec_from_file_location("qualification_transitions",SOURCE); transitions=importlib.util.module_from_spec(spec); spec.loader.exec_module(transitions); common=transitions.common
CONFIRM="STOP_VM9900_AFTER_INTERRUPTED_AUTHORIZED_RESTART"
def fail(reason): raise SystemExit(f"debian_qualification_interrupted_restart_stop=failed reason={reason}")
def sha(raw): return hashlib.sha256(raw).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc)
def contract_authorized():
 script='const fs=require("fs"),yaml=require("js-yaml"),c=yaml.load(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(JSON.stringify(c.lifecycle.qualification_route.interrupted_restart_safe_stop))'; result=subprocess.run(["node","-e",script,str(ROOT/"infrastructure/contract/home-lab.yml")],text=True,capture_output=True)
 expected={"stop_only":True,"vmid":9900,"requires_failed_receipt_absent":True,"requires_exact_failed_artifact_hashes":True,"requires_separate_saved_plan_approval":True}
 if result.returncode or result.stderr or json.loads(result.stdout)!=expected: fail("contract-authority")
def failed_restart(args,target,prior_sha,state_sha):
 host_sha,_=transitions.host_key(args,"restart",target,prior_sha,state_sha); value,raw=load_canonical_object(args.failed_manifest,"failed restart manifest"); digest=sha(raw)
 if args.failed_authorization_sha!=digest: fail("failed-manifest-digest")
 required={"actionable","admission_sha256","api_ca_sha256","apply_principal","authorized","automatic_apply","commit","created_at","endpoint","expires_at","format","host_key_receipt_sha256","node_name","operation","plan_json_sha256","plan_principal","plan_sha256","prior_receipt_sha256","resources","snippet_receipt_sha256","snippet_sha256","state_sha256","target_id","version","vmid"}
 if set(value)!=required or value.get("format")!="home-lab-debian-qualification-transition-plan-v1" or value.get("operation")!="restart" or value.get("plan_sha256")!=args.failed_plan_sha or value.get("prior_receipt_sha256")!=prior_sha or value.get("state_sha256")!=state_sha or value.get("host_key_receipt_sha256")!=host_sha or value.get("target_id")!=target["target_id"] or value.get("vmid")!=9900 or value.get("resources")!=["proxmox_virtual_environment_vm.qualification[0]"] or value.get("authorized") is not False or value.get("automatic_apply") is not False: fail("failed-manifest-binding")
 for key in ("admission_sha256","api_ca_sha256","host_key_receipt_sha256","plan_json_sha256","plan_sha256","prior_receipt_sha256","snippet_receipt_sha256","snippet_sha256","state_sha256"):
  if re.fullmatch(r"[0-9a-f]{64}",value.get(key,"") or "") is None: fail("failed-manifest-binding")
 binary=load_protected_bytes(args.output_dir/f"{args.failed_plan_sha}.tfplan","failed restart saved plan"); shown=load_protected_bytes(args.output_dir/f"{args.failed_plan_sha}.plan.json","failed restart plan JSON")
 if sha(binary)!=args.failed_plan_sha or sha(shown)!=value["plan_json_sha256"] or (args.output_dir/f"{args.failed_plan_sha}.receipt.json").exists(): fail("failed-restart-artifacts")
 return value,digest,host_sha
def live_started(env,state,target):
 shown=common.run_json(["tofu",f"-chdir={common.TF_ROOT}","show","-json"],env); resources=((shown.get("values") or {}).get("root_module") or {}).get("resources",[]); expected={"proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"}; vm=next((item.get("values",{}) for item in resources if item.get("address")=="proxmox_virtual_environment_vm.qualification[0]"),None)
 if {item.get("address") for item in resources}!=expected or vm is None or vm.get("vm_id")!=9900 or vm.get("node_name")!=target["node_name"] or vm.get("started") is not True or vm.get("on_boot") is not False: fail("interrupted-state")
 return sorted(expected)
def base(args):
 contract_authorized(); output=require_private_root(args.output_dir,()); target=transitions.target_with_snippet(args,"restart"); prior,prior_sha=transitions.prior(args,"restart",target); failed,failed_auth,host_sha=failed_restart(args,target,prior_sha,prior["state_sha256"]); return output,target,prior,prior_sha,failed,failed_auth,host_sha
def plan(args):
 output,target,prior,prior_sha,failed,failed_auth,host_sha=base(args); credentials=common.credential("plan",target); controller,run,env,state,host=common.locked_setup(output,credentials,target,args); current_sha=common.state_sha(state)
 try:
  if current_sha==prior["state_sha256"]: fail("restart-did-not-change-state")
  live_started(env,state,target); key=common.guest_key(args.guest_public_key,target); binary=run/"recovery-stop.tfplan"; shown=run/"recovery-stop.json"; common.run_locked(["tofu",f"-chdir={common.TF_ROOT}","plan","-input=false","-lock=true",*common.variables(target,key),"-var=start_qualification=false","-out",str(binary)],env,host,"tofu-recovery-stop-plan")
  with shown.open("wb") as stream: result=subprocess.run(["tofu",f"-chdir={common.TF_ROOT}","show","-json",str(binary)],env=env,stdout=stream,stderr=subprocess.PIPE)
  if result.returncode: fail("tofu-show")
  resources=transitions.inspect(json.loads(shown.read_text()),"stop",target); created=now(); manifest={"actionable":True,"admission_sha256":target["isolation_attestation_sha256"],"authorized":False,"automatic_apply":False,"commit":common.revision(),"created_at":created.isoformat().replace("+00:00","Z"),"expires_at":(created+dt.timedelta(minutes=30)).isoformat().replace("+00:00","Z"),"failed_authorization_sha256":failed_auth,"failed_plan_sha256":args.failed_plan_sha,"format":"home-lab-debian-qualification-interrupted-restart-stop-plan-v1","host_key_receipt_sha256":host_sha,"plan_json_sha256":"","plan_sha256":"","prior_receipt_sha256":prior_sha,"resources":resources,"snippet_receipt_sha256":target["snippet_receipt_sha256"],"snippet_sha256":target["snippet_sha256"],"state_sha256":current_sha,"target_id":target["target_id"],"version":1,"vmid":9900}; transitions.publish(output,run,binary,shown,manifest)
 finally: common.release_target(host); os.close(controller); shutil.rmtree(run,ignore_errors=True)
def publish_attempt(output,args,manifest):
 attempts=output/"interrupted-restart-stop-attempts"
 if not attempts.exists(): attempts.mkdir(mode=0o700)
 attempts=require_private_root(attempts,()); path=attempts/f"{args.plan_sha}.json"
 if path.exists(): fail("recovery plan already attempted; automatic retry forbidden")
 write_json(attempts,path.name,{"authorization_sha256":args.authorization_sha,"failed_authorization_sha256":manifest["failed_authorization_sha256"],"failed_plan_sha256":args.failed_plan_sha,"format":"home-lab-debian-qualification-interrupted-restart-stop-attempt-v1","plan_sha256":args.plan_sha,"state_sha256":manifest["state_sha256"],"version":1})
def apply(args):
 if args.approve_plan_sha!=args.plan_sha or args.authorization_sha!=args.approve_authorization_sha or args.confirm!=CONFIRM: fail("exact-authorization-required")
 output,target,prior,prior_sha,failed,failed_auth,host_sha=base(args); manifest,raw=load_canonical_object(args.manifest,"recovery stop manifest"); required={"actionable","admission_sha256","authorized","automatic_apply","commit","created_at","expires_at","failed_authorization_sha256","failed_plan_sha256","format","host_key_receipt_sha256","plan_json_sha256","plan_sha256","prior_receipt_sha256","resources","snippet_receipt_sha256","snippet_sha256","state_sha256","target_id","version","vmid"}
 created=transitions.parse_time(manifest.get("created_at","")); expires=transitions.parse_time(manifest.get("expires_at",""))
 if set(manifest)!=required or sha(raw)!=args.authorization_sha or manifest.get("format")!="home-lab-debian-qualification-interrupted-restart-stop-plan-v1" or manifest.get("plan_sha256")!=args.plan_sha or manifest.get("failed_plan_sha256")!=args.failed_plan_sha or manifest.get("failed_authorization_sha256")!=failed_auth or manifest.get("host_key_receipt_sha256")!=host_sha or manifest.get("prior_receipt_sha256")!=prior_sha or manifest.get("target_id")!=target["target_id"] or manifest.get("admission_sha256")!=target["isolation_attestation_sha256"] or manifest.get("authorized") is not False or manifest.get("automatic_apply") is not False or expires<=now() or expires-created>dt.timedelta(minutes=30): fail("recovery-manifest-binding")
 common.revision(manifest.get("commit"))
 binary=output/f"{args.plan_sha}.tfplan"; shown=output/f"{args.plan_sha}.plan.json"
 if sha(load_protected_bytes(binary,"recovery saved plan"))!=args.plan_sha or sha(load_protected_bytes(shown,"recovery plan JSON"))!=manifest["plan_json_sha256"]: fail("saved-plan-binding")
 transitions.inspect(json.loads(load_protected_bytes(shown,"recovery plan JSON")),"stop",target); credentials=common.credential("apply",target); controller,run,env,state,host=common.locked_setup(output,credentials,target,args)
 try:
  if common.state_sha(state)!=manifest["state_sha256"]: fail("state-drift")
  live_started(env,state,target); publish_attempt(output,args,manifest); common.run_locked(["tofu",f"-chdir={common.TF_ROOT}","apply","-input=false","-lock=true","-auto-approve",str(binary)],env,host,"tofu-recovery-stop-apply-no-retry"); post=common.run_json(["tofu",f"-chdir={common.TF_ROOT}","show","-json"],env); resources=((post.get("values") or {}).get("root_module") or {}).get("resources",[]); vm=next((item.get("values",{}) for item in resources if item.get("address")=="proxmox_virtual_environment_vm.qualification[0]"),None)
  expected=["proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"]
  if sorted(item.get("address") for item in resources)!=expected or vm is None or vm.get("started") is not False: fail("stop-postcondition")
  receipt={"admission_sha256":target["isolation_attestation_sha256"],"commit":manifest["commit"],"failed_authorization_sha256":failed_auth,"failed_plan_sha256":args.failed_plan_sha,"format":"home-lab-debian-qualification-interrupted-restart-stop-receipt-v1","operation":"stop","plan_sha256":args.plan_sha,"prior_receipt_sha256":prior_sha,"resources":expected,"snippet_receipt_sha256":target["snippet_receipt_sha256"],"snippet_sha256":target["snippet_sha256"],"state_sha256":common.state_sha(state),"target_id":target["target_id"],"version":1,"vm_started":False,"vmid":9900}; write_json(output,f"{args.plan_sha}.receipt.json",receipt); print(json.dumps({"receipt":str(output/f'{args.plan_sha}.receipt.json'),"vm_started":False},sort_keys=True))
 finally: common.release_target(host); os.close(controller); shutil.rmtree(run,ignore_errors=True)
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
 for name in ("plan","apply"):
  item=sub.add_parser(name); item.add_argument("--admission",type=Path,required=True); item.add_argument("--prior-admission",type=Path,required=True); item.add_argument("--known-hosts",type=Path,required=True); item.add_argument("--guest-public-key",type=Path,required=True); item.add_argument("--snippet-receipt",type=Path,required=True); item.add_argument("--prior-receipt",type=Path,required=True); item.add_argument("--host-key-receipt",type=Path,required=True); item.add_argument("--failed-manifest",type=Path,required=True); item.add_argument("--failed-plan-sha",required=True); item.add_argument("--failed-authorization-sha",required=True); item.add_argument("--output-dir",type=Path,required=True)
  if name=="apply": item.add_argument("--manifest",type=Path,required=True); item.add_argument("--plan-sha",required=True); item.add_argument("--approve-plan-sha",required=True); item.add_argument("--authorization-sha",required=True); item.add_argument("--approve-authorization-sha",required=True); item.add_argument("--confirm",required=True)
 args=parser.parse_args(); [setattr(args,key,value.resolve()) for key,value in vars(args).items() if isinstance(value,Path)]; apply(args) if args.command=="apply" else plan(args)
if __name__=="__main__": main()
