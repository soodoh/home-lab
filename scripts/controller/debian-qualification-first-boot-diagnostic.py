#!/usr/bin/env python3
"""Plan/apply fixed read-only VM9900 failed-first-boot disk diagnosis."""
import argparse,datetime as dt,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_canonical_object,load_protected_bytes,require_private_root,verify_exact_checkout,write_json
ROOT=Path(__file__).resolve().parents[2]; SNIPPET_SOURCE=ROOT/"scripts/controller/debian-qualification-snippet.py"; VALIDATOR=ROOT/"scripts/controller/validate-disposable-pve-target.js"; HELPER=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"; TRANSPORT=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transport"; SUDOERS=ROOT/"infrastructure/qualification/host/qualification-apply.sudoers"; spec=importlib.util.spec_from_file_location("qualification_snippet",SNIPPET_SOURCE); snippet=importlib.util.module_from_spec(spec); spec.loader.exec_module(snippet); CONFIRM="DIAGNOSE_VM9900_FAILED_FIRST_BOOT_READ_ONLY"
def fail(reason): raise SystemExit(f"debian_qualification_first_boot_diagnostic=failed reason={reason}")
def sha(raw): return hashlib.sha256(raw).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc)
def target(args):
 result=subprocess.run(["node",str(VALIDATOR),"--evidence",str(args.admission),"--known-hosts",str(args.known_hosts),"--allow-expired-offline-diagnostic"],text=True,capture_output=True)
 if result.returncode or result.stderr: fail("target")
 value=json.loads(result.stdout)
 if value.get("admitted") is not True or value.get("admission_mode")!="expired-offline-diagnostic" or value.get("target_id")!="production-pve-vm9900-qualification": fail("target")
 return value
def stopped(path,target,state):
 value,raw=load_canonical_object(path,"diagnostic stopped receipt"); required={"admission_sha256","commit","format","operation","plan_sha256","prior_receipt_sha256","resources","snippet_receipt_sha256","snippet_sha256","state_sha256","target_id","version","vm_started","vmid"}; resources=["proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"]
 if set(value)!=required or value.get("format")!="home-lab-debian-qualification-stop-receipt-v1" or value.get("operation")!="stop" or value.get("admission_sha256")!=target["isolation_attestation_sha256"] or value.get("target_id")!=target["target_id"] or value.get("resources")!=resources or value.get("vmid")!=9900 or value.get("vm_started") is not False or value.get("state_sha256")!=sha(load_protected_bytes(state,"qualification state")): fail("stopped-receipt")
 for key in ("admission_sha256","plan_sha256","prior_receipt_sha256","snippet_receipt_sha256","snippet_sha256","state_sha256"):
  if re.fullmatch(r"[0-9a-f]{64}",value.get(key,"") or "") is None: fail("stopped-receipt")
 return value,sha(raw)
def revision(expected=None):
 commit=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip(); verify_exact_checkout("git",expected or commit,os.environ.copy()); return commit
def parse_time(value):
 try: parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
 except Exception: fail("plan-time")
 if parsed.tzinfo is None: fail("plan-time")
 return parsed
def capability(path):
 raw=load_protected_bytes(path,"qualification capability receipt")
 for marker in (b"Verify installed qualification capability identities",b"failed=0",b"unreachable=0"):
  if marker not in raw: fail("capability-receipt")
 return sha(raw)
def validate_observed(observed,expected):
 outer={key:item for key,item in expected.items() if key not in ("helper_sha256","sudoers_sha256","transport_sha256")}
 if set(observed)!=set(outer)|{"diagnostic","producer"} or any(observed.get(key)!=item for key,item in outer.items()): fail("receipt-binding")
 producer=observed.get("producer"); expected_producer={"helper_sha256":expected["helper_sha256"],"sudoers_sha256":expected["sudoers_sha256"],"transport_sha256":expected["transport_sha256"]}
 if producer!=expected_producer: fail("producer-binding")
 value=observed.get("diagnostic"); paths={"/var/log/cloud-init.log","/var/log/cloud-init-output.log","/var/log/apt/history.log","/var/log/apt/term.log","/var/lib/cloud/data/result.json","/var/lib/dpkg/status"}; signals={"apt_failure","dns_failure","network_failure","qga_mentioned"}
 if not isinstance(value,dict) or set(value)!={"cloud_result_errors","cloud_result_present","errors","files","qemu_guest_agent_package","signals"} or set(value.get("files",{}))!=paths or set(value.get("signals",{}))!=signals or any(not isinstance(item,bool) for item in value["signals"].values()) or not isinstance(value["cloud_result_present"],bool): fail("diagnostic-schema")
 for item in value["files"].values():
  if set(item)!={"exists","sha256","size"} or not isinstance(item["exists"],bool) or (item["exists"] and (re.fullmatch(r"[0-9a-f]{64}",item["sha256"] or "") is None or not isinstance(item["size"],int) or item["size"]<0 or item["size"]>4*1024*1024)) or (not item["exists"] and (item["sha256"] is not None or item["size"] is not None)): fail("diagnostic-files")
 package=value["qemu_guest_agent_package"]
 if not isinstance(package,dict) or (package=={"present":False}) is False and (set(package)!={"present","status","version"} or package.get("present") is not True or not all(isinstance(package.get(key),str) for key in ("status","version"))): fail("diagnostic-package")
 if not isinstance(value["errors"],list) or not isinstance(value["cloud_result_errors"],list) or len(value["errors"])>40 or len(value["cloud_result_errors"])>40: fail("diagnostic-redaction")
 rows=value["errors"]+value["cloud_result_errors"]
 if any(not isinstance(row,str) or len(row)>512 or re.search(r"://[^/@\s]+@|(?i:bearer)\s+(?!<redacted>)\S+|(?i:(?:password|token|secret|authorization))\s*[:=]\s*(?!<redacted>)\S+",row) for row in rows): fail("diagnostic-redaction")
def remote_diagnostic(args,target,command,raw,plan_sha,output):
 try: result=subprocess.run(snippet.ssh_args(target,args.known_hosts,command),input=raw,capture_output=True,timeout=120)
 except subprocess.TimeoutExpired as error:
  detail=(error.stderr or b"").decode("utf-8","replace") if isinstance(error.stderr,bytes) else (error.stderr or "")
  result=None; returncode=124
 else:
  detail=result.stderr.decode("utf-8","replace"); returncode=result.returncode
 if result is None or returncode or detail:
  detail=re.sub(r"://[^/@\s]+@","://<redacted>@",detail); detail=re.sub(r"(?i)bearer\s+\S+","Bearer <redacted>",detail); detail=re.sub(r"(?i)(password|token|secret|authorization)(\s*[:=]\s*)\S+",r"\1\2<redacted>",detail)
  write_json(output,f"{plan_sha}.diagnostic-failure.json",{"automatic_retry":False,"detail":" ".join(detail.split())[:512],"format":"home-lab-debian-qualification-first-boot-diagnostic-failure-v1","plan_sha256":plan_sha,"returncode":returncode,"version":1})
  fail("remote-diagnostic")
 try: observed=json.loads(result.stdout)
 except json.JSONDecodeError:
  write_json(output,f"{plan_sha}.diagnostic-failure.json",{"automatic_retry":False,"detail":"non-canonical-response","format":"home-lab-debian-qualification-first-boot-diagnostic-failure-v1","plan_sha256":plan_sha,"returncode":0,"version":1}); fail("remote-diagnostic")
 if result.stdout!=canonical_bytes(observed)+b"\n": fail("remote-diagnostic-canonical")
 return observed
def plan(args):
 output=require_private_root(args.output_dir,()); lock=acquire_transfer_lock(output/"lifecycle.lock")
 try:
  admitted=target(args); state=output/"state.tfstate"; receipt,receipt_sha=stopped(args.stopped_receipt,admitted,state); capability_sha=capability(args.capability_log); helper_sha=sha(HELPER.read_bytes().removesuffix(b"\n")); transport_sha=sha(TRANSPORT.read_bytes().removesuffix(b"\n")); sudoers_sha=sha(SUDOERS.read_bytes().removesuffix(b"\n")); created=now(); value={"admission_sha256":admitted["isolation_attestation_sha256"],"authorized":False,"automatic_apply":False,"capability_receipt_sha256":capability_sha,"commit":revision(),"created_at":created.isoformat().replace("+00:00","Z"),"disk_volume":"local-lvm:vm-9900-disk-0","expires_at":(created+dt.timedelta(hours=4)).isoformat().replace("+00:00","Z"),"format":"home-lab-debian-qualification-first-boot-diagnostic-plan-v1","helper_sha256":helper_sha,"node_name":admitted["node_name"],"operation":"inspect-failed-first-boot-read-only","state_sha256":receipt["state_sha256"],"stopped_receipt_sha256":receipt_sha,"sudoers_sha256":sudoers_sha,"target_id":admitted["target_id"],"transport_sha256":transport_sha,"version":1,"vmid":9900}; raw=canonical_bytes(value)+b"\n"; digest=sha(raw); write_json(output,f"{digest}.diagnostic-plan.json",value); print(json.dumps({"actionable":True,"authorized":False,"plan":str(output/f'{digest}.diagnostic-plan.json'),"plan_sha256":digest},sort_keys=True))
 finally: os.close(lock)
def apply(args):
 if args.approve_plan_sha!=args.plan_sha or args.confirm!=CONFIRM: fail("exact-authorization-required")
 output=require_private_root(args.output_dir,()); value,raw=load_canonical_object(args.plan,"diagnostic plan")
 if sha(raw)!=args.plan_sha: fail("plan-sha")
 admitted=target(args); state=output/"state.tfstate"; receipt,receipt_sha=stopped(args.stopped_receipt,admitted,state); capability_sha=capability(args.capability_log); helper_sha=sha(HELPER.read_bytes().removesuffix(b"\n")); transport_sha=sha(TRANSPORT.read_bytes().removesuffix(b"\n")); sudoers_sha=sha(SUDOERS.read_bytes().removesuffix(b"\n")); revision(value.get("commit")); required={"admission_sha256","authorized","automatic_apply","capability_receipt_sha256","commit","created_at","disk_volume","expires_at","format","helper_sha256","node_name","operation","state_sha256","stopped_receipt_sha256","sudoers_sha256","target_id","transport_sha256","version","vmid"}; created=parse_time(value.get("created_at","")); expires=parse_time(value.get("expires_at",""))
 if set(value)!=required or value.get("format")!="home-lab-debian-qualification-first-boot-diagnostic-plan-v1" or value.get("operation")!="inspect-failed-first-boot-read-only" or value.get("capability_receipt_sha256")!=capability_sha or value.get("helper_sha256")!=helper_sha or value.get("sudoers_sha256")!=sudoers_sha or value.get("transport_sha256")!=transport_sha or value.get("admission_sha256")!=admitted["isolation_attestation_sha256"] or value.get("state_sha256")!=receipt["state_sha256"] or value.get("stopped_receipt_sha256")!=receipt_sha or value.get("disk_volume")!="local-lvm:vm-9900-disk-0" or value.get("node_name")!=admitted["node_name"] or value.get("target_id")!=admitted["target_id"] or value.get("vmid")!=9900 or value.get("version")!=1 or value.get("authorized") is not False or value.get("automatic_apply") is not False or created>now()+dt.timedelta(seconds=5) or created<now()-dt.timedelta(hours=4) or expires<=now() or expires-created>dt.timedelta(hours=4): fail("plan-binding")
 lock=acquire_transfer_lock(output/"lifecycle.lock")
 try:
  if sha(load_protected_bytes(state,"qualification state"))!=value["state_sha256"]: fail("state-drift")
  attempt_path=output/f"{args.plan_sha}.diagnostic-attempt.json"; receipt_path=output/f"{args.plan_sha}.diagnostic-receipt.json"
  if attempt_path.exists() or receipt_path.exists(): fail("diagnostic-plan-already-attempted")
  write_json(output,attempt_path.name,{"automatic_retry":False,"capability_receipt_sha256":capability_sha,"format":"home-lab-debian-qualification-first-boot-diagnostic-attempt-v1","helper_sha256":helper_sha,"plan_sha256":args.plan_sha,"started_at":now().isoformat().replace("+00:00","Z"),"sudoers_sha256":sudoers_sha,"transport_sha256":transport_sha,"version":1})
  observed=remote_diagnostic(args,admitted,f"diagnostic {args.plan_sha} {args.plan_sha}",raw,args.plan_sha,output)
 finally: os.close(lock)
 expected={"disk_volume":value["disk_volume"],"format":"home-lab-debian-qualification-first-boot-diagnostic-receipt-v1","helper_sha256":helper_sha,"plan_sha256":args.plan_sha,"state_sha256":value["state_sha256"],"stopped_receipt_sha256":receipt_sha,"sudoers_sha256":sudoers_sha,"target_id":value["target_id"],"transport_sha256":transport_sha,"version":1,"vmid":9900}
 validate_observed(observed,expected)
 write_json(output,f"{args.plan_sha}.diagnostic-receipt.json",observed); print(json.dumps({"receipt":str(output/f'{args.plan_sha}.diagnostic-receipt.json'),"status":"observed"},sort_keys=True))
def main():
 parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
 for name in ("plan","apply"):
  item=sub.add_parser(name); item.add_argument("--admission",type=Path,required=True); item.add_argument("--known-hosts",type=Path,required=True); item.add_argument("--stopped-receipt",type=Path,required=True); item.add_argument("--capability-log",type=Path,required=True); item.add_argument("--output-dir",type=Path,required=True)
  if name=="apply": item.add_argument("--plan",type=Path,required=True); item.add_argument("--plan-sha",required=True); item.add_argument("--approve-plan-sha",required=True); item.add_argument("--confirm",required=True)
 args=parser.parse_args()
 for key,value in vars(args).items():
  if isinstance(value,Path): setattr(args,key,value.resolve())
 apply(args) if args.command=="apply" else plan(args)
if __name__=="__main__": main()
