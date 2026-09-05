#!/usr/bin/env python3
"""Capture fixed, chain-bound QGA clean first-boot proof for VM9900."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import re
import os
import secrets
import math
import subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_protected_bytes,require_private_root,write_json
ROOT=Path(__file__).resolve().parents[2]
SNIPPET_CONTROLLER=ROOT/"scripts/controller/debian-qualification-snippet.py"
HELPER=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"
SUDOERS=ROOT/"infrastructure/qualification/host/qualification-apply.sudoers"
TRANSPORT=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transport"
TEMPLATE=ROOT/"infrastructure/debian/cloud-init/qualification-user-data.tftpl"
RESOURCES=["proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"]
spec=importlib.util.spec_from_file_location("qualification_snippet",SNIPPET_CONTROLLER)
snippet=importlib.util.module_from_spec(spec)
spec.loader.exec_module(snippet)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def commit():
 head=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
 origin=subprocess.run(["git","rev-parse","origin/main"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
 dirty=subprocess.run(["git","status","--porcelain=v1","--untracked-files=all"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
 if head!=origin or dirty: raise SystemExit("clean pushed commit required")
 return head
def receipt(path,label):
 raw=load_protected_bytes(path,label)
 try: value=json.loads(raw)
 except (ValueError,UnicodeError): raise SystemExit(f"invalid {label}")
 if not isinstance(value,dict): raise SystemExit(f"invalid {label}")
 if raw!=canonical_bytes(value)+b"\n": raise SystemExit(f"{label} is not canonical")
 if path.name!=f'{value.get("plan_sha256")}.receipt.json': raise SystemExit(f"{label} filename binding failed")
 return value,raw
def historical_target(admission,known_hosts):
 raw=load_protected_bytes(admission,"historical admission"); value=json.loads(raw)
 if raw!=canonical_bytes(value)+b"\n": raise SystemExit("historical admission is not canonical")
 expected_denies=["10.0.0.0/8","100.64.0.0/10","172.16.0.0/12","192.168.0.0/16"]
 if value.get("format")!="home-lab-disposable-pve-target-admission-v1" or value.get("route")!="production-pve-disposable-vm" or value.get("target_id")!="production-pve-vm9900-qualification" or value.get("node_name")!="proxmox" or value.get("endpoint")!="https://proxmox:8006/api2/json" or value.get("network",{}).get("production_cidrs_denied")!=expected_denies or value.get("network",{}).get("controller_ipv4")!="192.168.0.12" or value.get("credentials",{}).get("ssh_authentication")!="tailscale-policy" or value.get("credentials",{}).get("ssh_principal")!="qualification-apply" or value.get("storage",{}).get("snippet_content_enabled") is not True: raise SystemExit("historical admission binding failed")
 known=load_protected_bytes(known_hosts,"dedicated known-hosts")
 if sha(known)!=value.get("host_key",{}).get("known_hosts_sha256") or value.get("host_key",{}).get("ssh_address")!="proxmox" or value.get("host_key",{}).get("out_of_band_verified") is not True: raise SystemExit("historical host trust binding failed")
 return {"isolation_attestation_sha256":sha(raw),"ssh_address":"proxmox","ssh_username":"qualification-apply","target_id":"production-pve-vm9900-qualification"}
def remote_first_boot(target,known_hosts,output,start_raw,request):
 try: result=subprocess.run(snippet.ssh_args(target,known_hosts,"first-boot"),input=canonical_bytes(request)+b"\n",capture_output=True,timeout=120)
 except subprocess.TimeoutExpired as error:
  detail=(error.stderr or b"").decode("utf-8","replace") if isinstance(error.stderr,bytes) else (error.stderr or ""); result=None; returncode=124
 else: detail=result.stderr.decode("utf-8","replace"); returncode=result.returncode
 if result is None or returncode or detail:
  detail=re.sub(r"://[^/@\s]+@","://<redacted>@",detail); detail=re.sub(r"(?i)bearer\s+\S+","Bearer <redacted>",detail); detail=re.sub(r"(?i)(password|token|secret|authorization)(\s*[:=]\s*)\S+",r"\1\2<redacted>",detail)
  write_json(output,f"{sha(start_raw)}.first-boot-failure.json",{"detail":" ".join(detail.split())[:512],"format":"home-lab-debian-qualification-clean-first-boot-failure-v1","returncode":returncode,"start_receipt_sha256":sha(start_raw),"version":1}); raise SystemExit("isolated PVE snippet transport failed")
 try: value=json.loads(result.stdout)
 except json.JSONDecodeError: raise SystemExit("first-boot transport returned invalid JSON")
 if result.stdout!=canonical_bytes(value)+b"\n": raise SystemExit("first-boot transport returned non-canonical JSON")
 return value
def expected_producer():
 # Match Ansible file lookup's default rstrip, not the repository source bytes.
 return {key:sha(path.read_bytes().rstrip()) for key,path in (("helper_sha256",HELPER),("transport_sha256",TRANSPORT),("sudoers_sha256",SUDOERS))}
def snippet_evidence(path,public_key,admission_path,known_hosts,foundation,start):
 raw=load_protected_bytes(path,"snippet receipt")
 try: value=json.loads(raw)
 except (ValueError,UnicodeError): raise SystemExit("invalid snippet receipt")
 admission=json.loads(load_protected_bytes(admission_path,"historical admission"))
 public=snippet.guest_key(public_key,admission["credentials"])
 content=snippet.render(public)
 base={"admission_sha256":foundation["admission_sha256"],"file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml","guest_ssh_public_key_sha256":sha(public.encode()),"known_hosts_sha256":sha(load_protected_bytes(known_hosts,"known-hosts")),"mode":"0600","node_name":"proxmox","sha256":sha(content),"size":len(content),"target_id":foundation["target_id"],"version":1}
 observation=isinstance(value,dict) and value.get("format")=="home-lab-debian-qualification-snippet-observation-receipt-v1"
 required=set(base)|{"commit","format"}|({"observation_sha256"} if observation else {"changed","plan_sha256"})
 if not isinstance(value,dict) or raw!=canonical_bytes(value)+b"\n" or set(value)!=required or any(type(value.get(key)) is not type(item) or value.get(key)!=item for key,item in base.items()) or not isinstance(value.get("commit"),str) or not re.fullmatch(r"[0-9a-f]{40}",value["commit"]) or sha(raw)!=foundation["snippet_receipt_sha256"] or sha(raw)!=start["snippet_receipt_sha256"] or sha(content)!=start["snippet_sha256"]: raise SystemExit("snippet receipt/source binding failed")
 if observation:
  if not isinstance(value["observation_sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",value["observation_sha256"]) or path.name!=f"{sha(raw)}.observation-receipt.json": raise SystemExit("snippet observation receipt binding failed")
 elif value["format"]!="home-lab-debian-qualification-snippet-receipt-v1" or type(value["changed"]) is not bool or not isinstance(value["plan_sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",value["plan_sha256"]) or path.name!=f'{value["plan_sha256"]}.receipt.json': raise SystemExit("snippet apply receipt binding failed")
 return {"file_id":base["file_id"],"sha256":sha(content),"size":len(content)},raw

def observation_request(target,foundation_raw,start_raw,snippet_raw,expected_snippet):
 return {"format":"home-lab-debian-qualification-first-boot-request-v1","nonce":secrets.token_hex(32),"admission_sha256":target["isolation_attestation_sha256"],"foundation_receipt_sha256":sha(foundation_raw),"start_receipt_sha256":sha(start_raw),"snippet_receipt_sha256":sha(snippet_raw),"producer":expected_producer(),"snippet":expected_snippet,"vmid":9900}

def validated_envelope(value,request):
 required={"format","request","producer","snippet","booted_snippet_sha256","observation"}
 if not isinstance(value,dict) or set(value)!=required or value["format"]!="home-lab-debian-qualification-first-boot-envelope-v1" or canonical_bytes(value["request"])!=canonical_bytes(request) or canonical_bytes(value["producer"])!=canonical_bytes(request["producer"]) or canonical_bytes(value["snippet"])!=canonical_bytes(request["snippet"]) or value["booted_snippet_sha256"]!=request["snippet"]["sha256"]: raise SystemExit("first-boot producer/snippet envelope binding failed")
 validated_observation(value["observation"])
 return value["observation"]

def validated_observation(observation):
 try: return _validated_observation(observation)
 except (AttributeError,TypeError,ValueError,KeyError,OverflowError): raise SystemExit("malformed clean first-boot observation")
def _validated_observation(observation):
 if not isinstance(observation,dict): raise SystemExit("malformed clean first-boot observation")
 if not isinstance(observation.get("cloud_init_instance_id"),str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",observation["cloud_init_instance_id"]) or observation["cloud_init_instance_id"] in (".",".."): raise SystemExit("clean first-boot observation differs: invalid cloud-init instance identity")
 # JSON equality must not coerce boolean and numeric receipt fields.
 for key,expected in (("network_device",{"bridge":"vmbr0","firewall":True,"model":"virtio"}),("firewall_options",{"dhcp":1,"enable":1,"ipfilter":0,"macfilter":1,"policy_in":"DROP","policy_out":"DROP"}),("dhcp",{"address":observation.get("guest_ipv4"),"prefix_length":24,"provider":"192.168.0.1","source":"DHCPv4"})):
  if canonical_bytes(observation.get(key))!=canonical_bytes(expected): raise SystemExit("malformed first-boot network evidence")
 network=observation.get("network")
 if not isinstance(network,dict) or set(network)!={"blocked","https_status"} or type(network["https_status"]) is not int or canonical_bytes(network["blocked"])!=canonical_bytes({"10.255.255.1":True,"172.31.255.1":True,"192.168.0.1":True,"100.64.0.1":True}): raise SystemExit("malformed first-boot network probes")
 required={"boot_count","boot_id","cloud_init_errors","cloud_init_instance_id","cloud_init_status","dhcp","firewall_options","firewall_rules","first_boot_marker","format","guest_ipv4","guest_uptime_seconds","network","network_device","package","pve_uptime_seconds","qemu_guest_agent","startup_delta_seconds","vmid"}
 denied={rule.get("dest") for rule in observation.get("firewall_rules",[]) if rule.get("type")=="out" and rule.get("action")=="DROP" and rule.get("enable")==1} if isinstance(observation,dict) else set()
 probes={"10.255.255.1":True,"172.31.255.1":True,"192.168.0.1":True,"100.64.0.1":True}
 try: guest_address=ipaddress.ip_address(observation.get("guest_ipv4",""))
 except ValueError: guest_address=None
 guest_ipv4_valid=guest_address in ipaddress.ip_network("192.168.0.0/24") and str(guest_address) not in {"192.168.0.1","192.168.0.12","192.168.0.100","192.168.0.123"} if guest_address is not None else False
 uptime=(observation.get("pve_uptime_seconds"),observation.get("guest_uptime_seconds"),observation.get("startup_delta_seconds")) if isinstance(observation,dict) else (None,None,None); uptime_valid=isinstance(uptime[0],int) and not isinstance(uptime[0],bool) and all(isinstance(value,(int,float)) and not isinstance(value,bool) for value in uptime[1:]) and all(math.isfinite(value) for value in uptime) and uptime[0]>0 and uptime[1]>0 and -2<=uptime[2]<=120 and abs(round(uptime[0]-uptime[1],2)-uptime[2])<0.01
 if not isinstance(observation,dict) or not uptime_valid or set(observation)!=required or observation["format"]!="home-lab-debian-qualification-first-boot-observation-v1" or observation["vmid"]!=9900 or type(observation["vmid"]) is not int or type(observation["boot_count"]) is not int or observation["boot_count"]!=1 or observation.get("first_boot_marker")!={"boot_id":observation.get("boot_id"),"mode":"0600"} or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",observation["boot_id"]) is None or not observation["cloud_init_instance_id"] or observation["cloud_init_errors"]!=[] or observation["cloud_init_status"]!="done" or not guest_ipv4_valid or observation.get("dhcp")!={"address":str(guest_address),"prefix_length":24,"provider":"192.168.0.1","source":"DHCPv4"} or observation["qemu_guest_agent"]!="active" or re.fullmatch(r"install ok installed [^\s]+",observation["package"]) is None or observation["network_device"]!={"bridge":"vmbr0","firewall":True,"model":"virtio"} or observation["firewall_options"]!={"dhcp":1,"enable":1,"ipfilter":0,"macfilter":1,"policy_in":"DROP","policy_out":"DROP"} or len(observation["firewall_rules"])!=9 or denied!={"10.0.0.0/8","100.64.0.0/10","172.16.0.0/12","192.168.0.0/16"} or observation["network"].get("blocked")!=probes or observation["network"].get("https_status") not in (200,301,302): raise SystemExit("clean first-boot observation differs")
 return str(guest_address)
def main():
 parser=argparse.ArgumentParser()
 parser.add_argument("--admission",type=Path,required=True); parser.add_argument("--known-hosts",type=Path,required=True)
 parser.add_argument("--foundation-receipt",type=Path,required=True); parser.add_argument("--start-receipt",type=Path,required=True); parser.add_argument("--output-dir",type=Path,required=True)
 parser.add_argument("--snippet-receipt",type=Path,required=True); parser.add_argument("--guest-public-key",type=Path,required=True)
 args=parser.parse_args()
 for key,value in vars(args).items(): setattr(args,key,value.resolve())
 revision=commit(); output=require_private_root(args.output_dir,()); controller_lock=acquire_transfer_lock(output/"lifecycle.lock")
 try:
  capture(args,revision,output)
 finally: os.close(controller_lock)
def capture(args,revision,output):
 target=historical_target(args.admission,args.known_hosts)
 if args.foundation_receipt.parent!=output or args.start_receipt.parent!=output: raise SystemExit("clean-boot receipts must use the dedicated output root")
 foundation,foundation_raw=receipt(args.foundation_receipt,"foundation receipt"); start,start_raw=receipt(args.start_receipt,"start receipt")
 foundation_keys={"admission_sha256","commit","format","operation","plan_sha256","resources","snippet_receipt_sha256","state_sha256","target_id","version","vm_started","vmid"}
 start_keys=foundation_keys|{"prior_receipt_sha256","snippet_sha256"}
 digest_fields=("admission_sha256","plan_sha256","snippet_receipt_sha256","state_sha256")
 common=lambda value: type(value.get("version")) is int and value.get("version")==1 and type(value.get("vmid")) is int and isinstance(value.get("commit"),str) and re.fullmatch(r"[0-9a-f]{40}",value["commit"]) is not None and all(isinstance(value.get(key),str) and re.fullmatch(r"[0-9a-f]{64}",value[key]) is not None for key in digest_fields) and value.get("admission_sha256")==target["isolation_attestation_sha256"] and value.get("target_id")=="production-pve-vm9900-qualification" and value.get("vmid")==9900 and value.get("resources")==RESOURCES
 if set(foundation)!=foundation_keys or foundation.get("format")!="home-lab-debian-qualification-foundation-receipt-v1" or foundation.get("operation")!="create-stopped-foundation" or foundation.get("vm_started") is not False or not common(foundation): raise SystemExit("foundation receipt binding failed")
 if set(start)!=start_keys or start.get("format")!="home-lab-debian-qualification-start-receipt-v1" or start.get("operation")!="start" or start.get("vm_started") is not True or any(not isinstance(start.get(key),str) or re.fullmatch(r"[0-9a-f]{64}",start[key]) is None for key in ("prior_receipt_sha256","snippet_sha256")) or start.get("prior_receipt_sha256")!=sha(foundation_raw) or start.get("commit")!=foundation.get("commit") or start.get("snippet_receipt_sha256")!=foundation.get("snippet_receipt_sha256") or not common(start): raise SystemExit("start receipt binding failed")
 allowed={args.foundation_receipt,args.start_receipt}; present={path.resolve() for path in output.glob("*.receipt.json")}
 if present!=allowed: raise SystemExit("intervening qualification receipt detected")
 sources={path:path.read_bytes() for path in (HELPER,TRANSPORT,SUDOERS,TEMPLATE)}
 expected_snippet,snippet_raw=snippet_evidence(args.snippet_receipt,args.guest_public_key,args.admission,args.known_hosts,foundation,start)
 request=observation_request(target,foundation_raw,start_raw,snippet_raw,expected_snippet)
 envelope=remote_first_boot(target,args.known_hosts,output,start_raw,request)
 observation=validated_envelope(envelope,request)
 value={"admission_sha256":target["isolation_attestation_sha256"],"commit":revision,"format":"home-lab-debian-qualification-clean-first-boot-receipt-v2","foundation_receipt_sha256":sha(foundation_raw),"helper_sha256":sha(HELPER.read_bytes().rstrip()),"helper_source_sha256":sha(HELPER.read_bytes()),"observation":observation,"observation_sha256":sha(canonical_bytes(observation)+b"\n"),"observed_at":dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z"),"start_receipt_sha256":sha(start_raw),"status":"verified","target_id":target["target_id"],"template_sha256":sha(TEMPLATE.read_bytes()),"transport_sha256":sha(TRANSPORT.read_bytes().rstrip()),"transport_source_sha256":sha(TRANSPORT.read_bytes()),"version":2,"vmid":9900,"provenance":envelope,"booted_template_commit":revision,"snippet_receipt_sha256":sha(snippet_raw)}
 raw=canonical_bytes(value)+b"\n"; digest=sha(raw)
 if commit()!=revision or expected_producer()!=request["producer"] or any(path.read_bytes()!=raw for path,raw in sources.items()): raise SystemExit("first-boot source changed during observation")
 if {path.resolve() for path in output.glob("*.receipt.json")}!=allowed: raise SystemExit("intervening qualification receipt detected")
 write_json(output,f"{digest}.json",value)
 print(json.dumps({"receipt":str(output/f'{digest}.json'),"receipt_sha256":digest,"status":"verified"},sort_keys=True))
if __name__=="__main__": main()
