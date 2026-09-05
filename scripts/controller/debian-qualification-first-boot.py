#!/usr/bin/env python3
"""Capture fixed, chain-bound QGA clean first-boot proof for VM9900."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import re
import os
import subprocess
from pathlib import Path
from protected_execution import acquire_transfer_lock,canonical_bytes,load_protected_bytes,require_private_root,write_json
ROOT=Path(__file__).resolve().parents[2]
SNIPPET_CONTROLLER=ROOT/"scripts/controller/debian-qualification-snippet.py"
HELPER=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"
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
 raw=load_protected_bytes(path,label); value=json.loads(raw)
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
def main():
 parser=argparse.ArgumentParser()
 parser.add_argument("--admission",type=Path,required=True); parser.add_argument("--known-hosts",type=Path,required=True)
 parser.add_argument("--foundation-receipt",type=Path,required=True); parser.add_argument("--start-receipt",type=Path,required=True); parser.add_argument("--output-dir",type=Path,required=True)
 args=parser.parse_args()
 for key,value in vars(args).items(): setattr(args,key,value.resolve())
 revision=commit(); output=require_private_root(args.output_dir,()); controller_lock=acquire_transfer_lock(output/"lifecycle.lock"); target=historical_target(args.admission,args.known_hosts)
 if args.foundation_receipt.parent!=output or args.start_receipt.parent!=output: raise SystemExit("clean-boot receipts must use the dedicated output root")
 foundation,foundation_raw=receipt(args.foundation_receipt,"foundation receipt"); start,start_raw=receipt(args.start_receipt,"start receipt")
 foundation_keys={"admission_sha256","commit","format","operation","plan_sha256","resources","snippet_receipt_sha256","state_sha256","target_id","version","vm_started","vmid"}
 start_keys=foundation_keys|{"prior_receipt_sha256","snippet_sha256"}
 digest_fields=("admission_sha256","plan_sha256","snippet_receipt_sha256","state_sha256")
 common=lambda value: value.get("version")==1 and re.fullmatch(r"[0-9a-f]{40}",value.get("commit","")) is not None and all(re.fullmatch(r"[0-9a-f]{64}",value.get(key,"")) is not None for key in digest_fields) and value.get("admission_sha256")==target["isolation_attestation_sha256"] and value.get("target_id")=="production-pve-vm9900-qualification" and value.get("vmid")==9900 and value.get("resources")==RESOURCES
 if set(foundation)!=foundation_keys or foundation.get("format")!="home-lab-debian-qualification-foundation-receipt-v1" or foundation.get("operation")!="create-stopped-foundation" or foundation.get("vm_started") is not False or not common(foundation): raise SystemExit("foundation receipt binding failed")
 if set(start)!=start_keys or start.get("format")!="home-lab-debian-qualification-start-receipt-v1" or start.get("operation")!="start" or start.get("vm_started") is not True or re.fullmatch(r"[0-9a-f]{64}",start.get("prior_receipt_sha256","")) is None or re.fullmatch(r"[0-9a-f]{64}",start.get("snippet_sha256","")) is None or start.get("prior_receipt_sha256")!=sha(foundation_raw) or start.get("commit")!=foundation.get("commit") or start.get("snippet_receipt_sha256")!=foundation.get("snippet_receipt_sha256") or not common(start): raise SystemExit("start receipt binding failed")
 allowed={args.foundation_receipt,args.start_receipt}; present={path.resolve() for path in output.glob("*.receipt.json")}
 if present!=allowed: raise SystemExit("intervening qualification receipt detected")
 observation=snippet.remote(target,args.known_hosts,"first-boot")
 required={"boot_count","boot_id","cloud_init_errors","cloud_init_instance_id","cloud_init_status","firewall_options","firewall_rules","format","guest_uptime_seconds","network","network_device","package","pve_uptime_seconds","qemu_guest_agent","startup_delta_seconds","vmid"}
 denied={rule.get("dest") for rule in observation.get("firewall_rules",[]) if rule.get("type")=="out" and rule.get("action")=="DROP" and rule.get("enable")==1}
 probes={"10.255.255.1":True,"172.31.255.1":True,"192.168.0.1":True,"100.64.0.1":True}
 uptime=(observation.get("pve_uptime_seconds"),observation.get("guest_uptime_seconds"),observation.get("startup_delta_seconds")); uptime_valid=isinstance(uptime[0],int) and not isinstance(uptime[0],bool) and all(isinstance(value,(int,float)) and not isinstance(value,bool) for value in uptime[1:]) and uptime[0]>0 and uptime[1]>0 and 0<=uptime[2]<=30 and abs(round(uptime[0]-uptime[1],2)-uptime[2])<0.01
 if not uptime_valid or set(observation)!=required or observation["format"]!="home-lab-debian-qualification-first-boot-observation-v1" or observation["vmid"]!=9900 or observation["boot_count"]!=1 or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",observation["boot_id"]) is None or not observation["cloud_init_instance_id"] or observation["cloud_init_errors"]!=[] or observation["cloud_init_status"]!="done" or observation["qemu_guest_agent"]!="active" or re.fullmatch(r"install ok installed [^\s]+",observation["package"]) is None or observation["network_device"]!={"bridge":"vmbr0","firewall":True,"model":"virtio"} or observation["firewall_options"]!={"dhcp":1,"enable":1,"ipfilter":0,"macfilter":1,"policy_in":"DROP","policy_out":"DROP"} or len(observation["firewall_rules"])!=9 or denied!={"10.0.0.0/8","100.64.0.0/10","172.16.0.0/12","192.168.0.0/16"} or observation["network"].get("blocked")!=probes or observation["network"].get("https_status") not in (200,301,302): raise SystemExit("clean first-boot observation differs")
 value={"admission_sha256":target["isolation_attestation_sha256"],"commit":revision,"format":"home-lab-debian-qualification-clean-first-boot-receipt-v1","foundation_receipt_sha256":sha(foundation_raw),"helper_sha256":sha(HELPER.read_bytes()),"observation":observation,"observation_sha256":sha(canonical_bytes(observation)+b"\n"),"observed_at":dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z"),"start_receipt_sha256":sha(start_raw),"status":"verified","target_id":target["target_id"],"template_sha256":sha(TEMPLATE.read_bytes()),"transport_sha256":sha(TRANSPORT.read_bytes()),"version":1,"vmid":9900}
 raw=canonical_bytes(value)+b"\n"; digest=sha(raw)
 if {path.resolve() for path in output.glob("*.receipt.json")}!=allowed: raise SystemExit("intervening qualification receipt detected")
 write_json(output,f"{digest}.json",value); os.close(controller_lock)
 print(json.dumps({"receipt":str(output/f'{digest}.json'),"receipt_sha256":digest,"status":"verified"},sort_keys=True))
if __name__=="__main__": main()
