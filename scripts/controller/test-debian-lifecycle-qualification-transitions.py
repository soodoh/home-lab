#!/usr/bin/env python3
"""Verify separate start, recovery stop/restart, and destroy boundaries."""
import copy,importlib.util,json,tempfile
from types import SimpleNamespace
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"scripts/controller/debian-lifecycle-qualification-transitions.py"; spec=importlib.util.spec_from_file_location("qualification_transitions",SOURCE); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
target={"controller_ipv4":"192.168.0.12","disk_datastore_id":"local-lvm","image_datastore_id":"local","node_name":"proxmox"}; image=module.common.contract_image(); vm="proxmox_virtual_environment_vm.qualification[0]"; image_address="proxmox_download_file.qualification_image[0]"; options="proxmox_virtual_environment_firewall_options.qualification[0]"; rules="proxmox_virtual_environment_firewall_rules.qualification[0]"; addresses=[image_address,options,rules,vm]
def change(address,actions,before=None,after=None): return {"address":address,"change":{"actions":actions,"before":before,"after":after}}
def firewall_row(value):
 kind,action,dest,source,proto,dport,sport=value; return {"type":kind,"action":action,"dest":dest,"source":source,"proto":proto,"dport":dport,"sport":sport}
before_vm={"disk":[{"datastore_id":"local-lvm"}],"node_name":"proxmox","on_boot":False,"started":False,"vm_id":9900}; after_vm=copy.deepcopy(before_vm); after_vm["started"]=True
start={"resource_changes":[change(vm,["update"],before_vm,after_vm),*[change(address,["no-op"],{}, {}) for address in addresses if address!=vm]]}
start["resource_changes"][0]["change"]["after_unknown"]={"agent":[{"wait_for_ip":[{}]}],"ipv4_addresses":True}
stop={"resource_changes":[change(vm,["update"],after_vm,before_vm),*[change(address,["no-op"],{}, {}) for address in addresses if address!=vm]]}
stop["resource_changes"][0]["change"]["after_unknown"]={"ipv4_addresses":True}
restart=copy.deepcopy(start)
destroy={"resource_changes":[change(image_address,["delete"],{"checksum":image["sha512"],"datastore_id":"local","node_name":"proxmox","url":image["url"]},None),change(options,["delete"],{"node_name":"proxmox","vm_id":9900},None),change(rules,["delete"],{"node_name":"proxmox","vm_id":9900},None),change(vm,["delete"],after_vm,None)]}
expected_firewall=module.common.expected_firewall_rules(target); repair={"resource_changes":[change(rules,["update"],{"node_name":"proxmox","vm_id":9900,"rule":[firewall_row(row) for row in expected_firewall[2:]]},{"node_name":"proxmox","vm_id":9900,"rule":[firewall_row(row) for row in expected_firewall]}),*[change(address,["no-op"],{}, {}) for address in addresses if address!=rules]]}
assert module.inspect(start,"start",target)==[vm]
assert module.inspect(destroy,"destroy",target)==sorted(addresses)
assert module.inspect(repair,"repair-network",target)==[rules]
assert module.inspect(stop,"stop",target)==[vm]
assert module.inspect(restart,"restart",target)==[vm]
def refused(value,operation,mutate,reason):
 item=copy.deepcopy(value); mutate(item)
 try: module.inspect(item,operation,target)
 except SystemExit as error: assert reason in str(error)
 else: raise AssertionError(reason)
refused(start,"start",lambda x:x["resource_changes"][0]["change"]["after"].update(on_boot=True),"start-vm")
refused(start,"start",lambda x:x["resource_changes"][0]["change"].update(actions=["delete","create"]),"start-actions")
refused(start,"start",lambda x:x["resource_changes"][0]["change"]["after"]["disk"][0].update(datastore_id="production"),"start-vm")
refused(start,"start",lambda x:x["resource_changes"][0]["change"]["after_unknown"].update(disk=[{"file_id":True}]),"start-vm")
refused(stop,"stop",lambda x:x["resource_changes"][0]["change"]["after"].update(on_boot=True),"stop-vm")
refused(restart,"restart",lambda x:x["resource_changes"][0]["change"].update(actions=["delete","create"]),"restart-actions")
refused(repair,"repair-network",lambda x:x["resource_changes"][0]["change"]["after"]["rule"].pop(0),"repair-network-rules")
refused(destroy,"destroy",lambda x:x["resource_changes"][0]["change"].update(actions=["update"]),"destroy-actions")
refused(destroy,"destroy",lambda x:x["resource_changes"][0]["change"]["before"].update(datastore_id="production"),"destroy-actions")
refused(destroy,"destroy",lambda x:x["resource_changes"].append(change("proxmox_virtual_environment_vm.production",["delete"],{},None)),"destroy-actions")
with tempfile.TemporaryDirectory(dir=ROOT/".local") as directory:
 receipt={"admission_sha256":"a"*64,"commit":"b"*40,"format":"home-lab-debian-qualification-foundation-receipt-v1","operation":"create-stopped-foundation","plan_sha256":"c"*64,"resources":sorted(addresses),"snippet_receipt_sha256":"d"*64,"state_sha256":"e"*64,"target_id":"production-pve-vm9900-qualification","version":1,"vm_started":False,"vmid":9900}; path=Path(directory)/"receipt.json"; path.write_text(json.dumps(receipt,sort_keys=True,separators=(",",":"))+"\n"); path.chmod(0o600); args=SimpleNamespace(prior_receipt=path); admitted={"isolation_attestation_sha256":"f"*64,"target_id":"production-pve-vm9900-qualification"}; assert module.prior(args,"start",admitted)[0]==receipt
 try: module.prior(args,"start",{"target_id":"other-target"})
 except SystemExit as error: assert "prior-receipt" in str(error)
 else: raise AssertionError("prior receipt target substitution accepted")
source=SOURCE.read_text()
for required in ("START_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900","REPAIR_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900_DHCP","STOP_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900_FOR_HOSTKEY","RESTART_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900_AFTER_HOSTKEY","DESTROY_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900","plan-start","apply-start","plan-repair-network","apply-repair-network","plan-stop","apply-stop","plan-restart","apply-restart","plan-destroy","apply-destroy","prior_receipt_sha256","snippet_receipt_sha256","snippet_sha256",'target={**target,"snippet_file_id"',"approve_authorization_sha","tofu-{operation}-apply-no-retry","-destroy","locked_setup","state-drift",'split("-",1)[1]'):
 assert required in source,required
assert 'start_value="false" if operation=="stop" else "true"' in source
print("debian_lifecycle_qualification_transitions=verified hostile_plans=10")
