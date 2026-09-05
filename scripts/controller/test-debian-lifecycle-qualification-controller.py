#!/usr/bin/env python3
"""Verify guarded disposable foundation planning and hostile plan refusal."""
import copy,importlib.util,json,os,signal,subprocess,sys,tempfile,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"scripts/controller/debian-lifecycle-qualification.py"
spec=importlib.util.spec_from_file_location("qualification_controller",SOURCE); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
contract=module.contract_image(); target={"bridge":"vmbr0","controller_ipv4":"198.51.100.12","disk_datastore_id":"local-lvm","image_datastore_id":"local","node_name":"proxmox","snippet_file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml"}
def item(address,after): return {"address":address,"change":{"actions":["create"],"after":after}}
plan={"resource_changes":[
 item("proxmox_download_file.qualification_image[0]",{"checksum":contract["sha512"],"checksum_algorithm":"sha512","datastore_id":"local","node_name":"proxmox","overwrite":False,"url":contract["url"]}),
 item("proxmox_virtual_environment_vm.qualification[0]",{"boot_order":["scsi0"],"disk":[{"datastore_id":"local-lvm","interface":"scsi0","serial":"DEB-LIFE-ROOT-32G","size":32}],"initialization":[{"datastore_id":"local-lvm","dns":[{"servers":["1.1.1.1","9.9.9.9"]}],"ip_config":[{"ipv4":[{"address":"dhcp","gateway":None}],"ipv6":[]}],"upgrade":False,"user_data_file_id":"local:snippets/home-lab-debian-lifecycle-qualification.yaml"}],"network_device":[{"bridge":"vmbr0","firewall":True}],"node_name":"proxmox","on_boot":False,"protection":False,"reboot_after_update":False,"started":False,"vm_id":9900}),
 item("proxmox_virtual_environment_firewall_options.qualification[0]",{"dhcp":True,"enabled":True,"input_policy":"DROP","ipfilter":False,"macfilter":True,"output_policy":"DROP"}),
 item("proxmox_virtual_environment_firewall_rules.qualification[0]",{"rule":[{"action":"ACCEPT","dest":"255.255.255.255/32","dport":"67","proto":"udp","source":None,"sport":"68","type":"out"},{"action":"ACCEPT","dest":None,"dport":"68","proto":"udp","source":"0.0.0.0/0","sport":"67","type":"in"},{"action":"ACCEPT","dest":None,"dport":"22","proto":"tcp","source":"198.51.100.12/32","sport":None,"type":"in"},{"action":"ACCEPT","dest":"198.51.100.12/32","dport":"1024:65535","proto":"tcp","source":None,"sport":"22","type":"out"},{"action":"DROP","dest":"10.0.0.0/8","dport":None,"proto":None,"source":None,"sport":None,"type":"out"},{"action":"DROP","dest":"172.16.0.0/12","dport":None,"proto":None,"source":None,"sport":None,"type":"out"},{"action":"DROP","dest":"192.168.0.0/16","dport":None,"proto":None,"source":None,"sport":None,"type":"out"},{"action":"DROP","dest":"100.64.0.0/10","dport":None,"proto":None,"source":None,"sport":None,"type":"out"},{"action":"ACCEPT","dest":"0.0.0.0/0","dport":None,"proto":None,"source":None,"sport":None,"type":"out"}]})]}
assert len(module.inspect_plan(plan,target))==4
def refused(name,mutate,reason):
 value=copy.deepcopy(plan); mutate(value)
 try: module.inspect_plan(value,target)
 except SystemExit as error: assert reason in str(error),(name,error)
 else: raise AssertionError(name)
refused("start",lambda x:x["resource_changes"][1]["change"]["after"].update(started=True),"foundation-vm")
refused("vm100",lambda x:x["resource_changes"][1]["change"]["after"].update(vm_id=100),"foundation-vm")
refused("replace",lambda x:x["resource_changes"][1]["change"].update(actions=["delete","create"]),"foundation-actions")
refused("image",lambda x:x["resource_changes"][0]["change"]["after"].update(checksum="0"*128),"foundation-image")
refused("firewall",lambda x:x["resource_changes"][3]["change"]["after"]["rule"].reverse(),"foundation-firewall-rules")
refused("static-ip",lambda x:x["resource_changes"][1]["change"]["after"]["initialization"][0]["ip_config"][0]["ipv4"][0].update(address="192.168.0.53/24"),"foundation-vm")
refused("extra-ipv4",lambda x:x["resource_changes"][1]["change"]["after"]["initialization"][0]["ip_config"][0]["ipv4"].append({"address":"dhcp","gateway":None}),"foundation-vm")
refused("extra-ip-config",lambda x:x["resource_changes"][1]["change"]["after"]["initialization"][0]["ip_config"].append({"ipv4":[],"ipv6":[]}),"foundation-vm")
refused("ipv6",lambda x:x["resource_changes"][1]["change"]["after"]["initialization"][0]["ip_config"][0]["ipv6"].append({"address":"dhcp","gateway":None}),"foundation-vm")
host=subprocess.Popen([sys.executable,"-c","pass"])
try: module.run_locked([sys.executable,"-c","import time; time.sleep(30)"],None,host,"unexpected")
except SystemExit as error: assert "target-lock-lost" in str(error)
else: raise AssertionError("lost target lock did not terminate controlled command")
with tempfile.TemporaryDirectory() as directory:
 pidfile=Path(directory)/"child.pid"; host=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); timer=threading.Timer(0.5,lambda:os.kill(os.getpid(),signal.SIGTERM)); timer.start()
 try: module.run_locked([sys.executable,"-c",f"import os,time; open({str(pidfile)!r},'w').write(str(os.getpid())); time.sleep(30)"],None,host,"unexpected")
 except InterruptedError: pass
 else: raise AssertionError("controller signal did not interrupt controlled command")
 finally: timer.cancel(); host.terminate(); host.wait()
 pid=int(pidfile.read_text())
 try: os.kill(pid,0)
 except ProcessLookupError: pass
 else: raise AssertionError("controlled child survived controller interruption")
script='import json,sys; print(json.dumps({"admission_sha256":"a"*64,"format":"home-lab-disposable-qualification-lock-v1","held":True},sort_keys=True,separators=(",",":")),flush=True); line=sys.stdin.readline().strip(); address=line.split()[1]; print(json.dumps({"format":"home-lab-debian-qualification-guest-ipv4-observation-v1","guest_ipv4":address,"vmid":9900},sort_keys=True,separators=(",",":")),flush=True); sys.stdin.read()'
host=subprocess.Popen([sys.executable,"-c",script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE); json.loads(host.stdout.readline()); assert module.target_guest_ipv4(host,"192.168.0.53")["guest_ipv4"]=="192.168.0.53" and host.poll() is None; module.release_target(host)
source=SOURCE.read_text()
for required in ("{kind}-credentials.json","PROXMOX_VE_API_TOKEN","CREATE_PRODUCTION_PVE_DISPOSABLE_DEBIAN_9900","tofu-apply-no-retry","hold-lock","GlobalKnownHostsFile=/dev/null","IdentityFile=none","PreferredAuthentications=none","PubkeyAuthentication=no","target-lock-lost","lifecycle.lock",'"authorized":False','"automatic_apply":False','"actionable":True',"authorization_sha256","approve_authorization_sha","snippet_receipt_sha256",'target={**target,"snippet_file_id"',"api_ca_sha256","apply_principal","state-drift","saved-plan-binding"):
 assert required in source,required
assert '"apply","-input=false","-lock=true","-auto-approve",str(binary)' in source
assert "-var=enable_qualification=true" in source and "-var=proxmox_endpoint=" in source
print("debian_lifecycle_qualification_controller=verified hostile_plans=5")
