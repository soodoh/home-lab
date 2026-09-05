#!/usr/bin/env python3
"""Exercise fixed QGA-only clean first-boot observation logic."""
import importlib.machinery,importlib.util,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; SOURCE=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"
loader=importlib.machinery.SourceFileLoader("qualification_helper",str(SOURCE)); spec=importlib.util.spec_from_loader(loader.name,loader); helper=importlib.util.module_from_spec(spec); loader.exec_module(helper)
def qga(stdout="",exitcode=0): return json.dumps({"err-data":"","exitcode":exitcode,"exited":1,"out-data":stdout},sort_keys=True)
RULES=[
 {"action":"ACCEPT","comment":"DHCP discovery","dest":"255.255.255.255/32","dport":"67","proto":"udp","sport":"68","type":"out"},
 {"action":"ACCEPT","comment":"DHCP offer","dport":"68","proto":"udp","source":"0.0.0.0/0","sport":"67","type":"in"},
 {"action":"ACCEPT","comment":"bounded controller SSH","dport":"22","proto":"tcp","source":"192.168.0.12/32","type":"in"},
 {"action":"ACCEPT","comment":"SSH replies only","dest":"192.168.0.12/32","dport":"1024:65535","proto":"tcp","sport":"22","type":"out"},
 {"action":"DROP","comment":"deny private production networks","dest":"10.0.0.0/8","type":"out"},
 {"action":"DROP","comment":"deny private production networks","dest":"172.16.0.0/12","type":"out"},
 {"action":"DROP","comment":"deny production LAN","dest":"192.168.0.0/16","type":"out"},
 {"action":"DROP","comment":"deny tailnet and CGNAT destinations","dest":"100.64.0.0/10","type":"out"},
 {"action":"ACCEPT","comment":"public IPv4 egress after private and CGNAT denies","dest":"0.0.0.0/0","type":"out"}]
for index,rule in enumerate(RULES): rule.update({"enable":1,"pos":index})
status_calls=[]
def fake(command):
 if command[:3]==["/usr/sbin/qm","config","9900"]: return "net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1\nonboot: 0\nprotection: 0\n"
 if command[:3]==["/usr/sbin/qm","status","9900"]: status_calls.append(1); return f"status: running\nuptime: {175 if len(status_calls)==1 else 179}\n"
 if command[:3]==["/usr/bin/pvesh","get","/nodes/proxmox/qemu/9900/firewall/options"]: return json.dumps({"dhcp":1,"enable":1,"ipfilter":0,"macfilter":1,"policy_in":"DROP","policy_out":"DROP"})
 if command[:3]==["/usr/bin/pvesh","get","/nodes/proxmox/qemu/9900/firewall/rules"]: return json.dumps(RULES)
 if command[:4]==["/usr/sbin/qm","guest","cmd","9900"]: return "{}\n"
 argv=command[5:]
 if argv[:2]==["/usr/bin/cloud-init","status"]: return qga("status: done\n")
 if argv==["/usr/bin/cat","/run/cloud-init/result.json"]: return qga('{"v1":{"errors":[]}}\n')
 if argv==["/usr/bin/cat","/proc/sys/kernel/random/boot_id"]: return qga("efbec1bf-a7a8-4b17-8ba1-55521d98d923\n")
 if argv==["/usr/bin/cat","/proc/uptime"]: return qga("178.78 20.00\n")
 if argv and argv[0]=="/usr/bin/journalctl": return qga('{"boot_id":"efbec1bfa7a84b178ba155521d98d923","index":0}\n')
 if argv[:2]==["/usr/bin/cloud-init","query"]: return qga("iid-nocloud\n")
 if argv and argv[0]=="/usr/bin/dpkg-query": return qga("install ok installed 1:10.0.11+ds-0+deb13u1\n")
 if argv and argv[0]=="/usr/bin/systemctl": return qga("active\n")
 if argv and argv[0]=="/usr/bin/getent": return qga("151.101.2.132 STREAM deb.debian.org\n")
 if argv and argv[0]=="/usr/bin/python3" and "first-boot-id" in argv[-1]: return qga('{"boot_id":"efbec1bf-a7a8-4b17-8ba1-55521d98d923","mode":"0600"}\n')
 if argv and argv[0]=="/usr/bin/python3": return qga('{"blocked":{"10.255.255.1":true,"100.64.0.1":true,"172.31.255.1":true,"192.168.0.1":true},"https_status":200}\n')
 raise AssertionError(command)
original=helper.run; helper.run=fake; value=helper._first_boot(); helper.run=original
assert value["boot_count"]==1 and value["first_boot_marker"]=={"boot_id":"efbec1bf-a7a8-4b17-8ba1-55521d98d923","mode":"0600"} and value["cloud_init_errors"]==[] and value["cloud_init_status"]=="done" and value["network_device"]["firewall"] is True and value["startup_delta_seconds"]==0.22 and value["pve_uptime_seconds"]==179 and value["qemu_guest_agent"]=="active" and value["vmid"]==9900
def rebooted(command):
 if command[:3]==["/usr/sbin/qm","status","9900"]: return "status: running\nuptime: 600\n"
 return fake(command)
helper.run=rebooted
try: helper._first_boot(); raise AssertionError("rebooted guest accepted")
except RuntimeError as error: assert "reboot detected" in str(error)
finally: helper.run=original
def quick_reboot(command):
 if command[:3]==["/usr/sbin/qm","status","9900"]: return "status: running\nuptime: 200\n"
 if command[:4]==["/usr/sbin/qm","guest","exec","9900"] and command[5:6]==["/usr/bin/python3"] and "first-boot-id" in command[-1]: return qga('{"boot_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","mode":"0600"}\n')
 return fake(command)
helper.run=quick_reboot
try: helper._first_boot(); raise AssertionError("quick reboot with volatile journal accepted")
except RuntimeError as error: assert "first-boot marker differs" in str(error)
finally: helper.run=original
sys.path.insert(0,str(ROOT/"scripts/controller")); controller_path=ROOT/"scripts/controller/debian-qualification-first-boot.py"; controller_spec=importlib.util.spec_from_file_location("qualification_first_boot_controller",controller_path); controller_module=importlib.util.module_from_spec(controller_spec); controller_spec.loader.exec_module(controller_module)
def timeout_run(*args,**kwargs): raise subprocess.TimeoutExpired(args[0],120,stderr=b"Bearer exposed")
with tempfile.TemporaryDirectory(dir=ROOT/".local") as directory:
 original_run=controller_module.subprocess.run; controller_module.subprocess.run=timeout_run
 try:
  try: controller_module.remote_first_boot({"ssh_address":"proxmox","ssh_username":"qualification-apply"},Path("known_hosts"),Path(directory),b"start\n"); raise AssertionError("timeout accepted")
  except SystemExit: pass
 finally: controller_module.subprocess.run=original_run
 failure=json.loads(next(Path(directory).glob("*.first-boot-failure.json")).read_text()); assert failure["returncode"]==124 and failure["detail"]=="Bearer <redacted>"
helper_source=SOURCE.read_text(); assert 'if not (stat.S_ISREG' in helper_source and 'raise SystemExit(64)' in helper_source and 'raise SystemExit(65)' in helper_source and 'assert stat.S_ISREG' not in helper_source and 'assert (s.st_dev' not in helper_source
controller=controller_path.read_text()
for required in ("clean pushed commit required","historical_target","remote_first_boot","first-boot-failure.json","<redacted>","acquire_transfer_lock","intervening qualification receipt detected","foundation_receipt_sha256","start_receipt_sha256","first-boot","boot_count","startup_delta_seconds","network_device","firewall_rules","cloud_init_errors","qemu_guest_agent","observation_sha256","helper_sha256","helper_source_sha256","transport_sha256","transport_source_sha256","template_sha256"):
 assert required in controller
print("debian_qualification_first_boot=verified chain_bound=true one_boot=true firewall_live=true qga_only=true cloud_init=true dns_https=true isolation=true")
