#!/usr/bin/env python3
"""Verify guarded read-only VM9900 host-key extraction."""
import base64,datetime as dt,hashlib,importlib.util,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; HELPER=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"; TRANSPORT=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transport"; CONTROLLER=ROOT/"scripts/controller/debian-qualification-host-key.py"; SNIPPET=ROOT/"scripts/controller/debian-qualification-snippet.py"
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def digest(raw): return hashlib.sha256(raw).hexdigest()
blob=b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"+b"k"*32; public="ssh-ed25519 "+base64.b64encode(blob).decode(); current=dt.datetime.now(dt.timezone.utc)
plan={"admission_sha256":"a"*64,"authorized":False,"automatic_apply":False,"clean_boot_receipt_sha256":"f"*64,"commit":"b"*40,"created_at":current.isoformat().replace("+00:00","Z"),"disk_volume":"local-lvm:vm-9900-disk-0","expires_at":(current+dt.timedelta(minutes=10)).isoformat().replace("+00:00","Z"),"format":"home-lab-debian-qualification-host-key-plan-v1","guest_ipv4":"192.168.0.53","node_name":"proxmox","operation":"extract-host-key-read-only","state_sha256":"c"*64,"stopped_receipt_sha256":"d"*64,"target_id":"production-pve-vm9900-qualification","version":1,"vmid":9900}; raw=canonical(plan); plan_sha=digest(raw)
with tempfile.TemporaryDirectory(dir=ROOT/".local") as directory:
 root=Path(directory); (root/"var/lib/vz/snippets").mkdir(parents=True); (root/"run/lock").mkdir(parents=True); key=root/"vm9900/etc/ssh/ssh_host_ed25519_key.pub"; key.parent.mkdir(parents=True); key.write_text(public+" root@vm9900\n"); key.chmod(0o644)
 env={**os.environ,"HOME_LAB_QUALIFICATION_SNIPPET_FIXTURE_ROOT":directory}; result=subprocess.run([str(HELPER),"host-key",plan_sha,plan_sha],input=raw,capture_output=True,env=env)
 assert result.returncode==0,result.stderr; receipt=json.loads(result.stdout); assert receipt["public_key"]==public; assert receipt["vmid"]==9900; assert receipt["disk_volume"]=="local-lvm:vm-9900-disk-0"
 refused=subprocess.run([str(HELPER),"host-key",plan_sha,"e"*64],input=raw,capture_output=True,env=env); assert refused.returncode!=0
 ssh_dir=key.parent; real_dir=ssh_dir.with_name("ssh-real"); ssh_dir.rename(real_dir); ssh_dir.symlink_to(real_dir); refused=subprocess.run([str(HELPER),"host-key",plan_sha,plan_sha],input=raw,capture_output=True,env=env); assert refused.returncode!=0; ssh_dir.unlink(); real_dir.rename(ssh_dir)
 bad=dict(plan); bad["disk_volume"]="HOME-LAB-DEBIAN-64G"; bad_raw=canonical(bad); bad_sha=digest(bad_raw); refused=subprocess.run([str(HELPER),"host-key",bad_sha,bad_sha],input=bad_raw,capture_output=True,env=env); assert refused.returncode!=0
 bad=dict(plan); bad["guest_ipv4"]="192.168.0.100"; bad_raw=canonical(bad); bad_sha=digest(bad_raw); refused=subprocess.run([str(HELPER),"host-key",bad_sha,bad_sha],input=bad_raw,capture_output=True,env=env); assert refused.returncode!=0
for required in ("--read-only","--format=raw","unexpected VM9900 NBD size","VM9900 is not stopped","VM9900 stopped lock precondition",'\"/usr/sbin/qm\",\"set\"','\"/usr/sbin/qm\",\"unlock\"','\"/usr/bin/partx\",\"--add\"','\"/usr/bin/partx\",\"--delete\"',"O_DIRECTORY|os.O_NOFOLLOW","local-lvm:vm-9900-disk-0","ro,noload,nodev,nosuid,noexec","ssh_host_ed25519_key.pub","disk inspection cleanup failed"):
 assert required in HELPER.read_text(),required
for required in ("host-key","EXTRACT_VM9900_HOST_KEY_READ_ONLY","stopped_receipt_sha256","lifecycle.lock","StrictHostKeyChecking=yes"):
 assert required in TRANSPORT.read_text()+CONTROLLER.read_text()+SNIPPET.read_text(),required
spec=importlib.util.spec_from_file_location("host_key_controller",CONTROLLER); controller=importlib.util.module_from_spec(spec); spec.loader.exec_module(controller)
with tempfile.TemporaryDirectory(dir=ROOT/".local") as directory:
 root=Path(directory); admission=root/"admission.json"; admission.write_bytes(canonical({"forged":True})); admission.chmod(0o600)
 forged={"admission_sha256":"a"*64,"commit":"b"*40,"format":"home-lab-debian-qualification-clean-first-boot-receipt-v1","foundation_receipt_sha256":"c"*64,"helper_sha256":"d"*64,"helper_source_sha256":"e"*64,"observation":{"guest_ipv4":"192.168.0.53"},"observation_sha256":"f"*64,"observed_at":current.isoformat().replace("+00:00","Z"),"start_receipt_sha256":"1"*64,"status":"verified","target_id":"production-pve-vm9900-qualification","template_sha256":"2"*64,"transport_sha256":"3"*64,"transport_source_sha256":"4"*64,"version":1,"vmid":9900}; receipt=root/"clean.json"; receipt.write_bytes(canonical(forged)); receipt.chmod(0o600)
 try: controller.clean_boot(receipt,admission,root/"known_hosts",{"target_id":"production-pve-vm9900-qualification"},{"prior_receipt_sha256":"1"*64}); raise AssertionError("forged clean receipt accepted")
 except SystemExit as error: assert "clean first-boot observation differs" in str(error)
print("debian_qualification_host_key=verified read_only=true hostile_plans=5")
