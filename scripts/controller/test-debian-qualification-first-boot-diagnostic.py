#!/usr/bin/env python3
"""Exercise bounded VM9900 first-boot diagnostic parsing and guards."""
import hashlib,importlib.machinery,importlib.util,json,sys,tempfile,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; HELPER=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"; CONTROLLER=ROOT/"scripts/controller/debian-qualification-first-boot-diagnostic.py"
loader=importlib.machinery.SourceFileLoader("qualification_helper_diagnostic",str(HELPER)); spec=importlib.util.spec_from_loader(loader.name,loader); helper=importlib.util.module_from_spec(spec); loader.exec_module(helper)
with tempfile.TemporaryDirectory(dir=ROOT/".local") as directory:
 root=Path(directory)
 values={"var/log/cloud-init.log":"ERROR: failed to install qemu-guest-agent: Temporary failure resolving deb.debian.org\n","var/log/cloud-init-output.log":"cloud-init failed\n","var/log/apt/history.log":"","var/log/apt/term.log":"","var/lib/cloud/data/result.json":json.dumps({"v1":{"errors":["package failed at https://user:pass@example.invalid/x","Bearer abc-secret-token"]}}),"var/lib/dpkg/status":"Package: qemu-guest-agent\nStatus: install ok installed\nVersion: 1.2.3\n\n"}
 for path,value in values.items(): target=root/path; target.parent.mkdir(parents=True,exist_ok=True); target.write_text(value)
 result=helper.read_first_boot_diagnostic(str(root)); assert result["signals"]=={"apt_failure":True,"dns_failure":True,"network_failure":False,"qga_mentioned":True}; assert result["qemu_guest_agent_package"]=={"present":True,"status":"install ok installed","version":"1.2.3"}; assert result["cloud_result_errors"]==["package failed at https://<redacted>@example.invalid/x","Bearer <redacted>"] and result["cloud_result_present"] is True
 device=root/"nbd0"; unexpected=root/"nbd0p2"; device.touch(); unexpected.touch(); assert helper.nbd_mappings(str(device))==[str(unexpected)]
 assert helper.read_diagnostic_file(str(root),"/missing/parent/file") is None
sys.path.insert(0,str(ROOT/"scripts/controller")); controller_spec=importlib.util.spec_from_file_location("qualification_diagnostic_controller",CONTROLLER); diagnostic=importlib.util.module_from_spec(controller_spec); controller_spec.loader.exec_module(diagnostic)
with tempfile.TemporaryDirectory(dir=ROOT/".local") as directory:
 root=Path(directory); state=root/"state.tfstate"; state.write_bytes(b"state"); state.chmod(0o600)
 prior={"expires_at":"2026-01-01T00:30:00Z","observed_at":"2026-01-01T00:00:00Z","stable":"same"}; current={**prior,"expires_at":"2026-09-05T14:30:00Z","observed_at":"2026-09-05T14:00:00Z"}
 def put(name,value):
  path=root/name; path.write_bytes(diagnostic.canonical_bytes(value)+b"\n"); path.chmod(0o600); return path
 prior_path=put("prior.json",prior); current_path=put("current.json",current); prior_sha=diagnostic.sha(prior_path.read_bytes()); current_sha=diagnostic.sha(current_path.read_bytes()); state_sha=diagnostic.sha(b"state")
 resources=["proxmox_download_file.qualification_image[0]","proxmox_virtual_environment_firewall_options.qualification[0]","proxmox_virtual_environment_firewall_rules.qualification[0]","proxmox_virtual_environment_vm.qualification[0]"]
 receipt={"admission_sha256":prior_sha,"commit":"0"*40,"format":"home-lab-debian-qualification-stop-receipt-v1","operation":"stop","plan_sha256":"1"*64,"prior_receipt_sha256":"2"*64,"resources":resources,"snippet_receipt_sha256":"3"*64,"snippet_sha256":"4"*64,"state_sha256":state_sha,"target_id":"production-pve-vm9900-qualification","version":1,"vm_started":False,"vmid":9900}; receipt_path=put("receipt.json",receipt); args=types.SimpleNamespace(admission=current_path,prior_admission=prior_path); fresh={"admission_mode":"fresh","isolation_attestation_sha256":current_sha,"target_id":receipt["target_id"]}
 diagnostic.stopped(receipt_path,fresh,state,args)
 expired={**fresh,"admission_mode":"expired-offline-diagnostic"}
 try: diagnostic.stopped(receipt_path,expired,state,args); raise AssertionError("expired historical lineage accepted")
 except SystemExit as error: assert "historical-lineage-requires-fresh-admission" in str(error)
 direct={**receipt,"admission_sha256":current_sha}; direct_path=put("direct.json",direct); diagnostic.stopped(direct_path,expired,state,args)
controller=CONTROLLER.read_text()
for required in ("--allow-expired-offline-diagnostic","--prior-admission","historical diagnostic admission","current_stable","--capability-log","DIAGNOSE_VM9900_FAILED_FIRST_BOOT_READ_ONLY","exact-authorization-required","stopped_receipt_sha256","state-drift","diagnostic-attempt.json","diagnostic-plan-already-attempted","diagnostic-failure.json","remote-diagnostic","capability_receipt_sha256","helper_sha256","sudoers_sha256","transport_sha256","producer-binding","diagnostic-schema","diagnostic-redaction","diagnostic-receipt.json","automatic_apply"):
 assert required in controller,required
helper_text=HELPER.read_text()
for required in ("/var/lib/home-lab/reconciliation/operation.lock","/var/lib/iac-ansible-production.lock","qualification capability installation active","qualification-diagnostic-attempts","nbd_mappings"):
 assert required in helper_text,required
print("debian_qualification_first_boot_diagnostic=verified exact_plan=true read_only_disk=true bounded_evidence=true")
