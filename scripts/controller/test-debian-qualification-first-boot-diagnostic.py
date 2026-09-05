#!/usr/bin/env python3
"""Exercise bounded VM9900 first-boot diagnostic parsing and guards."""
import importlib.machinery,importlib.util,json,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; HELPER=ROOT/"infrastructure/qualification/host/debian-qualification-snippet-transaction"; CONTROLLER=ROOT/"scripts/controller/debian-qualification-first-boot-diagnostic.py"
loader=importlib.machinery.SourceFileLoader("qualification_helper_diagnostic",str(HELPER)); spec=importlib.util.spec_from_loader(loader.name,loader); helper=importlib.util.module_from_spec(spec); loader.exec_module(helper)
with tempfile.TemporaryDirectory(dir=ROOT/".local") as directory:
 root=Path(directory)
 values={"var/log/cloud-init.log":"ERROR: failed to install qemu-guest-agent: Temporary failure resolving deb.debian.org\n","var/log/cloud-init-output.log":"cloud-init failed\n","var/log/apt/history.log":"","var/log/apt/term.log":"","var/lib/cloud/data/result.json":json.dumps({"v1":{"errors":["package failed at https://user:pass@example.invalid/x","Bearer abc-secret-token"]}}),"var/lib/dpkg/status":"Package: qemu-guest-agent\nStatus: install ok installed\nVersion: 1.2.3\n\n"}
 for path,value in values.items(): target=root/path; target.parent.mkdir(parents=True,exist_ok=True); target.write_text(value)
 result=helper.read_first_boot_diagnostic(str(root)); assert result["signals"]=={"apt_failure":True,"dns_failure":True,"network_failure":False,"qga_mentioned":True}; assert result["qemu_guest_agent_package"]=={"present":True,"status":"install ok installed","version":"1.2.3"}; assert result["cloud_result_errors"]==["package failed at https://<redacted>@example.invalid/x","Bearer <redacted>"] and result["cloud_result_present"] is True
 device=root/"nbd0"; unexpected=root/"nbd0p2"; device.touch(); unexpected.touch(); assert helper.nbd_mappings(str(device))==[str(unexpected)]
controller=CONTROLLER.read_text()
for required in ("--allow-expired-offline-diagnostic","--capability-log","DIAGNOSE_VM9900_FAILED_FIRST_BOOT_READ_ONLY","exact-authorization-required","stopped_receipt_sha256","state-drift","diagnostic-attempt.json","diagnostic-plan-already-attempted","capability_receipt_sha256","helper_sha256","sudoers_sha256","transport_sha256","producer-binding","diagnostic-schema","diagnostic-redaction","diagnostic-receipt.json","automatic_apply"):
 assert required in controller,required
helper_text=HELPER.read_text()
for required in ("/var/lib/home-lab/reconciliation/operation.lock","/var/lib/iac-ansible-production.lock","qualification capability installation active","qualification-diagnostic-attempts","nbd_mappings"):
 assert required in helper_text,required
print("debian_qualification_first_boot_diagnostic=verified exact_plan=true read_only_disk=true bounded_evidence=true")
