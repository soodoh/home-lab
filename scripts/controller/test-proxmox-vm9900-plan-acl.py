#!/usr/bin/env python3
"""Verify the additive VM9900 plan-token ACL boundary."""
import importlib.util
from pathlib import Path
SOURCE=Path(__file__).with_name("proxmox-vm9900-plan-acl.py"); spec=importlib.util.spec_from_file_location("vm9900_acl",SOURCE); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
before=module.expected(False); after=module.expected(True)
assert len(before["records"])==2 and len(after["records"])==3
assert after["records"][-1]=={"path":"/vms/9900","propagate":1,"roleid":"HomeLabTofuPlanDiskInspect","ugid":"root@pam!tofu-plan"}
source=SOURCE.read_text()
for required in ("authorized\":False","automatic_apply\":False","add-vm9900-plan-acl-","/var/lib/home-lab/reconciliation/operation.lock","controller.lock",'"/usr/sbin/pveum","acl","modify","/vms/9900"',"HomeLabTofuPlanDiskInspect","ACL precondition changed","ACL postcondition failed","StrictHostKeyChecking=yes","GlobalKnownHostsFile=/dev/null","IdentityFile=none","PreferredAuthentications=none","PubkeyAuthentication=no"):
 assert required in source,required
for forbidden in ('"/vms/100","--tokens"','"tofu-apply"','pveum acl delete'):
 assert forbidden not in source
print("proxmox_vm9900_plan_acl=verified additive=true vm100_mutation=false")
