#!/usr/bin/env python3
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]
FILES=(ROOT/"infrastructure/policy/proxmox-firewall-plan.schema.json",ROOT/"infrastructure/policy/proxmox-firewall-private.schema.json",ROOT/"infrastructure/policy/proxmox-firewall-request.schema.json")

class SchemaTests(unittest.TestCase):
 def test_schemas_are_canonical_and_close_every_declared_object(self):
  def visit(value,path):
   if isinstance(value,dict):
    if value.get("type")=="object" or "properties" in value:
     self.assertIs(value.get("additionalProperties"),False,f"open object at {path}")
     if "properties" in value: self.assertEqual(set(value.get("required",[])),set(value["properties"]),f"optional field at {path}")
    for key,nested in value.items(): visit(nested,f"{path}.{key}")
   elif isinstance(value,list):
    for index,nested in enumerate(value): visit(nested,f"{path}[{index}]")
  for path in FILES:
   raw=path.read_bytes(); value=json.loads(raw); self.assertEqual(raw,(json.dumps(value,separators=(',',':'),sort_keys=True)+'\n').encode()); visit(value,path.name)
 def test_public_schema_has_no_protected_configuration_fields(self):
  text=FILES[0].read_text()
  for field in ("lanSshTarget","lanTlsUrl","tailnetSshTarget","tailnetTlsUrl","pveCaPem","tailscalePingTarget","archNfsSshTarget"):
   self.assertNotIn(field,text)
 def test_protected_key_inputs_keep_distinct_firewall_identity(self):
  docs=(ROOT/"docs/legacy-host-recovery.md").read_text()
  self.assertIn('proxmox-{plan,apply,firewall}-authorized-keys',docs)
  validator=ROOT/"scripts/validate-proxmox-bootstrap-keys"; base={**os.environ,"PROXMOX_PLAN_SSH_PUBLIC_KEYS":"ssh-ed25519 AAAA plan-a\nssh-ed25519 AAAB plan-b","PROXMOX_APPLY_SSH_PUBLIC_KEYS":"ssh-ed25519 AAAC apply","PROXMOX_FIREWALL_SSH_PUBLIC_KEYS":"ssh-ed25519 AAAD firewall"}
  self.assertEqual(subprocess.run((validator,),env=base,capture_output=True).returncode,0)
  overlap=dict(base); overlap["PROXMOX_FIREWALL_SSH_PUBLIC_KEYS"]="ssh-ed25519 AAAB different-firewall-comment"
  self.assertNotEqual(subprocess.run((validator,),env=overlap,capture_output=True).returncode,0)
 def test_legacy_recovery_keeps_distinct_session_and_boot_boundaries(self):
  docs=(ROOT/"docs/legacy-host-recovery.md").read_text()
  for boundary in ("not current mutation authority", "Invocation gap", "not standalone `status` or `rollback`",
                   "action-retryable", "rollback-in-progress", "released-committed", "released-recovered",
                   "commit-release-pending", "rollback-retry-pending", "boot-config-restored",
                   "boot-commit-config-verified", "Persistent=true", "120 seconds", "32 MiB", "48 MiB",
                   "Unknown or malformed runtime remnants keep both backends blocked"):
   self.assertIn(boundary,docs)
 def test_native_package_maintenance_does_not_grant_firewall_authority(self):
  plan=(ROOT/"ansible/playbooks/maintain-proxmox-packages.yml").read_text(); self.assertIn("role: proxmox_package_maintenance",plan); self.assertNotIn("ansible-deploy",plan); self.assertNotIn("proxmox_firewall",plan)
  self.assertFalse((ROOT/"ansible/playbooks/proxmox-packages-plan.yml").exists()); self.assertFalse((ROOT/"ansible/roles/proxmox_firewall").exists()); self.assertFalse((ROOT/"ansible/roles/proxmox_host").exists())
  inventory=(ROOT/"ansible/inventory/infrastructure.yml").read_text(); self.assertNotIn("proxmox_hosts:",inventory)
 def test_boot_and_timer_units_have_fixed_two_phase_order(self):
  files=ROOT/"infrastructure/proxmox-firewall/host"
  config=(files/"home-lab-proxmox-firewall-config-recovery.service").read_text(); post=(files/"home-lab-proxmox-firewall-post-recovery.service").read_text(); timer=(files/"home-lab-proxmox-firewall-rollback.service").read_text(); loop=(files/"proxmox-firewall-boot-recovery").read_text()
  self.assertIn("Before=pve-firewall.service proxmox-firewall.service",config); self.assertIn("ExecStart=/usr/local/libexec/home-lab/proxmox-firewall-boot-recovery",config)
  self.assertIn("After=home-lab-proxmox-firewall-config-recovery.service pve-firewall.service proxmox-firewall.service",post)
  timer_unit=(files/"home-lab-proxmox-firewall-rollback.timer").read_text()
  self.assertIn("After=home-lab-proxmox-firewall-post-recovery.service",timer); self.assertIn("OnCalendar=",timer_unit); self.assertIn("Persistent=true",timer_unit); self.assertNotIn("$1",loop); self.assertNotIn("$@",loop)

if __name__=="__main__": unittest.main()
