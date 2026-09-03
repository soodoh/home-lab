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
 def test_bootstrap_and_protected_preparer_require_distinct_firewall_key(self):
  prepare=(ROOT/"scripts/prepare-proxmox-nix-protected-inputs").read_text(); docs=(ROOT/"docs/proxmox-bootstrap.md").read_text()
  self.assertIn('proxmox-firewall-authorized-keys',prepare); self.assertIn('proxmox-{plan,apply,firewall}-authorized-keys',docs)
  validator=ROOT/"scripts/validate-proxmox-bootstrap-keys"; base={**os.environ,"PROXMOX_PLAN_SSH_PUBLIC_KEYS":"ssh-ed25519 AAAA plan-a\nssh-ed25519 AAAB plan-b","PROXMOX_APPLY_SSH_PUBLIC_KEYS":"ssh-ed25519 AAAC apply","PROXMOX_FIREWALL_SSH_PUBLIC_KEYS":"ssh-ed25519 AAAD firewall"}
  self.assertEqual(subprocess.run((validator,),env=base,capture_output=True).returncode,0)
  overlap=dict(base); overlap["PROXMOX_FIREWALL_SSH_PUBLIC_KEYS"]="ssh-ed25519 AAAB different-firewall-comment"
  self.assertNotEqual(subprocess.run((validator,),env=overlap,capture_output=True).returncode,0)
 def test_ansible_proxmox_surface_is_audit_only_during_nix_ownership(self):
  site=(ROOT/"ansible/playbooks/proxmox-site.yml").read_text(); self.assertIn("proxmox-audit.yml",site); self.assertNotIn("ansible-deploy",site); self.assertNotIn("proxmox_firewall",site)
  self.assertFalse((ROOT/"ansible/roles/proxmox_firewall").exists()); self.assertFalse((ROOT/"ansible/roles/proxmox_host").exists())
  inventory=(ROOT/"ansible/inventory/infrastructure.yml").read_text(); self.assertNotIn("proxmox_hosts:",inventory)
 def test_boot_and_timer_units_have_fixed_two_phase_order(self):
  files=ROOT/"infrastructure/proxmox-firewall/host"
  config=(files/"home-lab-proxmox-firewall-config-recovery.service").read_text(); post=(files/"home-lab-proxmox-firewall-post-recovery.service").read_text(); timer=(files/"home-lab-proxmox-firewall-rollback.service").read_text(); loop=(files/"proxmox-firewall-boot-recovery").read_text()
  self.assertIn("Before=pve-firewall.service proxmox-firewall.service",config); self.assertIn("ExecStart=/usr/local/libexec/home-lab/proxmox-firewall-boot-recovery",config)
  self.assertIn("After=home-lab-proxmox-firewall-config-recovery.service pve-firewall.service proxmox-firewall.service",post)
  timer_unit=(files/"home-lab-proxmox-firewall-rollback.timer").read_text()
  self.assertIn("After=home-lab-proxmox-firewall-post-recovery.service",timer); self.assertIn("OnCalendar=",timer_unit); self.assertIn("Persistent=true",timer_unit); self.assertNotIn("$1",loop); self.assertNotIn("$@",loop)

if __name__=="__main__": unittest.main()
