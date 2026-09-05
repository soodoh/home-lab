#!/usr/bin/env python3
"""Reject widening of the accepted production-PVE/VM9900 capability."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
role=(ROOT/"ansible/roles/qualification_snippet_capability/tasks/main.yml").read_text(); inventory=(ROOT/"ansible/inventory/proxmox-qualification-bootstrap.yml").read_text(); playbook=(ROOT/"ansible/playbooks/install-qualification-snippet-capability.yml").read_text(); site=(ROOT/"ansible/playbooks/site.yml").read_text()
for required in ("lifecycle_profile == 'maintenance'","ansible_user == 'proxmox'","qualification_snippet_capability_contract.lifecycle.qualification_route.mode","production_vm_mutation_allowed","production_disk_attachment_allowed","production_state_allowed","temporary_tailnet_user","conventional_ssh_key_allowed","production-pve-vm9900-qualification","disposable_pve_admission_sha256","install-production-pve-vm9900-qualification-capability","/storage/local","backup,import,iso,snippets,vztmpl","/var/lib/vz/snippets","uid: 1900","gid: 1900","password_lock: true","debian-qualification-snippet-transport","debian-qualification-snippet-transaction","state: absent", "visudo --check --file=%s","hold-lock *","host-key *","first-boot","mutation_authorized: false"):
 assert required in role,required
for forbidden in ("NOPASSWD: ALL","restrict,command=","qualification_pve_public_key","lifecycle_profile: production","vm_id: 100","HOME-LAB-DEBIAN-64G","HOME-LAB-STATE","HOME-LAB-GAMES"):
 assert forbidden not in role
for required in ("StrictHostKeyChecking=yes","GlobalKnownHostsFile=/dev/null","UpdateHostKeys=no","IdentitiesOnly=yes","IdentityFile=none","PreferredAuthentications=none","PubkeyAuthentication=no","PasswordAuthentication=no","KbdInteractiveAuthentication=no","RequestTTY=no","HOME_LAB_DISPOSABLE_PVE_HOST","HOME_LAB_DISPOSABLE_PVE_KNOWN_HOSTS"):
 assert required in inventory,required
assert "hosts: proxmox_qualification" in playbook and "gather_facts: true" in playbook and "serial: 1" in playbook and "any_errors_fatal: true" in playbook and playbook.count("name: apply_lock") == 2 and "/var/lib/home-lab/reconciliation/operation.lock" in playbook
assert "qualification_snippet_capability" not in site
print("qualification_snippet_capability=verified route=production-pve-disposable-vm production_vm_mutation=false automatic_apply=false")
