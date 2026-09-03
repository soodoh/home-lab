#!/usr/bin/env python3
"""Reject widening or production inclusion of the disposable snippet capability."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
role=(ROOT/"ansible/roles/qualification_snippet_capability/tasks/main.yml").read_text(); inventory=(ROOT/"ansible/inventory/proxmox-qualification-bootstrap.yml").read_text(); playbook=(ROOT/"ansible/playbooks/install-qualification-snippet-capability.yml").read_text(); site=(ROOT/"ansible/playbooks/site.yml").read_text()
for required in ("lifecycle_profile == 'bootstrap'","qualification_snippet_capability_contract.network.proxmox.ipv4","qualification_snippet_capability_contract.vm_100.networking.ipv4","disposable_pve_admission_sha256","qualification_pve_public_key_sha256","install-isolated-pve-qualification-capability","uid: 1900","gid: 1900","password_lock: true","debian-qualification-snippet-transport","debian-qualification-snippet-transaction","restrict,command=", "visudo --check --file=%s","hold-lock *","mutation_authorized: false"):
 assert required in role,required
for forbidden in ("NOPASSWD: ALL","ansible_host: proxmox","lifecycle_profile: production"):
 assert forbidden not in role
for required in ("StrictHostKeyChecking=yes","GlobalKnownHostsFile=/dev/null","UpdateHostKeys=no","IdentitiesOnly=yes","IdentityFile=","PreferredAuthentications=publickey","PasswordAuthentication=no","KbdInteractiveAuthentication=no","RequestTTY=no","HOME_LAB_DISPOSABLE_PVE_HOST","HOME_LAB_DISPOSABLE_PVE_KNOWN_HOSTS","HOME_LAB_DISPOSABLE_PVE_BOOTSTRAP_PUBLIC_KEY"):
 assert required in inventory,required
assert "hosts: proxmox_qualification" in playbook and "serial: 1" in playbook and "any_errors_fatal: true" in playbook
assert "qualification_snippet_capability" not in site
print("qualification_snippet_capability=verified production_unreachable=true automatic_apply=false")
