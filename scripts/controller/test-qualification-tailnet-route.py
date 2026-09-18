#!/usr/bin/env python3
"""Bind retained Tailscale SSH users after VM9900 host retirement."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; policy=(ROOT/"infrastructure/tofu/tailscale/main.tf").read_text(); contract=(ROOT/"infrastructure/contract/home-lab.yml").read_text(); role=(ROOT/"ansible/roles/qualification_snippet_capability/tasks/main.yml").read_text()
assert policy.count('"qualification-apply"') == 1
assert policy.count('"ansible-deploy"') == 3
assert 'users  = ["ansible-deploy", "ansible-package-apply"]' in policy
assert 'accept = ["docker", "ansible-deploy", "ansible-package-apply"]' in policy
assert 'users  = ["proxmox", "firewall-apply"]' in policy
assert 'users  = ["firewall-apply"]' in policy
assert 'accept = ["proxmox", "firewall-apply"]' in policy
assert 'deny   = ["ansible-deploy", "ansible-plan", "docker", "qualification-apply", "root", "tofu-plan", "tofu-apply"]' in policy
assert "- ansible-plan" in contract and policy.count('"ansible-plan"') == 1
assert "temporary_tailnet_user: qualification-apply" in contract and "conventional_ssh_key_allowed: false" in contract
assert "- path: /vms/9900" not in contract and contract.count("role: HomeLabTofuPlanDiskInspect") == 2
assert "/home/qualification-apply/.ssh/authorized_keys" in role and "state: absent" in role and "restrict,command=" not in role
print("qualification_tailnet_route=retired proxmox_ansible_deploy=false docker_ansible_deploy=true")
