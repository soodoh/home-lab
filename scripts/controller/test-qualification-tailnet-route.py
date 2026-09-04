#!/usr/bin/env python3
"""Bind the temporary VM9900 capability user to Tailscale SSH only."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; policy=(ROOT/"infrastructure/tofu/tailscale/main.tf").read_text(); contract=(ROOT/"infrastructure/contract/home-lab.yml").read_text(); role=(ROOT/"ansible/roles/qualification_snippet_capability/tasks/main.yml").read_text()
assert policy.count('"qualification-apply"') == 3
assert 'users  = ["proxmox", "ansible-plan", "ansible-deploy", "firewall-apply", "qualification-apply"]' in policy
assert 'users  = ["ansible-plan", "ansible-deploy", "firewall-apply", "qualification-apply"]' in policy
assert 'accept = ["proxmox", "ansible-plan", "ansible-deploy", "firewall-apply", "qualification-apply"]' in policy
assert 'deny   = ["docker", "root", "tofu-plan", "tofu-apply"]' in policy
assert "temporary_tailnet_user: qualification-apply" in contract and "conventional_ssh_key_allowed: false" in contract
assert "/home/qualification-apply/.ssh/authorized_keys" in role and "state: absent" in role and "restrict,command=" not in role
print("qualification_tailnet_route=verified conventional_keys=false root_denied=true")
