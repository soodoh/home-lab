mock_provider "proxmox" {}

variables {
  proxmox_endpoint                   = "https://proxmox.example.invalid:8006/api2/json"
  proxmox_firewall_enable_management = true
}

run "snapshot_rpc_has_only_the_backup_peer_host_rule" {
  command = plan

  assert {
    condition = length([
      for rule in proxmox_virtual_environment_firewall_rules.cluster[0].rule : rule
      if rule.dport == "2444"
    ]) == 1
    error_message = "Snapshot RPC needs exactly one explicit host firewall rule."
  }

  assert {
    condition = alltrue([
      for rule in proxmox_virtual_environment_firewall_rules.cluster[0].rule :
      rule.action == "ACCEPT" && rule.type == "in" && rule.proto == "tcp" && rule.source == "100.116.163.42/32"
      if rule.dport == "2444"
    ])
    error_message = "Do not expose root snapshot RPC to the LAN, the whole tailnet, UDP or any non-backup peer."
  }

  assert {
    condition = (
      proxmox_virtual_environment_cluster_firewall.policy[0].enabled &&
      proxmox_virtual_environment_cluster_firewall.policy[0].input_policy == "DROP"
    )
    error_message = "Adding snapshot RPC must preserve the enabled default-deny host boundary."
  }
}
