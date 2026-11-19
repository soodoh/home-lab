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
      if contains(["2444", "2445"], rule.dport)
    ]) == 2
    error_message = "The snapshot control and read-only data ports each need one host firewall rule."
  }

  assert {
    condition = alltrue([
      for rule in proxmox_virtual_environment_firewall_rules.cluster[0].rule :
      rule.action == "ACCEPT" && rule.type == "in" && rule.proto == "tcp" && rule.source == "100.116.163.42/32"
      if contains(["2444", "2445"], rule.dport)
    ])
    error_message = "Do not expose snapshot control or data to the LAN, the whole tailnet, UDP or any non-backup peer."
  }

  assert {
    condition = (
      proxmox_virtual_environment_cluster_firewall.policy[0].enabled &&
      proxmox_virtual_environment_cluster_firewall.policy[0].input_policy == "DROP"
    )
    error_message = "Adding snapshot RPC must preserve the enabled default-deny host boundary."
  }
}

run "peer_relay_admits_only_udp_on_3478" {
  command = plan

  assert {
    condition = [
      for rule in proxmox_virtual_environment_firewall_rules.cluster[0].rule :
      [rule.action, rule.type, rule.proto, rule.source]
      if rule.dport == "3478"
    ] == [["ACCEPT", "in", "udp", "0.0.0.0/0"]]
    error_message = "The peer relay needs exactly one ingress rule for IPv4 UDP 3478, not TCP."
  }
}
