# Operational adoption stays separate from disposable mock-provider plans.
import {
  for_each = var.proxmox_firewall_enable_management ? { cluster = "cluster" } : {}
  to       = proxmox_virtual_environment_cluster_firewall.policy[0]
  id       = each.value
}

import {
  for_each = var.proxmox_firewall_enable_management ? { cluster = "cluster" } : {}
  to       = proxmox_virtual_environment_firewall_rules.cluster[0]
  id       = each.value
}
