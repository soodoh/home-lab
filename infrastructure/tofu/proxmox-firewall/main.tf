# Cluster firewall ownership is separate from VM and hardware mapping state.
# An import apply still requires a separately approved remote-backed no-op plan.
locals {
  policy = jsondecode(file("${path.module}/../../policy/proxmox-firewall.json"))
}

resource "proxmox_virtual_environment_cluster_firewall" "policy" {
  count = var.proxmox_firewall_enable_management ? 1 : 0

  enabled       = local.policy.options.enable
  input_policy  = local.policy.options.policy_in
  output_policy = local.policy.options.policy_out

  lifecycle {
    prevent_destroy = true
    # PVE omits the default forward policy from GET, but the pinned provider
    # plans an update to ACCEPT on import. The host observer checks its value.
    ignore_changes = [forward_policy]

    precondition {
      condition = (
        local.policy.ownership == "pve-api" &&
        local.policy.activation == "pve-api" &&
        local.policy.options.enable &&
        local.policy.options.policy_in == "DROP" &&
        local.policy.options.policy_out == "ACCEPT" &&
        local.policy.options.policy_forward == "ACCEPT"
      )
      error_message = "The reviewed native Proxmox firewall policy must preserve its active access boundary."
    }
  }
}

resource "proxmox_virtual_environment_firewall_rules" "cluster" {
  count = var.proxmox_firewall_enable_management ? 1 : 0

  dynamic "rule" {
    for_each = local.policy.rules
    content {
      type   = lower(rule.value.direction)
      action = rule.value.action
      source = rule.value.source
      dport  = tostring(rule.value.destination_port)
      proto  = rule.value.protocol
      log    = rule.value.log
    }
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        length(local.policy.rules) > 0 &&
        alltrue([
          for rule in local.policy.rules :
          rule.direction == "IN" && rule.action == "ACCEPT" && rule.source != ""
        ])
      )
      error_message = "The reviewed Proxmox firewall must retain its ordered inbound access rules."
    }
  }
}

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
