# Staged ownership: leave disabled until independent console access, an exact live
# inventory and an import-only no-op plan have been verified. The same policy is
# independently checked by the native Proxmox host observer.
locals {
  cluster_firewall_policy = jsondecode(file("${path.module}/../../policy/proxmox-firewall.json"))
}

resource "proxmox_virtual_environment_cluster_firewall" "policy" {
  count = var.proxmox_manage_cluster_firewall ? 1 : 0

  enabled       = local.cluster_firewall_policy.options.enable
  input_policy  = local.cluster_firewall_policy.options.policy_in
  output_policy = local.cluster_firewall_policy.options.policy_out

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        local.cluster_firewall_policy.ownership == "pve-api" &&
        local.cluster_firewall_policy.activation == "pve-api" &&
        local.cluster_firewall_policy.options.enable &&
        local.cluster_firewall_policy.options.policy_in == "DROP" &&
        local.cluster_firewall_policy.options.policy_out == "ACCEPT"
      )
      error_message = "The reviewed native Proxmox firewall policy must preserve its active access boundary."
    }
  }
}

resource "proxmox_virtual_environment_firewall_rules" "cluster" {
  count = var.proxmox_manage_cluster_firewall ? 1 : 0

  dynamic "rule" {
    for_each = local.cluster_firewall_policy.rules
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
        length(local.cluster_firewall_policy.rules) > 0 &&
        alltrue([
          for rule in local.cluster_firewall_policy.rules :
          rule.direction == "IN" && rule.action == "ACCEPT" && rule.source != ""
        ])
      )
      error_message = "The reviewed Proxmox firewall must retain its ordered inbound access rules."
    }
  }
}

import {
  for_each = var.proxmox_manage_cluster_firewall ? { cluster = "cluster" } : {}
  to       = proxmox_virtual_environment_cluster_firewall.policy[0]
  id       = each.value
}

import {
  for_each = var.proxmox_manage_cluster_firewall ? { cluster = "cluster" } : {}
  to       = proxmox_virtual_environment_firewall_rules.cluster[0]
  id       = each.value
}
