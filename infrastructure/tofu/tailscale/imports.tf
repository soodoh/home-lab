# Native imports bootstrap ownership without rewriting existing configuration.
# Review a matching, import-only plan before admitting intentional changes.
import {
  for_each = var.tailscale_enable_management ? toset(["tailnet"]) : toset([])
  to       = tailscale_dns_configuration.tailnet[0]
  id       = "dns_configuration"
}

import {
  for_each = var.tailscale_enable_management ? toset(["tailnet"]) : toset([])
  to       = tailscale_tailnet_settings.tailnet[0]
  id       = "tailnet_settings"
}

import {
  for_each = local.managed_servers
  to       = tailscale_device_tags.servers[each.key]
  id       = each.value.node_id
}
