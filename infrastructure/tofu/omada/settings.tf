# Selective ownership: unset provider attributes retain controller values.
# SMTP/recipients belong to Ansible; individual notification selectors remain
# unchanged. Provider v0.11.10 cannot import sparse selector maps without updates.

import {
  for_each = local.wireless_networks

  to = omada_wireless_network.ssid[each.key]
  id = "${local.export.site.name}/${each.value.wlan_group_id}/${each.key}"
}

resource "omada_wireless_network" "ssid" {
  for_each = local.wireless_networks

  site                   = local.export.site.name
  wlan_group_id          = each.value.wlan_group_id
  name                   = each.value.name
  band                   = each.value.band
  security               = each.value.security
  broadcast              = each.value.broadcast
  vlan_enable            = each.value.vlan_enable
  vlan_id                = each.value.vlan_id
  guest_net              = each.value.guest_net
  enable_11r             = each.value.enable_11r
  pmf_mode               = each.value.pmf_mode
  psk_version            = each.value.psk_version
  psk_encryption         = each.value.psk_encryption
  multicast_enable       = each.value.multicast_enable
  multicast_channel_util = each.value.multicast_channel_util
  multicast_arp_cast     = each.value.multicast_arp_cast
  multicast_ipv6_cast    = each.value.multicast_ipv6_cast
  multicast_filter       = each.value.multicast_filter

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = var.omada_enable_management ? { site = local.export.site.name } : {}

  to = omada_gateway.site[0]
  id = "${each.value}/${local.desired.gateway.mac}"
}

resource "omada_gateway" "site" {
  count = var.omada_enable_management ? 1 : 0

  site              = local.export.site.name
  mac               = local.desired.gateway.mac
  hw_offload_enable = local.desired.gateway.hw_offload_enable
  lldp_enable       = local.desired.gateway.lldp_enable

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = var.omada_enable_management ? { site = local.export.site.name } : {}

  to = omada_upnp.site[0]
  id = each.value
}

resource "omada_upnp" "site" {
  count = var.omada_enable_management ? 1 : 0

  site   = local.export.site.name
  enable = local.desired.upnp.enable

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = var.omada_enable_management ? { site = local.export.site.name } : {}

  to = omada_ssh_settings.site[0]
  id = each.value
}

resource "omada_ssh_settings" "site" {
  count = var.omada_enable_management ? 1 : 0

  site          = local.export.site.name
  ssh_enable    = local.desired.ssh_settings.ssh_enable
  layer3_access = local.desired.ssh_settings.layer3_access

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = var.omada_enable_management ? { site = local.export.site.name } : {}

  to = omada_snmp.site[0]
  id = each.value
}

resource "omada_snmp" "site" {
  count = var.omada_enable_management ? 1 : 0

  site          = local.export.site.name
  v1_v2c_enable = local.desired.snmp.v1_v2c_enable
  v3_enable     = local.desired.snmp.v3_enable

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = var.omada_enable_management ? { site = local.export.site.name } : {}

  to = omada_site_settings.site[0]
  id = each.value
}

resource "omada_site_settings" "site" {
  count = var.omada_enable_management ? 1 : 0

  site                        = local.export.site.name
  auto_upgrade_enable         = local.desired.site_settings.auto_upgrade_enable
  mesh_enable                 = local.desired.site_settings.mesh_enable
  roaming_fast_roaming_enable = local.desired.site_settings.roaming_fast_roaming_enable

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = var.omada_enable_management ? { site = local.export.site.name } : {}

  to = omada_attack_defense.site[0]
  id = each.value
}

resource "omada_attack_defense" "site" {
  count = var.omada_enable_management ? 1 : 0

  site                      = local.export.site.name
  tcp_noflag_enable         = local.desired.attack_defense.tcp_noflag_enable
  tcp_winnuke_enable        = local.desired.attack_defense.tcp_winnuke_enable
  tcp_fin_syn_enable        = local.desired.attack_defense.tcp_fin_syn_enable
  tcp_fin_noack_enable      = local.desired.attack_defense.tcp_fin_noack_enable
  ping_death_enable         = local.desired.attack_defense.ping_death_enable
  ping_wan_enable           = local.desired.attack_defense.ping_wan_enable
  ip_option_enable          = local.desired.attack_defense.ip_option_enable
  ipopt_secure_enable       = local.desired.attack_defense.ipopt_secure_enable
  ipopt_loose_route_enable  = local.desired.attack_defense.ipopt_loose_route_enable
  ipopt_strict_route_enable = local.desired.attack_defense.ipopt_strict_route_enable
  ipopt_record_route_enable = local.desired.attack_defense.ipopt_record_route_enable
  ipopt_stream_enable       = local.desired.attack_defense.ipopt_stream_enable
  ipopt_timestamp_enable    = local.desired.attack_defense.ipopt_timestamp_enable
  ipopt_noop_enable         = local.desired.attack_defense.ipopt_noop_enable

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = var.omada_enable_management ? { site = local.export.site.name } : {}

  to = omada_iptv.site[0]
  id = each.value
}

resource "omada_iptv" "site" {
  count = var.omada_enable_management ? 1 : 0

  site              = local.export.site.name
  igmp_proxy_enable = local.desired.iptv.igmp_proxy_enable
  igmp_version      = local.desired.iptv.igmp_version
  enable            = local.desired.iptv.enable
  enabled_port_ids  = local.desired.iptv.enabled_port_ids

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = var.omada_enable_management ? { site = local.export.site.name } : {}

  to = omada_notification_settings.site[0]
  id = each.value
}

resource "omada_notification_settings" "site" {
  count = var.omada_enable_management ? 1 : 0

  site                     = local.export.site.name
  alert_email_enable       = local.desired.notification_settings.alert_email_enable
  alert_email_delay_enable = local.desired.notification_settings.alert_email_delay_enable
  alert_email_delay        = local.desired.notification_settings.alert_email_delay
  event_email_enable       = local.desired.notification_settings.event_email_enable
  event_email_delay_enable = local.desired.notification_settings.event_email_delay_enable
  event_email_delay        = local.desired.notification_settings.event_email_delay
  webhook_enable           = local.desired.notification_settings.webhook_enable

  lifecycle {
    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}
