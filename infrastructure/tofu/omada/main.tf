locals {
  export = var.omada_enable_management ? jsondecode(file(var.omada_export_path)) : {
    exported_at        = ""
    controller_version = ""
    site               = { id = "", name = "" }
    network            = { id = "", name = "", vlan_id = 1, gateway_subnet = "", dhcp_enabled = false, dhcp_start = "", dhcp_end = "" }
    vpn                = { id = "", name = "", enable = false, purpose = 0 }
    reservations       = []
  }
  reservations = var.omada_enable_management ? {
    for reservation in local.export.reservations : lower(replace(reservation.mac, "-", ":")) => reservation
  } : {}
}

provider "omada" {
  username        = var.omada_enable_management ? null : "disabled"
  password        = var.omada_enable_management ? null : "disabled"
  skip_tls_verify = false
}

check "export_identity" {
  assert {
    condition = !var.omada_enable_management || (
      local.export.controller_version == var.omada_domain.controller_version &&
      local.export.site.id != "" &&
      local.export.site.name == var.omada_domain.site_name &&
      local.export.network.id != "" &&
      local.export.network.name == var.omada_domain.network_name &&
      local.export.vpn.id != "" &&
      local.export.vpn.name == var.omada_domain.wireguard_server_name &&
      local.export.vpn.enable == true &&
      try(
        timecmp(local.export.exported_at, timeadd(plantimestamp(), "-15m")) >= 0 &&
        timecmp(local.export.exported_at, plantimestamp()) <= 0,
        false,
      ) &&
      length(local.export.reservations) > 0
    )
    error_message = "The ignored Omada export is stale, incomplete, or outside the contracted controller, site, network, and VPN identity."
  }
}

import {
  for_each = var.omada_enable_management ? { lan = local.export.network.id } : {}

  to = omada_network.lan[0]
  id = "${local.export.site.name}/${each.value}"
}

resource "omada_network" "lan" {
  count = var.omada_enable_management ? 1 : 0

  site           = local.export.site.name
  name           = local.export.network.name
  vlan_id        = local.export.network.vlan_id
  purpose        = "interface"
  gateway_subnet = local.export.network.gateway_subnet
  dhcp_enabled   = local.export.network.dhcp_enabled
  dhcp_start     = local.export.network.dhcp_start
  dhcp_end       = local.export.network.dhcp_end

  lifecycle {
    prevent_destroy = true
  }
}

import {
  for_each = local.reservations

  to = omada_dhcp_reservation.reservation[each.key]
  id = "${local.export.site.name}/${each.value.mac}"
}

import {
  for_each = var.omada_enable_management ? { wireguard = local.export.vpn.id } : {}

  to = omada_vpn.wireguard[0]
  id = "${local.export.site.name}/${each.value}"
}

resource "omada_vpn" "wireguard" {
  count = var.omada_enable_management ? 1 : 0

  site   = local.export.site.name
  name   = var.omada_domain.wireguard_server_name
  enable = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "omada_dhcp_reservation" "reservation" {
  for_each = local.reservations

  site       = local.export.site.name
  network_id = omada_network.lan[0].id
  mac        = upper(replace(each.value.mac, ":", "-"))
  ip         = each.value.ip
  name       = each.value.name
  enable     = each.value.enable
}
