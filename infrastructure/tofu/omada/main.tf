locals {
  desired = jsondecode(file("${path.module}/desired.json"))
  export = var.omada_enable_management ? jsondecode(file(var.omada_export_path)) : {
    exported_at        = ""
    controller_version = ""
    site               = { id = "", name = "" }
    network            = { id = "", name = "" }
    reservations       = []
    port_forwards      = []
  }
  live_reservations = {
    for reservation in local.export.reservations : lower(replace(reservation.mac, "-", ":")) => reservation
  }
  live_port_forwards = {
    for port_forward in local.export.port_forwards : port_forward.id => port_forward
  }
  reservations  = var.omada_enable_management ? local.desired.reservations : {}
  port_forwards = var.omada_enable_management ? local.desired.port_forwards : {}
  export_matches_boundary = !var.omada_enable_management || (
    local.export.controller_version == var.omada_domain.controller_version &&
    local.export.site.id != "" &&
    local.export.site.name == var.omada_domain.site_name &&
    local.export.network.id != "" &&
    local.export.network.name == var.omada_domain.network_name &&
    local.desired.network.name == var.omada_domain.network_name &&
    try(
      timecmp(local.export.exported_at, timeadd(plantimestamp(), "-15m")) >= 0 &&
      timecmp(local.export.exported_at, plantimestamp()) <= 0,
      false,
    ) &&
    length(local.export.reservations) > 0 &&
    length(local.export.port_forwards) > 0 &&
    toset(keys(local.live_reservations)) == toset(keys(local.reservations)) &&
    toset(keys(local.live_port_forwards)) == toset(keys(local.port_forwards))
  )
}

provider "omada" {
  username        = var.omada_enable_management ? null : "disabled"
  password        = var.omada_enable_management ? null : "disabled"
  skip_tls_verify = false
}

check "export_identity" {
  assert {
    condition     = local.export_matches_boundary
    error_message = "The fresh Omada inventory must match the reviewed site, network, reservations, and port-forward identities."
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
  name           = local.desired.network.name
  vlan_id        = local.desired.network.vlan_id
  purpose        = "interface"
  gateway_subnet = local.desired.network.gateway_subnet
  dhcp_enabled   = local.desired.network.dhcp_enabled
  dhcp_start     = local.desired.network.dhcp_start
  dhcp_end       = local.desired.network.dhcp_end

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = local.export_matches_boundary
      error_message = "Refusing Omada management without a fresh matching inventory of every owned identity."
    }
  }
}

import {
  for_each = local.reservations

  to = omada_dhcp_reservation.reservation[each.key]
  id = "${local.export.site.name}/${upper(replace(each.key, ":", "-"))}"
}

resource "omada_dhcp_reservation" "reservation" {
  for_each = local.reservations

  site       = local.export.site.name
  network_id = omada_network.lan[0].id
  mac        = upper(replace(each.key, ":", "-"))
  ip         = each.value.ip
  name       = each.value.name
  enable     = each.value.enable
}

import {
  for_each = local.port_forwards

  to = omada_port_forward.port_forward[each.key]
  id = "${local.export.site.name}/${each.key}"
}

resource "omada_port_forward" "port_forward" {
  for_each = local.port_forwards

  site          = local.export.site.name
  name          = each.value.name
  enable        = each.value.enable
  external_port = each.value.external_port
  forward_ip    = each.value.forward_ip
  forward_port  = each.value.forward_port
  protocol      = each.value.protocol
  wan_port_ids  = each.value.wan_port_ids
  dmz           = each.value.dmz
}
