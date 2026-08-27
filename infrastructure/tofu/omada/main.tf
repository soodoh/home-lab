locals {
  contract           = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  legacy_gateway_mac = lower(replace(local.contract.proxmox.legacy_container.mac, "-", ":"))
  export = var.omada_enable_management ? jsondecode(file(var.omada_export_path)) : {
    exported_at        = ""
    controller_version = ""
    site               = { id = "", name = "" }
    network            = { id = "", name = "", vlan_id = 1, gateway_subnet = "", dhcp_enabled = false, dhcp_start = "", dhcp_end = "" }
    reservations       = []
  }
  exported_reservations = {
    for reservation in local.export.reservations : lower(replace(reservation.mac, "-", ":")) => reservation
    if lower(replace(reservation.mac, "-", ":")) != local.legacy_gateway_mac
  }
  client_config = var.omada_enable_management ? jsondecode(file(var.omada_client_config_path)) : {
    client_aliases         = []
    requested_reservations = []
  }
  requested_reservations = {
    for reservation in local.client_config.requested_reservations :
    lower(replace(reservation.mac, "-", ":")) => reservation
  }
  reservations = var.omada_enable_management ? merge(local.exported_reservations, local.requested_reservations) : {}
  client_aliases = {
    for client in local.client_config.client_aliases :
    upper(replace(client.mac, ":", "-")) => client.alias
  }
}

provider "omada" {
  username        = var.omada_enable_management ? null : "disabled"
  password        = var.omada_enable_management ? null : "disabled"
  skip_tls_verify = false
}

check "export_identity" {
  assert {
    condition = !var.omada_enable_management || (
      local.export.controller_version == local.contract.omada.controller_version &&
      local.export.site.id != "" &&
      local.export.site.name != "" &&
      local.export.network.id != "" &&
      local.export.network.name != "" &&
      length(local.export.reservations) > 0
    )
    error_message = "The ignored Omada export is incomplete or does not match the contracted controller version."
  }
}


check "client_config" {
  assert {
    condition = !var.omada_enable_management || (
      length(local.client_aliases) == length(local.client_config.client_aliases) &&
      alltrue([
        for client in local.client_config.client_aliases :
        can(regex("^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$", client.mac)) && trimspace(client.alias) != ""
      ])
    )
    error_message = "The decrypted Omada client configuration must contain unique six-octet MAC addresses and non-empty aliases."
  }
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

resource "omada_dhcp_reservation" "reservation" {
  for_each = local.reservations

  site       = local.export.site.name
  network_id = omada_network.lan[0].id
  mac        = upper(replace(each.value.mac, ":", "-"))
  ip         = each.value.ip
  name       = each.value.name
  enable     = each.value.enable
}


resource "omada_client_alias" "client" {
  for_each = local.client_aliases

  site  = local.export.site.name
  mac   = each.key
  alias = each.value
}
