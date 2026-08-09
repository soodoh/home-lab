locals {
  contract               = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  legacy_gateway_retired = local.contract.proxmox.legacy_container.retirement_stage == "retired"
  legacy_gateway_mac     = lower(replace(local.contract.proxmox.legacy_container.mac, "-", ":"))
  export = var.omada_enable_management ? jsondecode(file(var.omada_export_path)) : {
    exported_at        = ""
    controller_version = ""
    site               = { id = "", name = "" }
    network            = { id = "", name = "", vlan_id = 1, gateway_subnet = "", dhcp_enabled = false, dhcp_start = "", dhcp_end = "" }
    reservations       = []
  }
  reservations = var.omada_enable_management ? {
    for reservation in local.export.reservations : lower(replace(reservation.mac, "-", ":")) => reservation
    if !(local.legacy_gateway_retired && lower(replace(reservation.mac, "-", ":")) == local.legacy_gateway_mac)
  } : {}
}

provider "omada" {
  username        = var.omada_enable_management ? null : "disabled"
  password        = var.omada_enable_management ? null : "disabled"
  skip_tls_verify = false
}

check "adoption_gate" {
  assert {
    condition     = !var.omada_enable_management || var.adoption_mode || var.qualification_mode || (var.adoption_complete && local.contract.omada.provider_qualified)
    error_message = "Omada management is blocked until import and live provider qualification are complete."
  }
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

resource "omada_dhcp_reservation" "qualification" {
  count = var.enable_qualification ? 1 : 0

  network_id = var.qualification_network_id
  mac        = var.qualification_mac
  ip         = var.qualification_ip
  name       = "tofu-provider-qualification"
  enable     = true

  lifecycle {
    precondition {
      condition = (
        var.qualification_network_id != "" &&
        var.qualification_mac != "" &&
        var.qualification_ip != ""
      )
      error_message = "Qualification requires an explicitly selected disposable network, MAC, and IP."
    }
  }
}
