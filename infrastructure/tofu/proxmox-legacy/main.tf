locals {
  contract = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  legacy   = local.contract.proxmox.legacy_container
}

check "retired_tombstone" {
  assert {
    condition = (
      local.legacy.retired &&
      local.legacy.vmid == 101 &&
      local.legacy.name == "tailscale-gateway"
    )
    error_message = "The legacy Proxmox root is a permanent empty tombstone for retired CT 101."
  }
}
