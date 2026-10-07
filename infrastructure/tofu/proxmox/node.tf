# Native API ownership. Network reloads affect the management path and require
# independent console access and review of all pending node network changes.
resource "proxmox_network_linux_bridge" "lan" {
  node_name = local.node
  name      = var.proxmox_vm.network.bridge
  address   = "192.168.0.123/24"
  gateway   = "192.168.0.1"
  ports     = ["eno1"]
  mtu       = var.proxmox_bridge_mtu
  autostart = true
  reload    = true
}

resource "proxmox_virtual_environment_dns" "node" {
  node_name = local.node
  domain    = "lan"
  servers   = ["192.168.0.1", "192.168.0.1"]
}

resource "proxmox_virtual_environment_time" "node" {
  node_name = local.node
  time_zone = "America/Los_Angeles"
}
