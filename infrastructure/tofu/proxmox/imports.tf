# Imports record ownership; they do not authorize an apply. In particular, the
# file resource cannot reconstruct source_raw on import and proposes replacement.
import {
  to = proxmox_storage_directory.local
  id = "local"
}

import {
  to = proxmox_storage_lvmthin.local
  id = "local-lvm"
}

import {
  to = proxmox_storage_zfspool.storage
  id = "storage"
}

import {
  to = proxmox_network_linux_bridge.lan
  id = "${local.node}:${var.proxmox_vm.network.bridge}"
}

import {
  to = proxmox_virtual_environment_dns.node
  id = local.node
}

import {
  to = proxmox_virtual_environment_time.node
  id = local.node
}

import {
  for_each = local.cloud_init_snippets
  to       = proxmox_virtual_environment_file.cloud_init[each.key]
  id       = "${local.node}/${proxmox_storage_directory.local.id}:snippets/${each.value}"
}
