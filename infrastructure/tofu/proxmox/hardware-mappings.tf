locals {
  pci_mappings = local.use_hardware_mappings ? {
    coral     = local.vm.pci.coral
    gpu       = local.vm.pci.gpu
    gpu_audio = local.vm.pci.gpu_audio
  } : {}
  serial_usb_paths = var.serial_usb_paths
  usb_mappings = local.use_hardware_mappings ? {
    zigbee    = local.vm.usb.zigbee
    zwave     = local.vm.usb.zwave
    bluetooth = local.vm.usb.bluetooth
  } : {}
}

resource "proxmox_hardware_mapping_pci" "device" {
  for_each = local.pci_mappings

  name    = each.value.mapping
  comment = "home-lab ${each.key}; managed by OpenTofu"
  map = [{
    id   = each.value.vendor_device
    node = local.node
    path = each.value.bdf
  }]

  lifecycle {
    prevent_destroy = true
  }
}

resource "proxmox_hardware_mapping_usb" "device" {
  for_each = local.usb_mappings

  name    = each.value.mapping
  comment = "home-lab ${each.key}; managed by OpenTofu"
  map = [{
    id   = each.value.vendor_device
    node = local.node
    path = contains(keys(local.serial_usb_paths), each.key) ? local.serial_usb_paths[each.key] : null
  }]

  lifecycle {
    prevent_destroy = true
  }
}
