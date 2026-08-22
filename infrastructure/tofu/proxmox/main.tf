locals {
  vm                    = local.contract.proxmox.vm
  node                  = local.contract.proxmox.node
  use_hardware_mappings = local.vm.hardware_attachment_mode == "managed"
}

resource "proxmox_virtual_environment_vm" "debian" {
  node_name = local.node
  vm_id     = local.vm.vmid
  name      = local.vm.name

  machine       = local.vm.machine
  kvm_arguments = local.vm.cpu.kvm_arguments
  boot_order    = local.contract.debian.os_disk.boot_order
  scsi_hardware = "virtio-scsi-single"
  on_boot       = local.vm.on_boot
  started       = local.vm.started
  protection    = local.vm.desired_protection

  reboot_after_update                  = true
  stop_on_destroy                      = false
  purge_on_destroy                     = false
  delete_unreferenced_disks_on_destroy = false

  agent {
    enabled = true
    trim    = false

    wait_for_ip {
      disabled = true
    }
  }

  cpu {
    cores   = local.vm.cpu.cores
    sockets = local.vm.cpu.sockets
    type    = local.vm.cpu.type
  }

  memory {
    dedicated = local.vm.memory_mb
    floating  = 0
  }

  # Preserve provider TypeList indexes after permanent retirement of the former disk[0].
  # The whole ignored block is inert and prevents index shifts from mutating scsi1 or scsi2.
  disk {
    datastore_id = local.vm.retired_disk_slot.datastore
    import_from  = ""
    interface    = local.vm.retired_disk_slot.interface
    size         = local.vm.retired_disk_slot.size_gb
    iothread     = local.vm.retired_disk_slot.iothread
    backup       = true
    cache        = "none"
    discard      = "ignore"
    replicate    = true
    ssd          = false
  }

  disk {
    datastore_id      = ""
    path_in_datastore = var.games_disk_by_id
    file_format       = "raw"
    interface         = local.vm.games_disk.interface
    backup            = local.vm.games_disk.backup
    cache             = "none"
    discard           = local.vm.games_disk.discard
    iothread          = local.vm.games_disk.iothread
    replicate         = true
    ssd               = local.vm.games_disk.ssd
  }

  disk {
    datastore_id = local.vm.state_disk.datastore
    interface    = local.vm.state_disk.interface
    serial       = local.vm.state_disk.serial
    size         = local.vm.state_disk.size_gb
    iothread     = local.vm.state_disk.iothread
    backup       = local.vm.state_disk.backup
    cache        = "none"
    discard      = local.vm.state_disk.discard
    replicate    = true
    ssd          = local.vm.state_disk.ssd
  }

  network_device {
    bridge      = local.contract.network.bridge
    firewall    = true
    mac_address = local.contract.network.docker_host.mac
    model       = "virtio"
  }

  hostpci {
    device  = "hostpci1"
    id      = local.use_hardware_mappings ? null : local.vm.pci.gpu.bdf
    mapping = local.use_hardware_mappings ? local.vm.pci.gpu.mapping : null
    pcie    = local.vm.pci.gpu.pcie
    xvga    = local.vm.pci.gpu.xvga
    rombar  = true
  }

  hostpci {
    device  = "hostpci2"
    id      = local.use_hardware_mappings ? null : local.vm.pci.gpu_audio.bdf
    mapping = local.use_hardware_mappings ? local.vm.pci.gpu_audio.mapping : null
    pcie    = local.vm.pci.gpu_audio.pcie
    rombar  = true
  }

  usb {
    host    = local.use_hardware_mappings ? null : local.serial_usb_paths.zigbee
    mapping = local.use_hardware_mappings ? local.vm.usb.zigbee.mapping : null
  }

  usb {
    host    = local.use_hardware_mappings ? null : local.serial_usb_paths.zwave
    mapping = local.use_hardware_mappings ? local.vm.usb.zwave.mapping : null
  }

  usb {
    host    = local.use_hardware_mappings ? null : local.vm.usb.bluetooth.host
    mapping = local.use_hardware_mappings ? local.vm.usb.bluetooth.mapping : null
    usb3    = local.vm.usb.bluetooth.usb3
  }

  serial_device {
    device = "socket"
  }

  operating_system {
    type = "l26"
  }

  vga {
    type = "none"
  }

  initialization {
    datastore_id = local.contract.debian.cloud_init.drive_datastore
    interface    = local.contract.debian.cloud_init.drive_interface
    upgrade      = true
    user_data_file_id = format(
      "%s:snippets/%s",
      local.contract.debian.cloud_init.datastore,
      basename(local.contract.debian.cloud_init.user_data.snippet_path),
    )
    meta_data_file_id = format(
      "%s:snippets/%s",
      local.contract.debian.cloud_init.datastore,
      basename(local.contract.debian.cloud_init.meta_data.snippet_path),
    )
    network_data_file_id = format(
      "%s:snippets/%s",
      local.contract.debian.cloud_init.datastore,
      basename(local.contract.debian.cloud_init.network_data.snippet_path),
    )
  }

  startup {
    order      = "2"
    up_delay   = "30"
    down_delay = "60"
  }

  depends_on = [
    proxmox_hardware_mapping_pci.device,
    proxmox_hardware_mapping_usb.device,
  ]

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [disk[0], disk[1].file_format]
  }
}
