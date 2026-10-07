locals {
  vm                = var.proxmox_vm.vm
  node              = var.proxmox_vm.node
  expected_hardware = jsondecode(file("${path.module}/expected-hardware.json"))
}

resource "proxmox_virtual_environment_vm" "debian" {
  node_name = local.node
  vm_id     = local.vm.vmid
  name      = local.vm.name

  machine       = local.vm.machine
  kvm_arguments = local.vm.cpu.kvm_arguments
  boot_order    = var.proxmox_vm.boot_order
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

  # Match the native importer's ascending bus order. Align old partial provider
  # state independently; none of these existing bus attachments is being moved.
  disk {
    datastore_id      = ""
    path_in_datastore = local.expected_hardware.gamesDiskIdentity
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

  # Adopt the existing boot volume, not a new disk or an image import.
  disk {
    datastore_id      = local.vm.boot_disk.datastore
    path_in_datastore = local.vm.boot_disk.volume
    file_format       = "raw"
    interface         = local.vm.boot_disk.interface
    serial            = local.vm.boot_disk.serial
    size              = local.vm.boot_disk.size_gb
    iothread          = local.vm.boot_disk.iothread
    backup            = local.vm.boot_disk.backup
    cache             = "none"
    discard           = local.vm.boot_disk.discard
    replicate         = true
    ssd               = local.vm.boot_disk.ssd
  }

  network_device {
    bridge      = var.proxmox_vm.network.bridge
    firewall    = true
    mac_address = var.proxmox_vm.network.docker_host_mac
    model       = "virtio"
  }

  hostpci {
    device  = "hostpci1"
    mapping = local.vm.pci.gpu.mapping
    pcie    = local.vm.pci.gpu.pcie
    xvga    = local.vm.pci.gpu.xvga
    rombar  = true
  }

  hostpci {
    device  = "hostpci2"
    mapping = local.vm.pci.gpu_audio.mapping
    pcie    = local.vm.pci.gpu_audio.pcie
    rombar  = true
  }

  usb {
    mapping = local.vm.usb.zigbee.mapping
  }

  usb {
    mapping = local.vm.usb.zwave.mapping
  }

  usb {
    mapping = local.vm.usb.bluetooth.mapping
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
    datastore_id         = var.proxmox_vm.cloud_init.drive_datastore
    interface            = var.proxmox_vm.cloud_init.drive_interface
    upgrade              = true
    user_data_file_id    = local.cloud_init_file_ids.user
    meta_data_file_id    = local.cloud_init_file_ids.meta
    network_data_file_id = local.cloud_init_file_ids.network
  }

  startup {
    order      = "2"
    up_delay   = "30"
    down_delay = "60"
  }

  depends_on = [
    proxmox_hardware_mapping_pci.device,
    proxmox_hardware_mapping_usb.device,
    proxmox_storage_lvmthin.local,
    proxmox_network_linux_bridge.lan,
  ]

  lifecycle {
    # PVE does not report a file format for a raw physical device.
    ignore_changes = [disk[0].file_format]

    precondition {
      condition = (
        startswith(local.expected_hardware.gamesDiskIdentity, "/dev/disk/by-id/") &&
        length(local.expected_hardware.usbMappings) == 2 &&
        toset(keys(local.serial_usb_paths)) == toset([
          local.vm.usb.zigbee.mapping,
          local.vm.usb.zwave.mapping,
        ]) &&
        length(toset(values(local.serial_usb_paths))) == 2 &&
        alltrue([
          for item in local.expected_hardware.usbMappings :
          can(regex("^[0-9]+-[0-9]+(?:\\.[0-9]+)*$", item.port)) && length(item.serial) > 0
        ])
      )
      error_message = "The reviewed disk and USB identities must be complete and unique."
    }
  }
}
