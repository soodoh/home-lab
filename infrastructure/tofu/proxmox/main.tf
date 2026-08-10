locals {
  vm                        = local.contract.proxmox.vm
  node                      = local.contract.proxmox.node
  recovery                  = var.phase == "recovery"
  retain_recovery_resources = local.recovery || local.vm.hardware_attachment_mode == "managed"
  use_hardware_mappings     = local.retain_recovery_resources
}

resource "proxmox_download_file" "arch_recovery_image" {
  count = local.retain_recovery_resources ? 1 : 0

  content_type       = "import"
  datastore_id       = "local"
  node_name          = local.node
  url                = local.vm.cloud_image.url
  checksum           = local.vm.cloud_image.sha256
  checksum_algorithm = "sha256"
  file_name          = "Arch-Linux-x86_64-cloudimg-${local.vm.cloud_image.version}.qcow2"
}

resource "proxmox_virtual_environment_vm" "arch" {
  node_name = local.node
  vm_id     = local.vm.vmid
  name      = local.vm.name

  machine       = local.vm.machine
  kvm_arguments = local.vm.cpu.kvm_arguments
  boot_order    = ["scsi0", "ide2", "net0"]
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

  disk {
    datastore_id = local.vm.root_disk.datastore
    import_from  = local.retain_recovery_resources ? proxmox_download_file.arch_recovery_image[0].id : ""
    interface    = local.vm.root_disk.interface
    size         = local.vm.root_disk.size_gb
    iothread     = local.vm.root_disk.iothread
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

  network_device {
    bridge      = local.contract.network.bridge
    firewall    = true
    mac_address = local.contract.network.arch.mac
    model       = "virtio"
  }

  hostpci {
    device  = "hostpci0"
    id      = local.use_hardware_mappings ? null : local.vm.pci.coral.bdf
    mapping = local.use_hardware_mappings ? local.vm.pci.coral.mapping : null
    rombar  = true
  }

  hostpci {
    device   = "hostpci1"
    id       = local.use_hardware_mappings ? null : local.vm.pci.gpu.bdf
    mapping  = local.use_hardware_mappings ? local.vm.pci.gpu.mapping : null
    pcie     = local.vm.pci.gpu.pcie
    rom_file = local.vm.pci.gpu.rom_file
    xvga     = local.vm.pci.gpu.xvga
    rombar   = true
  }

  hostpci {
    device  = "hostpci2"
    id      = local.use_hardware_mappings ? null : local.vm.pci.gpu_audio.bdf
    mapping = local.use_hardware_mappings ? local.vm.pci.gpu_audio.mapping : null
    pcie    = local.vm.pci.gpu_audio.pcie
    rombar  = true
  }

  usb {
    host    = local.use_hardware_mappings ? null : local.vm.usb.zigbee.host
    mapping = local.use_hardware_mappings ? local.vm.usb.zigbee.mapping : null
  }

  usb {
    host    = local.use_hardware_mappings ? null : local.vm.usb.zwave.host
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

  smbios {
    uuid = local.vm.smbios_uuid
  }

  operating_system {
    type = "l26"
  }

  vga {
    type = "none"
  }

  dynamic "initialization" {
    for_each = local.recovery ? [1] : []
    content {
      datastore_id = local.vm.root_disk.datastore
      upgrade      = false

      dns {
        servers = local.contract.network.dns
      }

      ip_config {
        ipv4 {
          address = local.contract.network.arch.ipv4
          gateway = local.contract.network.gateway
        }
      }

      user_account {
        username = local.contract.arch.user
        keys     = [var.recovery_ssh_public_key]
      }
    }
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
    ignore_changes  = [disk[1].file_format]

    precondition {
      condition     = !local.recovery || var.recovery_ssh_public_key != ""
      error_message = "Fresh recovery requires a bootstrap SSH public key."
    }

    precondition {
      condition     = !local.recovery || local.use_hardware_mappings
      error_message = "Fresh recovery requires managed hardware mappings; raw host-device IDs cannot use API-token auth."
    }
  }
}
