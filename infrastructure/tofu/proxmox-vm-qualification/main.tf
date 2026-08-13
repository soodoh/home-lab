variable "proxmox_endpoint" {
  type = string
}

variable "enable_qualification" {
  type    = bool
  default = false
}

variable "qualification_ssh_public_key" {
  type      = string
  sensitive = true
  default   = ""
}

locals {
  contract = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  node     = local.contract.proxmox.node
  vm       = local.contract.proxmox.vm
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  insecure = false

  ssh {
    agent    = true
    username = "root"

    node {
      name    = local.node
      address = "192.168.0.123"
    }
  }
}

resource "proxmox_download_file" "arch_cloud_image" {
  count = var.enable_qualification ? 1 : 0

  content_type       = "iso"
  datastore_id       = "local"
  node_name          = local.node
  url                = local.vm.cloud_image.url
  checksum           = local.vm.cloud_image.sha256
  checksum_algorithm = "sha256"
  file_name          = "VM100-NixOS-Qualification-Arch-${local.vm.cloud_image.version}.qcow2.img"
}

resource "proxmox_virtual_environment_vm" "qualification" {
  count = var.enable_qualification ? 1 : 0

  node_name   = local.node
  vm_id       = 9900
  name        = "vm-100-nixos-qualification"
  description = "Disposable provider, Disko, and isolated-dockerd qualification; never production VM 100"
  tags        = ["qualification", "disposable", "nixos-migration"]

  machine       = "q35"
  scsi_hardware = "virtio-scsi-single"
  boot_order    = ["scsi0"]
  on_boot       = false
  started       = false
  protection    = false

  reboot_after_update                  = true
  stop_on_destroy                      = true
  purge_on_destroy                     = true
  delete_unreferenced_disks_on_destroy = true

  agent {
    enabled = true
    wait_for_ip {
      disabled = true
    }
  }

  cpu {
    cores = 8
    type  = "host"
  }

  memory {
    dedicated = 16384
    floating  = 0
  }

  disk {
    datastore_id = "local-lvm"
    file_id      = proxmox_download_file.arch_cloud_image[0].id
    interface    = "scsi0"
    serial       = "QUAL-SOURCE-32G"
    size         = 32
    iothread     = true
    backup       = false
    cache        = "none"
    discard      = "on"
    replicate    = false
  }

  disk {
    datastore_id = "local-lvm"
    interface    = "scsi1"
    serial       = "QUAL-GAMES-32G"
    size         = 32
    iothread     = true
    backup       = false
    cache        = "none"
    discard      = "on"
    replicate    = false
  }

  disk {
    datastore_id = "local-lvm"
    interface    = "scsi2"
    serial       = "QUAL-NIXOS-128G"
    size         = 128
    iothread     = true
    backup       = false
    cache        = "none"
    discard      = "on"
    replicate    = false
  }

  initialization {
    datastore_id = "local-lvm"
    upgrade      = false

    ip_config {
      ipv4 {
        address = "dhcp"
      }
    }

    user_account {
      keys     = [var.qualification_ssh_public_key]
      username = "arch"
    }
  }

  network_device {
    bridge   = local.contract.network.bridge
    firewall = true
    model    = "virtio"
  }

  serial_device {
    device = "socket"
  }

  operating_system {
    type = "l26"
  }

  lifecycle {
    precondition {
      condition     = var.qualification_ssh_public_key != ""
      error_message = "Qualification requires a dedicated SSH public key."
    }
    precondition {
      condition     = local.vm.vmid == 100 && local.contract.network.arch.ipv4 != "dhcp"
      error_message = "Qualification safety bindings require production VMID 100 and a non-DHCP production address."
    }
  }
}

output "qualification" {
  value = var.enable_qualification ? {
    vm_id      = proxmox_virtual_environment_vm.qualification[0].vm_id
    name       = proxmox_virtual_environment_vm.qualification[0].name
    started    = proxmox_virtual_environment_vm.qualification[0].started
    boot_order = proxmox_virtual_environment_vm.qualification[0].boot_order
    disks = {
      source    = { interface = "scsi0", serial = "QUAL-SOURCE-32G", size_gb = 32 }
      games     = { interface = "scsi1", serial = "QUAL-GAMES-32G", size_gb = 32 }
      candidate = { interface = "scsi2", serial = "QUAL-NIXOS-128G", size_gb = 128 }
    }
  } : null
}
