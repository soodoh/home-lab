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

variable "qualification_cloud_init_user_data" {
  type      = string
  sensitive = true
  default   = ""
}

locals {
  contract = yamldecode(file("${path.module}/../../contract/home-lab.yml"))
  node     = local.contract.proxmox.node
  image    = local.contract.debian.image
  vm_id    = 9900
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  insecure = false
}

resource "proxmox_download_file" "recovery_image" {
  count = var.enable_qualification ? 1 : 0

  content_type       = "import"
  datastore_id       = "local"
  node_name          = local.node
  url                = local.image.url
  checksum           = local.image.sha512
  checksum_algorithm = "sha512"
  file_name          = "home-lab-restic-recovery-debian-${local.contract.debian.build_id}.qcow2"
}

resource "proxmox_virtual_environment_file" "recovery_cloud_init" {
  count = var.enable_qualification ? 1 : 0

  content_type = "snippets"
  datastore_id = "local"
  node_name    = local.node

  source_raw {
    data      = var.qualification_cloud_init_user_data
    file_name = "home-lab-restic-recovery-cloud-init.yaml"
  }
}

resource "proxmox_virtual_environment_vm" "recovery" {
  count = var.enable_qualification ? 1 : 0

  node_name   = local.node
  vm_id       = local.vm_id
  name        = "home-lab-restic-recovery"
  description = "Disposable isolated Proton Restic restore qualification; never production VM 100"
  tags        = ["qualification", "disposable", "restic-recovery"]

  machine       = "q35"
  scsi_hardware = "virtio-scsi-single"
  boot_order    = ["scsi0"]
  on_boot       = false
  started       = true
  protection    = false

  reboot_after_update                  = true
  stop_on_destroy                      = true
  purge_on_destroy                     = true
  delete_unreferenced_disks_on_destroy = true

  agent {
    enabled = true
    wait_for_ip {
      ipv4 = true
      ipv6 = false
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
    import_from  = proxmox_download_file.recovery_image[0].id
    interface    = "scsi0"
    serial       = "RESTIC-RECOVERY-ROOT-32G"
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
    serial       = "RESTIC-RECOVERY-128G"
    size         = 128
    iothread     = true
    backup       = false
    cache        = "none"
    discard      = "on"
    replicate    = false
  }

  initialization {
    datastore_id      = "local-lvm"
    upgrade           = false
    user_data_file_id = proxmox_virtual_environment_file.recovery_cloud_init[0].id

    ip_config {
      ipv4 {
        address = "dhcp"
      }
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
      condition     = var.qualification_ssh_public_key != "" && var.qualification_cloud_init_user_data != ""
      error_message = "Qualification requires dedicated SSH user and host keys."
    }
    precondition {
      condition     = local.contract.proxmox.vm.vmid == 100 && local.vm_id == 9900
      error_message = "Recovery qualification safety bindings differ."
    }
    precondition {
      condition     = local.contract.proxmox.vm.name == "docker-host" && local.contract.proxmox.vm.desired_protection
      error_message = "Production VM identity or protection contract differs."
    }
  }
}

output "qualification" {
  value = var.enable_qualification ? {
    vm_id      = proxmox_virtual_environment_vm.recovery[0].vm_id
    name       = proxmox_virtual_environment_vm.recovery[0].name
    started    = proxmox_virtual_environment_vm.recovery[0].started
    boot_order = proxmox_virtual_environment_vm.recovery[0].boot_order
    ipv4       = proxmox_virtual_environment_vm.recovery[0].ipv4_addresses
  } : null
}
