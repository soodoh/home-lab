variable "proxmox_endpoint" {
  type = string
}

variable "qualification_enabled" {
  type    = bool
  default = false
}

variable "qualification_vmid" {
  type = number

  validation {
    condition     = var.qualification_vmid >= 9901 && var.qualification_vmid <= 9999
    error_message = "Disk adoption qualification VMID must be in the reviewed disposable 9901-9999 range."
  }
}

variable "qualification_node" {
  type = string

  validation {
    condition     = length(var.qualification_node) > 0
    error_message = "Qualification node is required."
  }
}

variable "qualification_datastore" {
  type = string

  validation {
    condition     = length(var.qualification_datastore) > 0
    error_message = "Qualification datastore is required."
  }
}

variable "qualification_adopt_scsi3" {
  type    = bool
  default = false
}

variable "qualification_candidate_volume" {
  type    = string
  default = ""

  validation {
    condition     = !var.qualification_adopt_scsi3 || can(regex("^[0-9]+/vm-[0-9]+-disk-[0-9]+\\.raw$", var.qualification_candidate_volume))
    error_message = "scsi3 adoption requires an exact qualification-only raw volume path."
  }
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  insecure = false
}

resource "proxmox_virtual_environment_vm" "disk_adoption" {
  count = var.qualification_enabled ? 1 : 0

  node_name   = var.qualification_node
  vm_id       = var.qualification_vmid
  name        = "home-lab-disk-adoption-qualification-${var.qualification_vmid}"
  description = "Disposable offline VM for bpg/proxmox TypeList disk-adoption qualification; never VM 100 or VM 9900"
  tags        = ["disk-adoption", "disposable", "qualification"]

  machine       = "q35"
  scsi_hardware = "virtio-scsi-single"
  boot_order    = ["scsi0"]
  started       = false
  on_boot       = false
  protection    = false

  reboot_after_update                  = false
  stop_on_destroy                      = true
  purge_on_destroy                     = false
  delete_unreferenced_disks_on_destroy = false

  cpu {
    cores = 1
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = 512
    floating  = 0
  }

  disk {
    datastore_id = var.qualification_datastore
    interface    = "scsi0"
    serial       = "QUAL-DISK-BASE-0"
    size         = 1
    backup       = false
    cache        = "none"
    discard      = "ignore"
    iothread     = false
    replicate    = false
    ssd          = false
  }

  disk {
    datastore_id = var.qualification_datastore
    interface    = "scsi1"
    serial       = "QUAL-DISK-BASE-1"
    size         = 1
    backup       = false
    cache        = "none"
    discard      = "ignore"
    iothread     = false
    replicate    = false
    ssd          = false
  }

  disk {
    datastore_id = var.qualification_datastore
    interface    = "scsi2"
    serial       = "QUAL-DISK-BASE-2"
    size         = 1
    backup       = false
    cache        = "none"
    discard      = "ignore"
    iothread     = false
    replicate    = false
    ssd          = false
  }

  dynamic "disk" {
    for_each = var.qualification_adopt_scsi3 ? [var.qualification_candidate_volume] : []

    content {
      datastore_id      = var.qualification_datastore
      path_in_datastore = disk.value
      interface         = "scsi3"
      serial            = "QUAL-DISK-CANDIDATE-3"
      size              = 1
      backup            = false
      cache             = "none"
      discard           = "ignore"
      iothread          = false
      replicate         = false
      ssd               = false
    }
  }

  lifecycle {
    precondition {
      condition     = var.qualification_vmid != 100 && var.qualification_vmid != 9900
      error_message = "Production VM 100 and recovery VM 9900 are forbidden."
    }
    precondition {
      condition     = !var.qualification_enabled || startswith(var.qualification_datastore, "qual-")
      error_message = "An enabled qualification requires a dedicated qual-* datastore identifier."
    }
    precondition {
      condition     = !var.qualification_adopt_scsi3 || startswith(var.qualification_candidate_volume, "${var.qualification_vmid}/vm-${var.qualification_vmid}-")
      error_message = "The candidate volume path must be bound to the disposable qualification VMID."
    }
  }
}

output "qualification" {
  value = var.qualification_enabled ? {
    vm_id     = proxmox_virtual_environment_vm.disk_adoption[0].vm_id
    name      = proxmox_virtual_environment_vm.disk_adoption[0].name
    started   = proxmox_virtual_environment_vm.disk_adoption[0].started
    protected = proxmox_virtual_environment_vm.disk_adoption[0].protection
  } : null
}
