variable "proxmox_endpoint" {
  type = string

  validation {
    condition     = startswith(var.proxmox_endpoint, "https://")
    error_message = "The Proxmox API endpoint must use HTTPS."
  }
}

variable "proxmox_vm" {
  type = object({
    boot_order = list(string)
    cloud_init = object({
      datastore                 = string
      drive_datastore           = string
      drive_interface           = string
      meta_data_snippet_path    = string
      network_data_snippet_path = string
      user_data_snippet_path    = string
    })
    network = object({
      bridge          = string
      docker_host_mac = string
    })
    node = string
    vm = object({
      cpu = object({
        cores         = number
        kvm_arguments = string
        sockets       = number
        type          = string
      })
      desired_protection       = bool
      hardware_attachment_mode = string
      machine                  = string
      memory_mb                = number
      name                     = string
      on_boot                  = bool
      started                  = bool
      vmid                     = number
      games_disk = object({
        backup    = bool
        discard   = string
        interface = string
        iothread  = bool
        ssd       = bool
      })
      retired_disk_slot = object({
        datastore = string
        interface = string
        iothread  = bool
        size_gb   = number
      })
      state_disk = object({
        backup    = bool
        datastore = string
        discard   = string
        interface = string
        iothread  = bool
        serial    = string
        size_gb   = number
        ssd       = bool
      })
      pci = object({
        gpu = object({
          bdf           = string
          iommu_group   = number
          mapping       = string
          pcie          = bool
          subsystem_id  = string
          vendor_device = string
          xvga          = bool
        })
        gpu_audio = object({
          bdf           = string
          iommu_group   = number
          mapping       = string
          pcie          = bool
          subsystem_id  = string
          vendor_device = string
        })
      })
      usb = object({
        bluetooth = object({
          host          = string
          mapping       = string
          usb3          = bool
          vendor_device = string
        })
        zigbee = object({
          mapping       = string
          vendor_device = string
        })
        zwave = object({
          mapping       = string
          vendor_device = string
        })
      })
    })
  })

  validation {
    condition = (
      var.proxmox_vm.vm.vmid == 100 &&
      var.proxmox_vm.vm.name == "docker-host" &&
      var.proxmox_vm.boot_order == tolist(["scsi3", "net0"]) &&
      var.proxmox_vm.vm.retired_disk_slot.interface == "scsi0" &&
      var.proxmox_vm.vm.games_disk.interface == "scsi1" &&
      var.proxmox_vm.vm.state_disk.interface == "scsi2" &&
      var.proxmox_vm.cloud_init.drive_interface == "ide2"
    )
    error_message = "The adopted VM 100 identity and disk/interface ordering must remain unchanged."
  }
}

variable "games_disk_by_id" {
  type      = string
  sensitive = true

  validation {
    condition     = startswith(var.games_disk_by_id, "/dev/disk/by-id/")
    error_message = "games_disk_by_id must be an absolute /dev/disk/by-id path."
  }
}

variable "serial_usb_paths" {
  type = object({
    zigbee = string
    zwave  = string
  })
  sensitive = true

  validation {
    condition = alltrue([
      for path in values(var.serial_usb_paths) : can(regex("^[0-9]+-[0-9]+(?:\\.[0-9]+)*$", path))
    ]) && var.serial_usb_paths.zigbee != var.serial_usb_paths.zwave
    error_message = "Each serial USB path must be a unique physical USB port such as 1-6 or 1-6.2."
  }
}
