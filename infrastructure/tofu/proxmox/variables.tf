variable "proxmox_endpoint" {
  type = string

  validation {
    condition     = startswith(var.proxmox_endpoint, "https://")
    error_message = "The Proxmox API endpoint must use HTTPS."
  }
}

variable "proxmox_bridge_mtu" {
  description = "Explicit bridge MTU; null preserves PVE's implicit default without configuring it."
  type        = number
  default     = 1500
  nullable    = true

  validation {
    condition = var.proxmox_bridge_mtu == null ? true : (
      var.proxmox_bridge_mtu >= 1280 && var.proxmox_bridge_mtu <= 65535 &&
      floor(var.proxmox_bridge_mtu) == var.proxmox_bridge_mtu
    )
    error_message = "An explicit MTU must be an integer from 1280 through 65535."
  }
}

variable "proxmox_vm" {
  type = object({
    boot_order = list(string)
    cloud_init = object({
      drive_datastore = string
      drive_interface = string
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
      desired_protection = bool
      machine            = string
      memory_mb          = number
      name               = string
      on_boot            = bool
      started            = bool
      vmid               = number
      games_disk = object({
        backup    = bool
        discard   = string
        interface = string
        iothread  = bool
        ssd       = bool
      })
      boot_disk = object({
        backup    = bool
        datastore = string
        discard   = string
        interface = string
        iothread  = bool
        serial    = string
        size_gb   = number
        ssd       = bool
        volume    = string
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
      var.proxmox_vm.vm.boot_disk.interface == "scsi3" &&
      var.proxmox_vm.vm.boot_disk.datastore == "local-lvm" &&
      var.proxmox_vm.vm.boot_disk.volume == "vm-100-disk-2" &&
      var.proxmox_vm.vm.boot_disk.serial == "HOME-LAB-DEBIAN-64G" &&
      var.proxmox_vm.vm.boot_disk.size_gb == 64 &&
      var.proxmox_vm.vm.games_disk.interface == "scsi1" &&
      var.proxmox_vm.vm.state_disk.interface == "scsi2" &&
      var.proxmox_vm.cloud_init.drive_interface == "ide2"
    )
    error_message = "The adopted VM 100 identity and disk/interface ordering must remain unchanged."
  }
}
