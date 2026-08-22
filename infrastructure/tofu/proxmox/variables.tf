variable "proxmox_endpoint" {
  type = string
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
