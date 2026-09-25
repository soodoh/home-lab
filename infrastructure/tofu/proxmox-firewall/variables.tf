variable "proxmox_endpoint" {
  type = string

  validation {
    condition     = startswith(var.proxmox_endpoint, "https://")
    error_message = "The Proxmox API endpoint must use HTTPS."
  }
}

variable "proxmox_firewall_enable_management" {
  type        = bool
  description = "Enable cluster firewall imports only after remote backend access and an exact no-op plan have been verified."
  default     = false
}
