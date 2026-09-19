variable "tailscale_enable_management" {
  type    = bool
  default = false
}

variable "tailscale_policy_identity" {
  type = object({
    owner_identity = string
    tags = object({
      docker_host = string
      proxmox     = string
    })
  })

  validation {
    condition = (
      endswith(var.tailscale_policy_identity.owner_identity, "@github") &&
      startswith(var.tailscale_policy_identity.tags.docker_host, "tag:") &&
      startswith(var.tailscale_policy_identity.tags.proxmox, "tag:") &&
      var.tailscale_policy_identity.tags.docker_host != var.tailscale_policy_identity.tags.proxmox
    )
    error_message = "The policy owner must be a GitHub identity and the two device tags must be distinct tag: values."
  }
}
