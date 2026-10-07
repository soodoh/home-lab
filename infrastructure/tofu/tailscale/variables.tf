variable "tailscale_enable_management" {
  type    = bool
  default = false
}

variable "tailscale_settings" {
  description = "Reviewed tailnet settings; host auto-update preferences remain Ansible-owned."
  nullable    = false
  type = object({
    acls_externally_managed_on                  = bool
    acls_external_link                          = string
    devices_approval_on                         = bool
    devices_auto_updates_on                     = bool
    devices_key_duration_days                   = number
    users_approval_on                           = bool
    users_role_allowed_to_join_external_tailnet = string
    regional_routing_on                         = bool
    posture_identity_collection_on              = bool
  })

  validation {
    condition = (
      var.tailscale_settings.devices_key_duration_days >= 1 &&
      var.tailscale_settings.devices_key_duration_days <= 180 &&
      floor(var.tailscale_settings.devices_key_duration_days) == var.tailscale_settings.devices_key_duration_days &&
      contains(["none", "admin", "member"], var.tailscale_settings.users_role_allowed_to_join_external_tailnet)
    )
    error_message = "Key duration must be a whole number from 1 to 180 days, and external-tailnet access must be none, admin or member."
  }
}

variable "tailscale_servers" {
  description = "Reviewed permanent server names and stable node IDs; never discover and automatically authorize replacement nodes."
  nullable    = false
  type = object({
    docker_host = object({ name = string, node_id = string })
    proxmox     = object({ name = string, node_id = string })
  })

  validation {
    condition = (
      alltrue([
        for server in values(var.tailscale_servers) :
        endswith(server.name, ".ts.net") && can(regex("^[A-Za-z0-9]+CNTRL$", server.node_id))
      ]) &&
      length(toset([for server in values(var.tailscale_servers) : server.name])) == 2 &&
      length(toset([for server in values(var.tailscale_servers) : server.node_id])) == 2
    )
    error_message = "Both permanent servers require distinct full MagicDNS names and stable node IDs."
  }
}

variable "tailscale_policy_identity" {
  type = object({
    owner_identity       = string
    github_owner_id      = string
    github_repository    = string
    github_repository_id = string
    github_environment   = string
    github_ref           = string
    tags = object({
      docker_host = string
      proxmox     = string
      ci_deploy   = string
    })
  })

  validation {
    condition = (
      endswith(var.tailscale_policy_identity.owner_identity, "@github") &&
      can(regex("^[0-9]+$", var.tailscale_policy_identity.github_owner_id)) &&
      can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.tailscale_policy_identity.github_repository)) &&
      can(regex("^[0-9]+$", var.tailscale_policy_identity.github_repository_id)) &&
      can(regex("^[A-Za-z0-9_.-]+$", var.tailscale_policy_identity.github_environment)) &&
      startswith(var.tailscale_policy_identity.github_ref, "refs/heads/") &&
      alltrue([
        for tag in values(var.tailscale_policy_identity.tags) : startswith(tag, "tag:")
      ]) &&
      length(toset(values(var.tailscale_policy_identity.tags))) == 3
    )
    error_message = "The policy requires immutable GitHub IDs, repository, environment, branch ref, and three distinct tag: values."
  }
}
