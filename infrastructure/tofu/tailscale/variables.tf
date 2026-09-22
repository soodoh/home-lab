variable "tailscale_enable_management" {
  type    = bool
  default = false
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
