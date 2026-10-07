variable "proxmox_access_api_token" {
  description = "Separately approved owner plan/apply token; never the managed automation tokens."
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition = (
      can(regex("^[^!=]+@[^!=]+![^!=]+=[^=]+$", var.proxmox_access_api_token)) &&
      !contains([
        for token in local.access.tokens : "${token.user_id}!${token.token_name}"
      ], split("=", var.proxmox_access_api_token)[0])
    )
    error_message = "Access management requires an independently approved owner token, not tofu-plan or tofu-apply."
  }
}
