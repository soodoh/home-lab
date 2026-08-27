variable "authentik_enable_management" {
  type        = bool
  description = "Enable import-first management after the complete live inventory, SOPS client secrets, least-privilege credentials, and every import are ready."
  default     = false
}

variable "authentik_client_secrets_path" {
  type        = string
  description = "Absolute path to the mode-0600 JSON decrypted from client-secrets.sops.json by the trusted local controller."
  default     = ""
}

variable "authentik_url" {
  type    = string
  default = "https://authentik.invalid"
}

variable "authentik_token" {
  type      = string
  default   = "disabled-not-a-credential"
  sensitive = true
  ephemeral = true
}
