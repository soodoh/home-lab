variable "authentik_enable_management" {
  type        = bool
  description = "Enable import-first management after the complete live inventory, SOPS client secrets, least-privilege credentials, and every import are ready."
  default     = false
}

variable "authentik_client_secrets_path" {
  type        = string
  description = "Absolute path to a mode-0600 JSON decrypted into this run's private temporary directory."
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
