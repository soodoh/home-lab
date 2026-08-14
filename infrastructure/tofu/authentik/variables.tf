variable "authentik_enable_management" {
  type        = bool
  description = "Enable the import-first production Authentik resources. The controller must keep this false until protected credentials and every import are ready."
  default     = false
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
