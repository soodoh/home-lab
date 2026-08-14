variable "authentik_enable_management" {
  type        = bool
  description = "Enable the import-first production Authentik resources. The controller must keep this false until protected credentials and every import are ready."
  default     = false
}
