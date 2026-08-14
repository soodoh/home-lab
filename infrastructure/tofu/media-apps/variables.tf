variable "media_apps_enable_management" {
  type        = bool
  description = "Enable the import-first production media resources. Keep false until protected ephemeral credentials and every import are ready."
  default     = false
}

variable "sonarr_url" {
  type    = string
  default = "https://sonarr.invalid"
}

variable "sonarr_api_key" {
  type      = string
  default   = "disabled-not-a-credential"
  sensitive = true
  ephemeral = true
}

variable "radarr_url" {
  type    = string
  default = "https://radarr.invalid"
}

variable "radarr_api_key" {
  type      = string
  default   = "disabled-not-a-credential"
  sensitive = true
  ephemeral = true
}

variable "radarr_4k_url" {
  type    = string
  default = "https://radarr-4k.invalid"
}

variable "radarr_4k_api_key" {
  type      = string
  default   = "disabled-not-a-credential"
  sensitive = true
  ephemeral = true
}

variable "prowlarr_url" {
  type    = string
  default = "https://prowlarr.invalid"
}

variable "prowlarr_api_key" {
  type      = string
  default   = "disabled-not-a-credential"
  sensitive = true
  ephemeral = true
}
