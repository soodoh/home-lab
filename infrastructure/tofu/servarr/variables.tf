# Provider credentials come from the protected per-run controller session, not
# from Compose's Docker-only application URLs or committed tfvars files.
variable "sonarr_api_key" {
  type      = string
  sensitive = true
}
variable "radarr_api_key" {
  type      = string
  sensitive = true
}
# Pinned internal Radarr URL from production SOPS, used by the existing 4K
# Radarr-to-Radarr import list. Do not point it at the tailnet provider route.
variable "radarr_internal_url" {
  type = string
}
variable "radarr_4k_api_key" {
  type      = string
  sensitive = true
}
variable "prowlarr_api_key" {
  type      = string
  sensitive = true
}
# Download-client resource attributes can enter remote state even if marked
# sensitive. Use only the values from secrets/download-clients.sops.yaml.
variable "qbittorrent_username" {
  type      = string
  sensitive = true
}
variable "qbittorrent_password" {
  type      = string
  sensitive = true
}
variable "sabnzbd_api_key" {
  type      = string
  sensitive = true
}

# Non-public application paths and indexer credentials are in
# secrets/servarr.sops.yaml, supplied only during a private run.
variable "root_folders" {
  type      = map(map(string))
  sensitive = true
}
variable "indexer_secrets" {
  type      = map(map(string))
  sensitive = true
}
