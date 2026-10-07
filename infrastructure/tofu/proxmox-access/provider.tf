provider "proxmox" {
  endpoint  = "https://proxmox:8006/api2/json"
  api_token = var.proxmox_access_api_token
  insecure  = false
}
