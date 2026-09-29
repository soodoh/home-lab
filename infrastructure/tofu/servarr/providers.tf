provider "sonarr" {
  url     = "https://sonarr.ts.diloreto.com"
  api_key = var.sonarr_api_key
}

provider "radarr" {
  url     = "https://radarr.ts.diloreto.com"
  api_key = var.radarr_api_key
}

provider "radarr" {
  alias   = "uhd"
  url     = "https://radarr-4k.ts.diloreto.com"
  api_key = var.radarr_4k_api_key
}

provider "prowlarr" {
  url     = "https://prowlarr.ts.diloreto.com"
  api_key = var.prowlarr_api_key
}
