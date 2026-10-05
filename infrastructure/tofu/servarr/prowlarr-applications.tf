# Prowlarr remains sole writer of the indexers it synchronizes into Arr.
resource "prowlarr_application_radarr" "standard" {
  name            = "Radarr"
  sync_level      = "fullSync"
  base_url        = "http://localhost:7878"
  prowlarr_url    = "http://localhost:9696"
  api_key         = var.radarr_api_key
  sync_categories = [2000, 2010, 2020, 2030, 2040, 2045, 2050, 2060, 2070, 2080, 2090]
  tags            = [3]
}

resource "prowlarr_application_radarr" "uhd" {
  name            = "Radarr 4k"
  sync_level      = "fullSync"
  base_url        = "http://gluetun:7879"
  prowlarr_url    = "http://gluetun:9696"
  api_key         = var.radarr_4k_api_key
  sync_categories = [2000, 2010, 2020, 2030, 2040, 2045, 2050, 2060, 2070, 2080, 2090]
  tags            = [3]
}

resource "prowlarr_application_sonarr" "existing" {
  name                  = "Sonarr"
  sync_level            = "fullSync"
  base_url              = "http://gluetun:8989"
  prowlarr_url          = "http://gluetun:9696"
  api_key               = var.sonarr_api_key
  sync_categories       = [5000, 5010, 5020, 5030, 5040, 5045, 5050, 5090]
  anime_sync_categories = [5070]
  tags                  = [4]
}

import {
  to = prowlarr_application_radarr.standard
  id = "6"
}
import {
  to = prowlarr_application_radarr.uhd
  id = "4"
}
import {
  to = prowlarr_application_sonarr.existing
  id = "5"
}
