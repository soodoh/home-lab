# Preserve observed application-wide download and indexer behavior.
resource "sonarr_download_client_config" "existing" {
  enable_completed_download_handling = true
  auto_redownload_failed             = true
}
resource "radarr_download_client_config" "existing" {
  enable_completed_download_handling   = true
  auto_redownload_failed               = true
  check_for_finished_download_interval = 1
}
resource "radarr_download_client_config" "uhd" {
  provider                             = radarr.uhd
  enable_completed_download_handling   = true
  auto_redownload_failed               = true
  check_for_finished_download_interval = 1
}

resource "sonarr_indexer_config" "existing" {
  maximum_size      = 0
  minimum_age       = 0
  retention         = 0
  rss_sync_interval = 15
}
resource "radarr_indexer_config" "existing" {
  maximum_size               = 0
  minimum_age                = 0
  retention                  = 0
  rss_sync_interval          = 30
  availability_delay         = 0
  whitelisted_hardcoded_subs = ""
  prefer_indexer_flags       = false
  allow_hardcoded_subs       = false
}
resource "radarr_indexer_config" "uhd" {
  provider                   = radarr.uhd
  maximum_size               = 0
  minimum_age                = 0
  retention                  = 0
  rss_sync_interval          = 30
  availability_delay         = 0
  whitelisted_hardcoded_subs = ""
  prefer_indexer_flags       = false
  allow_hardcoded_subs       = false
}

resource "radarr_import_list_config" "existing" {
  sync_level = "disabled"
}
resource "radarr_import_list_config" "uhd" {
  provider   = radarr.uhd
  sync_level = "disabled"
}

import {
  to = sonarr_download_client_config.existing
  id = ""
}
import {
  to = radarr_download_client_config.existing
  id = ""
}
import {
  to = radarr_download_client_config.uhd
  id = ""
}
import {
  to = sonarr_indexer_config.existing
  id = ""
}
import {
  to = radarr_indexer_config.existing
  id = ""
}
import {
  to = radarr_indexer_config.uhd
  id = ""
}
import {
  to = radarr_import_list_config.existing
  id = ""
}
import {
  to = radarr_import_list_config.uhd
  id = ""
}
