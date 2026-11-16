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
resource "radarr_import_list_config" "existing" {
  sync_level = "disabled"
}
# The observed singleton /config resources have native API ID 1. Use a
# nonempty ID in import blocks: the provider's CLI example uses "", but an
# empty import-block ID planned a create instead of an adoption.
import {
  to = sonarr_download_client_config.existing
  id = "1"
}
import {
  to = radarr_download_client_config.existing
  id = "1"
}
import {
  to = sonarr_indexer_config.existing
  id = "1"
}
import {
  to = radarr_indexer_config.existing
  id = "1"
}
import {
  to = radarr_import_list_config.existing
  id = "1"
}
