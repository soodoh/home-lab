# These adopted connection records are distinct from the native accounts on
# qBittorrent and SABnzbd. The native credentials come from the same SOPS
# source, applied first by Ansible during an explicit rotation.
locals {
  download_clients = jsondecode(file("${path.module}/download-clients.json"))
}

resource "sonarr_download_client_qbittorrent" "existing" {
  for_each = local.download_clients.sonarr.qbittorrent

  name                       = each.value.name
  enable                     = true
  host                       = each.value.host
  port                       = each.value.port
  use_ssl                    = false
  tv_category                = each.value.category
  priority                   = each.value.priority
  username                   = var.qbittorrent_username
  password                   = var.qbittorrent_password
  initial_state              = 0
  sequential_order           = false
  first_and_last             = false
  older_tv_priority          = 0
  recent_tv_priority         = 0
  remove_completed_downloads = each.value.remove_completed
  remove_failed_downloads    = true
}

resource "sonarr_download_client_sabnzbd" "existing" {
  for_each = local.download_clients.sonarr.sabnzbd

  name                       = each.value.name
  enable                     = true
  host                       = each.value.host
  port                       = each.value.port
  use_ssl                    = false
  tv_category                = each.value.category
  priority                   = each.value.priority
  api_key                    = var.sabnzbd_api_key
  older_tv_priority          = -100
  recent_tv_priority         = -100
  remove_completed_downloads = true
  remove_failed_downloads    = true
}

resource "radarr_download_client_qbittorrent" "existing" {
  for_each = local.download_clients.radarr.qbittorrent

  name                       = each.value.name
  enable                     = true
  host                       = each.value.host
  port                       = each.value.port
  use_ssl                    = false
  movie_category             = each.value.category
  priority                   = each.value.priority
  username                   = var.qbittorrent_username
  password                   = var.qbittorrent_password
  initial_state              = 0
  sequential_order           = false
  first_and_last             = false
  older_movie_priority       = 0
  recent_movie_priority      = 0
  remove_completed_downloads = each.value.remove_completed
  remove_failed_downloads    = true
}

resource "radarr_download_client_sabnzbd" "existing" {
  for_each = local.download_clients.radarr.sabnzbd

  name                       = each.value.name
  enable                     = true
  host                       = each.value.host
  port                       = each.value.port
  use_ssl                    = false
  movie_category             = each.value.category
  priority                   = each.value.priority
  api_key                    = var.sabnzbd_api_key
  older_movie_priority       = -100
  recent_movie_priority      = -100
  remove_completed_downloads = true
  remove_failed_downloads    = true
}

resource "radarr_download_client_qbittorrent" "uhd" {
  provider = radarr.uhd
  for_each = local.download_clients.radarr_4k.qbittorrent

  name                       = each.value.name
  enable                     = true
  host                       = each.value.host
  port                       = each.value.port
  use_ssl                    = false
  movie_category             = each.value.category
  priority                   = each.value.priority
  username                   = var.qbittorrent_username
  password                   = var.qbittorrent_password
  initial_state              = 0
  sequential_order           = false
  first_and_last             = false
  older_movie_priority       = 0
  recent_movie_priority      = 0
  remove_completed_downloads = each.value.remove_completed
  remove_failed_downloads    = true
}

resource "radarr_download_client_sabnzbd" "uhd" {
  provider = radarr.uhd
  for_each = local.download_clients.radarr_4k.sabnzbd

  name                       = each.value.name
  enable                     = true
  host                       = each.value.host
  port                       = each.value.port
  use_ssl                    = false
  movie_category             = each.value.category
  priority                   = each.value.priority
  api_key                    = var.sabnzbd_api_key
  older_movie_priority       = -100
  recent_movie_priority      = -100
  remove_completed_downloads = true
  remove_failed_downloads    = true
}

resource "prowlarr_download_client_qbittorrent" "existing" {
  for_each = local.download_clients.prowlarr.qbittorrent

  name     = each.value.name
  enable   = true
  host     = each.value.host
  port     = each.value.port
  use_ssl  = false
  category = each.value.category
  priority = each.value.priority
  username = var.qbittorrent_username
  password = var.qbittorrent_password
}

resource "prowlarr_download_client_sabnzbd" "existing" {
  for_each = local.download_clients.prowlarr.sabnzbd

  name     = each.value.name
  enable   = true
  host     = each.value.host
  port     = each.value.port
  use_ssl  = false
  category = each.value.category
  priority = each.value.priority
  api_key  = var.sabnzbd_api_key
}

import {
  for_each = local.download_clients.sonarr.qbittorrent
  to       = sonarr_download_client_qbittorrent.existing[each.key]
  id       = each.key
}
import {
  for_each = local.download_clients.sonarr.sabnzbd
  to       = sonarr_download_client_sabnzbd.existing[each.key]
  id       = each.key
}
import {
  for_each = local.download_clients.radarr.qbittorrent
  to       = radarr_download_client_qbittorrent.existing[each.key]
  id       = each.key
}
import {
  for_each = local.download_clients.radarr.sabnzbd
  to       = radarr_download_client_sabnzbd.existing[each.key]
  id       = each.key
}
import {
  for_each = local.download_clients.radarr_4k.qbittorrent
  to       = radarr_download_client_qbittorrent.uhd[each.key]
  id       = each.key
}
import {
  for_each = local.download_clients.radarr_4k.sabnzbd
  to       = radarr_download_client_sabnzbd.uhd[each.key]
  id       = each.key
}
import {
  for_each = local.download_clients.prowlarr.qbittorrent
  to       = prowlarr_download_client_qbittorrent.existing[each.key]
  id       = each.key
}
import {
  for_each = local.download_clients.prowlarr.sabnzbd
  to       = prowlarr_download_client_sabnzbd.existing[each.key]
  id       = each.key
}
