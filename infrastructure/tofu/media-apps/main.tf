locals {
  desired                = jsondecode(file("${path.module}/desired.json"))
  sonarr_root_folders    = var.media_apps_enable_management ? local.desired.sonarrRootFolders : {}
  radarr_root_folders    = var.media_apps_enable_management ? local.desired.radarrRootFolders : {}
  radarr4k_root_folders  = var.media_apps_enable_management ? local.desired.radarr4kRootFolders : {}
  prowlarr_tags          = var.media_apps_enable_management ? local.desired.prowlarrTags : {}
  prowlarr_sync_profiles = var.media_apps_enable_management ? local.desired.prowlarrSyncProfiles : {}
}

provider "sonarr" {
  url     = var.sonarr_url
  api_key = var.sonarr_api_key
}

provider "radarr" {
  url     = var.radarr_url
  api_key = var.radarr_api_key
}

provider "radarr" {
  alias   = "radarr_4k"
  url     = var.radarr_4k_url
  api_key = var.radarr_4k_api_key
}

provider "prowlarr" {
  url     = var.prowlarr_url
  api_key = var.prowlarr_api_key
}

check "desired_inventory" {
  assert {
    condition = (
      local.desired.schemaVersion == 1 &&
      length(local.desired.sonarrRootFolders) == 2 &&
      length(local.desired.radarrRootFolders) == 1 &&
      length(local.desired.radarr4kRootFolders) == 1 &&
      length(local.desired.prowlarrTags) == 4 &&
      length(local.desired.prowlarrSyncProfiles) == 1
    )
    error_message = "The checked media-app desired inventory is incomplete or has an unsupported schema version."
  }
}

resource "sonarr_root_folder" "root_folders" {
  for_each = local.sonarr_root_folders
  path     = each.value.path

  lifecycle {
    prevent_destroy = true
  }
}

resource "radarr_root_folder" "root_folders" {
  for_each = local.radarr_root_folders
  path     = each.value.path

  lifecycle {
    prevent_destroy = true
  }
}

resource "radarr_root_folder" "root_folders_4k" {
  provider = radarr.radarr_4k
  for_each = local.radarr4k_root_folders
  path     = each.value.path

  lifecycle {
    prevent_destroy = true
  }
}

resource "prowlarr_tag" "tags" {
  for_each = local.prowlarr_tags
  label    = each.value.label

  lifecycle {
    prevent_destroy = true
  }
}

resource "prowlarr_sync_profile" "sync_profiles" {
  for_each = local.prowlarr_sync_profiles

  name                      = each.value.name
  enable_rss                = each.value.enableRss
  enable_interactive_search = each.value.enableInteractiveSearch
  enable_automatic_search   = each.value.enableAutomaticSearch
  minimum_seeders           = each.value.minimumSeeders

  lifecycle {
    prevent_destroy = true
  }
}

import {
  for_each = local.sonarr_root_folders
  to       = sonarr_root_folder.root_folders[each.key]
  id       = tostring(each.value.importId)
}

import {
  for_each = local.radarr_root_folders
  to       = radarr_root_folder.root_folders[each.key]
  id       = tostring(each.value.importId)
}

import {
  for_each = local.radarr4k_root_folders
  to       = radarr_root_folder.root_folders_4k[each.key]
  id       = tostring(each.value.importId)
}

import {
  for_each = local.prowlarr_tags
  to       = prowlarr_tag.tags[each.key]
  id       = tostring(each.value.importId)
}

import {
  for_each = local.prowlarr_sync_profiles
  to       = prowlarr_sync_profile.sync_profiles[each.key]
  id       = tostring(each.value.importId)
}
