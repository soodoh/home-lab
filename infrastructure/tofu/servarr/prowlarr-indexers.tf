# Prowlarr remains the only owner of these indexers; it synchronizes them to
# Sonarr/Radarr. Cookies, API keys and tracker URLs come from protected SOPS.
resource "prowlarr_indexer" "iptorrents" {
  name            = "IPTorrents"
  implementation  = "IPTorrents"
  config_contract = "IPTorrentsSettings"
  protocol        = "torrent"
  app_profile_id  = 1
  enable          = true
  priority        = 5
  redirect        = false
  tags            = [2, 3, 4, 5]
  fields = [
    { name = "baseUrl", text_value = var.indexer_secrets["5"].baseUrl },
    { name = "cookie", sensitive_value = var.indexer_secrets["5"].cookie },
    { name = "userAgent", text_value = var.indexer_secrets["5"].userAgent },
    { name = "freeLeechOnly", bool_value = false },
    { name = "searchSortBy", number_value = 0 },
    { name = "baseSettings.limitsUnit", number_value = 0 },
    { name = "torrentBaseSettings.preferMagnetUrl", bool_value = false },
  ]
}

resource "prowlarr_indexer" "myanonamouse" {
  name            = "MyAnonamouse"
  implementation  = "MyAnonamouse"
  config_contract = "MyAnonamouseSettings"
  protocol        = "torrent"
  app_profile_id  = 1
  enable          = false
  priority        = 3
  redirect        = false
  tags            = [5]
  fields = [
    { name = "baseUrl", text_value = var.indexer_secrets["8"].baseUrl },
    { name = "mamId", text_value = var.indexer_secrets["8"].mamId },
    { name = "searchLanguages", set_value = [] },
    { name = "searchType", number_value = 0 },
    { name = "searchInDescription", bool_value = false },
    { name = "searchInSeries", bool_value = false },
    { name = "searchInFilenames", bool_value = false },
    { name = "useFreeleechWedge", bool_value = true },
    { name = "baseSettings.limitsUnit", number_value = 0 },
    { name = "torrentBaseSettings.preferMagnetUrl", bool_value = false },
  ]
}

resource "prowlarr_indexer" "nyaa" {
  name            = "Nyaa.si"
  implementation  = "Cardigann"
  config_contract = "CardigannSettings"
  protocol        = "torrent"
  app_profile_id  = 1
  enable          = true
  priority        = 10
  redirect        = false
  tags            = [4]
  fields = [
    { name = "definitionFile", text_value = var.indexer_secrets["3"].definitionFile },
    { name = "prefer_magnet_links", bool_value = true },
    { name = "sonarr_compatibility", bool_value = false },
    { name = "strip_s01", bool_value = false },
    { name = "radarr_compatibility", bool_value = false },
    { name = "filter-id", number_value = 0 },
    { name = "cat-id", number_value = 1 },
    { name = "sort", number_value = 0 },
    { name = "type", number_value = 1 },
    { name = "baseSettings.limitsUnit", number_value = 0 },
    { name = "torrentBaseSettings.preferMagnetUrl", bool_value = false },
  ]
}

resource "prowlarr_indexer" "nzbgeek" {
  name            = "NZBgeek"
  implementation  = "Newznab"
  config_contract = "NewznabSettings"
  protocol        = "usenet"
  app_profile_id  = 1
  enable          = false
  priority        = 10
  redirect        = true
  tags            = [3, 4, 5]
  fields = [
    { name = "baseUrl", text_value = var.indexer_secrets["7"].baseUrl },
    { name = "apiPath", text_value = "/api" },
    { name = "apiKey", sensitive_value = var.indexer_secrets["7"].apiKey },
    { name = "vipExpiration", text_value = "" },
    { name = "baseSettings.limitsUnit", number_value = 0 },
  ]
}

import {
  to = prowlarr_indexer.iptorrents
  id = "5"
}
import {
  to = prowlarr_indexer.myanonamouse
  id = "8"
}
import {
  to = prowlarr_indexer.nyaa
  id = "3"
}
import {
  to = prowlarr_indexer.nzbgeek
  id = "7"
}
