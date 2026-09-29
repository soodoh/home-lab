# The existing list's top-level rootFolderPath is /data/movies/4k. Do not
# confuse it with the separate, empty fields.rootFolderPaths setting. Preserve
# the live root on import; the reviewed plan should not change it. The source
# Radarr API key and internal URL come from the same SOPS values used by
# Compose, Recyclarr, Unpackerr and the Prowlarr integration.
resource "radarr_import_list_radarr" "standard_to_uhd" {
  provider = radarr.uhd

  name                 = "Radarr"
  enabled              = true
  enable_auto          = true
  search_on_add        = true
  list_order           = 0
  base_url             = var.radarr_internal_url
  api_key              = var.radarr_api_key
  root_folder_path     = radarr_root_folder.uhd["5"].path
  monitor              = "movieOnly"
  minimum_availability = "released"
  quality_profile_id   = 13
  profile_ids          = []
  tag_ids              = []
  tags                 = []
}

import {
  to = radarr_import_list_radarr.standard_to_uhd
  id = "1"
}
