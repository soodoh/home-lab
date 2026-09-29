locals {
  prowlarr_tags = {
    "2" = "lidarr"
    "3" = "radarr"
    "4" = "sonarr"
    "5" = "readarr"
  }
}

resource "prowlarr_tag" "existing" {
  for_each = local.prowlarr_tags
  label    = each.value
}

import {
  for_each = local.prowlarr_tags
  to       = prowlarr_tag.existing[each.key]
  id       = each.key
}
