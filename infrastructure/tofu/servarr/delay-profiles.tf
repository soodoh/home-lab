# Default delay profiles. Sonarr delays low-scoring torrent grabs by 90 minutes
# unless the release meets the Custom Format bypass threshold (1650+), avoiding
# early scene grabs before preferred WEB-DL/anime releases appear.
resource "sonarr_delay_profile" "existing" {
  tags                                = []
  enable_torrent                      = true
  enable_usenet                       = true
  preferred_protocol                  = "usenet"
  bypass_if_highest_quality           = false
  bypass_if_above_custom_format_score = true
  minimum_custom_format_score         = 1650
  order                               = 2147483647
  torrent_delay                       = 90
  usenet_delay                        = 0
}

resource "radarr_delay_profile" "existing" {
  tags                      = []
  enable_torrent            = true
  enable_usenet             = true
  preferred_protocol        = "usenet"
  bypass_if_highest_quality = true
  order                     = 2147483647
  torrent_delay             = 0
  usenet_delay              = 0
}

import {
  to = sonarr_delay_profile.existing
  id = "1"
}
import {
  to = radarr_delay_profile.existing
  id = "1"
}
