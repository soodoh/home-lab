# Existing default delay profiles; preserve Usenet preference and no delays.
resource "sonarr_delay_profile" "existing" {
  tags                                = []
  enable_torrent                      = true
  enable_usenet                       = true
  preferred_protocol                  = "usenet"
  bypass_if_highest_quality           = true
  bypass_if_above_custom_format_score = false
  minimum_custom_format_score         = 0
  order                               = 2147483647
  torrent_delay                       = 0
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

resource "radarr_delay_profile" "uhd" {
  provider                  = radarr.uhd
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
import {
  to = radarr_delay_profile.uhd
  id = "1"
}
