# Existing Standard profile referenced by the four Prowlarr indexers.
resource "prowlarr_sync_profile" "standard" {
  name                      = "Standard"
  minimum_seeders           = 1
  enable_rss                = true
  enable_automatic_search   = true
  enable_interactive_search = true
}

import {
  to = prowlarr_sync_profile.standard
  id = "1"
}
