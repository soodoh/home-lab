# Root paths remain encrypted in secrets/servarr.sops.yaml. IDs are the
# freshly observed existing folders, not new create/delete candidates.
locals {
  sonarr_root_ids = toset(["7", "8"])
  radarr_root_ids = toset(["1"])
}

resource "sonarr_root_folder" "existing" {
  for_each = local.sonarr_root_ids
  path     = var.root_folders.sonarr[each.key]
}
resource "radarr_root_folder" "existing" {
  for_each = local.radarr_root_ids
  path     = var.root_folders.radarr[each.key]
}
import {
  for_each = local.sonarr_root_ids
  to       = sonarr_root_folder.existing[each.key]
  id       = each.key
}
import {
  for_each = local.radarr_root_ids
  to       = radarr_root_folder.existing[each.key]
  id       = each.key
}
