# Preserve the existing file-management policies (including doNotPrefer).
resource "sonarr_media_management" "existing" {
  unmonitor_previous_episodes = false
  hardlinks_copy              = true
  create_empty_folders        = true
  delete_empty_folders        = true
  enable_media_info           = true
  import_extra_files          = false
  set_permissions             = false
  skip_free_space_check       = false
  minimum_free_space          = 100000
  recycle_bin_days            = 7
  chmod_folder                = "755"
  chown_group                 = ""
  download_propers_repacks    = "doNotPrefer"
  episode_title_required      = "always"
  extra_file_extensions       = "srt"
  file_date                   = "none"
  recycle_bin_path            = ""
  rescan_after_refresh        = "always"
}

resource "radarr_media_management" "existing" {
  auto_rename_folders                         = false
  auto_unmonitor_previously_downloaded_movies = false
  chmod_folder                                = "755"
  chown_group                                 = ""
  copy_using_hardlinks                        = true
  create_empty_movie_folders                  = false
  delete_empty_folders                        = false
  download_propers_and_repacks                = "doNotPrefer"
  enable_media_info                           = true
  extra_file_extensions                       = "srt"
  file_date                                   = "none"
  import_extra_files                          = false
  minimum_free_space_when_importing           = 100
  paths_default_static                        = false
  recycle_bin                                 = ""
  recycle_bin_cleanup_days                    = 7
  rescan_after_refresh                        = "always"
  set_permissions_linux                       = false
  skip_free_space_check_when_importing        = false
}

resource "radarr_media_management" "uhd" {
  provider = radarr.uhd

  auto_rename_folders                         = false
  auto_unmonitor_previously_downloaded_movies = false
  chmod_folder                                = "755"
  chown_group                                 = ""
  copy_using_hardlinks                        = true
  create_empty_movie_folders                  = false
  delete_empty_folders                        = true
  download_propers_and_repacks                = "doNotPrefer"
  enable_media_info                           = true
  extra_file_extensions                       = "srt"
  file_date                                   = "none"
  import_extra_files                          = false
  minimum_free_space_when_importing           = 500000
  paths_default_static                        = false
  recycle_bin                                 = ""
  recycle_bin_cleanup_days                    = 7
  rescan_after_refresh                        = "always"
  set_permissions_linux                       = false
  skip_free_space_check_when_importing        = false
}

import {
  to = sonarr_media_management.existing
  id = ""
}
import {
  to = radarr_media_management.existing
  id = ""
}
import {
  to = radarr_media_management.uhd
  id = ""
}
