# Existing naming policies adopted without changing filenames or library entries.
resource "sonarr_naming" "existing" {
  rename_episodes            = true
  replace_illegal_characters = true
  multi_episode_style        = 5
  colon_replacement_format   = 4
  standard_episode_format    = "{Series Title} - S{season:00}E{episode:00} - {Episode Title} {Quality Full}"
  daily_episode_format       = "{Series Title} - {Air-Date} - {Episode Title} {Quality Full}"
  anime_episode_format       = "{Series Title} - S{season:00}E{episode:00} - {Episode Title} {Quality Full}"
  series_folder_format       = "{Series Title}"
  season_folder_format       = "Season {season}"
  specials_folder_format     = "Specials"
}

resource "radarr_naming" "existing" {
  rename_movies              = false
  replace_illegal_characters = true
  colon_replacement_format   = "smart"
  standard_movie_format      = "{Movie Title} ({Release Year}) {Quality Full}"
  movie_folder_format        = "{Movie Title} ({Release Year})"
}

resource "radarr_naming" "uhd" {
  provider = radarr.uhd

  rename_movies              = true
  replace_illegal_characters = true
  colon_replacement_format   = "delete"
  standard_movie_format      = "{Movie Title} ({Release Year}) {Quality Full}"
  movie_folder_format        = "{Movie Title} ({Release Year})"
}

import {
  to = sonarr_naming.existing
  id = "1"
}
import {
  to = radarr_naming.existing
  id = "1"
}
import {
  to = radarr_naming.uhd
  id = "1"
}
