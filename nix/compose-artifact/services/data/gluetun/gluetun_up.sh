#!/bin/sh

DIR=$(dirname "$0")

"$DIR"/qbittorrent_port.sh
# Update MAM after qBittorrent is running & forwarded port updated,
# to ensure that torrent client is reporting same IP before attempting
# to update the dynamicSeedbox endpoint.
"$DIR"/mam_seedbox.sh
