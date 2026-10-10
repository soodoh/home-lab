#!/bin/sh

set -e

DIR=$(dirname "$0")

"$DIR"/qbittorrent_port.sh
# Register the VPN egress only after verifying the client's listening port.
# MAM session authorization alone does not prove public reachability.
"$DIR"/mam_seedbox.sh
