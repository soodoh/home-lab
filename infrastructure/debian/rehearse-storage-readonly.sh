#!/bin/bash
set -Eeuo pipefail

readonly ROOT=/run/home-lab-storage-rehearsal
readonly STATE_MOUNT=$ROOT/state
readonly GAMES_MOUNT=$ROOT/games
readonly NFS_MOUNT=$ROOT/nfs
readonly MARKER=/var/lib/home-lab/debian-storage-rehearsed.json
readonly STATE_UUID=d4a19647-7879-4079-9fc9-b3e79711b449
readonly STATE_LABEL=home-lab-state
readonly STATE_SERIAL=QUAL-NIXOS-128G
readonly STATE_DISK_BYTES=137438953472
readonly STATE_MIN_AVAILABLE_BYTES=50000000000
readonly GAMES_UUID=31602ce7-0054-498a-9f24-f51ca491e7b3
readonly GAMES_LABEL=games
readonly GAMES_SERIAL=drive-scsi1
readonly GAMES_DISK_BYTES=4000787030016
readonly GAMES_MIN_AVAILABLE_BYTES=2000000000000
readonly NFS_SOURCE=192.168.0.123:/storage/docker
readonly NFS_MIN_AVAILABLE_BYTES=10000000000000
readonly SERVICES_STATE=docker-disabled-containerd-masked-inactive

fail() {
  echo "error: $*" >&2
  exit 1
}

unmount_rehearsal() {
  local result=$?
  trap - EXIT INT TERM HUP
  timeout 30 umount "$NFS_MOUNT" >/dev/null 2>&1 || true
  timeout 30 umount "$GAMES_MOUNT" >/dev/null 2>&1 || true
  timeout 30 umount "$STATE_MOUNT" >/dev/null 2>&1 || true
  if mountpoint -q "$NFS_MOUNT" || mountpoint -q "$GAMES_MOUNT" || mountpoint -q "$STATE_MOUNT"; then
    echo "critical: a read-only rehearsal mount remains active" >&2
    exit 1
  fi
  rm -rf -- "$ROOT"
  exit "$result"
}

verify_service_state() {
  local active enabled service
  for service in docker.service docker.socket; do
    enabled=$(systemctl is-enabled "$service" 2>/dev/null || true)
    active=$(systemctl is-active "$service" 2>/dev/null || true)
    [[ $enabled == disabled && $active == inactive ]] || return 1
  done
  [[ $(systemctl is-enabled containerd.service 2>/dev/null || true) == masked ]] || return 1
  [[ $(systemctl is-active containerd.service 2>/dev/null || true) == inactive ]] || return 1
  [[ ! -S /run/docker.sock ]]
}

resolve_ext4_device() {
  local uuid=$1 label=$2 serial=$3 disk_bytes=$4 device parent
  device=$(readlink -f "/dev/disk/by-uuid/$uuid")
  [[ $device == /dev/* && -b $device ]] || return 1
  [[ $(blkid -s UUID -o value "$device") == "$uuid" ]] || return 1
  [[ $(blkid -s LABEL -o value "$device") == "$label" ]] || return 1
  [[ $(blkid -s TYPE -o value "$device") == ext4 ]] || return 1
  parent=/dev/$(lsblk -no PKNAME "$device")
  [[ -b $parent ]] || return 1
  [[ $(lsblk -ndo SERIAL "$parent") == "$serial" ]] || return 1
  [[ $(blockdev --getsize64 "$parent") -eq $disk_bytes ]] || return 1
  printf '%s\n' "$device"
}

verify_owner_manifest() {
  local mountpoint=$1 manifest=$2 name uid gid mode actual
  while IFS=: read -r name uid gid mode; do
    [[ -n $name ]] || continue
    [[ -e $mountpoint/$name && ! -L $mountpoint/$name ]] || return 1
    actual=$(stat -c %u:%g:%a "$mountpoint/$name")
    [[ $actual == "$uid:$gid:$mode" ]] || return 1
  done <<< "$manifest"
}

[[ $# -eq 0 ]] || fail "usage: rehearse-storage-readonly.sh"
[[ $(id -u) -eq 0 ]] || fail "storage rehearsal requires root"
[[ -r /etc/os-release ]] || fail "operating-system identity is unavailable"
os_id=$(awk -F= '$1 == "ID" { gsub(/^"|"$/, "", $2); print $2 }' /etc/os-release)
os_version=$(awk -F= '$1 == "VERSION_ID" { gsub(/^"|"$/, "", $2); print $2 }' /etc/os-release)
[[ $os_id == debian && $os_version == 13 ]] || fail "Debian 13 is required"
[[ -f /var/lib/home-lab/debian-inert-provisioned ]] || fail "inert qualification marker is absent"
[[ -f /var/lib/home-lab/debian-packages-prepared.json ]] || fail "package preparation marker is absent"
jq -e --arg services "$SERVICES_STATE" '.format == "home-lab-debian-packages-prepared-v1" and .services == $services' /var/lib/home-lab/debian-packages-prepared.json >/dev/null || fail "package preparation marker differs"
verify_service_state || fail "Docker or containerd is not inert"
[[ ! -e /etc/home-lab/allow-storage-activation ]] || fail "storage activation marker must remain absent"
[[ ! -e /etc/sops/age && ! -e /etc/docker-compose && ! -e /var/lib/tailscale ]] || fail "credentials or Tailscale state must remain absent"
for target in /srv/home-lab-state /mnt/games /mnt/storage; do
  ! findmnt -rn --target "$target" >/dev/null || fail "a production mount is active: $target"
done
[[ ! -e $ROOT && ! -L $ROOT ]] || fail "rehearsal root requires reconciliation"
[[ ! -L $MARKER ]] || fail "storage rehearsal marker is unsafe"
[[ $(id -u docker) -eq 1000 && $(id -g docker) -eq 1000 ]] || fail "workload UID/GID differs"

state_device=$(resolve_ext4_device "$STATE_UUID" "$STATE_LABEL" "$STATE_SERIAL" "$STATE_DISK_BYTES") || fail "state device identity differs"
games_device=$(resolve_ext4_device "$GAMES_UUID" "$GAMES_LABEL" "$GAMES_SERIAL" "$GAMES_DISK_BYTES") || fail "games device identity differs"
[[ $state_device != "$games_device" ]] || fail "state and games devices alias"
! findmnt -rn --source "$state_device" >/dev/null || fail "state device is already mounted"
! findmnt -rn --source "$games_device" >/dev/null || fail "games device is already mounted"

kernel_cursor=$(journalctl -k -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
[[ -n $kernel_cursor ]] || fail "kernel journal cursor is unavailable"
install -d -o root -g root -m 0700 "$STATE_MOUNT" "$GAMES_MOUNT" "$NFS_MOUNT"
trap unmount_rehearsal EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mount -t ext4 -o ro,noload,nodev,nosuid,noexec "$state_device" "$STATE_MOUNT"
mount -t ext4 -o ro,noload,nodev,nosuid,noexec "$games_device" "$GAMES_MOUNT"
timeout 60 mount -t nfs4 -o ro,nodev,nosuid,noexec,vers=4.2,hard,timeo=600,retrans=2 "$NFS_SOURCE" "$NFS_MOUNT"

for target in "$STATE_MOUNT" "$GAMES_MOUNT" "$NFS_MOUNT"; do
  findmnt -rn --target "$target" >/dev/null || fail "rehearsal mount is absent: $target"
  findmnt -rn -o VFS-OPTIONS --target "$target" | tr ',' '\n' | grep -Fxq ro || fail "rehearsal mount is not read-only: $target"
done
for target in "$STATE_MOUNT" "$GAMES_MOUNT"; do
  findmnt -rn -o FS-OPTIONS --target "$target" | tr ',' '\n' | grep -Fxq noload || fail "ext4 journal replay is not disabled: $target"
done
[[ $(findmnt -rn -o SOURCE --target "$NFS_MOUNT") == "$NFS_SOURCE" ]] || fail "NFS source differs"

state_manifest='audiobookshelf-data:1000:1000:755
authentik-data:1000:1000:777
bookshelf-data:1000:1000:755
caddy-data:1000:1000:755
calibre-data:1000:1000:755
calibre-web-data:1000:1000:755
calibre-web-ingest:1000:1000:755
caro-tachidesk-data:1000:1000:777
ddns-updater-data:1000:1000:755
flaresolverr-data:1000:1000:755
frigate-data:1000:1000:777
gluetun-data:1000:1000:755
jellyfin-data:1000:1000:755
karaoke-eternal-data:1000:1000:755
litellm-data:0:0:755
mosquitto-data:1000:1000:755
nextcloud-db-data:999:999:755
nextcloud-redis-data:999:1000:755
omada-data:1000:1000:755
openfit-data:0:0:755
pihole-data:1000:1000:755
prowlarr-data:1000:1000:755
qbittorrent-data:1000:1000:755
radarr-4k-data:1000:1000:755
radarr-data:1000:1000:755
recyclarr-data:1000:1000:755
sabnzbd-data:1000:1000:755
seerr-data:1000:1000:755
sonarr-data:1000:1000:755
tachidesk-data:1000:1000:777
vaultwarden-data:0:0:755
vikunja-data:1000:1000:700
zwave-data:1000:1000:755'
games_manifest='backups:0:0:700
bioses:1000:1000:755
es-de-media:1000:1000:775
roms:1000:1000:755
wolf:1000:1000:755'
nfs_manifest='backups:0:0:700
media:1000:1000:777
vuetorrent:1000:1000:755'
verify_owner_manifest "$STATE_MOUNT" "$state_manifest" || fail "state ownership manifest differs"
verify_owner_manifest "$GAMES_MOUNT" "$games_manifest" || fail "games ownership manifest differs"
verify_owner_manifest "$NFS_MOUNT" "$nfs_manifest" || fail "NFS ownership manifest differs"

state_available=$(df -B1 --output=avail "$STATE_MOUNT" | tail -1 | tr -d ' ')
games_available=$(df -B1 --output=avail "$GAMES_MOUNT" | tail -1 | tr -d ' ')
nfs_available=$(df -B1 --output=avail "$NFS_MOUNT" | tail -1 | tr -d ' ')
[[ $state_available -ge $STATE_MIN_AVAILABLE_BYTES ]] || fail "state free space is below threshold"
[[ $games_available -ge $GAMES_MIN_AVAILABLE_BYTES ]] || fail "games free space is below threshold"
[[ $nfs_available -ge $NFS_MIN_AVAILABLE_BYTES ]] || fail "NFS free space is below threshold"
state_options=$(findmnt -rn -o VFS-OPTIONS,FS-OPTIONS --target "$STATE_MOUNT")
games_options=$(findmnt -rn -o VFS-OPTIONS,FS-OPTIONS --target "$GAMES_MOUNT")
nfs_options=$(findmnt -rn -o VFS-OPTIONS,FS-OPTIONS --target "$NFS_MOUNT")

kernel_events=$(journalctl -k --after-cursor "$kernel_cursor" --no-pager)
if grep -Eiq 'EXT4-fs.*(error|warning|abort)|NFS.*(error|server not responding)|I/O error|Buffer I/O error' <<< "$kernel_events"; then
  fail "kernel reported a storage error during rehearsal"
fi

timeout 30 umount "$NFS_MOUNT"
timeout 30 umount "$GAMES_MOUNT"
timeout 30 umount "$STATE_MOUNT"
for target in "$STATE_MOUNT" "$GAMES_MOUNT" "$NFS_MOUNT"; do
  ! mountpoint -q "$target" || fail "rehearsal unmount failed: $target"
done
trap - EXIT INT TERM HUP
rm -rf -- "$ROOT"

install -d -o root -g root -m 0755 /var/lib/home-lab
temporary=$(mktemp --tmpdir=/var/lib/home-lab debian-storage-rehearsed.XXXXXX)
jq -cn \
  --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg gamesDevice "$games_device" --arg gamesOptions "$games_options" --arg gamesUuid "$GAMES_UUID" \
  --arg nfsOptions "$nfs_options" --arg nfsSource "$NFS_SOURCE" \
  --arg services "$SERVICES_STATE" --arg stateDevice "$state_device" --arg stateOptions "$state_options" --arg stateUuid "$STATE_UUID" \
  --argjson gamesAvailableBytes "$games_available" --argjson nfsAvailableBytes "$nfs_available" --argjson stateAvailableBytes "$state_available" \
  '{completedAt:$completedAt,dockerServices:$services,format:"home-lab-debian-storage-rehearsal-v1",games:{availableBytes:$gamesAvailableBytes,device:$gamesDevice,options:$gamesOptions,uuid:$gamesUuid},kernelStorageErrors:0,nfs:{availableBytes:$nfsAvailableBytes,options:$nfsOptions,source:$nfsSource},readOnly:true,state:{availableBytes:$stateAvailableBytes,device:$stateDevice,options:$stateOptions,uuid:$stateUuid},unmounted:true,workloadIdentity:"1000:1000"}' > "$temporary"
chown root:root "$temporary"
chmod 0644 "$temporary"
mv -T "$temporary" "$MARKER"
echo "Debian storage rehearsal passed read-only and all rehearsal mounts were removed"
