#!/bin/bash
set -Eeuo pipefail

readonly ARTIFACT_SHA256=d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c
readonly IMAGE='ghcr.io/soodoh/openfit:latest@sha256:5ce56f1db33881ec5216aaaeff89fa7eeba281e5e1c497e27c5afc78b3c79778'
readonly ARTIFACT_ROOT=/var/lib/home-lab/compose-staging/$ARTIFACT_SHA256
readonly STAGED_ENV=/etc/docker-compose/staging/$ARTIFACT_SHA256.env
readonly TRANSFER=/srv/home-lab-state/.debian-openfit-canary-image.tar
readonly TRANSFER_MARKER=/srv/home-lab-state/.debian-openfit-canary-transfer.json
readonly ACTIVATION_MARKER=/etc/home-lab/allow-storage-activation
readonly OUTPUT_MARKER=/var/lib/home-lab/debian-openfit-canary.json
readonly STATE_UNIT='srv-home\x2dlab\x2dstate.mount'
readonly GAMES_UNIT=mnt-games.mount
readonly NFS_UNIT=mnt-storage.mount
readonly CANARY_IMAGE_TAG=home-lab/openfit-canary:stage4
readonly CANARY_OVERRIDE=/run/home-lab-openfit-canary.override.yml

fail() { echo "error: $*" >&2; exit 1; }
service_active() { [[ $(systemctl is-active "$1" 2>/dev/null || true) == active ]]; }
mount_active() { mountpoint -q "$1"; }

[[ $# -eq 2 ]] || fail "usage: run-openfit-production-canary.sh IMAGE_SHA256 IMAGE_BYTES"
[[ $(id -u) -eq 0 ]] || fail "production canary requires root"
expected_image_sha=$1
expected_image_bytes=$2
[[ $expected_image_sha =~ ^[0-9a-f]{64}$ ]] || fail "expected image checksum is invalid"
[[ $expected_image_bytes =~ ^[0-9]+$ && $expected_image_bytes -gt 0 ]] || fail "expected image size is invalid"
if ! grep -Fxq 'ID=debian' /etc/os-release || ! grep -Eq '^VERSION_ID="?13"?$' /etc/os-release; then fail "candidate is not Debian 13"; fi
[[ $(uname -r) == 6.12.101+deb13-amd64 ]] || fail "candidate kernel differs"
[[ -f /var/lib/home-lab/debian-compose-staged.json && ! -L /var/lib/home-lab/debian-compose-staged.json ]] || fail "credential staging marker is absent or unsafe"
jq -e --arg artifact "$ARTIFACT_SHA256" '.format == "home-lab-debian-credentials-compose-staged-v1" and .artifactSha256 == $artifact and .composeValidation == "quiet-pass" and .runtimeEnvironmentInstalled == false' /var/lib/home-lab/debian-compose-staged.json >/dev/null || fail "credential staging marker differs"
[[ -d $ARTIFACT_ROOT && ! -L $ARTIFACT_ROOT ]] || fail "staged artifact is absent or unsafe"
[[ $(python3 "$ARTIFACT_ROOT/scripts/compose-artifact.py" --root "$ARTIFACT_ROOT" --no-git hash) == "$ARTIFACT_SHA256" ]] || fail "staged artifact hash differs"
[[ -f $STAGED_ENV && ! -L $STAGED_ENV && $(stat -c %U:%G:%a "$STAGED_ENV") == root:root:600 ]] || fail "staged environment is absent or unsafe"
[[ ! -e /etc/docker-compose/production.env && ! -e /var/lib/tailscale && ! -e /etc/default/tailscaled ]] || fail "runtime credentials or Tailscale state exists"
[[ ! -e $ACTIVATION_MARKER && ! -e $OUTPUT_MARKER ]] || fail "a prior storage activation or canary marker requires reconciliation"
[[ $(systemctl show -p What --value "$STATE_UNIT") == /dev/disk/by-uuid/d4a19647-7879-4079-9fc9-b3e79711b449 && $(systemctl show -p Where --value "$STATE_UNIT") == /srv/home-lab-state && $(systemctl show -p Type --value "$STATE_UNIT") == ext4 && $(systemctl show -p Options --value "$STATE_UNIT") == noatime,nofail ]] || fail "state mount unit differs"
[[ $(systemctl show -p What --value "$GAMES_UNIT") == /dev/disk/by-uuid/31602ce7-0054-498a-9f24-f51ca491e7b3 && $(systemctl show -p Where --value "$GAMES_UNIT") == /mnt/games && $(systemctl show -p Type --value "$GAMES_UNIT") == ext4 && $(systemctl show -p Options --value "$GAMES_UNIT") == noatime,nofail ]] || fail "games mount unit differs"
[[ $(systemctl show -p What --value "$NFS_UNIT") == 192.168.0.123:/storage/docker && $(systemctl show -p Where --value "$NFS_UNIT") == /mnt/storage && $(systemctl show -p Type --value "$NFS_UNIT") == nfs4 && $(systemctl show -p Options --value "$NFS_UNIT") == defaults ]] || fail "NFS mount unit differs"
for unit in "$STATE_UNIT" "$GAMES_UNIT" "$NFS_UNIT"; do [[ $(systemctl is-enabled "$unit" 2>/dev/null || true) == disabled ]] || fail "a protected mount unit is enabled"; done
for target in /srv/home-lab-state /mnt/games /mnt/storage; do ! mount_active "$target" || fail "a protected mount is already active"; done
for service in docker.service docker.socket containerd.service; do [[ $(systemctl is-active "$service" 2>/dev/null || true) == inactive ]] || fail "Docker or containerd is already active"; done
[[ $(systemctl is-enabled docker.service 2>/dev/null || true) == disabled && $(systemctl is-enabled docker.socket 2>/dev/null || true) == disabled && $(systemctl is-enabled containerd.service 2>/dev/null || true) == masked ]] || fail "Docker or containerd enablement differs"
[[ ! -S /run/docker.sock ]] || fail "Docker socket already exists"

started_epoch=$(date +%s)
canary_healthy=false
cleanup_complete=false
docker_objects_clean=false
docker_started=false
loaded_image_id=
cleanup() {
  local result=$?
  trap - EXIT
  trap '' INT TERM HUP
  set +e
  if service_active docker.service; then
    docker ps -aq --filter name='^/openfit$' | xargs -r docker rm --force >/dev/null 2>&1 || true
    docker network ls --format '{{.Name}}' | grep -Ev '^(bridge|host|none)$' | while read -r network; do docker network rm "$network" >/dev/null 2>&1 || true; done
    if [[ -n $loaded_image_id ]]; then docker image rm --force "$loaded_image_id" >/dev/null 2>&1 || true; fi
    if [[ $(docker ps -aq | wc -l) -eq 0 && $(docker volume ls -q | wc -l) -eq 0 && $(docker network ls --format '{{.Name}}' | grep -Evc '^(bridge|host|none)$' || true) -eq 0 && $(docker image ls -aq | wc -l) -eq 0 ]]; then
      docker_objects_clean=true
    fi
  elif [[ $docker_started == false ]]; then
    docker_objects_clean=true
  fi
  timeout 60 systemctl stop docker.service docker.socket >/dev/null 2>&1 || true
  timeout 60 systemctl stop containerd.service >/dev/null 2>&1 || true
  systemctl disable docker.service docker.socket >/dev/null 2>&1 || true
  systemctl mask containerd.service >/dev/null 2>&1 || true
  rm -f -- "$TRANSFER" "$TRANSFER_MARKER"
  rm -f -- "$CANARY_OVERRIDE"
  timeout 60 systemctl stop "$NFS_UNIT" >/dev/null 2>&1 || timeout 30 umount /mnt/storage >/dev/null 2>&1 || true
  timeout 60 systemctl stop "$GAMES_UNIT" >/dev/null 2>&1 || timeout 30 umount /mnt/games >/dev/null 2>&1 || true
  timeout 60 systemctl stop "$STATE_UNIT" >/dev/null 2>&1 || timeout 30 umount /srv/home-lab-state >/dev/null 2>&1 || true
  rm -f -- "$ACTIVATION_MARKER"
  systemctl daemon-reload >/dev/null 2>&1 || true
  if ! mount_active /srv/home-lab-state && ! mount_active /mnt/games && ! mount_active /mnt/storage && \
     [[ $(systemctl is-active docker.service 2>/dev/null || true) == inactive ]] && \
     [[ $(systemctl is-active containerd.service 2>/dev/null || true) == inactive ]] && [[ ! -S /run/docker.sock ]] && \
     [[ $(systemctl is-enabled docker.service 2>/dev/null || true) == disabled ]] && \
     [[ $(systemctl is-enabled docker.socket 2>/dev/null || true) == disabled ]] && \
     [[ $(systemctl is-enabled containerd.service 2>/dev/null || true) == masked ]] && \
     [[ $docker_objects_clean == true ]]; then
    cleanup_complete=true
  fi
  if [[ $result -ne 0 || $cleanup_complete != true ]]; then
    echo "critical: canary cleanup incomplete; candidate must remain stopped until protected mounts are released" >&2
    exit 1
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

install -d -o root -g root -m 0755 /etc/home-lab
install -o root -g root -m 0400 /dev/null "$ACTIVATION_MARKER"
systemctl daemon-reload
systemctl start "$STATE_UNIT"
systemctl start "$GAMES_UNIT"
systemctl start "$NFS_UNIT"
[[ $(findmnt -rn -S UUID=d4a19647-7879-4079-9fc9-b3e79711b449 -o TARGET) == /srv/home-lab-state ]] || fail "state mount identity differs"
[[ $(findmnt -rn -S UUID=31602ce7-0054-498a-9f24-f51ca491e7b3 -o TARGET) == /mnt/games ]] || fail "games mount identity differs"
[[ $(findmnt -rn -T /mnt/storage -o SOURCE) == 192.168.0.123:/storage/docker ]] || fail "NFS mount identity differs"
for target in /srv/home-lab-state /mnt/games /mnt/storage; do findmnt -rn -T "$target" -o OPTIONS | tr ',' '\n' | grep -Fxq rw || fail "protected mount is not read-write"; done
findmnt -rn -T /mnt/storage -o OPTIONS | tr ',' '\n' | grep -Fxq hard || fail "NFS hard option is absent"
findmnt -rn -T /mnt/storage -o OPTIONS | tr ',' '\n' | grep -Fxq vers=4.2 || fail "NFS version differs"
[[ $(df -B1 --output=avail /srv/home-lab-state | tail -1 | tr -d ' ') -ge 40000000000 ]] || fail "state filesystem free space is below canary threshold"
[[ $(df -B1 --output=avail /mnt/games | tail -1 | tr -d ' ') -ge 2000000000000 ]] || fail "games filesystem free space is below canary threshold"
[[ $(df -B1 --output=avail /mnt/storage | tail -1 | tr -d ' ') -ge 10000000000000 ]] || fail "NFS free space is below canary threshold"
[[ -f $TRANSFER && ! -L $TRANSFER && $(stat -c %s "$TRANSFER") -eq $expected_image_bytes ]] || fail "canary image transfer differs"
[[ $(sha256sum "$TRANSFER" | awk '{print $1}') == "$expected_image_sha" ]] || fail "canary image checksum differs"
[[ -f $TRANSFER_MARKER && ! -L $TRANSFER_MARKER ]] || fail "canary transfer marker is absent or unsafe"
transfer_marker=$(cat "$TRANSFER_MARKER")
jq -e --arg image "$IMAGE" --arg imageSha256 "$expected_image_sha" --argjson imageBytes "$expected_image_bytes" '.format == "home-lab-debian-openfit-canary-transfer-v1" and .image == $image and .imageSha256 == $imageSha256 and .imageBytes == $imageBytes and (.imageId | test("^sha256:[0-9a-f]{64}$")) and .backupReplicaCount == 3 and (.backupSha256 | test("^[0-9a-f]{64}$")) and .backupBytes >= 1000000000 and .openfitStoppedForSnapshot == true and .privateDataExported == false' <<< "$transfer_marker" >/dev/null || fail "canary transfer marker differs"
[[ -d /srv/home-lab-state/openfit-data && ! -L /srv/home-lab-state/openfit-data && $(stat -c %u:%g:%a /srv/home-lab-state/openfit-data) == 0:0:755 ]] || fail "Openfit state metadata differs"

systemctl unmask containerd.service
systemctl start containerd.service
systemctl start docker.service
service_active docker.service || fail "Docker failed to start"
docker_started=true
[[ -S /run/docker.sock ]] || fail "Docker socket is absent"
docker load --input "$TRANSFER" >/dev/null
rm -f -- "$TRANSFER"
loaded_image_id=$(jq -er .imageId <<< "$transfer_marker")
docker image inspect "$loaded_image_id" >/dev/null || fail "loaded Openfit image ID is absent"
[[ $(docker image inspect "$loaded_image_id" --format '{{.Id}}') == "$loaded_image_id" ]] || fail "loaded Openfit image ID differs"
docker image tag "$loaded_image_id" "$CANARY_IMAGE_TAG"
printf 'services:\n  openfit:\n    image: %s\n' "$CANARY_IMAGE_TAG" > "$CANARY_OVERRIDE"
chown root:root "$CANARY_OVERRIDE"
chmod 0600 "$CANARY_OVERRIDE"
HOME=/root docker compose --project-name docker-compose --project-directory "$ARTIFACT_ROOT" \
  --env-file "$STAGED_ENV" --file "$ARTIFACT_ROOT/docker-compose.yml" --file "$CANARY_OVERRIDE" \
  up --detach --no-deps --pull never openfit >/dev/null
[[ $(docker ps -aq | wc -l) -eq 1 ]] || fail "canary created an unexpected container set"
for ((attempt = 0; attempt < 90; attempt += 1)); do
  if [[ $(docker inspect openfit --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || true) == healthy ]]; then canary_healthy=true; break; fi
  sleep 5
done
[[ $canary_healthy == true ]] || fail "Openfit canary did not become healthy"
[[ $(docker inspect openfit | jq '[.[0].Mounts[] | select(.Type == "bind" and .Source == "/srv/home-lab-state/openfit-data" and .Destination == "/app/data" and .RW == true)] | length') -eq 1 ]] || fail "Openfit state bind differs"
[[ $(docker inspect openfit | jq '[.[0].Mounts[] | select(.Type == "volume")] | length') -eq 0 ]] || fail "Openfit canary used a Docker volume"
[[ $(docker inspect openfit --format '{{.Image}}') == "$loaded_image_id" && $(docker inspect openfit --format '{{.Config.Image}}') == "$CANARY_IMAGE_TAG" ]] || fail "Openfit canary image differs"

backup_fields=$(jq -c '{backupBytes,backupCommandStatus,backupName,backupReplicaCount,backupSha256,openfitStoppedForSnapshot}' <<< "$transfer_marker")
model_sha=$(jq -er .modelInventorySha256 /var/lib/home-lab/debian-compose-staged.json)
cleanup
trap - EXIT INT TERM HUP
[[ $cleanup_complete == true ]] || fail "canary cleanup differs"
[[ $docker_objects_clean == true ]] || fail "Docker objects remain after canary cleanup"
kernel_errors=$(journalctl -k --since "@$started_epoch" --no-pager | grep -Eci 'I/O error|EXT4-fs error|Buffer I/O|blk_update_request|nfs: server .* not responding' || true)
[[ $kernel_errors -eq 0 ]] || fail "kernel storage errors occurred during canary"
marker_temporary=$(mktemp /var/lib/home-lab/.debian-openfit-canary.XXXXXX)
jq -cn --arg artifactSha256 "$ARTIFACT_SHA256" --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg image "$IMAGE" --arg modelInventorySha256 "$model_sha" --argjson backup "$backup_fields" \
  '{artifactSha256:$artifactSha256,backup:$backup,canaryHealthy:true,cleanupComplete:true,completedAt:$completedAt,dockerRuntime:"stopped-disabled-containerd-masked",format:"home-lab-debian-openfit-production-canary-v1",image:$image,kernelStorageErrors:0,modelInventorySha256:$modelInventorySha256,privateIdentityExported:false,protectedMountsUnmounted:true,pulls:"disabled",runtimeEnvironmentInstalled:false,service:"openfit",stateBind:"rw-verified",tailscaleEnrolled:false}' > "$marker_temporary"
chown root:root "$marker_temporary"
chmod 0644 "$marker_temporary"
mv -T "$marker_temporary" "$OUTPUT_MARKER"
printf 'debian_openfit_canary=pass health=healthy cleanup=complete pulls=disabled\n'
