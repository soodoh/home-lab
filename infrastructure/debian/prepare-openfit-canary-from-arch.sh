#!/bin/bash
set -Eeuo pipefail

readonly IMAGE='ghcr.io/soodoh/openfit:latest@sha256:5ce56f1db33881ec5216aaaeff89fa7eeba281e5e1c497e27c5afc78b3c79778'
readonly IMAGE_REPO_DIGEST='ghcr.io/soodoh/openfit@sha256:5ce56f1db33881ec5216aaaeff89fa7eeba281e5e1c497e27c5afc78b3c79778'
readonly TRANSFER=/srv/home-lab-state/.debian-openfit-canary-image.tar
readonly TRANSFER_MARKER=/srv/home-lab-state/.debian-openfit-canary-transfer.json
readonly OUTPUT_MARKER=/run/home-lab-openfit-canary-transfer.json
readonly BACKUP_LOG=/var/log/home-lab-debian-canary-backup.log
readonly BACKUP_PATTERN='daily-local-backup-????-??-??T??-??-??.tar.gz.gpg'
readonly MINIMUM_BACKUP_BYTES=1000000000
readonly MAXIMUM_BACKUP_AGE_SECONDS=86400
readonly BACKUP_ROOTS='/home/docker/backups /mnt/games/backups /mnt/storage/backups'
readonly CONTAINER_BACKUP_PID=/tmp/home-lab-debian-canary-backup.pid

fail() { echo "error: $*" >&2; exit 1; }
verify_arch_workloads() {
  local ids=()
  mapfile -t ids < <(docker ps -q)
  [[ ${#ids[@]} -eq 41 ]]
  [[ $(docker ps --filter health=unhealthy -q | wc -l) -eq 0 ]]
  docker inspect "${ids[@]}" | jq -e 'all(.[]; if .State.Health then .State.Health.Status == "healthy" else true end)' >/dev/null
  [[ $(docker inspect "${ids[@]}" | jq '[.[].Mounts[] | select(.Type == "volume")] | length') -eq 0 ]]
}

[[ $# -eq 0 ]] || fail "usage: prepare-openfit-canary-from-arch.sh"
[[ $(id -u) -eq 0 ]] || fail "Arch canary preparation requires root"
grep -Fxq 'ID=arch' /etc/os-release || fail "source guest is not Arch"
[[ $(findmnt -rn -S UUID=d4a19647-7879-4079-9fc9-b3e79711b449 -o TARGET) == /srv/home-lab-state ]] || fail "state filesystem identity differs"
[[ $(findmnt -rn -S UUID=31602ce7-0054-498a-9f24-f51ca491e7b3 -o TARGET) == /mnt/games ]] || fail "games filesystem identity differs"
[[ $(findmnt -rn -T /mnt/storage -o SOURCE) == 192.168.0.123:/storage/docker ]] || fail "NFS source differs"
verify_arch_workloads || fail "Arch workload health differs before backup"
[[ ! -e $TRANSFER && ! -L $TRANSFER && ! -e $TRANSFER_MARKER && ! -L $TRANSFER_MARKER ]] || fail "a prior canary transfer requires reconciliation"
[[ -d /srv/home-lab-state/openfit-data && ! -L /srv/home-lab-state/openfit-data ]] || fail "Openfit state directory is absent or unsafe"
[[ $(stat -c %u:%g:%a /srv/home-lab-state/openfit-data) == 0:0:755 ]] || fail "Openfit state metadata differs"
docker image inspect "$IMAGE" >/dev/null || fail "exact Openfit image is absent"
docker image inspect "$IMAGE" | jq -e --arg digest "$IMAGE_REPO_DIGEST" '.[0].RepoDigests | index($digest) != null' >/dev/null || fail "Openfit image digest differs"
image_id=$(docker image inspect "$IMAGE" --format '{{.Id}}')
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Openfit image ID differs"

started_epoch=$(date +%s)
openfit_stopped=false
backup_pid=
stop_container_backup() {
  local container_pid
  if docker exec daily-local-backup test -f "$CONTAINER_BACKUP_PID" >/dev/null 2>&1; then
    container_pid=$(docker exec daily-local-backup cat "$CONTAINER_BACKUP_PID" 2>/dev/null || true)
    if [[ $container_pid =~ ^[1-9][0-9]*$ ]]; then
      docker exec daily-local-backup kill -TERM "$container_pid" >/dev/null 2>&1 || true
      for ((stop_attempt = 0; stop_attempt < 30; stop_attempt += 1)); do
        docker exec daily-local-backup kill -0 "$container_pid" >/dev/null 2>&1 || break
        sleep 1
      done
      docker exec daily-local-backup kill -KILL "$container_pid" >/dev/null 2>&1 || true
    fi
    docker exec daily-local-backup rm -f "$CONTAINER_BACKUP_PID" >/dev/null 2>&1 || true
  fi
}
restore_openfit() {
  trap - EXIT
  trap '' INT TERM HUP
  if [[ -n $backup_pid ]]; then kill "$backup_pid" >/dev/null 2>&1 || true; fi
  stop_container_backup
  if [[ -n $backup_pid ]]; then wait "$backup_pid" >/dev/null 2>&1 || true; fi
  if [[ $openfit_stopped == true ]]; then docker start openfit >/dev/null 2>&1 || true; fi
}
trap restore_openfit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
docker stop --time 60 openfit >/dev/null
openfit_stopped=true
[[ $(docker inspect openfit --format '{{.State.Status}}') == exited ]] || fail "Openfit did not stop for its backup snapshot"
set +e
timeout 7200 docker exec daily-local-backup /bin/sh -c 'printf "%s\n" "$$" > /tmp/home-lab-debian-canary-backup.pid; exec /usr/bin/backup' >"$BACKUP_LOG" 2>&1 &
backup_pid=$!
set -e
snapshot_complete=false
for ((attempt = 0; attempt < 360; attempt += 1)); do
  if grep -Fq 'Created backup of ' "$BACKUP_LOG" 2>/dev/null; then snapshot_complete=true; break; fi
  kill -0 "$backup_pid" >/dev/null 2>&1 || break
  sleep 5
done
if [[ $snapshot_complete != true ]]; then
  kill "$backup_pid" >/dev/null 2>&1 || true
  wait "$backup_pid" >/dev/null 2>&1 || true
  fail "backup snapshot did not complete while Openfit was stopped"
fi
docker start openfit >/dev/null
openfit_stopped=false
set +e
wait "$backup_pid"
backup_status=$?
set -e
docker exec daily-local-backup rm -f "$CONTAINER_BACKUP_PID" >/dev/null 2>&1 || true
chmod 0600 "$BACKUP_LOG"
for ((attempt = 0; attempt < 120; attempt += 1)); do
  if verify_arch_workloads; then break; fi
  sleep 5
done
verify_arch_workloads || fail "Arch workloads did not recover after backup"

home_backup=$(find /home/docker/backups -maxdepth 1 -type f -name "$BACKUP_PATTERN" -newermt "@$((started_epoch - 60))" -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
[[ -n $home_backup ]] || fail "fresh home backup replica is absent"
backup_name=${home_backup##*/}
[[ $backup_name =~ ^daily-local-backup-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.tar\.gz\.gpg$ ]] || fail "backup filename differs"
backup_size=$(stat -c %s "$home_backup")
[[ $backup_size -ge $MINIMUM_BACKUP_BYTES ]] || fail "fresh backup is unexpectedly small"
now_epoch=$(date +%s)
backup_mtime=$(stat -c %Y "$home_backup")
backup_age=$((now_epoch - backup_mtime))
[[ $backup_age -ge -300 && $backup_age -le $MAXIMUM_BACKUP_AGE_SECONDS ]] || fail "fresh backup is stale or future-dated"
backup_sha=
for root in $BACKUP_ROOTS; do
  archive=$root/$backup_name
  sidecar=$archive.sha256
  [[ -f $archive && ! -L $archive && -f $sidecar && ! -L $sidecar ]] || fail "a backup replica or checksum is absent"
  [[ $(stat -c %s "$archive") -eq $backup_size ]] || fail "backup replica size differs"
  read -r recorded_sha recorded_name < "$sidecar"
  [[ $recorded_name == "$backup_name" && $recorded_sha =~ ^[0-9a-f]{64}$ ]] || fail "backup checksum sidecar differs"
  actual_sha=$(sha256sum "$archive" | awk '{print $1}')
  [[ $actual_sha == "$recorded_sha" ]] || fail "backup replica checksum differs"
  if [[ -z $backup_sha ]]; then backup_sha=$actual_sha; else [[ $actual_sha == "$backup_sha" ]] || fail "backup replicas diverge"; fi
done
if [[ $backup_status -ne 0 ]]; then
  grep -Fq 'Stored copy of backup' "$BACKUP_LOG" || fail "manual backup failed before durable storage"
fi

transfer_pending=$TRANSFER.pending
marker_pending=$TRANSFER_MARKER.pending
completed=false
cleanup() {
  rm -f -- "$transfer_pending" "$marker_pending"
  if [[ $completed != true ]]; then rm -f -- "$TRANSFER" "$TRANSFER_MARKER" "$OUTPUT_MARKER"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
rm -f -- "$OUTPUT_MARKER"
umask 077
docker image save --output "$transfer_pending" "$image_id"
transfer_size=$(stat -c %s "$transfer_pending")
[[ $transfer_size -gt 0 ]] || fail "Openfit image transfer is empty"
transfer_sha=$(sha256sum "$transfer_pending" | awk '{print $1}')
chown root:root "$transfer_pending"
chmod 0600 "$transfer_pending"
mv -T "$transfer_pending" "$TRANSFER"

jq -cn --arg backupName "$backup_name" --arg backupSha256 "$backup_sha" \
  --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg image "$IMAGE" --arg imageId "$image_id" \
  --arg imageSha256 "$transfer_sha" --argjson backupBytes "$backup_size" \
  --argjson backupStatus "$backup_status" --argjson imageBytes "$transfer_size" \
  '{backupBytes:$backupBytes,backupCommandStatus:$backupStatus,backupName:$backupName,backupReplicaCount:3,backupSha256:$backupSha256,completedAt:$completedAt,format:"home-lab-debian-openfit-canary-transfer-v1",image:$image,imageBytes:$imageBytes,imageId:$imageId,imageSha256:$imageSha256,openfitState:"0:0:755",openfitStoppedForSnapshot:true,privateDataExported:false}' > "$marker_pending"
chown root:root "$marker_pending"
chmod 0600 "$marker_pending"
mv -T "$marker_pending" "$TRANSFER_MARKER"
install -o root -g root -m 0600 "$TRANSFER_MARKER" "$OUTPUT_MARKER"
completed=true
trap - EXIT INT TERM HUP
printf 'openfit_canary_transfer=pass backup=%s replicas=3 image_sha256=%s\n' "$backup_name" "$transfer_sha"
