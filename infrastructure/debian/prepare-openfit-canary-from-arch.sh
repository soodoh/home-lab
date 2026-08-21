#!/bin/bash
set -Eeuo pipefail

readonly IMAGE='ghcr.io/soodoh/openfit:latest@sha256:5ce56f1db33881ec5216aaaeff89fa7eeba281e5e1c497e27c5afc78b3c79778'
readonly IMAGE_REPO_DIGEST='ghcr.io/soodoh/openfit@sha256:5ce56f1db33881ec5216aaaeff89fa7eeba281e5e1c497e27c5afc78b3c79778'
readonly TRANSFER=/srv/home-lab-state/.debian-openfit-canary-image.tar
readonly TRANSFER_MARKER=/srv/home-lab-state/.debian-openfit-canary-transfer.json
readonly OUTPUT_MARKER=/run/home-lab-openfit-canary-transfer.json
readonly BACKUP_PATTERN='daily-local-backup-????-??-??T??-??-??.tar.gz.gpg'
readonly MINIMUM_BACKUP_BYTES=1000000000
readonly MAXIMUM_BACKUP_AGE_SECONDS=604800
readonly SAMPLE_BYTES=1048576
readonly BACKUP_ROOTS='/mnt/games/backups /mnt/storage/backups'

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
verify_arch_workloads || fail "Arch workload health differs"
[[ ! -e $TRANSFER && ! -L $TRANSFER && ! -e $TRANSFER_MARKER && ! -L $TRANSFER_MARKER ]] || fail "a prior canary transfer requires reconciliation"
[[ -d /srv/home-lab-state/openfit-data && ! -L /srv/home-lab-state/openfit-data ]] || fail "Openfit state directory is absent or unsafe"
[[ $(stat -c %u:%g:%a /srv/home-lab-state/openfit-data) == 0:0:755 ]] || fail "Openfit state metadata differs"
docker image inspect "$IMAGE" >/dev/null || fail "exact Openfit image is absent"
docker image inspect "$IMAGE" | jq -e --arg digest "$IMAGE_REPO_DIGEST" '.[0].RepoDigests | index($digest) != null' >/dev/null || fail "Openfit image digest differs"
image_id=$(docker image inspect "$IMAGE" --format '{{.Id}}')
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Openfit image ID differs"

reference_backup=$(find /mnt/games/backups -maxdepth 1 -type f -name "$BACKUP_PATTERN" -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
[[ -n $reference_backup ]] || fail "local backup evidence is absent"
backup_name=${reference_backup##*/}
[[ $backup_name =~ ^daily-local-backup-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.tar\.gz\.gpg$ ]] || fail "backup filename differs"
backup_size=$(stat -c %s "$reference_backup")
[[ $backup_size -ge $MINIMUM_BACKUP_BYTES ]] || fail "local backup is unexpectedly small"
now_epoch=$(date +%s)
backup_mtime=$(stat -c %Y "$reference_backup")
backup_age=$((now_epoch - backup_mtime))
[[ $backup_age -ge -300 && $backup_age -le $MAXIMUM_BACKUP_AGE_SECONDS ]] || fail "local backup evidence is stale or future-dated"
backup_sha=
backup_sample_sha=
for root in $BACKUP_ROOTS; do
  archive=$root/$backup_name
  sidecar=$archive.sha256
  [[ -f $archive && ! -L $archive && -f $sidecar && ! -L $sidecar ]] || fail "a local backup replica or checksum is absent"
  [[ $(stat -c %s "$archive") -eq $backup_size ]] || fail "local backup replica size differs"
  read -r recorded_sha recorded_name < "$sidecar"
  [[ $recorded_name == "$backup_name" && $recorded_sha =~ ^[0-9a-f]{64}$ ]] || fail "local backup checksum sidecar differs"
  sample_sha=$({ head -c "$SAMPLE_BYTES" "$archive"; tail -c "$SAMPLE_BYTES" "$archive"; } | sha256sum | awk '{print $1}')
  if [[ -z $backup_sha ]]; then
    backup_sha=$recorded_sha
    backup_sample_sha=$sample_sha
  else
    [[ $recorded_sha == "$backup_sha" && $sample_sha == "$backup_sample_sha" ]] || fail "local backup replicas diverge"
  fi
done

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
  --arg backupSampleSha256 "$backup_sample_sha" --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg image "$IMAGE" --arg imageId "$image_id" --arg imageSha256 "$transfer_sha" \
  --argjson backupAgeSeconds "$backup_age" --argjson backupBytes "$backup_size" --argjson imageBytes "$transfer_size" \
  '{backupActualFullHashRecomputed:false,backupAgeSeconds:$backupAgeSeconds,backupBytes:$backupBytes,backupName:$backupName,backupReplicaCount:2,backupSampleSha256:$backupSampleSha256,backupSha256:$backupSha256,backupValidation:"existing-local-replicas-sidecar-and-sample",completedAt:$completedAt,format:"home-lab-debian-openfit-canary-transfer-v1",image:$image,imageBytes:$imageBytes,imageId:$imageId,imageSha256:$imageSha256,openfitState:"0:0:755",openfitStoppedForSnapshot:false,privateDataExported:false,s3Checked:false}' > "$marker_pending"
chown root:root "$marker_pending"
chmod 0600 "$marker_pending"
mv -T "$marker_pending" "$TRANSFER_MARKER"
install -o root -g root -m 0600 "$TRANSFER_MARKER" "$OUTPUT_MARKER"
completed=true
trap - EXIT INT TERM HUP
printf 'openfit_canary_transfer=pass backup=%s replicas=2 s3=not-checked image_sha256=%s\n' "$backup_name" "$transfer_sha"
