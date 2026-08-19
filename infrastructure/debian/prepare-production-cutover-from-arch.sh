#!/bin/bash
set -Eeuo pipefail

readonly ARTIFACT_ROOT=/srv/docker-compose/current
readonly PRODUCTION_ENV=/etc/docker-compose/production.env
readonly PROJECT=docker-compose
readonly ARTIFACT_SHA256=d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c
readonly MODEL_SHA256=f36ba480734143d51affdc789b2ef782bee063dfb96a248d5048568a82f5a16e
readonly IMAGE_LOCK_SHA256=c74199885009f0082cc7b5956eeb526ad895d1cab1605df15998767185aec726
readonly TRANSFER=/srv/home-lab-state/.debian-production-images.tar
readonly TRANSFER_MARKER=/srv/home-lab-state/.debian-production-images.json
readonly OUTPUT_MARKER=/run/home-lab-debian-production-transfer.json
readonly TAILSCALE_ARCHIVE=/srv/home-lab-state/.debian-tailscale-1.98.4-amd64.tgz
readonly TAILSCALE_URL=https://pkgs.tailscale.com/stable/tailscale_1.98.4_amd64.tgz
readonly TAILSCALE_SHA256=e6c08a8ee7e63e69aaf1b62ecd12672b3883fbcd2a176bf6cfa42a15fdce0b6b
readonly BACKUP_PATTERN='daily-local-backup-????-??-??T??-??-??.tar.gz.gpg'
readonly BACKUP_ROOTS='/home/docker/backups /mnt/games/backups /mnt/storage/backups'
readonly MINIMUM_BACKUP_BYTES=1000000000
readonly MAXIMUM_BACKUP_AGE_SECONDS=604800
readonly SAMPLE_BYTES=1048576

fail() { echo "error: $*" >&2; exit 1; }

[[ $# -eq 1 ]] || fail "usage: prepare-production-cutover-from-arch.sh IMAGE_LOCK"
lock=$1
[[ $(id -u) -eq 0 ]] || fail "production transfer preparation requires root"
grep -Fxq 'ID=arch' /etc/os-release || fail "source guest is not Arch"
[[ -f $lock && ! -L $lock && $(sha256sum "$lock" | awk '{print $1}') == "$IMAGE_LOCK_SHA256" ]] || fail "production image lock differs"
jq -e '.schema == 1 and .project == "docker-compose" and (.images | length) == 41 and ([.images[].service] | unique | length) == 41 and ([.images[].image_id] | unique | length) == 36 and all(.images[]; (.image_id | test("^sha256:[0-9a-f]{64}$")) and (.repo_digests | length) > 0)' "$lock" >/dev/null || fail "production image lock schema differs"
[[ $(findmnt -rn -S UUID=d4a19647-7879-4079-9fc9-b3e79711b449 -o TARGET) == /srv/home-lab-state ]] || fail "state filesystem identity differs"
[[ $(findmnt -rn -S UUID=31602ce7-0054-498a-9f24-f51ca491e7b3 -o TARGET) == /mnt/games ]] || fail "games filesystem identity differs"
[[ $(findmnt -rn -T /mnt/storage -o SOURCE) == 192.168.0.123:/storage/docker ]] || fail "NFS source differs"
[[ ! -e $TRANSFER && ! -L $TRANSFER && ! -e $TRANSFER_MARKER && ! -L $TRANSFER_MARKER && ! -e $TAILSCALE_ARCHIVE && ! -L $TAILSCALE_ARCHIVE ]] || fail "a prior production transfer requires reconciliation"
ids=()
mapfile -t ids < <(docker ps -q)
[[ ${#ids[@]} -eq 41 ]] || fail "Arch container count differs"
[[ $(docker ps --filter health=unhealthy -q | wc -l) -eq 0 ]] || fail "Arch has an unhealthy container"
docker inspect "${ids[@]}" | jq -e 'all(.[]; if .State.Health then .State.Health.Status == "healthy" else true end)' >/dev/null || fail "Arch health checks differ"
[[ $(docker inspect "${ids[@]}" | jq '[.[].Mounts[] | select(.Type == "bind")] | length') -eq 115 ]] || fail "Arch bind count differs"
[[ $(docker inspect "${ids[@]}" | jq '[.[].Mounts[] | select(.Type == "volume")] | length') -eq 0 ]] || fail "Arch Docker volume use differs"
[[ -d $ARTIFACT_ROOT && ! -L $ARTIFACT_ROOT && -f $PRODUCTION_ENV && ! -L $PRODUCTION_ENV ]] || fail "Arch production artifact or environment is unsafe"
[[ $(stat -c %U:%G:%a "$PRODUCTION_ENV") == root:root:600 ]] || fail "Arch production environment metadata differs"
model=/run/home-lab-arch-production-model.json
captured_lock=/run/home-lab-arch-production-image-lock.json
rm -f -- "$model" "$captured_lock" "$OUTPUT_MARKER"
HOME=/root python3 "$ARTIFACT_ROOT/scripts/compose-model-inventory.py" desired --artifact-root "$ARTIFACT_ROOT" --project-directory "$ARTIFACT_ROOT" --env-file "$PRODUCTION_ENV" --project-name "$PROJECT" --output "$model" >/dev/null
[[ $(sha256sum "$model" | awk '{print $1}') == "$MODEL_SHA256" ]] || fail "Arch production Compose model differs"
python3 "$ARTIFACT_ROOT/scripts/compose-image-lock.py" capture --project "$PROJECT" --output "$captured_lock" >/dev/null
jq -e --slurpfile expected "$lock" '.images == $expected[0].images' "$captured_lock" >/dev/null || fail "Arch runtime images diverge from production lock"
mapfile -t image_ids < <(jq -r '[.images[].image_id] | unique[]' "$lock")
[[ ${#image_ids[@]} -eq 36 ]] || fail "unique production image count differs"
for image_id in "${image_ids[@]}"; do docker image inspect "$image_id" >/dev/null || fail "a locked production image is absent"; done

home_backup=$(find /home/docker/backups -maxdepth 1 -type f -name "$BACKUP_PATTERN" -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
[[ -n $home_backup ]] || fail "local backup evidence is absent"
backup_name=${home_backup##*/}
backup_size=$(stat -c %s "$home_backup")
backup_age=$(($(date +%s) - $(stat -c %Y "$home_backup")))
[[ $backup_name =~ ^daily-local-backup-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.tar\.gz\.gpg$ ]] || fail "backup filename differs"
[[ $backup_size -ge $MINIMUM_BACKUP_BYTES && $backup_age -ge -300 && $backup_age -le $MAXIMUM_BACKUP_AGE_SECONDS ]] || fail "local backup evidence is invalid or stale"
backup_sha=
backup_sample_sha=
for root in $BACKUP_ROOTS; do
  archive=$root/$backup_name
  sidecar=$archive.sha256
  [[ -f $archive && ! -L $archive && -f $sidecar && ! -L $sidecar && $(stat -c %s "$archive") -eq $backup_size ]] || fail "a local backup replica differs"
  read -r recorded_sha recorded_name < "$sidecar"
  [[ $recorded_name == "$backup_name" && $recorded_sha =~ ^[0-9a-f]{64}$ ]] || fail "a local backup checksum sidecar differs"
  sample_sha=$({ head -c "$SAMPLE_BYTES" "$archive"; tail -c "$SAMPLE_BYTES" "$archive"; } | sha256sum | awk '{print $1}')
  if [[ -z $backup_sha ]]; then backup_sha=$recorded_sha; backup_sample_sha=$sample_sha; else [[ $recorded_sha == "$backup_sha" && $sample_sha == "$backup_sample_sha" ]] || fail "local backup replicas diverge"; fi
done

transfer_pending=$TRANSFER.pending
marker_pending=$TRANSFER_MARKER.pending
completed=false
cleanup() {
  rm -f -- "$model" "$captured_lock" "$transfer_pending" "$marker_pending" "${TAILSCALE_ARCHIVE}.pending"
  if [[ $completed != true ]]; then rm -f -- "$TRANSFER" "$TRANSFER_MARKER" "$TAILSCALE_ARCHIVE" "$OUTPUT_MARKER"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
umask 077
tailscale_pending=$TAILSCALE_ARCHIVE.pending
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 600 --retry 3 --retry-all-errors --silent --show-error "$TAILSCALE_URL" --output "$tailscale_pending"
[[ $(sha256sum "$tailscale_pending" | awk '{print $1}') == "$TAILSCALE_SHA256" ]] || fail "Tailscale archive checksum differs"
chown root:root "$tailscale_pending"
chmod 0600 "$tailscale_pending"
mv -T "$tailscale_pending" "$TAILSCALE_ARCHIVE"
docker image save --output "$transfer_pending" "${image_ids[@]}"
transfer_bytes=$(stat -c %s "$transfer_pending")
[[ $transfer_bytes -ge 1000000000 && $transfer_bytes -le 60000000000 ]] || fail "production image transfer size differs"
transfer_sha=$(sha256sum "$transfer_pending" | awk '{print $1}')
chown root:root "$transfer_pending"
chmod 0600 "$transfer_pending"
mv -T "$transfer_pending" "$TRANSFER"
jq -cn --arg artifactSha256 "$ARTIFACT_SHA256" --arg backupName "$backup_name" --arg backupSampleSha256 "$backup_sample_sha" --arg backupSha256 "$backup_sha" --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg imageLockSha256 "$IMAGE_LOCK_SHA256" --arg modelInventorySha256 "$MODEL_SHA256" --arg tailscaleArchiveSha256 "$TAILSCALE_SHA256" --arg tailscaleVersion "1.98.4" --arg transferSha256 "$transfer_sha" --argjson backupAgeSeconds "$backup_age" --argjson backupBytes "$backup_size" --argjson transferBytes "$transfer_bytes" '{artifactSha256:$artifactSha256,backup:{backupActualFullHashRecomputed:false,backupAgeSeconds:$backupAgeSeconds,backupBytes:$backupBytes,backupName:$backupName,backupReplicaCount:3,backupSampleSha256:$backupSampleSha256,backupSha256:$backupSha256,backupValidation:"existing-local-replicas-sidecar-and-sample",s3Checked:false},completedAt:$completedAt,format:"home-lab-debian-production-transfer-v1",imageLockSha256:$imageLockSha256,imageServiceCount:41,modelInventorySha256:$modelInventorySha256,privateDataExported:false,tailscaleArchiveSha256:$tailscaleArchiveSha256,tailscaleVersion:$tailscaleVersion,transferBytes:$transferBytes,transferSha256:$transferSha256,uniqueImageCount:36}' > "$marker_pending"
chown root:root "$marker_pending"
chmod 0600 "$marker_pending"
mv -T "$marker_pending" "$TRANSFER_MARKER"
install -o root -g root -m 0600 "$TRANSFER_MARKER" "$OUTPUT_MARKER"
completed=true
trap - EXIT INT TERM HUP
rm -f -- "$model" "$captured_lock"
printf 'debian_production_transfer=pass services=41 unique_images=36 bytes=%s sha256=%s\n' "$transfer_bytes" "$transfer_sha"
