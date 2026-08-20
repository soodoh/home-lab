#!/bin/bash
set -Eeuo pipefail

readonly ARTIFACT_SHA256=d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c
readonly MODEL_SHA256=f36ba480734143d51affdc789b2ef782bee063dfb96a248d5048568a82f5a16e
readonly IMAGE_LOCK_SHA256=c74199885009f0082cc7b5956eeb526ad895d1cab1605df15998767185aec726
readonly TAILSCALE_SHA256=e6c08a8ee7e63e69aaf1b62ecd12672b3883fbcd2a176bf6cfa42a15fdce0b6b
readonly TAILSCALE_VERSION=1.98.4
readonly TAILSCALE_TAG=tag:docker-host
readonly TAILSCALE_HOSTNAME=docker-host-debian
readonly ARTIFACT_ROOT=/var/lib/home-lab/compose-staging/$ARTIFACT_SHA256
readonly DEPLOY_ROOT=/srv/docker-compose/current
readonly STAGED_ENV=/etc/docker-compose/staging/$ARTIFACT_SHA256.env
readonly PRODUCTION_ENV=/etc/docker-compose/production.env
readonly IMAGE_TRANSFER=/srv/home-lab-state/.debian-production-images.tar
readonly TRANSFER_MARKER=/srv/home-lab-state/.debian-production-images.json
readonly TAILSCALE_ARCHIVE=/srv/home-lab-state/.debian-tailscale-1.98.4-amd64.tgz
readonly ACTIVATION_MARKER=/etc/home-lab/allow-storage-activation
readonly OUTPUT_MARKER=/var/lib/home-lab/debian-production.json
readonly IMAGE_LOCK_TARGET=/var/lib/home-lab/production-image-lock.json
readonly COMPOSE_UNIT=/etc/systemd/system/home-lab-compose.service
readonly ACTIVATION_JOURNAL=/var/lib/home-lab/debian-production-activation.json
readonly FAILED_MARKER=/var/lib/home-lab/debian-production-failed.json
readonly GUARD_SCRIPT=/usr/local/sbin/home-lab-production-guard
readonly GUARD_UNIT=/etc/systemd/system/home-lab-production-guard.service
readonly DOCKER_DROPIN=/etc/systemd/system/docker.service.d/10-home-lab-storage.conf
readonly TAILSCALE_DROPIN=/etc/systemd/system/tailscaled.service.d/10-home-lab-production-guard.conf
readonly TRANSACTION_MARKER=/run/home-lab-production-transaction
readonly STATE_UNIT='srv-home\x2dlab\x2dstate.mount'
readonly GAMES_UNIT=mnt-games.mount
readonly NFS_UNIT=mnt-storage.mount
readonly PROJECT=docker-compose

fail() { echo "error: $*" >&2; exit 1; }
mount_active() { mountpoint -q "$1"; }
write_phase() {
  local phase=$1 temporary
  temporary=$(mktemp /var/lib/home-lab/.debian-production-activation.XXXXXX)
  jq -c --arg phase "$phase" --arg updatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '. + {format:"home-lab-debian-production-activation-v1",phase:$phase,updatedAt:$updatedAt}' "$ACTIVATION_JOURNAL" > "$temporary"
  chown root:root "$temporary"
  chmod 0600 "$temporary"
  mv -T "$temporary" "$ACTIVATION_JOURNAL"
}

persist_tailscale_node_id() {
  local node_id status temporary
  [[ -f $ACTIVATION_JOURNAL && ! -L $ACTIVATION_JOURNAL ]] || return 0
  command -v tailscale >/dev/null 2>&1 || return 0
  status=$(tailscale status --json 2>/dev/null) || return 0
  node_id=$(jq -er '.Self.ID // empty' <<< "$status") || return 0
  [[ -n $node_id ]] || return 0
  temporary=$(mktemp /var/lib/home-lab/.debian-production-activation.XXXXXX)
  jq -c --arg nodeId "$node_id" '.tailscale = ((.tailscale // {}) + {nodeId:$nodeId})' "$ACTIVATION_JOURNAL" > "$temporary"
  chown root:root "$temporary"
  chmod 0600 "$temporary"
  mv -T "$temporary" "$ACTIVATION_JOURNAL"
}

[[ $# -eq 4 ]] || fail "usage: run-production-cutover.sh IMAGE_SHA256 IMAGE_BYTES IMAGE_LOCK ENCRYPTED_TAILSCALE_KEY"
expected_image_sha=$1
expected_image_bytes=$2
lock=$3
encrypted_key=$4
[[ $(id -u) -eq 0 ]] || fail "production cutover requires root"
[[ $expected_image_sha =~ ^[0-9a-f]{64}$ && $expected_image_bytes =~ ^[0-9]+$ ]] || fail "production transfer expectation is invalid"
grep -Fxq 'ID=debian' /etc/os-release || fail "candidate is not Debian"
[[ $(uname -r) == 6.12.101+deb13-amd64 ]] || fail "candidate kernel differs"
[[ -f $lock && ! -L $lock && $(sha256sum "$lock" | awk '{print $1}') == "$IMAGE_LOCK_SHA256" ]] || fail "production image lock differs"
[[ -f $encrypted_key && ! -L $encrypted_key && $(stat -c %U:%G:%a "$encrypted_key") == root:root:600 ]] || fail "encrypted Tailscale key is absent or unsafe"
[[ -f $ARTIFACT_ROOT/scripts/compose-artifact.py && -f $STAGED_ENV && ! -L $STAGED_ENV ]] || fail "staged production artifact or environment is absent"
[[ $(python3 "$ARTIFACT_ROOT/scripts/compose-artifact.py" --root "$ARTIFACT_ROOT" --no-git hash) == "$ARTIFACT_SHA256" ]] || fail "staged artifact hash differs"
[[ $(stat -c %U:%G:%a "$STAGED_ENV") == root:root:600 ]] || fail "staged environment metadata differs"
[[ ! -e $PRODUCTION_ENV && ! -e $OUTPUT_MARKER && ! -e $ACTIVATION_JOURNAL && ! -e /var/lib/tailscale && ! -e $DEPLOY_ROOT && ! -L $DEPLOY_ROOT ]] || fail "runtime environment, deployment root, activation journal, production marker, or Tailscale state already exists"
for target in /srv/home-lab-state /mnt/games /mnt/storage; do ! mount_active "$target" || fail "a protected mount is already active"; done
for service in docker.service docker.socket containerd.service; do [[ $(systemctl is-active "$service" 2>/dev/null || true) == inactive ]] || fail "Docker or containerd is already active"; done
[[ ! -S /run/docker.sock ]] || fail "Docker socket already exists"
[[ ! -e $ACTIVATION_MARKER ]] || fail "storage activation marker already exists"
! command -v tailscale >/dev/null 2>&1 || fail "Tailscale tooling already exists"

started_epoch=$(date +%s)
cutover_complete=false
tailscale_enrolled=false
cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  if [[ $cutover_complete == true ]]; then return "$result"; fi
  set +e
  persist_tailscale_node_id || true
  if [[ -f $ACTIVATION_JOURNAL && ! -L $ACTIVATION_JOURNAL ]]; then
    failed_temporary=$(mktemp /var/lib/home-lab/.debian-production-failed.XXXXXX)
    jq -c --arg failedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '. + {failedAt:$failedAt,phase:"failed"}' "$ACTIVATION_JOURNAL" > "$failed_temporary" 2>/dev/null || true
    if [[ -s $failed_temporary ]]; then chown root:root "$failed_temporary"; chmod 0600 "$failed_temporary"; mv -T "$failed_temporary" "$FAILED_MARKER"; else rm -f -- "$failed_temporary"; fi
  fi
  if command -v tailscale >/dev/null 2>&1; then tailscale down >/dev/null 2>&1 || true; fi
  systemctl disable --now tailscaled.service home-lab-compose.service >/dev/null 2>&1 || true
  if systemctl is-active docker.service >/dev/null 2>&1; then
    HOME=/root docker compose --project-name "$PROJECT" --project-directory "$DEPLOY_ROOT" --env-file "$PRODUCTION_ENV" --file "$DEPLOY_ROOT/docker-compose.yml" down --remove-orphans >/dev/null 2>&1 || true
    docker system prune --all --force --volumes >/dev/null 2>&1 || true
  fi
  systemctl disable --now docker.service docker.socket >/dev/null 2>&1 || true
  systemctl stop containerd.service >/dev/null 2>&1 || true
  systemctl mask containerd.service >/dev/null 2>&1 || true
  for unit in "$NFS_UNIT" "$GAMES_UNIT" "$STATE_UNIT"; do systemctl disable --now "$unit" >/dev/null 2>&1 || true; done
  rm -f -- "$PRODUCTION_ENV" "$ACTIVATION_MARKER" "$ACTIVATION_JOURNAL" "$COMPOSE_UNIT" "$IMAGE_LOCK_TARGET" "$DEPLOY_ROOT" "$GUARD_SCRIPT" "$GUARD_UNIT" "$DOCKER_DROPIN" "$TAILSCALE_DROPIN" "$TRANSACTION_MARKER" /etc/systemd/system/tailscaled.service /etc/systemd/system/tailscale-online.target /etc/systemd/system/tailscale-wait-online.service /etc/default/tailscaled /usr/bin/tailscale /usr/sbin/tailscaled
  rm -rf -- /var/lib/tailscale /var/cache/tailscale /run/tailscale
  rm -f -- "$IMAGE_TRANSFER" "$TRANSFER_MARKER" "$TAILSCALE_ARCHIVE" "$encrypted_key" /run/home-lab-production-model.json /run/home-lab-production-runtime-lock.json /run/home-lab-production-authkey
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "critical: Debian production activation rolled back in the candidate; Arch recovery requires a physical host reboot" >&2
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

install -d -o root -g root -m 0755 /etc/home-lab /etc/docker-compose /usr/local/sbin /etc/systemd/system/docker.service.d /etc/systemd/system/tailscaled.service.d
rm -f -- "$FAILED_MARKER"
install -o root -g root -m 0400 /dev/null "$ACTIVATION_MARKER"
install -o root -g root -m 0400 /dev/null "$TRANSACTION_MARKER"
printf '{}\n' > "$ACTIVATION_JOURNAL"
chown root:root "$ACTIVATION_JOURNAL"
chmod 0600 "$ACTIVATION_JOURNAL"
cat > "$GUARD_SCRIPT" <<'EOF'
#!/bin/bash
set -euo pipefail
jq -e '.format == "home-lab-debian-production-activation-v1" and .phase == "committed"' /var/lib/home-lab/debian-production-activation.json >/dev/null 2>&1 || test -f /run/home-lab-production-transaction
EOF
chown root:root "$GUARD_SCRIPT"
chmod 0755 "$GUARD_SCRIPT"
cat > "$GUARD_UNIT" <<EOF
[Unit]
Description=Fail-closed guard for Home Lab production activation
After=local-fs.target
Before=docker.service tailscaled.service home-lab-compose.service

[Service]
Type=oneshot
ExecStart=$GUARD_SCRIPT
RemainAfterExit=yes
EOF
cat > "$DOCKER_DROPIN" <<EOF
[Unit]
Requires=home-lab-production-guard.service $STATE_UNIT $GAMES_UNIT $NFS_UNIT
After=home-lab-production-guard.service $STATE_UNIT $GAMES_UNIT $NFS_UNIT network-online.target
Wants=network-online.target
EOF
chown root:root "$GUARD_UNIT" "$DOCKER_DROPIN"
chmod 0644 "$GUARD_UNIT" "$DOCKER_DROPIN"
write_phase validated
systemctl daemon-reload
systemctl start "$STATE_UNIT" "$GAMES_UNIT" "$NFS_UNIT"
[[ $(findmnt -rn -S UUID=d4a19647-7879-4079-9fc9-b3e79711b449 -o TARGET) == /srv/home-lab-state ]] || fail "state mount identity differs"
[[ $(findmnt -rn -S UUID=31602ce7-0054-498a-9f24-f51ca491e7b3 -o TARGET) == /mnt/games ]] || fail "games mount identity differs"
[[ $(findmnt -rn -T /mnt/storage -o SOURCE) == 192.168.0.123:/storage/docker ]] || fail "NFS mount identity differs"
for target in /srv/home-lab-state /mnt/games /mnt/storage; do findmnt -rn -T "$target" -o OPTIONS | tr ',' '\n' | grep -Fxq rw || fail "a protected mount is not read-write"; done
write_phase mounts-active
[[ -f $IMAGE_TRANSFER && ! -L $IMAGE_TRANSFER && $(stat -c %s "$IMAGE_TRANSFER") -eq $expected_image_bytes ]] || fail "production image transfer differs"
[[ $(sha256sum "$IMAGE_TRANSFER" | awk '{print $1}') == "$expected_image_sha" ]] || fail "production image transfer checksum differs"
[[ -f $TRANSFER_MARKER && ! -L $TRANSFER_MARKER && -f $TAILSCALE_ARCHIVE && ! -L $TAILSCALE_ARCHIVE ]] || fail "production transfer metadata differs"
[[ $(sha256sum "$TAILSCALE_ARCHIVE" | awk '{print $1}') == "$TAILSCALE_SHA256" ]] || fail "Tailscale archive checksum differs"
transfer_marker=$(cat "$TRANSFER_MARKER")
jq -e --arg imageSha "$expected_image_sha" --argjson imageBytes "$expected_image_bytes" '.format == "home-lab-debian-production-transfer-v1" and .artifactSha256 == "d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c" and .modelInventorySha256 == "f36ba480734143d51affdc789b2ef782bee063dfb96a248d5048568a82f5a16e" and .imageLockSha256 == "c74199885009f0082cc7b5956eeb526ad895d1cab1605df15998767185aec726" and .imageServiceCount == 41 and .uniqueImageCount == 36 and .transferSha256 == $imageSha and .transferBytes == $imageBytes and .tailscaleVersion == "1.98.4" and .tailscaleArchiveSha256 == "e6c08a8ee7e63e69aaf1b62ecd12672b3883fbcd2a176bf6cfa42a15fdce0b6b" and .privateDataExported == false' <<< "$transfer_marker" >/dev/null || fail "production transfer marker differs"

install -o root -g root -m 0600 "$STAGED_ENV" "$PRODUCTION_ENV"
install -o root -g root -m 0644 "$lock" "$IMAGE_LOCK_TARGET"
systemctl unmask containerd.service
systemctl enable "$STATE_UNIT" "$GAMES_UNIT" "$NFS_UNIT" docker.service docker.socket
systemctl start containerd.service docker.service
[[ -S /run/docker.sock ]] || fail "Docker socket is absent"
write_phase docker-active
docker load --input "$IMAGE_TRANSFER" >/dev/null
rm -f -- "$IMAGE_TRANSFER"
python3 "$ARTIFACT_ROOT/scripts/compose-image-lock.py" verify --current "$IMAGE_LOCK_TARGET" --previous "$IMAGE_LOCK_TARGET" >/dev/null
python3 "$ARTIFACT_ROOT/scripts/compose-image-lock.py" activate --lock "$IMAGE_LOCK_TARGET" >/dev/null
HOME=/root python3 "$ARTIFACT_ROOT/scripts/compose-model-inventory.py" desired --artifact-root "$ARTIFACT_ROOT" --project-directory "$ARTIFACT_ROOT" --env-file "$PRODUCTION_ENV" --project-name "$PROJECT" --bind-root-override /srv/docker-compose/current --output /run/home-lab-production-model.json >/dev/null
[[ $(sha256sum /run/home-lab-production-model.json | awk '{print $1}') == "$MODEL_SHA256" ]] || fail "production Compose model differs"
install -d -o root -g root -m 0755 /srv/docker-compose
ln -s "$ARTIFACT_ROOT" "$DEPLOY_ROOT"
cat > "$COMPOSE_UNIT" <<EOF
[Unit]
Description=Home lab production Compose stack
Requires=home-lab-production-guard.service docker.service $STATE_UNIT $GAMES_UNIT $NFS_UNIT
After=home-lab-production-guard.service docker.service $STATE_UNIT $GAMES_UNIT $NFS_UNIT network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=HOME=/root
WorkingDirectory=$DEPLOY_ROOT
ExecStart=/usr/bin/docker compose --project-name $PROJECT --project-directory $DEPLOY_ROOT --env-file $PRODUCTION_ENV --file $DEPLOY_ROOT/docker-compose.yml up --detach --pull never --remove-orphans
ExecStop=/usr/bin/docker compose --project-name $PROJECT --project-directory $DEPLOY_ROOT --env-file $PRODUCTION_ENV --file $DEPLOY_ROOT/docker-compose.yml stop --timeout 120
TimeoutStartSec=1200
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
EOF
chown root:root "$COMPOSE_UNIT"
chmod 0644 "$COMPOSE_UNIT"
systemctl daemon-reload
systemctl enable --now home-lab-compose.service

healthy=false
for ((attempt = 0; attempt < 180; attempt += 1)); do
  mapfile -t ids < <(docker ps -q)
  if [[ ${#ids[@]} -eq 41 && $(docker ps --filter health=unhealthy -q | wc -l) -eq 0 ]] && docker inspect "${ids[@]}" | jq -e 'all(.[]; if .State.Health then .State.Health.Status == "healthy" else true end)' >/dev/null; then healthy=true; break; fi
  sleep 5
done
[[ $healthy == true ]] || fail "production containers did not become healthy"
mapfile -t ids < <(docker ps -q)
[[ $(docker inspect "${ids[@]}" | jq '[.[].Mounts[] | select(.Type == "bind" and (.Source | startswith("/srv/home-lab-state/")))] | length') -eq 115 ]] || fail "production state bind count differs"
[[ $(docker inspect "${ids[@]}" | jq '[.[].Mounts[] | select(.Type == "volume")] | length') -eq 0 ]] || fail "production Docker volume use differs"
python3 "$ARTIFACT_ROOT/scripts/compose-image-lock.py" capture --project "$PROJECT" --output /run/home-lab-production-runtime-lock.json >/dev/null
jq -e --slurpfile expected "$IMAGE_LOCK_TARGET" '.images == $expected[0].images' /run/home-lab-production-runtime-lock.json >/dev/null || fail "production runtime images differ"
for port in 80 443 8123 8096; do timeout 10 /bin/bash -lc "</dev/tcp/127.0.0.1/$port" || fail "LAN production port $port is unavailable"; done
kernel_errors=$(journalctl -k --since "@$started_epoch" --no-pager | grep -Eci 'I/O error|EXT4-fs error|Buffer I/O|blk_update_request|nfs: server .* not responding' || true)
[[ $kernel_errors -eq 0 ]] || fail "kernel storage errors occurred during production activation"
write_phase compose-healthy

archive_root=$(mktemp -d /run/home-lab-tailscale.XXXXXX)
tar -C "$archive_root" -xzf "$TAILSCALE_ARCHIVE"
install -o root -g root -m 0755 "$archive_root/tailscale_${TAILSCALE_VERSION}_amd64/tailscale" /usr/bin/tailscale
install -o root -g root -m 0755 "$archive_root/tailscale_${TAILSCALE_VERSION}_amd64/tailscaled" /usr/sbin/tailscaled
install -o root -g root -m 0644 "$archive_root/tailscale_${TAILSCALE_VERSION}_amd64/systemd/tailscaled.service" /etc/systemd/system/tailscaled.service
install -o root -g root -m 0644 "$archive_root/tailscale_${TAILSCALE_VERSION}_amd64/systemd/tailscale-online.target" /etc/systemd/system/tailscale-online.target
install -o root -g root -m 0644 "$archive_root/tailscale_${TAILSCALE_VERSION}_amd64/systemd/tailscale-wait-online.service" /etc/systemd/system/tailscale-wait-online.service
install -o root -g root -m 0644 "$archive_root/tailscale_${TAILSCALE_VERSION}_amd64/systemd/tailscaled.defaults" /etc/default/tailscaled
cat > "$TAILSCALE_DROPIN" <<EOF
[Unit]
Requires=home-lab-production-guard.service
After=home-lab-production-guard.service network-online.target
Wants=network-online.target
EOF
chown root:root "$TAILSCALE_DROPIN"
chmod 0644 "$TAILSCALE_DROPIN"
rm -rf -- "$archive_root"
rm -f -- "$TAILSCALE_ARCHIVE"
[[ $(tailscale version | head -1) == "$TAILSCALE_VERSION" ]] || fail "Tailscale version differs"
systemctl daemon-reload
systemctl enable --now tailscaled.service
for ((attempt = 0; attempt < 60; attempt += 1)); do [[ -S /run/tailscale/tailscaled.sock ]] && break; sleep 1; done
[[ -S /run/tailscale/tailscaled.sock ]] || fail "Tailscale socket is absent"
umask 077
age --decrypt --identity /etc/sops/age/keys.txt --output /run/home-lab-production-authkey "$encrypted_key"
rm -f -- "$encrypted_key"
[[ $(stat -c %U:%G:%a /run/home-lab-production-authkey) == root:root:600 ]] || fail "decrypted Tailscale key metadata differs"
auth_key=$(tr -d '\r\n' < /run/home-lab-production-authkey)
rm -f -- /run/home-lab-production-authkey
[[ $auth_key == tskey-auth-* ]] || fail "decrypted Tailscale key differs"
tailscale_up_status=0
tailscale up --reset --auth-key="$auth_key" --hostname="$TAILSCALE_HOSTNAME" --accept-dns=false || tailscale_up_status=$?
unset auth_key
persist_tailscale_node_id || true
[[ $tailscale_up_status -eq 0 ]] || exit "$tailscale_up_status"
for ((attempt = 0; attempt < 60; attempt += 1)); do
  tailscale_status=$(tailscale status --json 2>/dev/null || true)
  persist_tailscale_node_id || true
  if jq -e --arg tag "$TAILSCALE_TAG" --arg host "$TAILSCALE_HOSTNAME" '.BackendState == "Running" and .Self.Online == true and .Self.HostName == $host and (.Self.Tags | index($tag) != null) and (.Self.TailscaleIPs | length) >= 1' <<< "$tailscale_status" >/dev/null 2>&1; then tailscale_enrolled=true; break; fi
  sleep 2
done
[[ $tailscale_enrolled == true ]] || fail "Tailscale enrollment did not become healthy"
tailscale_ipv4=$(jq -er '.Self.TailscaleIPs[] | select(test("^[0-9]+\\."))' <<< "$tailscale_status" | head -1)
tailscale_dns=$(jq -er '.Self.DNSName | select(endswith(".ts.net."))' <<< "$tailscale_status")
tailscale_node_id=$(jq -er '.Self.ID | select(length > 0)' <<< "$tailscale_status")
write_phase tailscale-enrolled
journal_temporary=$(mktemp /var/lib/home-lab/.debian-production-activation.XXXXXX)
jq -c --arg dnsName "$tailscale_dns" --arg ipv4 "$tailscale_ipv4" --arg nodeId "$tailscale_node_id" '. + {tailscale:{dnsName:$dnsName,ipv4:$ipv4,nodeId:$nodeId}}' "$ACTIVATION_JOURNAL" > "$journal_temporary"
chown root:root "$journal_temporary"
chmod 0600 "$journal_temporary"
mv -T "$journal_temporary" "$ACTIVATION_JOURNAL"
rm -f -- "$TRANSFER_MARKER" /run/home-lab-production-model.json /run/home-lab-production-runtime-lock.json

marker_temporary=$(mktemp /var/lib/home-lab/.debian-production.XXXXXX)
jq -cn --arg artifactSha256 "$ARTIFACT_SHA256" --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg imageLockSha256 "$IMAGE_LOCK_SHA256" --arg modelInventorySha256 "$MODEL_SHA256" --arg tailscaleDns "$tailscale_dns" --arg tailscaleIpv4 "$tailscale_ipv4" --arg tailscaleNodeId "$tailscale_node_id" --arg tailscaleTag "$TAILSCALE_TAG" --arg tailscaleVersion "$TAILSCALE_VERSION" --argjson backup "$(jq -c .backup <<< "$transfer_marker")" '{artifactSha256:$artifactSha256,backup:$backup,completedAt:$completedAt,containerCount:41,dockerRuntime:"enabled-active",dockerVolumeMountCount:0,format:"home-lab-debian-production-v1",imageLockSha256:$imageLockSha256,kernelStorageErrors:0,modelInventorySha256:$modelInventorySha256,protectedMounts:"enabled-mounted-rw",pulls:"disabled",runtimeEnvironmentInstalled:true,stateBindCount:115,tailscale:{dnsName:$tailscaleDns,enrolled:true,hostname:"docker-host-debian",ipv4:$tailscaleIpv4,nodeId:$tailscaleNodeId,tag:$tailscaleTag,version:$tailscaleVersion},unhealthyContainerCount:0}' > "$marker_temporary"
chown root:root "$marker_temporary"
chmod 0600 "$marker_temporary"
mv -T "$marker_temporary" "$OUTPUT_MARKER"
rm -f -- "$FAILED_MARKER"
write_phase committed
rm -f -- "$TRANSACTION_MARKER"
cutover_complete=true
trap - EXIT INT TERM HUP
printf 'debian_production=pass containers=41 unhealthy=0 binds=115 volumes=0 tailscale=%s\n' "$tailscale_ipv4"
