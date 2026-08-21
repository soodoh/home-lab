#!/bin/bash
set -Eeuo pipefail

readonly FAILED_MARKER=/var/lib/home-lab/debian-production-failed.json
readonly ACTIVATION_JOURNAL=/var/lib/home-lab/debian-production-activation.json
readonly OUTPUT_MARKER=/var/lib/home-lab/debian-production.json
readonly LEGACY_OUTPUT_SHA256=1771b2516d738d8c7d70dbf3dbdb205168b2f3d38c4cc5d513b263e4600c0b08
readonly LEGACY_ACTIVATION_SHA256=01954d544d39da5d58a88f171fbcc9ead93366576decc6f306bdd66407354198
readonly ACTIVATION_MARKER=/etc/home-lab/allow-storage-activation
readonly PRODUCTION_ENV=/etc/docker-compose/production.env
readonly DEPLOY_ROOT=/srv/docker-compose/current
readonly COMPOSE_UNIT=/etc/systemd/system/home-lab-compose.service
readonly IMAGE_LOCK=/var/lib/home-lab/production-image-lock.json
readonly IMAGE_OVERRIDE=/var/lib/home-lab/production-image-override.json
readonly GUARD_SCRIPT=/usr/local/sbin/home-lab-production-guard
readonly GUARD_UNIT=/etc/systemd/system/home-lab-production-guard.service
readonly DOCKER_DROPIN=/etc/systemd/system/docker.service.d/10-home-lab-storage.conf
readonly TAILSCALE_DROPIN=/etc/systemd/system/tailscaled.service.d/10-home-lab-production-guard.conf
readonly SERIAL_RULES=/etc/udev/rules.d/71-home-lab-usb-serial.rules
readonly AMDGPU_GRUB_DROPIN=/etc/default/grub.d/99-home-lab-amdgpu.cfg
readonly AMDGPU_GRUB_BACKUP=/etc/default/grub.d/99-home-lab-amdgpu.cfg.cleanup-pending
readonly AMDGPU_GRUB_CONTENT="GRUB_CMDLINE_LINUX=\"\${GRUB_CMDLINE_LINUX:-} amdgpu.runpm=0\""
readonly STATE_UNIT='srv-home\x2dlab\x2dstate.mount'
readonly GAMES_UNIT=mnt-games.mount
readonly NFS_UNIT=mnt-storage.mount

fail() { echo "error: $*" >&2; exit 1; }
verified_mount_state() { awk -v target="$1" 'BEGIN { state="unmounted" } $5 == target { state="mounted" } END { print state }' /proc/self/mountinfo; }
verified_service_state() { systemctl show --property=ActiveState --value "$1"; }
amdgpu_grub_file_valid() {
  local path=$1
  [[ -f $path && ! -L $path && $(stat -c %U:%G:%a "$path") == root:root:644 ]] || return 1
  [[ $(cat "$path") == "$AMDGPU_GRUB_CONTENT" ]]
}
grub_linux_entries_exclude_runpm() {
  local -a entries
  mapfile -t entries < <(grep -E '^[[:space:]]*linux[[:space:]]' /boot/grub/grub.cfg)
  [[ ${#entries[@]} -gt 0 ]] || return 1
  ! printf '%s\n' "${entries[@]}" | grep -Fq 'amdgpu.runpm=0'
}

[[ $# -eq 0 ]] || fail "usage: reconcile-failed-production.sh"
[[ $(id -u) -eq 0 ]] || fail "failed production reconciliation requires root"
grep -Fxq 'ID=debian' /etc/os-release || fail "candidate is not Debian"
if [[ ! -e $FAILED_MARKER && ! -L $FAILED_MARKER && -e $OUTPUT_MARKER && -e $ACTIVATION_JOURNAL ]]; then
  [[ -f $OUTPUT_MARKER && ! -L $OUTPUT_MARKER && $(stat -c %U:%G:%a "$OUTPUT_MARKER") == root:root:600 ]] || fail "legacy rejected output marker is unsafe"
  [[ -f $ACTIVATION_JOURNAL && ! -L $ACTIVATION_JOURNAL && $(stat -c %U:%G:%a "$ACTIVATION_JOURNAL") == root:root:600 ]] || fail "legacy rejected activation journal is unsafe"
  [[ $(sha256sum "$OUTPUT_MARKER" | awk '{print $1}') == "$LEGACY_OUTPUT_SHA256" ]] || fail "legacy rejected output marker digest differs"
  [[ $(sha256sum "$ACTIVATION_JOURNAL" | awk '{print $1}') == "$LEGACY_ACTIVATION_SHA256" ]] || fail "legacy rejected activation journal digest differs"
  legacy_failed=$(mktemp /var/lib/home-lab/.debian-production-failed.XXXXXX)
  trap 'rm -f -- "$legacy_failed"' EXIT
  jq -c --arg failedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg outputSha256 "$LEGACY_OUTPUT_SHA256" '. + {failedAt:$failedAt,outputSha256:$outputSha256,phase:"failed",rejection:"post-reboot-health"}' "$ACTIVATION_JOURNAL" > "$legacy_failed"
  chown root:root "$legacy_failed"
  chmod 0600 "$legacy_failed"
  mv -T "$legacy_failed" "$FAILED_MARKER"
  legacy_failed=
  trap - EXIT
fi

runtime_paths=(
  "$OUTPUT_MARKER" "$ACTIVATION_JOURNAL" "$ACTIVATION_MARKER" "$PRODUCTION_ENV" "$DEPLOY_ROOT"
  "$COMPOSE_UNIT" "$IMAGE_LOCK" "$IMAGE_OVERRIDE" "$GUARD_SCRIPT" "$GUARD_UNIT"
  "$DOCKER_DROPIN" "$TAILSCALE_DROPIN" "$SERIAL_RULES" "$AMDGPU_GRUB_DROPIN" "$AMDGPU_GRUB_BACKUP" /var/lib/tailscale
)
if [[ ! -f $FAILED_MARKER || -L $FAILED_MARKER ]]; then
  for path in "${runtime_paths[@]}"; do
    [[ ! -e $path && ! -L $path ]] || fail "ambiguous production runtime artifact exists without a failed marker: $path"
  done
  echo "debian_failed_production_reconciliation=noop"
  exit 0
fi
jq -e '.format == "home-lab-debian-production-activation-v1" and .phase == "failed"' "$FAILED_MARKER" >/dev/null || fail "failed production marker differs"
if [[ -e $OUTPUT_MARKER || -L $OUTPUT_MARKER ]]; then
  [[ -f $OUTPUT_MARKER && ! -L $OUTPUT_MARKER ]] || fail "rejected production marker is unsafe"
  jq -e '.format == "home-lab-debian-production-v1" and .containerCount == 41 and .unhealthyContainerCount == 0' "$OUTPUT_MARKER" >/dev/null || fail "rejected production marker differs"
  jq -e '.rejection == "post-reboot-health"' "$FAILED_MARKER" >/dev/null || fail "a committed production marker cannot be reconciled automatically"
  expected_output_sha=$(jq -er '.outputSha256 | select(test("^[0-9a-f]{64}$"))' "$FAILED_MARKER") || fail "rejected production marker provenance is absent"
  actual_output_sha=$(sha256sum "$OUTPUT_MARKER" | awk '{print $1}') || fail "rejected production marker digest is unreadable"
  [[ $actual_output_sha == "$expected_output_sha" ]] || fail "rejected production marker digest differs from failed-marker provenance"
fi
rejection=$(jq -r '.rejection // empty' "$FAILED_MARKER") || fail "failed production rejection field is unreadable"
if [[ $rejection == post-reboot-health ]]; then
  [[ -f $ACTIVATION_JOURNAL && ! -L $ACTIVATION_JOURNAL ]] || fail "post-reboot rejection requires its committed activation journal"
  jq -e '.format == "home-lab-debian-production-activation-v1" and .phase == "committed"' "$ACTIVATION_JOURNAL" >/dev/null || fail "post-reboot rejection activation journal is not committed"
  activation_basis=$(jq -cS 'del(.phase,.failedAt,.rejection,.outputSha256)' "$ACTIVATION_JOURNAL") || fail "committed activation basis is unreadable"
  failed_basis=$(jq -cS 'del(.phase,.failedAt,.rejection,.outputSha256)' "$FAILED_MARKER") || fail "failed activation basis is unreadable"
  [[ $activation_basis == "$failed_basis" ]] || fail "failed marker was not derived from the committed activation journal"
elif [[ -e $ACTIVATION_JOURNAL || -L $ACTIVATION_JOURNAL ]]; then
  [[ -f $ACTIVATION_JOURNAL && ! -L $ACTIVATION_JOURNAL ]] || fail "activation journal is unsafe"
  jq -e '.format == "home-lab-debian-production-activation-v1" and .phase != "committed"' "$ACTIVATION_JOURNAL" >/dev/null || fail "ordinary failed activation journal is committed or invalid"
fi

set +e
if command -v tailscale >/dev/null 2>&1; then tailscale down >/dev/null 2>&1 || true; fi
systemctl disable --now tailscaled.service home-lab-compose.service docker.service docker.socket >/dev/null 2>&1 || true
systemctl stop containerd.service >/dev/null 2>&1 || true
for unit in "$NFS_UNIT" "$GAMES_UNIT" "$STATE_UNIT"; do systemctl disable --now "$unit" >/dev/null 2>&1 || true; done
for ((attempt = 0; attempt < 30; attempt += 1)); do
  for target in /mnt/storage /mnt/games /srv/home-lab-state; do
    mountpoint -q "$target" && umount "$target" >/dev/null 2>&1 || true
  done
  active=false
  for target in /srv/home-lab-state /mnt/games /mnt/storage; do mountpoint -q "$target" && active=true; done
  [[ $active == false ]] && break
  sleep 1
done
systemctl reset-failed tailscaled.service home-lab-compose.service docker.service docker.socket containerd.service >/dev/null 2>&1 || true
set -e

for service in tailscaled.service home-lab-compose.service docker.service docker.socket containerd.service; do
  state=$(verified_service_state "$service" 2>/dev/null) || fail "runtime service state is unreadable: $service"
  [[ $state == inactive ]] || fail "runtime service is not explicitly inactive: $service ($state)"
done
if [[ -S /run/docker.sock && ! -L /run/docker.sock ]]; then
  socket_listeners=$(ss -Hxl 'src /run/docker.sock') || fail "Docker socket listener state is unreadable"
  [[ -z $socket_listeners ]] || fail "Docker socket listener remains active"
  rm -f -- /run/docker.sock
fi
[[ ! -e /run/docker.sock && ! -L /run/docker.sock ]] || fail "unsafe Docker socket artifact remains"
for target in /srv/home-lab-state /mnt/games /mnt/storage; do
  state=$(verified_mount_state "$target") || fail "protected mount state is unreadable: $target"
  [[ $state == unmounted ]] || fail "protected mount is not explicitly unmounted: $target ($state)"
done
if [[ -e $AMDGPU_GRUB_BACKUP || -L $AMDGPU_GRUB_BACKUP ]]; then
  amdgpu_grub_file_valid "$AMDGPU_GRUB_BACKUP" || fail "AMDGPU GRUB cleanup backup is unsafe"
  [[ ! -e $AMDGPU_GRUB_DROPIN && ! -L $AMDGPU_GRUB_DROPIN ]] || fail "AMDGPU GRUB cleanup artifacts conflict"
  mv -T "$AMDGPU_GRUB_BACKUP" "$AMDGPU_GRUB_DROPIN"
fi
if [[ -e $AMDGPU_GRUB_DROPIN || -L $AMDGPU_GRUB_DROPIN ]]; then
  amdgpu_grub_file_valid "$AMDGPU_GRUB_DROPIN" || fail "AMDGPU GRUB drop-in is unsafe"
  mv -T "$AMDGPU_GRUB_DROPIN" "$AMDGPU_GRUB_BACKUP"
  if update-grub >/dev/null && grub_linux_entries_exclude_runpm; then
    rm -f -- "$AMDGPU_GRUB_BACKUP"
  else
    mv -T "$AMDGPU_GRUB_BACKUP" "$AMDGPU_GRUB_DROPIN" >/dev/null 2>&1 || true
    fail "GRUB cleanup failed"
  fi
fi
[[ ! -e $AMDGPU_GRUB_DROPIN && ! -L $AMDGPU_GRUB_DROPIN && ! -e $AMDGPU_GRUB_BACKUP && ! -L $AMDGPU_GRUB_BACKUP ]] || fail "AMDGPU GRUB cleanup artifacts remain"
update-grub >/dev/null || fail "GRUB baseline regeneration failed"
grub_linux_entries_exclude_runpm || fail "GRUB baseline retains AMDGPU runtime-PM override"

rm -rf -- /var/lib/docker /var/lib/containerd /var/lib/tailscale /var/cache/tailscale /run/tailscale
rm -f -- "$OUTPUT_MARKER" "$ACTIVATION_JOURNAL" "$ACTIVATION_MARKER" "$PRODUCTION_ENV" "$DEPLOY_ROOT" \
  "$COMPOSE_UNIT" "$IMAGE_LOCK" "$IMAGE_OVERRIDE" "$GUARD_SCRIPT" "$GUARD_UNIT" \
  "$DOCKER_DROPIN" "$TAILSCALE_DROPIN" "$SERIAL_RULES" "$FAILED_MARKER" \
  /etc/systemd/system/tailscaled.service /etc/systemd/system/tailscale-online.target \
  /etc/systemd/system/tailscale-wait-online.service /etc/default/tailscaled \
  /usr/bin/tailscale /usr/sbin/tailscaled /run/home-lab-production-authkey
systemctl mask containerd.service >/dev/null
systemctl daemon-reload
udevadm control --reload >/dev/null 2>&1 || true

for path in "${runtime_paths[@]}" "$FAILED_MARKER"; do
  [[ ! -e $path && ! -L $path ]] || fail "failed production artifact remains: $path"
done
[[ $(systemctl is-enabled containerd.service 2>/dev/null || true) == masked ]] || fail "containerd is not masked"
echo "debian_failed_production_reconciliation=pass"
