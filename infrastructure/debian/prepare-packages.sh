#!/bin/bash
set -Eeuo pipefail

readonly MARKER=/var/lib/home-lab/debian-packages-prepared.json
readonly POLICY=/usr/sbin/policy-rc.d
readonly EXPECTED_KERNEL=6.12.101+deb13-amd64
readonly PACKAGES=(docker.io docker-compose)
readonly SERVICES=(docker.service docker.socket containerd.service)

fail() {
  echo "error: $*" >&2
  exit 1
}

verify_protected_mounts_inactive() {
  local target
  for target in /srv/home-lab-state /mnt/games /mnt/storage; do
    if findmnt -rn --target "$target" >/dev/null; then return 1; fi
  done
  return 0
}

verify_credentials_and_tailscale_absent() {
  [[ ! -e /etc/sops/age && ! -e /etc/docker-compose && ! -e /var/lib/tailscale && ! -e /etc/default/tailscaled ]] || return 1
  if command -v tailscale >/dev/null 2>&1; then return 1; fi
  if command -v tailscaled >/dev/null 2>&1; then return 1; fi
  if systemctl list-unit-files --no-legend | grep -q '^tailscaled\.'; then return 1; fi
  if pgrep -x tailscaled >/dev/null 2>&1; then return 1; fi
  return 0
}

verify_docker_objects_absent() {
  local root
  for root in /var/lib/docker/containers /var/lib/docker/image /var/lib/docker/overlay2 /var/lib/docker/volumes; do
    [[ ! -d $root || -z $(find "$root" -mindepth 1 -print -quit) ]] || return 1
  done
  return 0
}

write_live_evidence() {
  local target=$1
  python3 - "$target" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

def output(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()

result = {
    "composePackageVersion": output("/usr/bin/dpkg-query", "-W", "-f=${Version}", "docker-compose"),
    "composeVersion": output("/usr/bin/docker", "compose", "version", "--short"),
    "dockerPackageVersion": output("/usr/bin/dpkg-query", "-W", "-f=${Version}", "docker.io"),
    "format": "home-lab-debian-packages-prepared-v1",
    "services": "disabled-inactive",
}
Path(sys.argv[1]).write_text(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
PY
}

verify_prepared() {
  local package service
  command -v docker >/dev/null || return 1
  docker compose version --short >/dev/null || return 1
  for package in "${PACKAGES[@]}"; do
    dpkg-query -W -f='${db:Status-Status}\n' "$package" | grep -Fxq installed || return 1
  done
  for service in "${SERVICES[@]}"; do
    [[ $(systemctl is-enabled "$service" 2>/dev/null || true) == disabled ]] || return 1
    [[ $(systemctl is-active "$service" 2>/dev/null || true) == inactive ]] || return 1
  done
  [[ ! -S /run/docker.sock ]] || return 1
  [[ ! -e /etc/home-lab/allow-storage-activation ]] || return 1
  verify_protected_mounts_inactive || return 1
  verify_docker_objects_absent || return 1
  verify_credentials_and_tailscale_absent || return 1
  return 0
}

[[ $# -eq 0 ]] || fail "usage: prepare-packages.sh"
[[ $(id -u) -eq 0 ]] || fail "Debian package preparation requires root"
[[ -r /etc/os-release ]] || fail "operating-system identity is unavailable"
os_id=$(awk -F= '$1 == "ID" { gsub(/^"|"$/, "", $2); print $2 }' /etc/os-release)
os_version=$(awk -F= '$1 == "VERSION_ID" { gsub(/^"|"$/, "", $2); print $2 }' /etc/os-release)
[[ $os_id == debian && $os_version == 13 ]] || fail "Debian 13 is required"
[[ $(uname -r) == "$EXPECTED_KERNEL" ]] || fail "qualified Debian kernel differs"
[[ -f /var/lib/home-lab/debian-inert-provisioned ]] || fail "inert qualification marker is absent"
[[ ! -e /etc/home-lab/allow-storage-activation ]] || fail "storage activation marker must remain absent"
verify_protected_mounts_inactive || fail "a protected mount is active"
verify_credentials_and_tailscale_absent || fail "credentials or Tailscale state must remain absent"
[[ ! -e $POLICY && ! -L $POLICY ]] || fail "an existing service-start policy requires reconciliation"

if [[ -f $MARKER && ! -L $MARKER ]]; then
  verify_prepared
  live_marker=$(mktemp --tmpdir=/run debian-packages-live.XXXXXX)
  trap 'rm -f -- "$live_marker"' EXIT
  write_live_evidence "$live_marker"
  cmp -s "$live_marker" "$MARKER" || fail "package preparation marker differs from live versions"
  exit 0
fi
[[ ! -e $MARKER && ! -L $MARKER ]] || fail "package preparation marker is unsafe"

preparation_complete=false
temporary=
cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  if [[ $preparation_complete != true ]]; then
    systemctl disable --now "${SERVICES[@]}" >/dev/null 2>&1 || true
  fi
  rm -f -- "$POLICY"
  if [[ -n $temporary ]]; then rm -f -- "$temporary"; fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

systemctl mask "${SERVICES[@]}" >/dev/null
cat > "$POLICY" <<'EOF'
#!/bin/sh
exit 101
EOF
chown root:root "$POLICY"
chmod 0755 "$POLICY"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --no-install-recommends --yes "${PACKAGES[@]}"
systemctl disable --now "${SERVICES[@]}" >/dev/null
systemctl unmask "${SERVICES[@]}" >/dev/null
systemctl disable --now "${SERVICES[@]}" >/dev/null
rm -f -- "$POLICY"
verify_prepared

install -d -o root -g root -m 0755 /var/lib/home-lab
temporary=$(mktemp --tmpdir=/var/lib/home-lab debian-packages-prepared.XXXXXX)
write_live_evidence "$temporary"
chown root:root "$temporary"
chmod 0644 "$temporary"
mv -T "$temporary" "$MARKER"
temporary=
verify_prepared
live_marker=$(mktemp --tmpdir=/run debian-packages-live.XXXXXX)
write_live_evidence "$live_marker"
cmp -s "$live_marker" "$MARKER"
rm -f -- "$live_marker"
preparation_complete=true
trap - EXIT INT TERM HUP
echo "Debian Docker and Compose packages prepared; services, storage, credentials, and Tailscale remain inactive"
