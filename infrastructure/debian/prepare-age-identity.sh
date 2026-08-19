#!/bin/bash
set -Eeuo pipefail

readonly IDENTITY_DIR=/etc/sops/age
readonly IDENTITY_FILE=$IDENTITY_DIR/keys.txt
readonly MARKER=/var/lib/home-lab/debian-age-identity.json
readonly SOPS_VERSION=3.13.3
readonly AGE_VERSION=1.3.1
readonly SOPS_SHA256=e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b
readonly AGE_ARCHIVE_SHA256=bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377
readonly AGE_SHA256=2e305637f2a0555305e21c17fb74446acbb39b53135d43d4b744e50c287133a5
readonly AGE_KEYGEN_SHA256=c56ef69834e18ca4d3b953117f4481522c35fb6862a5d2871685aa4685893664
readonly SOPS_URL=https://github.com/getsops/sops/releases/download/v3.13.3/sops-v3.13.3.linux.amd64
readonly AGE_URL=https://github.com/FiloSottile/age/releases/download/v1.3.1/age-v1.3.1-linux-amd64.tar.gz

fail() {
  echo "error: $*" >&2
  exit 1
}

verify_inert() {
  local service
  for service in docker.service docker.socket; do
    [[ $(systemctl is-enabled "$service" 2>/dev/null || true) == disabled ]] || return 1
    [[ $(systemctl is-active "$service" 2>/dev/null || true) == inactive ]] || return 1
  done
  [[ $(systemctl is-enabled containerd.service 2>/dev/null || true) == masked ]] || return 1
  [[ $(systemctl is-active containerd.service 2>/dev/null || true) == inactive ]] || return 1
  [[ ! -S /run/docker.sock ]]
}

[[ $# -eq 0 ]] || fail "usage: prepare-age-identity.sh"
[[ $(id -u) -eq 0 ]] || fail "Debian age identity preparation requires root"
[[ -r /etc/os-release ]] || fail "operating-system identity is unavailable"
os_id=$(awk -F= '$1 == "ID" { gsub(/^"|"$/, "", $2); print $2 }' /etc/os-release)
os_version=$(awk -F= '$1 == "VERSION_ID" { gsub(/^"|"$/, "", $2); print $2 }' /etc/os-release)
[[ $os_id == debian && $os_version == 13 ]] || fail "Debian 13 is required"
[[ -f /var/lib/home-lab/debian-inert-provisioned ]] || fail "inert qualification marker is absent"
[[ -f /var/lib/home-lab/debian-packages-prepared.json ]] || fail "package preparation marker is absent"
verify_inert || fail "Docker or containerd is not inert"
[[ ! -e /etc/home-lab/allow-storage-activation ]] || fail "storage activation marker must remain absent"
for target in /srv/home-lab-state /mnt/games /mnt/storage; do
  ! findmnt -rn --target "$target" >/dev/null || fail "a protected mount is active: $target"
done
[[ ! -e /etc/docker-compose ]] || fail "Compose credentials or staging already exist"
[[ ! -e /var/lib/tailscale && ! -e /etc/default/tailscaled ]] || fail "Tailscale state must remain absent"
! command -v tailscale >/dev/null 2>&1 || fail "Tailscale must remain absent"
[[ ! -L $IDENTITY_DIR && ! -L $IDENTITY_FILE && ! -L $MARKER ]] || fail "identity or marker path is unsafe"

temporary=$(mktemp -d /run/home-lab-debian-age.XXXXXX)
trap 'rm -rf -- "$temporary"' EXIT INT TERM HUP
chmod 0700 "$temporary"
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors --silent --show-error "$SOPS_URL" --output "$temporary/sops"
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors --silent --show-error "$AGE_URL" --output "$temporary/age.tar.gz"
printf '%s  %s\n%s  %s\n' "$SOPS_SHA256" "$temporary/sops" "$AGE_ARCHIVE_SHA256" "$temporary/age.tar.gz" | sha256sum --check --status || fail "tool download digest differs"
mapfile -t archive_entries < <(tar -tzf "$temporary/age.tar.gz" | LC_ALL=C sort)
expected_entries=(age/ age/LICENSE age/age age/age-inspect age/age-keygen age/age-plugin-batchpass)
mapfile -t expected_entries < <(printf '%s\n' "${expected_entries[@]}" | LC_ALL=C sort)
[[ ${archive_entries[*]} == "${expected_entries[*]}" ]] || fail "age archive entries differ"
tar -xzf "$temporary/age.tar.gz" -C "$temporary"
printf '%s  %s\n%s  %s\n' "$AGE_SHA256" "$temporary/age/age" "$AGE_KEYGEN_SHA256" "$temporary/age/age-keygen" | sha256sum --check --status || fail "age binary digest differs"
install -o root -g root -m 0755 "$temporary/sops" /usr/local/bin/sops
install -o root -g root -m 0755 "$temporary/age/age" /usr/local/bin/age
install -o root -g root -m 0755 "$temporary/age/age-keygen" /usr/local/bin/age-keygen
[[ $(sha256sum /usr/local/bin/sops | awk '{print $1}') == "$SOPS_SHA256" ]] || fail "installed SOPS digest differs"
[[ $(sha256sum /usr/local/bin/age | awk '{print $1}') == "$AGE_SHA256" ]] || fail "installed age digest differs"
[[ $(sha256sum /usr/local/bin/age-keygen | awk '{print $1}') == "$AGE_KEYGEN_SHA256" ]] || fail "installed age-keygen digest differs"

install -d -o root -g root -m 0700 "$IDENTITY_DIR"
if [[ ! -e $IDENTITY_FILE ]]; then
  umask 077
  /usr/local/bin/age-keygen -o "$IDENTITY_FILE" >/dev/null 2>&1
fi
[[ -f $IDENTITY_FILE && ! -L $IDENTITY_FILE ]] || fail "Debian age identity is absent or unsafe"
chown root:root "$IDENTITY_FILE"
chmod 0600 "$IDENTITY_FILE"
[[ $(stat -c %U:%G:%a "$IDENTITY_FILE") == root:root:600 ]] || fail "Debian age identity metadata differs"
recipient=$(/usr/local/bin/age-keygen -y "$IDENTITY_FILE")
[[ $recipient =~ ^age1[0-9a-z]{58}$ ]] || fail "Debian age recipient is invalid"

install -d -o root -g root -m 0755 /var/lib/home-lab
marker_temporary=$(mktemp --tmpdir=/var/lib/home-lab debian-age-identity.XXXXXX)
jq -cn --arg ageVersion "$AGE_VERSION" --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg recipient "$recipient" --arg sopsVersion "$SOPS_VERSION" \
  '{ageVersion:$ageVersion,createdAt:$createdAt,format:"home-lab-debian-age-identity-v1",identityMetadata:"root:root:600",identityPath:"/etc/sops/age/keys.txt",privateIdentityExported:false,recipient:$recipient,sopsVersion:$sopsVersion}' > "$marker_temporary"
chown root:root "$marker_temporary"
chmod 0644 "$marker_temporary"
mv -T "$marker_temporary" "$MARKER"
trap - EXIT INT TERM HUP
rm -rf -- "$temporary"
echo "Debian age identity prepared; only its public recipient is available to the coordinator"
