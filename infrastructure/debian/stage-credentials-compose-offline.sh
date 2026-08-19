#!/bin/bash
set -Eeuo pipefail

readonly ARTIFACT_SHA256=d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c
readonly RECOVERY_RECIPIENT=age1vvzm5pczjum52v5alall8euucjen9q4v9xa5g0xmswhna5vare9qwv9rq6
readonly ARCH_RECIPIENT=age1ddk0qtwjclc2za5afrz5pl4j5kley02rqv2vh0s07c27a8t5u58sph58qm
readonly DEBIAN_RECIPIENT=age1atumjua6hxyls6z8v20tsgy72304x72lqjstwmwzqy5ma4txyfsse7xakv
readonly ARTIFACT_ROOT=/var/lib/home-lab/compose-staging/$ARTIFACT_SHA256
readonly STAGED_ENV=/etc/docker-compose/staging/$ARTIFACT_SHA256.env
readonly IDENTITY=/etc/sops/age/keys.txt
readonly IDENTITY_MARKER=/var/lib/home-lab/debian-age-identity.json
readonly PACKAGE_MARKER=/var/lib/home-lab/debian-packages-prepared.json
readonly MARKER=/var/lib/home-lab/debian-compose-staged.json

fail() { echo "error: $*" >&2; exit 1; }
verify_inert() {
  local service
  for service in docker.service docker.socket containerd.service; do
    [[ $(systemctl is-active "$service" 2>/dev/null || true) == inactive ]] || return 1
  done
  [[ $(systemctl is-enabled docker.service 2>/dev/null || true) == disabled ]]
  [[ $(systemctl is-enabled docker.socket 2>/dev/null || true) == disabled ]]
  [[ $(systemctl is-enabled containerd.service 2>/dev/null || true) == masked ]]
  [[ ! -S /run/docker.sock ]]
  [[ $(docker ps -aq 2>/dev/null | wc -l) -eq 0 ]]
  [[ $(docker image ls -aq 2>/dev/null | wc -l) -eq 0 ]]
  [[ $(docker volume ls -q 2>/dev/null | wc -l) -eq 0 ]]
  [[ $(docker network ls --format '{{.Name}}' 2>/dev/null | grep -Evc '^(bridge|host|none)$' || true) -eq 0 ]]
}
verify_protected_mounts_absent() {
  local target
  for target in /srv/home-lab-state /mnt/games /mnt/storage; do
    ! findmnt -rn --target "$target" >/dev/null || return 1
  done
}

[[ $# -eq 1 ]] || fail "usage: stage-credentials-compose-offline.sh ARTIFACT_ARCHIVE"
[[ $(id -u) -eq 0 ]] || fail "offline credential staging requires root"
archive=$1
[[ -f $archive && ! -L $archive ]] || fail "artifact archive is absent or unsafe"
if ! grep -Fxq 'ID=debian' /etc/os-release || ! grep -Eq '^VERSION_ID="?13"?$' /etc/os-release; then
  fail "candidate is not Debian 13"
fi
[[ $(uname -r) == 6.12.101+deb13-amd64 ]] || fail "candidate kernel differs"
[[ -f $PACKAGE_MARKER && ! -L $PACKAGE_MARKER ]] || fail "package marker is absent or unsafe"
jq -e '.format == "home-lab-debian-packages-prepared-v1" and .services == "docker-disabled-containerd-masked-inactive"' "$PACKAGE_MARKER" >/dev/null || fail "package marker differs"
[[ -f $IDENTITY_MARKER && ! -L $IDENTITY_MARKER ]] || fail "identity marker is absent or unsafe"
jq -e --arg recipient "$DEBIAN_RECIPIENT" '.format == "home-lab-debian-age-identity-v1" and .recipient == $recipient and .privateIdentityExported == false' "$IDENTITY_MARKER" >/dev/null || fail "identity marker differs"
[[ -f $IDENTITY && ! -L $IDENTITY && $(stat -c %U:%G:%a "$IDENTITY") == root:root:600 ]] || fail "private identity is absent or unsafe"
[[ $(age-keygen -y "$IDENTITY") == "$DEBIAN_RECIPIENT" ]] || fail "private identity recipient differs"
verify_inert || fail "Docker or containerd is not inert"
verify_protected_mounts_absent || fail "a protected production mount is active"
[[ ! -e /etc/home-lab/allow-storage-activation && ! -e /var/lib/tailscale && ! -e /etc/default/tailscaled ]] || fail "storage activation or Tailscale state exists"
[[ ! -e /etc/docker-compose/production.env && ! -e /etc/docker-compose/previous.env ]] || fail "a runtime credential environment exists"
[[ ! -e $ARTIFACT_ROOT && ! -L $ARTIFACT_ROOT ]] || fail "the immutable artifact already exists or is unsafe"
[[ ! -e $STAGED_ENV && ! -L $STAGED_ENV ]] || fail "the staged environment already exists or is unsafe"
[[ ! -e $MARKER && ! -L $MARKER ]] || fail "offline staging marker already exists or is unsafe"

mapfile -t archive_paths < <(tar -tzf "$archive")
[[ ${#archive_paths[@]} -gt 0 ]] || fail "artifact archive is empty"
for path in "${archive_paths[@]}"; do
  [[ $path == . || $path == ./* ]] || fail "artifact archive contains an unsafe path"
  [[ $path != *'/../'* && $path != ../* && $path != /* ]] || fail "artifact archive contains traversal"
done
while IFS= read -r mode _; do
  [[ ${mode:0:1} == d || ${mode:0:1} == - ]] || fail "artifact archive contains a non-file entry"
done < <(tar -tvzf "$archive")

install -d -o root -g root -m 0700 /var/lib/home-lab/compose-staging /etc/docker-compose /etc/docker-compose/staging
workspace=$(mktemp -d /var/lib/home-lab/.compose-stage.XXXXXX)
decrypt_workspace=$(mktemp -d /etc/docker-compose/.decrypt.XXXXXX)
marker_temporary=$(mktemp /var/lib/home-lab/.debian-compose-staged.XXXXXX)
completed=false
cleanup() {
  rm -rf -- "$workspace" "$decrypt_workspace"
  rm -f -- "$marker_temporary" "$STAGED_ENV.pending"
  if [[ $completed != true ]]; then
    rm -rf -- "$ARTIFACT_ROOT"
    rm -f -- "$STAGED_ENV" "$MARKER"
  fi
}
trap cleanup EXIT INT TERM HUP
chmod 0700 "$workspace" "$decrypt_workspace"
tar -xzf "$archive" -C "$workspace" --no-same-owner --no-same-permissions
chown -R root:root "$workspace"
[[ $(python3 "$workspace/scripts/compose-artifact.py" --root "$workspace" --no-git hash) == "$ARTIFACT_SHA256" ]] || fail "immutable Compose artifact hash differs"
python3 "$workspace/scripts/check-sops-env.py" \
  "$workspace/secrets/production.sops.env" "$workspace/secrets/production.env.keys" \
  "$workspace/secrets/production.env.layout.json" \
  "$RECOVERY_RECIPIENT" "$ARCH_RECIPIENT" "$DEBIAN_RECIPIENT" >/dev/null || fail "SOPS ciphertext structure differs"

umask 077
SOPS_AGE_KEY_FILE=$IDENTITY sops decrypt --input-type dotenv --output-type dotenv \
  --output "$decrypt_workspace/canonical.env" "$workspace/secrets/production.sops.env" >/dev/null 2>&1 || fail "SOPS decryption failed"
python3 "$workspace/scripts/restore-dotenv-layout.py" "$decrypt_workspace/canonical.env" \
  "$workspace/secrets/production.env.layout.json" "$decrypt_workspace/production.env" >/dev/null 2>&1 || fail "dotenv layout restoration failed"
[[ $(stat -c %a "$decrypt_workspace/production.env") == 600 ]] || fail "decrypted environment metadata differs"
awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/{print $1}' "$decrypt_workspace/production.env" | LC_ALL=C sort > "$decrypt_workspace/keys"
cmp -s "$decrypt_workspace/keys" "$workspace/secrets/production.env.keys" || fail "decrypted environment key set differs"
install -o root -g root -m 0600 "$decrypt_workspace/production.env" "$STAGED_ENV.pending"
mv -T "$STAGED_ENV.pending" "$STAGED_ENV"

HOME=/root DOCKER_HOST=unix:///run/home-lab-no-docker.sock docker compose \
  --project-name docker-compose --project-directory "$workspace" --env-file "$STAGED_ENV" \
  --file "$workspace/docker-compose.yml" config --quiet >/dev/null 2>&1 || fail "quiet Compose validation failed"
HOME=/root DOCKER_HOST=unix:///run/home-lab-no-docker.sock python3 "$workspace/scripts/compose-model-inventory.py" desired \
  --artifact-root "$workspace" --project-directory "$workspace" --env-file "$STAGED_ENV" \
  --project-name docker-compose --bind-root-override /srv/docker-compose/current \
  --output "$decrypt_workspace/model.json" >/dev/null 2>&1 || fail "secret-free model inventory failed"
[[ $(jq '.services | length' "$decrypt_workspace/model.json") -eq 41 ]] || fail "Compose service count differs"
model_sha=$(sha256sum "$decrypt_workspace/model.json" | awk '{print $1}')
mv -T "$workspace" "$ARTIFACT_ROOT"
chmod 0700 "$ARTIFACT_ROOT"

jq -cn --arg artifactRoot "$ARTIFACT_ROOT" --arg artifactSha256 "$ARTIFACT_SHA256" \
  --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg modelSha256 "$model_sha" \
  --arg stagedEnvironment "$STAGED_ENV" \
  '{artifactRoot:$artifactRoot,artifactSha256:$artifactSha256,completedAt:$completedAt,composeValidation:"quiet-pass",dockerServices:"docker-disabled-containerd-masked-inactive",format:"home-lab-debian-credentials-compose-staged-v1",modelInventorySha256:$modelSha256,privateIdentityExported:false,protectedMountsActivated:false,recipientCount:3,runtimeEnvironmentInstalled:false,serviceCount:41,stagedEnvironment:$stagedEnvironment,tailscaleEnrolled:false,variableCount:90}' > "$marker_temporary"
chown root:root "$marker_temporary"
chmod 0644 "$marker_temporary"
mv -T "$marker_temporary" "$MARKER"
verify_inert || fail "Docker or containerd changed state during offline validation"
verify_protected_mounts_absent || fail "a protected production mount became active"
[[ ! -e /etc/docker-compose/production.env && ! -e /var/lib/tailscale ]] || fail "runtime credentials or Tailscale state appeared"
completed=true
trap - EXIT INT TERM HUP
rm -rf -- "$decrypt_workspace"
rm -f -- "$archive"
printf 'debian_credentials_compose_staging=pass artifact=%s services=41 variables=90\n' "$ARTIFACT_SHA256"
