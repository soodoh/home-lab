#!/bin/bash
set -Eeuo pipefail

readonly MODEL=/run/home-lab-finalize-model.json
readonly RUNTIME_LOCK=/run/home-lab-finalize-images.json
readonly DEPLOY_ROOT=/srv/docker-compose/current
readonly DEPLOY_STASH=/srv/docker-compose/.current.finalize
readonly ARTIFACT_ROOT=/var/lib/home-lab/compose-staging/d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c
readonly MODEL_SHA256=f36ba480734143d51affdc789b2ef782bee063dfb96a248d5048568a82f5a16e
readonly IMAGE_LOCK=/var/lib/home-lab/production-image-lock.json
readonly IMAGE_OVERRIDE=/var/lib/home-lab/production-image-override.json

cleanup() {
  local result=$?
  if [[ -e $DEPLOY_STASH || -L $DEPLOY_STASH ]]; then
    if [[ ! -e $DEPLOY_ROOT && ! -L $DEPLOY_ROOT ]]; then mv "$DEPLOY_STASH" "$DEPLOY_ROOT"; else result=1; fi
  fi
  rm -f -- "$MODEL" "$RUNTIME_LOCK"
  exit "$result"
}
trap cleanup EXIT INT TERM HUP

wait_for_lan_ports() {
  local all_ready port
  for ((attempt = 0; attempt < 120; attempt += 1)); do
    all_ready=true
    for port in 80 443 8123 8096; do
      timeout --kill-after=1 2 /bin/bash -lc "</dev/tcp/192.168.0.100/$port" || all_ready=false
    done
    [[ $all_ready == true ]] && return 0
    sleep 5
  done
  return 1
}

[[ $(findmnt -rn -S UUID=d4a19647-7879-4079-9fc9-b3e79711b449 -o TARGET) == /srv/home-lab-state ]]
[[ $(findmnt -rn -S UUID=31602ce7-0054-498a-9f24-f51ca491e7b3 -o TARGET) == /mnt/games ]]
[[ $(findmnt -rn -T /mnt/storage -o SOURCE) == 192.168.0.123:/storage/docker ]]
for target in /srv/home-lab-state /mnt/games /mnt/storage; do
  findmnt -rn -T "$target" -o OPTIONS | tr ',' '\n' | grep -Fxq rw
done
for device in zigbee zwave; do [[ -L /dev/$device && -c $(readlink -f "/dev/$device") ]]; done
jq -e '.format == "home-lab-debian-production-activation-v1" and .phase == "committed"' /var/lib/home-lab/debian-production-activation.json >/dev/null
[[ $(systemctl is-active home-lab-production-guard.service home-lab-compose.service docker.service containerd.service tailscaled.service | grep -c '^active$') -eq 5 ]]
for unit in 'srv-home\x2dlab\x2dstate.mount' mnt-games.mount mnt-storage.mount docker.service home-lab-compose.service tailscaled.service; do
  [[ $(systemctl is-enabled "$unit") == enabled ]]
done

healthy=false
for ((attempt = 0; attempt < 120; attempt += 1)); do
  mapfile -t ids < <(docker ps -q)
  if [[ ${#ids[@]} -eq 41 && $(docker ps --filter health=unhealthy -q | wc -l) -eq 0 ]] &&
    docker inspect "${ids[@]}" | jq -e 'all(.[]; if .State.Health then .State.Health.Status == "healthy" else true end)' >/dev/null; then
    healthy=true
    break
  fi
  sleep 5
done
[[ $healthy == true ]]
[[ $(docker inspect "${ids[@]}" | jq '[.[].Mounts[] | select(.Type == "bind" and (.Source | startswith("/srv/home-lab-state/")))] | length') -eq 115 ]]
[[ $(docker inspect "${ids[@]}" | jq '[.[].Mounts[] | select(.Type == "volume")] | length') -eq 0 ]]

[[ ! -e $DEPLOY_STASH && ! -L $DEPLOY_STASH ]]
mv "$DEPLOY_ROOT" "$DEPLOY_STASH"
HOME=/root python3 "$ARTIFACT_ROOT/scripts/compose-model-inventory.py" desired \
  --artifact-root "$ARTIFACT_ROOT" --project-directory "$ARTIFACT_ROOT" \
  --env-file /etc/docker-compose/production.env --project-name docker-compose \
  --bind-root-override "$DEPLOY_ROOT" --output "$MODEL" >/dev/null
mv "$DEPLOY_STASH" "$DEPLOY_ROOT"
[[ $(sha256sum "$MODEL" | awk '{print $1}') == "$MODEL_SHA256" ]]
jq -e --slurpfile expected "$IMAGE_LOCK" '(.services | length) == 41 and ([.services | to_entries[] | {service:.key,image_id:.value.image}] | sort_by(.service)) == ([$expected[0].images[] | {service,image_id}] | sort_by(.service))' "$IMAGE_OVERRIDE" >/dev/null
python3 "$DEPLOY_ROOT/scripts/compose-image-lock.py" capture --project docker-compose --output "$RUNTIME_LOCK" >/dev/null
jq -e --slurpfile expected "$IMAGE_LOCK" '[.images[] | {service,image_id}] == [$expected[0].images[] | {service,image_id}]' "$RUNTIME_LOCK" >/dev/null

wait_for_lan_ports
tailscale status --json | jq -e '.BackendState == "Running" and .Self.Online == true and .Self.HostName == "docker-host-debian" and (.Self.Tags | index("tag:docker-host") != null)' >/dev/null
grep -Eq '(^|[[:space:]])amdgpu\.runpm=0($|[[:space:]])' /proc/cmdline
[[ $(cat /sys/module/amdgpu/parameters/runpm) == 0 ]]
[[ $(journalctl -k -b --no-pager | grep -Eci 'I/O error|EXT4-fs error|Buffer I/O|blk_update_request|nfs: server .* not responding|amdgpu_device_ip_resume failed|resume of IP block <[^>]+> failed' || true) -eq 0 ]]
