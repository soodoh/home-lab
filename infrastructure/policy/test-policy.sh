#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
policy="$root/inspect-plan.py"
fixtures="$root/fixtures"
export TF_VAR_games_disk_by_id=/dev/disk/by-id/PROTECTED-GAMES-DISK

expect_rejection() {
  local fixture=$1 mode=$2
  if python3 "$policy" "$fixtures/$fixture.json" --mode "$mode" >/dev/null 2>&1; then
    echo "expected policy rejection for $fixture in $mode mode" >&2
    exit 1
  fi
}

python3 "$policy" "$fixtures/noop.json"
python3 "$policy" "$fixtures/protection-enable.json"
python3 "$policy" "$fixtures/custom-rom-removal.json"
python3 "$policy" "$fixtures/hardware-mapping-transition.json"
python3 "$policy" "$fixtures/vm-start-prerequisite.json" --mode vm-start-prerequisite
python3 "$policy" "$fixtures/candidate-disk-attach.json"
python3 "$policy" "$fixtures/omada-client-alias-delete.json"
expect_rejection vm-cutover-forward-safe vm-cutover-forward
expect_rejection vm-cutover-reverse-safe vm-cutover-reverse
expect_rejection import normal
import_allow=$(mktemp)
trap 'rm -f "$import_allow"' EXIT
printf 'example.imported\n' >"$import_allow"
python3 "$policy" "$fixtures/import.json" --allow-change-file "$import_allow"
if python3 "$policy" "$fixtures/vm-cutover-forward-safe.json" --mode vm-cutover-forward --allow-change-file "$import_allow" >/dev/null 2>&1; then
  echo "expected VM cutover mode to reject an allowlist" >&2
  exit 1
fi
rm -f "$import_allow"
trap - EXIT
for fixture in noop protection-enable custom-rom-removal hardware-mapping-transition delete replace protection-disable ct-create ct-recreate root-disk-size-change network-device-change hardware-mapping-partial omada-client-alias-delete; do
  expect_rejection "$fixture" vm-start-prerequisite
done
for fixture in delete replace protection-disable ct-create ct-recreate root-disk-size-change network-device-change hardware-mapping-partial candidate-disk-unsafe boot-order-change vm-lifecycle-change omada-client-alias-replace; do
  expect_rejection "$fixture" normal
done
python3 "$root/../../scripts/controller/test-tailscale-gateway-policy.py"
python3 "$root/../../scripts/controller/test-omada-host-alias.py"
python3 "$root/../../scripts/controller/test-normalize-ansible-plan.py"

echo "plan policy fixtures passed"
