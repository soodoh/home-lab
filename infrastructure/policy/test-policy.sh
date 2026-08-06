#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
policy="$root/inspect-plan.py"
fixtures="$root/fixtures"

expect_rejection() {
  local fixture=$1 mode=$2
  if python3 "$policy" "$fixtures/$fixture.json" --mode "$mode" >/dev/null 2>&1; then
    echo "expected policy rejection for $fixture in $mode mode" >&2
    exit 1
  fi
}

lxc_policy="$root/../../scripts/controller/proxmox-lxc-qualification.py"
export TF_VAR_qualification_vm_id=9020
export TF_VAR_qualification_template_file_id=local:vztmpl/debian-test_1_amd64.tar.zst
lxc_expect_rejection() {
  local fixture=$1 mode=$2
  if python3 "$lxc_policy" inspect-plan --plan-json "$fixtures/$fixture.json" --mode "$mode" >/dev/null 2>&1; then
    echo "expected LXC qualification rejection for $fixture in $mode mode" >&2
    exit 1
  fi
}

python3 "$policy" "$fixtures/noop.json"
python3 "$policy" "$fixtures/adopt-import.json" --mode adopt
python3 "$policy" "$fixtures/adopt-noop.json" --mode adopt-or-noop
python3 "$policy" "$fixtures/recovery-create.json" --mode recovery
python3 "$policy" "$fixtures/network-migration.json" --mode network-migration
python3 "$policy" "$fixtures/disk-growth.json" --mode disk-growth
python3 "$policy" "$fixtures/ct-unprotect.json" --mode ct-unprotect
python3 "$policy" "$fixtures/ct-delete.json" --mode ct-delete
python3 "$policy" "$fixtures/protection-enable.json"
python3 "$policy" "$fixtures/qualification-create.json" --mode qualification
python3 "$policy" "$fixtures/qualification-delete.json" --mode qualification
python3 "$root/../../scripts/controller/test-tailscale-gateway-policy.py"
python3 "$root/../../scripts/controller/test-reconcile-apply-source.py"
python3 "$root/../../scripts/controller/test-proxmox-lxc-qualification.py"
python3 "$root/../../scripts/controller/test-qualify-proxmox-lxc.py"

python3 "$lxc_policy" inspect-plan --plan-json "$fixtures/lxc-qualification-create.json" --mode create
python3 "$lxc_policy" inspect-plan --plan-json "$fixtures/lxc-qualification-protected-delete.json" --mode probe-protected-delete
python3 "$lxc_policy" inspect-plan --plan-json "$fixtures/lxc-qualification-unprotect.json" --mode unprotect
python3 "$lxc_policy" inspect-plan --plan-json "$fixtures/lxc-qualification-reprotect.json" --mode reprotect
python3 "$lxc_policy" inspect-plan --plan-json "$fixtures/lxc-qualification-delete.json" --mode delete
python3 "$lxc_policy" inspect-plan --plan-json "$fixtures/lxc-qualification-noop-protected.json" --mode verify-protected
python3 "$lxc_policy" inspect-plan --plan-json "$fixtures/lxc-qualification-empty.json" --mode verify-empty
for fixture in lxc-qualification-wrong-address lxc-qualification-wrong-mode \
  lxc-qualification-wrong-provider lxc-qualification-wrong-vmid-100 \
  lxc-qualification-wrong-vmid-101 lxc-qualification-storage lxc-qualification-network \
  lxc-qualification-mount-point lxc-qualification-device lxc-qualification-features \
  lxc-qualification-start lxc-qualification-extra-action lxc-qualification-replace \
  lxc-qualification-import; do
  lxc_expect_rejection "$fixture" create
done
lxc_expect_rejection lxc-qualification-protected-delete delete
lxc_expect_rejection lxc-qualification-empty create
lxc_expect_rejection lxc-qualification-empty verify-protected
lxc_expect_rejection lxc-qualification-noop-protected verify-empty

for fixture in delete replace protection-disable ct-create ct-recreate; do
  expect_rejection "$fixture" normal
done
for fixture in recovery-wrong-vm recovery-update; do
  expect_rejection "$fixture" recovery
done
for fixture in network-migration-extra-change mapping-device-change; do
  expect_rejection "$fixture" network-migration
done
expect_rejection disk-growth-extra disk-growth
expect_rejection disk-growth normal
expect_rejection qualification-wrong-resource qualification

# CT retirement modes are intentionally non-interchangeable and non-repeatable.
expect_rejection ct-delete ct-unprotect
expect_rejection ct-unprotect ct-delete
expect_rejection noop ct-unprotect
expect_rejection noop ct-delete
expect_rejection ct-wrong-id ct-unprotect
expect_rejection ct-wrong-id ct-delete
expect_rejection ct-delete-protected ct-unprotect
expect_rejection ct-delete-protected ct-delete
expect_rejection ct-extra-change ct-unprotect
expect_rejection ct-extra-change ct-delete
expect_rejection ct-delete-extra-resource ct-delete

echo "plan policy fixtures passed"
