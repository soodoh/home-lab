#!/usr/bin/env bash
# Shared ordinary-controller input admission; source after parsing the required path.
# repo_root and boundary_manifest are supplied by the calling controller.
# shellcheck disable=SC2154
initialize_controller_boundaries() {
  local inputs
  [[ -n $boundary_manifest ]] || {
    echo 'controller boundary manifest is required (--boundary-manifest)' >&2
    return 64
  }
  inputs=$(python3 -B -E -s -S "$repo_root/scripts/controller/controller-boundary-manifest.py" \
    load --manifest "$boundary_manifest") || return
  IFS=$'\t' read -r boundary_plan_arn boundary_apply_arn boundary_binding <<<"$inputs"
  export TF_VAR_controller_plan_permissions_boundary_arn=$boundary_plan_arn
  export TF_VAR_controller_apply_permissions_boundary_arn=$boundary_apply_arn
}

verify_controller_boundaries() {
  local args=(verify --manifest "$boundary_manifest" --binding "$boundary_binding")
  [[ $# == 0 ]] || args+=(--saved-plan "$1")
  python3 -B -E -s -S "$repo_root/scripts/controller/controller-boundary-manifest.py" "${args[@]}"
}
