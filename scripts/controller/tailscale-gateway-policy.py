#!/usr/bin/env python3
"""Validate the guarded Tailscale gateway-policy lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, TextIO

STAGES = {"active", "detached", "retired"}
OPERATIONS = {"none", "detach", "retire"}
DEVICE_ABSENCE_APPROVAL_ENVIRONMENT = "TAILSCALE_GATEWAY_DEVICE_ABSENCE_APPROVED"
TRANSITION_OPERATIONS = {
    ("active", "active"): "none",
    ("active", "detached"): "detach",
    ("detached", "active"): "none",
    ("detached", "detached"): "none",
    ("detached", "retired"): "retire",
    ("retired", "retired"): "none",
}


class GatewayPolicyError(ValueError):
    """Raised when a gateway-policy lifecycle invariant is not met."""


def contract_value(path: Path, target: tuple[str, ...]) -> str:
    ancestors: list[tuple[int, str]] = []
    for line in path.read_text().splitlines():
        match = re.match(r"^( *)([A-Za-z_][A-Za-z0-9_]*):(?:[ ]+(.*))?$", line)
        if not match:
            continue
        indent = len(match.group(1))
        key = match.group(2)
        value = match.group(3)
        while ancestors and indent <= ancestors[-1][0]:
            ancestors.pop()
        current = tuple(entry[1] for entry in ancestors) + (key,)
        if current == target:
            return (value or "").split(" #", 1)[0].strip().strip("\"'")
        if value is None:
            ancestors.append((indent, key))
    raise GatewayPolicyError(f"contract value {'.'.join(target)} is missing")


def gateway_stage(path: Path, legacy_active: bool = False) -> str:
    try:
        stage = contract_value(path, ("tailscale", "gateway_policy_stage"))
    except GatewayPolicyError:
        if legacy_active:
            return "active"
        raise
    if stage not in STAGES:
        raise GatewayPolicyError("contract gateway_policy_stage is invalid")
    return stage


def ct_stage(path: Path) -> str:
    stage = contract_value(path, ("proxmox", "legacy_container", "retirement_stage"))
    if stage not in {"protected", "unprotected", "retired"}:
        raise GatewayPolicyError("contract CT retirement_stage is invalid")
    return stage


def operation_matches_stage(operation: str, stage: str, container_stage: str) -> bool:
    if operation not in OPERATIONS or stage not in STAGES:
        return False
    if stage == "active" and container_stage == "retired":
        return False
    if stage == "retired" and container_stage != "retired":
        return False
    if operation == "none":
        return True
    if operation == "detach":
        return stage == "detached"
    return stage == "retired" and container_stage == "retired"


def device_absence_approved(operation: str) -> bool:
    return operation != "retire" or os.environ.get(DEVICE_ABSENCE_APPROVAL_ENVIRONMENT) == "true"


def transition_operation(base: Path, head: Path) -> str:
    base_gateway = gateway_stage(base, legacy_active=True)
    head_gateway = gateway_stage(head)
    base_ct = ct_stage(base)
    head_ct = ct_stage(head)
    try:
        operation = TRANSITION_OPERATIONS[(base_gateway, head_gateway)]
    except KeyError as error:
        raise GatewayPolicyError("gateway_policy_stage transition is not permitted") from error
    if base_gateway != head_gateway and base_ct != head_ct:
        raise GatewayPolicyError("gateway-policy and CT retirement transitions cannot be combined")
    if (base_gateway, head_gateway) == ("detached", "active") and (
        base_ct == "retired" or head_ct == "retired"
    ):
        raise GatewayPolicyError("gateway-policy rollback is forbidden after CT retirement")
    if operation == "retire" and not (base_ct == head_ct == "retired"):
        raise GatewayPolicyError("gateway-policy retirement requires an already retired CT")
    return operation


def reject_json_constant(value: str) -> None:
    raise GatewayPolicyError(f"policy JSON contains invalid constant {value}")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GatewayPolicyError(f"policy JSON contains duplicate key {key}")
        result[key] = value
    return result


def parse_policy_json(value: str) -> dict[str, Any]:
    try:
        policy = json.loads(
            value,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise GatewayPolicyError("policy JSON is not canonicalizable") from error
    if not isinstance(policy, dict):
        raise GatewayPolicyError("policy JSON must contain an object")
    return policy


def canonical_policy(policy: dict[str, Any]) -> str:
    try:
        return json.dumps(
            policy,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ) + "\n"
    except (TypeError, ValueError) as error:
        raise GatewayPolicyError("policy JSON is not canonicalizable") from error


def policy_from_plan(plan: Any, side: str) -> dict[str, Any]:
    if side not in {"before", "after"} or not isinstance(plan, dict):
        raise GatewayPolicyError("saved plan policy input is invalid")
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise GatewayPolicyError("saved plan resource changes are missing")
    matches = [
        change
        for change in changes
        if isinstance(change, dict)
        and change.get("address") == "terraform_data.tailscale_policy[0]"
    ]
    if len(matches) != 1:
        raise GatewayPolicyError("saved plan must contain exactly one Tailscale policy resource")
    change = matches[0].get("change")
    side_value = change.get(side) if isinstance(change, dict) else None
    input_value = side_value.get("input") if isinstance(side_value, dict) else None
    policy_json = input_value.get("policy_json") if isinstance(input_value, dict) else None
    if not isinstance(policy_json, str):
        raise GatewayPolicyError(f"saved plan Tailscale {side} policy JSON is missing")
    return parse_policy_json(policy_json)


def canonical_policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy(policy).encode()).hexdigest()


def validate_policy_sha(label: str, value: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise GatewayPolicyError(f"{label} policy SHA is invalid")


def validate_etag(label: str, value: str) -> None:
    if re.fullmatch(r'(?:W/)?"[^"\x00-\x1f\x7f]+"', value) is None:
        raise GatewayPolicyError(f"{label} ETag is invalid")


def validate_before_identity(planned_before_sha: str, live_before_sha: str) -> None:
    validate_policy_sha("planned before", planned_before_sha)
    validate_policy_sha("live before", live_before_sha)
    if planned_before_sha != live_before_sha:
        raise GatewayPolicyError("saved plan before policy differs from the live policy captured at plan time")


def apply_disposition(
    current_sha: str,
    current_etag: str,
    planned_before_sha: str,
    planned_after_sha: str,
    planned_etag: str,
) -> str:
    for label, value in (
        ("current", current_sha),
        ("planned before", planned_before_sha),
        ("planned after", planned_after_sha),
    ):
        validate_policy_sha(label, value)
    validate_etag("current", current_etag)
    validate_etag("planned", planned_etag)
    if planned_before_sha == planned_after_sha:
        raise GatewayPolicyError("saved lifecycle plan does not change the policy")
    if current_sha == planned_after_sha:
        return "recovered"
    if current_sha != planned_before_sha or current_etag != planned_etag:
        raise GatewayPolicyError("live Tailscale policy differs from the saved-plan before identity")
    return "post"


def read_json_input(path: str) -> Any:
    input_file: TextIO
    if path == "-":
        input_file = sys.stdin
    else:
        input_file = Path(path).open(encoding="utf-8")
    try:
        return json.load(
            input_file,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    finally:
        if path != "-":
            input_file.close()


def verify_manifest_fields(manifest: Any, operation: str, stage: str) -> None:
    if not isinstance(manifest, dict) or manifest.get("version") != 2:
        raise GatewayPolicyError("saved-plan manifest version is invalid")
    if manifest.get("tailscale_gateway_operation") != operation:
        raise GatewayPolicyError("saved-plan manifest gateway operation mismatch")
    if manifest.get("tailscale_gateway_policy_stage") != stage:
        raise GatewayPolicyError("saved-plan manifest gateway stage mismatch")
    plans = manifest.get("plans", [])
    tailscale_plans = [plan for plan in plans if isinstance(plan, dict) and plan.get("root") == "tailscale"] if isinstance(plans, list) else []
    if len(tailscale_plans) > 1:
        raise GatewayPolicyError("saved-plan manifest has duplicate Tailscale roots")
    if tailscale_plans:
        plan = tailscale_plans[0]
        before = plan.get("tailscale_policy_before_sha256")
        after = plan.get("tailscale_policy_after_sha256")
        etag = plan.get("tailscale_policy_etag")
        if not isinstance(before, str) or re.fullmatch(r"[0-9a-f]{64}", before) is None:
            raise GatewayPolicyError("saved-plan manifest Tailscale before SHA is invalid")
        if not isinstance(after, str) or re.fullmatch(r"[0-9a-f]{64}", after) is None:
            raise GatewayPolicyError("saved-plan manifest Tailscale after SHA is invalid")
        if not isinstance(etag, str) or re.fullmatch(r'(?:W/)?"[^"\x00-\x1f\x7f]+"', etag) is None:
            raise GatewayPolicyError("saved-plan manifest Tailscale ETag is invalid")
        if operation != "none" and before == after:
            raise GatewayPolicyError("saved-plan manifest lifecycle policy is unchanged")
    elif operation != "none":
        raise GatewayPolicyError("saved-plan manifest is missing the Tailscale root")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-operation")
    validate.add_argument("--contract", type=Path, required=True)
    validate.add_argument("--operation", choices=sorted(OPERATIONS), required=True)

    transition = subparsers.add_parser("transition")
    transition.add_argument("--base-contract", type=Path, required=True)
    transition.add_argument("--head-contract", type=Path, required=True)

    manifest = subparsers.add_parser("verify-manifest")
    manifest.add_argument("--manifest", type=Path, required=True)
    manifest.add_argument("--contract", type=Path, required=True)
    manifest.add_argument("--operation", choices=sorted(OPERATIONS), required=True)

    canonicalize = subparsers.add_parser("canonicalize-policy")
    canonicalize.add_argument("--policy", required=True)

    extract = subparsers.add_parser("extract-plan-policy")
    extract.add_argument("--plan-json", required=True)
    extract.add_argument("--side", choices=("before", "after"), required=True)

    before_identity = subparsers.add_parser("validate-before-identity")
    before_identity.add_argument("--planned-before-sha", required=True)
    before_identity.add_argument("--live-before-sha", required=True)

    disposition = subparsers.add_parser("apply-disposition")
    disposition.add_argument("--current-sha", required=True)
    disposition.add_argument("--current-etag", required=True)
    disposition.add_argument("--planned-before-sha", required=True)
    disposition.add_argument("--planned-after-sha", required=True)
    disposition.add_argument("--planned-etag", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "canonicalize-policy":
            policy = read_json_input(args.policy)
            if not isinstance(policy, dict):
                raise GatewayPolicyError("policy JSON must contain an object")
            sys.stdout.write(canonical_policy(policy))
            return 0
        if args.command == "extract-plan-policy":
            sys.stdout.write(canonical_policy(policy_from_plan(read_json_input(args.plan_json), args.side)))
            return 0
        if args.command == "validate-before-identity":
            validate_before_identity(args.planned_before_sha, args.live_before_sha)
            return 0
        if args.command == "apply-disposition":
            print(apply_disposition(
                args.current_sha,
                args.current_etag,
                args.planned_before_sha,
                args.planned_after_sha,
                args.planned_etag,
            ))
            return 0
        if args.command == "validate-operation":
            stage = gateway_stage(args.contract)
            if not operation_matches_stage(args.operation, stage, ct_stage(args.contract)):
                raise GatewayPolicyError("gateway operation does not match the contract stages")
            if not device_absence_approved(args.operation):
                raise GatewayPolicyError("retirement requires exact protected device-absence approval")
            return 0
        if args.command == "transition":
            operation = transition_operation(args.base_contract, args.head_contract)
            print(operation)
            return 0
        stage = gateway_stage(args.contract)
        if not operation_matches_stage(args.operation, stage, ct_stage(args.contract)):
            raise GatewayPolicyError("gateway operation does not match the contract stages")
        if not device_absence_approved(args.operation):
            raise GatewayPolicyError("retirement requires exact protected device-absence approval")
        verify_manifest_fields(json.loads(args.manifest.read_text()), args.operation, stage)
        return 0
    except (OSError, json.JSONDecodeError, UnicodeError, GatewayPolicyError) as error:
        print(f"Tailscale gateway-policy validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
