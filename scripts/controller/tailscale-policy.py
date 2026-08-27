#!/usr/bin/env python3
"""Canonicalize and bind the managed Tailscale policy to saved plans."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, TextIO


class PolicyError(ValueError):
    """Raised when a managed-policy invariant is not met."""


def reject_json_constant(value: str) -> None:
    raise PolicyError(f"policy JSON contains invalid constant {value}")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"policy JSON contains duplicate key {key}")
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
        raise PolicyError("policy JSON is not canonicalizable") from error
    if not isinstance(policy, dict):
        raise PolicyError("policy JSON must contain an object")
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
        raise PolicyError("policy JSON is not canonicalizable") from error


def policy_from_plan(plan: Any, side: str) -> dict[str, Any]:
    if side not in {"before", "after"} or not isinstance(plan, dict):
        raise PolicyError("saved plan policy input is invalid")
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise PolicyError("saved plan resource changes are missing")
    matches = [
        change
        for change in changes
        if isinstance(change, dict)
        and change.get("address") == "terraform_data.tailscale_policy[0]"
    ]
    if len(matches) != 1:
        raise PolicyError("saved plan must contain exactly one Tailscale policy resource")
    change = matches[0].get("change")
    side_value = change.get(side) if isinstance(change, dict) else None
    input_value = side_value.get("input") if isinstance(side_value, dict) else None
    policy_json = input_value.get("policy_json") if isinstance(input_value, dict) else None
    if not isinstance(policy_json, str):
        raise PolicyError(f"saved plan Tailscale {side} policy JSON is missing")
    return parse_policy_json(policy_json)


def canonical_policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy(policy).encode()).hexdigest()


def validate_policy_sha(label: str, value: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise PolicyError(f"{label} policy SHA is invalid")


def validate_etag(label: str, value: str) -> None:
    if re.fullmatch(r'(?:W/)?"[^"\x00-\x1f\x7f]+"', value) is None:
        raise PolicyError(f"{label} ETag is invalid")


def validate_before_identity(planned_before_sha: str, live_before_sha: str) -> None:
    validate_policy_sha("planned before", planned_before_sha)
    validate_policy_sha("live before", live_before_sha)
    if planned_before_sha != live_before_sha:
        raise PolicyError("saved plan before policy differs from the live policy captured at plan time")


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
        raise PolicyError("saved plan does not change the policy")
    if current_sha == planned_after_sha:
        return "recovered"
    if current_sha != planned_before_sha or current_etag != planned_etag:
        raise PolicyError("live Tailscale policy differs from the saved-plan before identity")
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

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
                raise PolicyError("policy JSON must contain an object")
            sys.stdout.write(canonical_policy(policy))
        elif args.command == "extract-plan-policy":
            policy = policy_from_plan(read_json_input(args.plan_json), args.side)
            sys.stdout.write(canonical_policy(policy))
        elif args.command == "validate-before-identity":
            validate_before_identity(args.planned_before_sha, args.live_before_sha)
        else:
            print(
                apply_disposition(
                    args.current_sha,
                    args.current_etag,
                    args.planned_before_sha,
                    args.planned_after_sha,
                    args.planned_etag,
                )
            )
        return 0
    except (OSError, json.JSONDecodeError, UnicodeError, PolicyError) as error:
        print(f"Tailscale policy validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
