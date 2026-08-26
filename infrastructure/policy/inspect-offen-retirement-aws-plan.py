#!/usr/bin/env python3
"""Fail-closed semantic inspector for both saved Offen AWS retirement plans."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def fail(reason: str) -> None:
    raise SystemExit(f"offen_retirement_plan=failed reason={reason}")


def one(changes: list[dict], address: str) -> dict:
    values = [item for item in changes if item.get("address") == address]
    if len(values) != 1:
        fail("required_resource_missing")
    after = values[0].get("change", {}).get("after")
    if not isinstance(after, dict):
        fail("required_after_missing")
    return values[0]


def actions(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    fail("policy_actions_invalid")


def resources(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    fail("policy_resources_invalid")


def validate_policy(raw: str, recovery_bucket: str, state_bucket: str, recovery_kms: str, state_kms: str, object_key: str, grant: bool) -> None:
    try:
        policy = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        fail("policy_json_invalid")
    statements = policy.get("Statement")
    if not isinstance(statements, list) or not statements:
        fail("shared_policy_absent")
    if any(item.get("Effect") != "Allow" or set(item) - {"Action", "Effect", "Resource", "Sid"} for item in statements):
        fail("shared_policy_shape_invalid")
    by_actions = {frozenset(actions(item.get("Action"))): item for item in statements}
    if len(by_actions) != len(statements):
        fail("duplicate_policy_statement")
    list_actions = frozenset({"s3:ListBucket", "s3:ListBucketVersions"})
    object_actions = frozenset({"s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"})
    kms_actions = frozenset({"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"})
    delete_actions = frozenset({"s3:DeleteObjectVersion"})
    expected_keys = {list_actions, object_actions, kms_actions} | ({delete_actions} if grant else set())
    if set(by_actions) != expected_keys:
        fail("shared_policy_actions_differ")
    bucket_resources = resources(by_actions[list_actions].get("Resource"))
    if bucket_resources != {recovery_bucket, state_bucket}:
        fail("shared_bucket_resources_differ")
    expected_objects = {item + "/*" for item in bucket_resources}
    if resources(by_actions[object_actions].get("Resource")) != expected_objects:
        fail("shared_object_resources_differ")
    kms_resources = resources(by_actions[kms_actions].get("Resource"))
    if kms_resources != {recovery_kms, state_kms}:
        fail("shared_kms_resources_differ")
    if grant and resources(by_actions[delete_actions].get("Resource")) != {f"{recovery_bucket}/{object_key}"}:
        fail("delete_grant_differs")


def validate_lifecycle(rules: object, operation: str, manifest: dict) -> None:
    if not isinstance(rules, list) or any(not isinstance(item, dict) for item in rules):
        fail("lifecycle_rules_invalid")
    marker = {
        "id": "expired-delete-marker-cleanup",
        "status": "Enabled",
        "expiration": [{"expired_object_delete_marker": True}],
    }
    if operation == "grant":
        expected = [
            {
                "id": "critical-backup-retention",
                "status": "Enabled",
                "expiration": [{"days": manifest["aws"]["temporary_hold_days"]}],
                "noncurrent_version_expiration": [{"noncurrent_days": 1}],
                "abort_incomplete_multipart_upload": [{"days_after_initiation": manifest["aws"]["multipart_abort_days"]}],
            },
            marker,
        ]
    else:
        expected = [
            {
                "id": "incomplete-multipart-cleanup",
                "status": "Enabled",
                "abort_incomplete_multipart_upload": [{"days_after_initiation": manifest["aws"]["multipart_abort_days"]}],
            },
            marker,
        ]
    # Exact equality deliberately rejects every unreviewed filter, prefix/tag
    # selector, transition, noncurrent transition, alternate expiration,
    # object-size condition, status, and provider-added lifecycle attribute.
    if rules != expected:
        fail("lifecycle_complete_shape_differs")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation", choices=("grant", "finalize"), required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text())
    plan = json.loads(Path(args.plan).read_text())
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        fail("resource_changes_invalid")
    changed = {item.get("address") for item in changes if item.get("change", {}).get("actions") != ["no-op"]}
    expected = {"aws_iam_user_policy.recovery"} if args.operation == "grant" else {
        "aws_iam_user_policy.recovery", "aws_s3_bucket_lifecycle_configuration.recovery"
    }
    if changed != expected:
        fail("resource_scope_differs")
    for address in expected:
        if one(changes, address).get("change", {}).get("actions") != ["update"]:
            fail("action_scope_differs")
    lifecycle = one(changes, "aws_s3_bucket_lifecycle_configuration.recovery")["change"]["after"]
    if set(lifecycle) != {"bucket", "rule"}:
        fail("lifecycle_resource_shape_differs")
    bucket_name = lifecycle.get("bucket")
    if not isinstance(bucket_name, str) or not bucket_name:
        fail("recovery_bucket_binding_absent")
    recovery_bucket = f"arn:aws:s3:::{bucket_name}"
    state_bucket_value = one(changes, "aws_s3_bucket.state")["change"]["after"].get("bucket")
    if not isinstance(state_bucket_value, str) or not state_bucket_value:
        fail("state_bucket_binding_absent")
    state_bucket = f"arn:aws:s3:::{state_bucket_value}"
    encryption = one(changes, "aws_s3_bucket_server_side_encryption_configuration.recovery")["change"]["after"]
    encryption_rules = encryption.get("rule") or []
    try:
        recovery_kms = encryption_rules[0]["apply_server_side_encryption_by_default"][0]["kms_master_key_id"]
    except (IndexError, KeyError, TypeError):
        fail("recovery_kms_binding_absent")
    state_kms = one(changes, "aws_kms_key.opentofu")["change"]["after"].get("arn")
    if not isinstance(state_kms, str) or not state_kms:
        fail("state_kms_binding_absent")
    policy_after = one(changes, "aws_iam_user_policy.recovery")["change"]["after"]
    validate_policy(policy_after.get("policy"), recovery_bucket, state_bucket, recovery_kms, state_kms, manifest["aws"]["object_key"], args.operation == "grant")
    validate_lifecycle(lifecycle.get("rule"), args.operation, manifest)
    print(f"offen_retirement_plan=verified operation={args.operation}")


if __name__ == "__main__":
    main()
