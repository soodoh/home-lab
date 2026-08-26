#!/usr/bin/env python3
"""Normalize only exact AWS provider lifecycle defaults before pinned retirement inspection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def fail(reason: str) -> None:
    raise SystemExit(f"offen_retirement_plan_normalization=failed reason={reason}")


def validate_concise_rule(rule: dict) -> None:
    identifier = rule.get("id")
    if rule.get("status") != "Enabled":
        fail("concise_rule_status_differs")
    if identifier == "critical-backup-retention":
        if set(rule) != {"id", "status", "expiration", "noncurrent_version_expiration", "abort_incomplete_multipart_upload"}:
            fail("concise_retention_shape_differs")
        expiration = rule.get("expiration")
        noncurrent = rule.get("noncurrent_version_expiration")
        abort = rule.get("abort_incomplete_multipart_upload")
        if (not isinstance(expiration, list) or len(expiration) != 1 or set(expiration[0]) != {"days"}
                or type(expiration[0].get("days")) is not int):
            fail("concise_retention_expiration_differs")
        if (not isinstance(noncurrent, list) or len(noncurrent) != 1 or set(noncurrent[0]) != {"noncurrent_days"}
                or type(noncurrent[0].get("noncurrent_days")) is not int or noncurrent[0].get("noncurrent_days") != 1):
            fail("concise_retention_noncurrent_differs")
        if (not isinstance(abort, list) or len(abort) != 1 or set(abort[0]) != {"days_after_initiation"}
                or type(abort[0].get("days_after_initiation")) is not int or abort[0].get("days_after_initiation") != 1):
            fail("concise_retention_multipart_differs")
    elif identifier == "expired-delete-marker-cleanup":
        expiration = rule.get("expiration")
        if (set(rule) != {"id", "status", "expiration"} or not isinstance(expiration, list)
                or len(expiration) != 1 or set(expiration[0]) != {"expired_object_delete_marker"}
                or expiration[0].get("expired_object_delete_marker") is not True):
            fail("concise_delete_marker_differs")
    elif identifier == "incomplete-multipart-cleanup":
        abort = rule.get("abort_incomplete_multipart_upload")
        if (set(rule) != {"id", "status", "abort_incomplete_multipart_upload"}
                or not isinstance(abort, list) or len(abort) != 1 or set(abort[0]) != {"days_after_initiation"}
                or type(abort[0].get("days_after_initiation")) is not int or abort[0].get("days_after_initiation") != 1):
            fail("concise_multipart_differs")
    else:
        fail("concise_rule_unknown")


def normalize_rule(rule: object) -> dict:
    if not isinstance(rule, dict):
        fail("lifecycle_rule_invalid")
    concise_keys = {"id", "status", "expiration", "noncurrent_version_expiration", "abort_incomplete_multipart_upload"}
    if set(rule) <= concise_keys:
        validate_concise_rule(rule)
        return rule
    expected_keys = concise_keys | {"filter", "prefix", "transition", "noncurrent_version_transition"}
    if set(rule) != expected_keys or rule.get("status") != "Enabled" or rule.get("prefix") != "":
        fail("lifecycle_rule_shape_differs")
    if rule.get("filter") != [{"and": [], "object_size_greater_than": None, "object_size_less_than": None, "prefix": "", "tag": []}]:
        fail("lifecycle_filter_differs")
    if rule.get("transition") != [] or rule.get("noncurrent_version_transition") != []:
        fail("lifecycle_transition_forbidden")
    identifier = rule.get("id")
    expiration = rule.get("expiration")
    noncurrent = rule.get("noncurrent_version_expiration")
    abort = rule.get("abort_incomplete_multipart_upload")
    normalized = {"id": identifier, "status": "Enabled"}
    if identifier == "critical-backup-retention":
        if (not isinstance(expiration, list) or len(expiration) != 1
                or set(expiration[0]) != {"date", "days", "expired_object_delete_marker"}
                or expiration[0].get("date") is not None or expiration[0].get("expired_object_delete_marker") is not False
                or type(expiration[0].get("days")) is not int):
            fail("retention_expiration_shape_differs")
        if (not isinstance(noncurrent, list) or len(noncurrent) != 1
                or set(noncurrent[0]) != {"newer_noncurrent_versions", "noncurrent_days"}
                or noncurrent[0].get("newer_noncurrent_versions") is not None
                or type(noncurrent[0].get("noncurrent_days")) is not int
                or noncurrent[0].get("noncurrent_days") != 1):
            fail("retention_noncurrent_shape_differs")
        if (not isinstance(abort, list) or len(abort) != 1
                or set(abort[0]) != {"days_after_initiation"}
                or type(abort[0].get("days_after_initiation")) is not int
                or abort[0].get("days_after_initiation") != 1):
            fail("retention_multipart_shape_differs")
        normalized.update({
            "expiration": [{"days": expiration[0]["days"]}],
            "noncurrent_version_expiration": [{"noncurrent_days": 1}],
            "abort_incomplete_multipart_upload": [{"days_after_initiation": 1}],
        })
    elif identifier == "expired-delete-marker-cleanup":
        if (not isinstance(expiration, list) or len(expiration) != 1
                or set(expiration[0]) != {"date", "days", "expired_object_delete_marker"}
                or expiration[0].get("date") is not None
                or type(expiration[0].get("days")) is not int or expiration[0].get("days") != 0
                or expiration[0].get("expired_object_delete_marker") is not True
                or noncurrent != [] or abort != []):
            fail("delete_marker_shape_differs")
        normalized["expiration"] = [{"expired_object_delete_marker": True}]
    elif identifier == "incomplete-multipart-cleanup":
        if (expiration != [] or noncurrent != [] or not isinstance(abort, list) or len(abort) != 1
                or set(abort[0]) != {"days_after_initiation"}
                or type(abort[0].get("days_after_initiation")) is not int
                or abort[0].get("days_after_initiation") != 1):
            fail("multipart_only_shape_differs")
        normalized["abort_incomplete_multipart_upload"] = [{"days_after_initiation": 1}]
    else:
        fail("lifecycle_rule_unknown")
    return normalized


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = Path(args.input)
    target = Path(args.output)
    if source == target or target.exists() or target.is_symlink():
        fail("path_state_invalid")
    value = json.loads(source.read_text())
    changes = value.get("resource_changes")
    if not isinstance(changes, list):
        fail("resource_changes_invalid")
    matches = [item for item in changes if item.get("address") == "aws_s3_bucket_lifecycle_configuration.recovery"]
    if len(matches) != 1:
        fail("lifecycle_resource_missing")
    after = matches[0].get("change", {}).get("after")
    if not isinstance(after, dict):
        fail("lifecycle_after_invalid")
    if set(after) == {"bucket", "rule"}:
        bucket = after.get("bucket")
        rules = after.get("rule")
        if not isinstance(bucket, str) or not bucket or not isinstance(rules, list):
            fail("concise_lifecycle_resource_invalid")
        normalized_after = {"bucket": bucket, "rule": [normalize_rule(rule) for rule in rules]}
    else:
        if set(after) != {"bucket", "expected_bucket_owner", "id", "region", "rule", "timeouts", "transition_default_minimum_object_size"}:
            fail("lifecycle_resource_shape_differs")
        bucket = after.get("bucket")
        if (not isinstance(bucket, str) or not bucket or after.get("id") != bucket
                or after.get("expected_bucket_owner") != "" or after.get("region") != "us-west-2"
                or after.get("timeouts") is not None
                or after.get("transition_default_minimum_object_size") != "all_storage_classes_128K"):
            fail("lifecycle_resource_defaults_differ")
        rules = after.get("rule")
        if not isinstance(rules, list):
            fail("lifecycle_rules_invalid")
        normalized_after = {"bucket": bucket, "rule": [normalize_rule(rule) for rule in rules]}
    matches[0]["change"]["after"] = normalized_after
    descriptor = target.open("x")
    with descriptor:
        json.dump(value, descriptor, sort_keys=True, separators=(",", ":"))
        descriptor.write("\n")


if __name__ == "__main__":
    main()
