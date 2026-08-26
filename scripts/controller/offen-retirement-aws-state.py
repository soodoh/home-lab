#!/usr/bin/env python3
"""Exact, testable S3 version-state classifier for Offen retirement."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def fail(reason: str) -> None:
    raise SystemExit(f"offen_retirement_aws_state=failed reason={reason}")


def load(path: str) -> dict:
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict) or value.get("IsTruncated") is True or value.get("NextToken") or value.get("NextKeyMarker"):
        fail("pagination_incomplete")
    return value


def matching(value: dict, key: str) -> tuple[list[dict], list[dict]]:
    versions = [item for item in value.get("Versions", []) if item.get("Key") == key]
    markers = [item for item in value.get("DeleteMarkers", []) if item.get("Key") == key]
    return versions, markers


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("select", "prove-absent"))
    parser.add_argument("--input", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--bytes", type=int)
    parser.add_argument("--version-id-sha256")
    parser.add_argument("--output")
    args = parser.parse_args()
    value = load(args.input)
    versions, markers = matching(value, args.key)
    if args.action == "prove-absent":
        if versions or markers:
            fail("object_retained")
        print("offen_retirement_aws_state=absent")
        return
    if args.bytes is None or not args.version_id_sha256 or not args.output:
        fail("select_arguments_missing")
    if len(versions) != 1 or markers or versions[0].get("Size") != args.bytes or versions[0].get("IsLatest") is not True:
        fail("exact_version_differs")
    version = versions[0].get("VersionId", "")
    if hashlib.sha256(version.encode()).hexdigest() != args.version_id_sha256:
        fail("version_identity_differs")
    Path(args.output).write_text(version)
    print("offen_retirement_aws_state=selected")


if __name__ == "__main__":
    main()
