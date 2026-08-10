#!/usr/bin/env python3
"""Validate and atomically claim one consumed controller approval for apply."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("approval", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--operation", choices=("steady", "recovery"), required=True)
    parser.add_argument("--manifest-sha256", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    value = json.loads(args.approval.read_text())
    expected_keys = {
        "approved_at", "commit", "consumed", "consumed_at", "manifest_sha256", "operation", "version"
    }
    if set(value) != expected_keys:
        raise SystemExit("apply approval fields are invalid or the approval was already claimed")
    if (
        value.get("version") != 1
        or value.get("commit") != args.commit
        or value.get("operation") != args.operation
        or value.get("manifest_sha256") != args.manifest_sha256
        or value.get("consumed") is not True
        or not isinstance(value.get("approved_at"), str)
        or not value["approved_at"]
        or not isinstance(value.get("consumed_at"), str)
        or not value["consumed_at"]
    ):
        raise SystemExit("apply approval is unconsumed or does not match the commit, operation, and manifest")
    value["apply_started_at"] = datetime.now(timezone.utc).isoformat()
    with tempfile.NamedTemporaryFile(
        mode="w", dir=args.approval.parent, prefix=".approval-started.", delete=False
    ) as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        temporary = Path(stream.name)
    temporary.chmod(0o600)
    temporary.replace(args.approval)


if __name__ == "__main__":
    main()
