#!/usr/bin/env python3
"""Parse `zpool status -P` into a stable topology summary."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SECTION_NAMES = {"logs", "cache", "spares", "special", "dedup"}
STATE_NAMES = {"ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED", "SUSPENDED"}


def parse_status(text: str, expected_pool: str) -> dict[str, object]:
    lines = text.splitlines()
    pool_name = ""
    pool_state = ""
    scan_lines: list[str] = []
    mirrors: list[dict[str, object]] = []
    unexpected_data: list[dict[str, object]] = []
    extras: dict[str, list[dict[str, object]]] = {name: [] for name in sorted(SECTION_NAMES)}
    section = "data"
    current_mirror: dict[str, object] | None = None
    in_config = False
    collecting_scan = False

    for raw_line in lines:
        stripped = raw_line.strip()
        if stripped.startswith("pool:"):
            pool_name = stripped.split(":", 1)[1].strip()
            collecting_scan = False
            continue
        if stripped.startswith("state:"):
            pool_state = stripped.split(":", 1)[1].strip()
            collecting_scan = False
            continue
        if stripped.startswith("scan:"):
            scan_lines.append(stripped.split(":", 1)[1].strip())
            collecting_scan = True
            continue
        if stripped == "config:":
            in_config = True
            collecting_scan = False
            continue
        if stripped.startswith("errors:"):
            in_config = False
            collecting_scan = False
            continue
        if collecting_scan and stripped and not re.match(r"^[a-z]+:", stripped):
            scan_lines.append(stripped)
            continue
        if not in_config or not stripped or stripped.startswith("NAME "):
            continue
        if stripped in SECTION_NAMES:
            section = stripped
            current_mirror = None
            continue

        fields = stripped.split()
        if len(fields) < 2 or fields[1] not in STATE_NAMES:
            continue
        record = {"name": fields[0], "state": fields[1]}
        if len(fields) >= 5 and all(value.isdigit() or value == "-" for value in fields[2:5]):
            record.update({"read": fields[2], "write": fields[3], "cksum": fields[4]})

        if section != "data":
            extras[section].append(record)
            continue
        if record["name"] == expected_pool:
            if pool_state and record["state"] != pool_state:
                raise ValueError("pool state differs between status header and topology")
            continue
        if str(record["name"]).startswith("mirror-"):
            current_mirror = {**record, "leaves": []}
            mirrors.append(current_mirror)
            continue
        if current_mirror is not None and str(record["name"]).startswith("/dev/disk/by-id/"):
            leaves = current_mirror["leaves"]
            if not isinstance(leaves, list):
                raise ValueError("invalid mirror leaf accumulator")
            leaves.append(record)
            continue
        unexpected_data.append(record)
        current_mirror = None

    if pool_name != expected_pool:
        raise ValueError(f"expected pool {expected_pool!r}, observed {pool_name!r}")
    if not pool_state:
        raise ValueError("pool state is missing")

    return {
        "pool": {"name": pool_name, "state": pool_state},
        "scan": " ".join(scan_lines),
        "mirrors": mirrors,
        "unexpected_data": unexpected_data,
        "extras": extras,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pool", required=True)
    parser.add_argument("--input", type=Path)
    arguments = parser.parse_args()
    text = arguments.input.read_text() if arguments.input else sys.stdin.read()
    try:
        result = parse_status(text, arguments.pool)
    except ValueError as error:
        print(f"zpool topology parse failed: {error}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
