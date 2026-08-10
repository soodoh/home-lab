#!/usr/bin/env python3
"""Report root-local paths not covered by explicit preserve or removal policy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_paths(policy: dict[str, object], key: str) -> list[Path]:
    values = policy.get(key)
    if not isinstance(values, list) or not all(isinstance(value, str) and value.startswith("/") for value in values):
        raise ValueError(f"policy {key} must be a list of absolute paths")
    return [Path(value) for value in values]


def covered(path: Path, policies: list[Path]) -> bool:
    return any(path == policy or policy in path.parents for policy in policies)


def contains_policy(path: Path, policies: list[Path]) -> bool:
    return any(path == policy or path in policy.parents for policy in policies)


def audit(policy: dict[str, object]) -> list[str]:
    inspect_roots = load_paths(policy, "inspect_roots")
    preserved = load_paths(policy, "preserve_paths")
    removable = load_paths(policy, "remove_paths")
    covered_paths = preserved + removable
    unknown: list[str] = []

    def inspect(path: Path) -> None:
        if covered(path, covered_paths):
            return
        if path.is_dir() and not path.is_symlink() and contains_policy(path, covered_paths):
            for entry in sorted(path.iterdir(), key=lambda item: item.name):
                inspect(entry)
            return
        unknown.append(str(path))

    for root in inspect_roots:
        if not root.exists():
            continue
        for entry in sorted(root.iterdir(), key=lambda item: item.name):
            inspect(entry)
    return unknown


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-json", required=True)
    arguments = parser.parse_args()
    policy = json.loads(arguments.policy_json)
    if not isinstance(policy, dict):
        raise SystemExit("root cleanup policy must be an object")
    try:
        unknown = audit(policy)
    except (OSError, ValueError) as error:
        raise SystemExit(f"root-local audit failed: {error}") from error
    json.dump({"unknown": unknown}, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
