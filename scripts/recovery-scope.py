#!/usr/bin/env python3
"""Resolve declared generic Restic recovery groups to services and paths."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re

NAME = re.compile(r"^[a-z][a-z0-9-]*$")
SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def load_scope(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"version", "common_paths", "groups"} or value["version"] != 1:
        raise ValueError("recovery scope schema differs")
    if not isinstance(value["common_paths"], list) or not isinstance(value["groups"], dict):
        raise ValueError("recovery scope collections differ")
    seen_paths: set[str] = set()
    seen_services: set[str] = set()
    for name, group in value["groups"].items():
        if not NAME.fullmatch(name) or set(group) != {"services", "paths"}:
            raise ValueError("recovery group schema differs")
        if not group["services"] or not group["paths"]:
            raise ValueError("recovery groups must contain services and paths")
        for service in group["services"]:
            if not isinstance(service, str) or not SERVICE.fullmatch(service) or service in seen_services:
                raise ValueError("recovery service identity differs or is duplicated")
            seen_services.add(service)
        for item in group["paths"]:
            validate_path(item)
            if item in seen_paths:
                raise ValueError("recovery path is duplicated")
            seen_paths.add(item)
    for item in value["common_paths"]:
        validate_path(item)
        if item in seen_paths:
            raise ValueError("common recovery path is duplicated")
        seen_paths.add(item)
    return value


def validate_path(value: object) -> None:
    if not isinstance(value, str):
        raise ValueError("recovery path must be a string")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("recovery path must be normalized and absolute")


def resolve(scope: dict, requested: list[str]) -> dict:
    groups = sorted(scope["groups"]) if requested == ["all"] else sorted(set(requested))
    if not groups or "all" in groups or any(name not in scope["groups"] for name in groups):
        raise ValueError("unknown or mixed recovery group selection")
    services: set[str] = set()
    paths = set(scope["common_paths"])
    for name in groups:
        services.update(scope["groups"][name]["services"])
        paths.update(scope["groups"][name]["paths"])
    return {"version": 1, "groups": groups, "services": sorted(services), "paths": sorted(paths)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scope", type=Path)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--all", action="store_true")
    selection.add_argument("--group", action="append", default=[])
    args = parser.parse_args()
    result = resolve(load_scope(args.scope), ["all"] if args.all else args.group)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
