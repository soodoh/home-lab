#!/usr/bin/env python3
"""Validate a controller-owned protected input before another tool reads it."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--label", default="protected input file")
    return parser.parse_args()


def validate(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise SystemExit(f"{label} does not exist") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.getuid():
        raise SystemExit(f"{label} must be owned by the controller user with mode 0600")


def main() -> None:
    args = parse_args()
    validate(args.path, args.label)


if __name__ == "__main__":
    main()
