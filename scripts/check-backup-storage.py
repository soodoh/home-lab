#!/usr/bin/env python3
"""Validate independent local backup destinations and retention capacity."""

from argparse import ArgumentParser
from pathlib import Path
import os
import re
import shutil
import sys

ARCHIVE = re.compile(r"^(daily-local-backup|daily-backup)-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.tar\.gz\.gpg$")


def fail(reason: str) -> None:
    print(f"backup_storage=failed reason={reason}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--path", action="append", required=True, type=Path)
    parser.add_argument("--home-retention-days", required=True, type=int)
    parser.add_argument("--replica-retention-days", required=True, type=int)
    parser.add_argument("--estimated-archive-bytes", required=True, type=int)
    args = parser.parse_args()

    if len(args.path) != 3 or len(set(args.path)) != 3:
        fail("path_set_invalid")
    if args.home_retention_days != 2 or args.replica_retention_days != 7 or args.estimated_archive_bytes < 1:
        fail("retention_contract_invalid")

    devices: set[int] = set()
    for index, path in enumerate(args.path):
        retention_days = args.home_retention_days if index == 0 else args.replica_retention_days
        if not path.is_absolute() or not path.is_dir() or path.is_symlink():
            fail("path_invalid")
        if not os.access(path, os.W_OK | os.X_OK):
            fail("path_not_writable")
        device = path.stat().st_dev
        if device in devices:
            fail("filesystems_not_independent")
        devices.add(device)

        archives = [
            item for item in path.iterdir()
            if item.is_file() and not item.is_symlink() and ARCHIVE.fullmatch(item.name)
        ]
        largest = max((item.stat().st_size for item in archives), default=0)
        projected_archive_bytes = max(largest, args.estimated_archive_bytes)
        current_archive_bytes = sum(item.stat().st_size for item in archives)
        available = shutil.disk_usage(path).free
        if available < projected_archive_bytes:
            fail("incoming_archive_capacity_insufficient")
        required_capacity = projected_archive_bytes * (retention_days + 1)
        if available + current_archive_bytes < required_capacity:
            fail("retention_capacity_insufficient")

    print("backup_storage=verified paths=3 home_retention_days=2 replica_retention_days=7")


if __name__ == "__main__":
    main()
