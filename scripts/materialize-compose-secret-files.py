#!/usr/bin/env python3
"""Atomically materialize selected dotenv values as protected Compose secret files."""

from __future__ import annotations

from argparse import ArgumentParser
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile

KEY_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
FILENAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]*")


def fail(reason: str) -> None:
    raise SystemExit(f"compose_secret_materialization=failed reason={reason}")


def protected_regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail("source_missing")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("source_identity")
    return info


def parse_dotenv(path: Path) -> dict[str, str]:
    protected_regular_file(path)
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        key, separator, encoded = line.partition("=")
        key = key.strip()
        if not separator or KEY_PATTERN.fullmatch(key) is None or key in values:
            fail(f"dotenv_assignment_{line_number}")
        try:
            decoded = shlex.split(encoded, comments=True, posix=True)
        except ValueError:
            fail(f"dotenv_value_{line_number}")
        if len(decoded) != 1 or not decoded[0] or "\x00" in decoded[0] or "\n" in decoded[0]:
            fail(f"dotenv_value_{line_number}")
        values[key] = decoded[0]
    return values


def validate_directory(path: Path, owner_uid: int, group_gid: int) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True)
        os.chown(path, owner_uid, group_gid)
        info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink < 2
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != owner_uid
        or info.st_gid != group_gid
    ):
        fail("destination_directory_identity")


def validate_destination(path: Path, owner_uid: int, group_gid: int, expected: bytes | None = None) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != owner_uid
        or info.st_gid != group_gid
    ):
        fail("destination_file_identity")
    if expected is not None and path.read_bytes() != expected:
        fail("destination_content")


def write_secret(path: Path, value: str, owner_uid: int, group_gid: int) -> bool:
    payload = value.encode()
    if path.exists() or path.is_symlink():
        validate_destination(path, owner_uid, group_gid)
        if path.read_bytes() == payload:
            return False
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, owner_uid, group_gid)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        validate_destination(path, owner_uid, group_gid, payload)
    finally:
        if temporary.exists():
            temporary.unlink()
    return True


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--dotenv", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--secret", action="append", required=True)
    parser.add_argument("--owner-uid", type=int, default=0)
    parser.add_argument("--group-gid", type=int, default=0)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    mappings: dict[str, str] = {}
    for item in args.secret:
        key, separator, filename = item.partition("=")
        if (
            not separator
            or KEY_PATTERN.fullmatch(key) is None
            or FILENAME_PATTERN.fullmatch(filename) is None
            or key in mappings
            or filename in mappings.values()
        ):
            fail("secret_mapping")
        mappings[key] = filename

    values = parse_dotenv(args.dotenv)
    if any(key not in values for key in mappings):
        fail("secret_key_missing")
    validate_directory(args.directory, args.owner_uid, args.group_gid)

    changed = 0
    for key, filename in mappings.items():
        destination = args.directory / filename
        if destination.parent != args.directory:
            fail("destination_escape")
        if args.check:
            validate_destination(destination, args.owner_uid, args.group_gid, values[key].encode())
        elif write_secret(destination, values[key], args.owner_uid, args.group_gid):
            changed += 1

    action = "checked" if args.check else "materialized"
    print(f"compose_secret_materialization=pass action={action} files={len(mappings)} changed={changed}")


if __name__ == "__main__":
    main()
