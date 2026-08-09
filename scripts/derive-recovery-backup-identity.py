#!/usr/bin/env python3
"""Derive the canonical secret-free selected-backup identity hash."""

from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

SHA256 = re.compile(r"^[0-9a-f]{64}$")
LOCAL_ID = re.compile(r"^(daily-local-backup|daily-backup)-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.tar\.gz\.gpg$")
REMOTE_ID = re.compile(r"^weekly-backup-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.tar\.gz\.gpg$")


def fail(reason: str) -> None:
    print(f"recovery_backup_identity=failed reason={reason}", file=sys.stderr)
    raise SystemExit(1)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def canonical_identity(source: str, backup_id: str, ciphertext_sha256: str, version_id: str) -> dict[str, object]:
    pattern = LOCAL_ID if source == "local" else REMOTE_ID
    if source not in {"local", "remote"} or not pattern.fullmatch(backup_id):
        fail("backup_id_invalid")
    if not SHA256.fullmatch(ciphertext_sha256):
        fail("ciphertext_sha256_invalid")
    if source == "local" and version_id:
        fail("local_version_invalid")
    if source == "remote" and not re.fullmatch(r"[A-Za-z0-9._~+-]{1,1024}", version_id):
        fail("remote_version_invalid")
    return {
        "backup_id_sha256": digest(backup_id),
        "ciphertext_sha256": ciphertext_sha256,
        "remote_version_id_sha256": digest(version_id) if source == "remote" else None,
        "source": source,
        "version": 1,
    }


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()
    if not args.input.is_file() or stat.S_IMODE(args.input.stat().st_mode) != 0o600:
        fail("input_file_invalid")
    try:
        value = json.loads(args.input.read_text())
        identity = canonical_identity(
            str(value["source"]),
            str(value["backup_id"]),
            str(value["ciphertext_sha256"]),
            str(value.get("remote_version_id", "")),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        fail("input_schema_invalid")
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    print(f"recovery_backup_identity_sha256={digest(encoded)}")


if __name__ == "__main__":
    main()
