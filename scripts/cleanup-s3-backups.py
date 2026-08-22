#!/usr/bin/env python3
"""Build and apply an approved manifest for exact S3 backup-version cleanup."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from argparse import ArgumentParser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from s3_backup_api import S3BackupApiError, S3BackupClient, S3Version

DEFAULT_PREFIXES = ("weekly-backup-", "daily-remote-backup-")
PREFIX_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*-$")
TIMESTAMP_SUFFIX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.tar\.gz\.gpg$")


def fail(reason: str) -> None:
    print(f"s3_backup_cleanup=failed reason={reason}", file=sys.stderr)
    raise SystemExit(1)


def encoded(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value: Any) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


def checked_prefixes(additional: list[str]) -> tuple[str, ...]:
    prefixes = (*DEFAULT_PREFIXES, *additional)
    if len(set(prefixes)) != len(prefixes) or any(not PREFIX_PATTERN.fullmatch(item) for item in prefixes):
        fail("recognized_prefix_invalid")
    return tuple(prefixes)


def is_recognized(key: str, prefixes: tuple[str, ...]) -> bool:
    return any(key.startswith(prefix) and TIMESTAMP_SUFFIX.fullmatch(key[len(prefix) :]) for prefix in prefixes)


def version_record(version: S3Version) -> dict[str, Any]:
    return {
        "key": version.key,
        "version_id": version.version_id,
        "kind": version.kind,
        "is_latest": version.is_latest,
        "last_modified": version.last_modified,
        "size": version.size,
        "key_sha256": hashlib.sha256(version.key.encode()).hexdigest(),
        "version_id_sha256": hashlib.sha256(version.version_id.encode()).hexdigest(),
        "identity_sha256": digest([version.key, version.version_id, version.kind]),
    }


def unrelated_summary(versions: list[S3Version], prefixes: tuple[str, ...]) -> dict[str, Any]:
    identities = sorted(
        [version.key, version.version_id, version.kind]
        for version in versions
        if not is_recognized(version.key, prefixes)
    )
    unrelated = [version for version in versions if not is_recognized(version.key, prefixes)]
    return {
        "count": len(unrelated),
        "aggregate_version_bytes": sum(version.size for version in unrelated if version.kind == "Version"),
        "identities_sha256": digest(identities),
    }


def build_manifest(client: S3BackupClient, versions: list[S3Version], prefixes: tuple[str, ...]) -> dict[str, Any]:
    recognized = [version for version in versions if is_recognized(version.key, prefixes)]
    recognized.sort(key=lambda item: item.identity())
    current = [item for item in recognized if item.kind == "Version" and item.is_latest]
    noncurrent = [item for item in recognized if item.kind == "Version" and not item.is_latest]
    markers = [item for item in recognized if item.kind == "DeleteMarker"]
    latest_timestamp = max(
        (item.last_modified for item in recognized if item.kind == "Version"), default=""
    )
    return {
        "version": 1,
        "action": "delete-recognized-s3-backup-versions",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "region": client.region,
        "bucket_sha256": hashlib.sha256(client.bucket.encode()).hexdigest(),
        "recognized_prefixes": list(prefixes),
        "recognized_counts": {
            "current_objects": len(current),
            "noncurrent_versions": len(noncurrent),
            "delete_markers": len(markers),
            "all_entries": len(recognized),
        },
        "recognized_aggregate_version_bytes": sum(
            item.size for item in recognized if item.kind == "Version"
        ),
        "latest_recognized_object_last_modified": latest_timestamp,
        "unrelated": unrelated_summary(versions, prefixes),
        "entries": [version_record(item) for item in recognized],
    }


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    if not path.is_absolute():
        fail("manifest_path_not_absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as output:
            os.chmod(temporary, 0o600)
            output.write(encoded(manifest))
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_mode & 0o077:
            fail("manifest_file_invalid")
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        fail("manifest_read_error")
    if not isinstance(manifest, dict):
        fail("manifest_invalid")
    return manifest


def manifest_versions(manifest: dict[str, Any]) -> list[S3Version]:
    try:
        return [
            S3Version(
                key=entry["key"],
                version_id=entry["version_id"],
                kind=entry["kind"],
                is_latest=entry["is_latest"],
                last_modified=entry["last_modified"],
                size=entry["size"],
                etag="",
            )
            for entry in manifest["entries"]
        ]
    except (KeyError, TypeError):
        fail("manifest_entries_invalid")


def comparable_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    value = dict(manifest)
    value.pop("generated_at", None)
    return value


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--additional-prefix", action="append", default=[])
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approve-manifest-sha256")
    args = parser.parse_args()
    prefixes = checked_prefixes(args.additional_prefix)

    try:
        client = S3BackupClient.from_container()
        versions = client.list_versions()
    except S3BackupApiError as error:
        fail(str(error))

    if not args.apply:
        if args.approve_manifest_sha256:
            fail("approval_without_apply")
        manifest = build_manifest(client, versions, prefixes)
        write_manifest(args.manifest, manifest)
        print(
            "s3_backup_cleanup=dry-run "
            f"entries={manifest['recognized_counts']['all_entries']} "
            f"manifest_sha256={digest(manifest)}"
        )
        return

    manifest = load_manifest(args.manifest)
    manifest_digest = digest(manifest)
    if args.approve_manifest_sha256 != manifest_digest:
        fail("manifest_approval_mismatch")
    if manifest.get("recognized_prefixes") != list(prefixes):
        fail("manifest_prefix_mismatch")
    fresh = build_manifest(client, versions, prefixes)
    if comparable_manifest(manifest) != comparable_manifest(fresh):
        fail("manifest_stale")
    selected = manifest_versions(manifest)
    try:
        deleted = client.delete_versions(selected)
        remaining = client.list_versions()
    except S3BackupApiError as error:
        fail(str(error))
    if any(is_recognized(item.key, prefixes) for item in remaining):
        fail("recognized_entries_remain")
    if unrelated_summary(remaining, prefixes) != manifest["unrelated"]:
        fail("unrelated_entries_changed")
    print(
        f"s3_backup_cleanup=applied entries={deleted} manifest_sha256={manifest_digest} "
        "recognized_remaining=0 unrelated=unchanged"
    )


if __name__ == "__main__":
    main()
