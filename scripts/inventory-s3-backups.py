#!/usr/bin/env python3
"""Inventory encrypted S3 backups without emitting credentials or bucket names."""

import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any

from s3_backup_api import S3BackupApiError, S3BackupClient, S3Version

MATCH_SUFFIX = ".gpg"


def metadata(version: S3Version, *, include_version: bool) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": version.key.rsplit("/", 1)[-1],
        "key_sha256": hashlib.sha256(version.key.encode()).hexdigest(),
        "size": version.size,
        "last_modified": version.last_modified,
        "etag": version.etag,
    }
    if include_version:
        value.update(
            {
                "kind": version.kind,
                "is_latest": version.is_latest,
                "version_id_sha256": hashlib.sha256(version.version_id.encode()).hexdigest()
                if version.version_id
                else "",
            }
        )
    return value


def main() -> None:
    try:
        client = S3BackupClient.from_container()
        all_versions = client.list_versions()
    except S3BackupApiError as error:
        print(f"remote_backup_inventory=failed reason={error}", file=sys.stderr)
        raise SystemExit(1) from None

    current = [
        version
        for version in all_versions
        if version.kind == "Version" and version.is_latest and version.key.endswith(MATCH_SUFFIX)
    ]
    encrypted_versions = [version for version in all_versions if version.key.endswith(MATCH_SUFFIX)]
    print(
        json.dumps(
            {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "region": client.region,
                "total_current_key_count": sum(
                    version.kind == "Version" and version.is_latest for version in all_versions
                ),
                "encrypted_current_count": len(current),
                "encrypted_current_objects": [metadata(version, include_version=False) for version in current],
                "encrypted_version_count": len(encrypted_versions),
                "encrypted_versions": [
                    metadata(version, include_version=True) for version in encrypted_versions
                ],
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
