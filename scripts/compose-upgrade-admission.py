#!/usr/bin/env python3
"""Read-only admission for scheduled, image-only Compose upgrades.

GitHub concurrency and the existing production lock own serialization. This adapter
only fills the gap between Renovate's update classification and the actual deployed
source, and evaluates a timezone-aware start window. It never extracts an archive,
prints source contents, clears ownership, or changes production.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from zoneinfo import ZoneInfo

# Restrict edits to the existing service-image fields and shared Nextcloud image.
# Preserve every other byte, including anchors, comments and formatting.
IMAGE_LINE = re.compile(
    rb"(?m)^(?P<prefix>(?: {4}image: |x-nextcloud-image: &nextcloud-image ))"
    rb"(?P<image>[^\s]+@sha256:[a-f0-9]{64})(?P<suffix>[ \t]*\r?)$"
)
VERSIONED_IMAGE = re.compile(
    r"(?P<name>.+):v?(?P<version>[0-9]+(?:\.[0-9]+){1,3})"
    r"(?P<variant>-(?:alpine[0-9.]*|apache|ubi[0-9]+|openssl))?"
    r"@sha256:[a-f0-9]{64}"
)


def window_open(policy: dict, now: datetime | None = None) -> bool:
    zone = ZoneInfo(policy["timezone"])
    start, end, reserve = (
        policy["start_hour"], policy["end_hour"], policy["minimum_remaining_minutes"]
    )
    if (any(type(value) is not int for value in (start, end, reserve))
            or not 0 <= start < end <= 23 or not 0 < reserve < (end - start) * 60):
        raise ValueError("invalid_window")
    instant = now if now is not None else datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("timezone_required")
    local = instant.astimezone(zone)
    beginning = local.replace(hour=start, minute=0, second=0, microsecond=0)
    cutoff = local.replace(hour=end, minute=0, second=0, microsecond=0) - timedelta(minutes=reserve)
    return beginning <= local < cutoff


def read_archive(path: Path) -> dict:
    entries = {}
    with tarfile.open(path, "r:") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or ".." in name.parts or str(name) in entries
                    or not (member.isfile() or member.isdir() or member.issym())):
                raise ValueError("archive_shape")
            stream = archive.extractfile(member) if member.isfile() else None
            entries[str(name)] = (
                member.type, member.mode, member.linkname,
                stream.read() if stream is not None else b"",
            )
    if "docker-compose.yml" not in entries:
        raise ValueError("archive_source_missing")
    return entries


def admit_image(old: bytes, new: bytes) -> None:
    before = VERSIONED_IMAGE.fullmatch(old.decode("ascii"))
    after = VERSIONED_IMAGE.fullmatch(new.decode("ascii"))
    if before is None or after is None:
        raise ValueError("unversioned_or_prerelease_image")
    old_version = tuple(int(value) for value in before["version"].split("."))
    new_version = tuple(int(value) for value in after["version"].split("."))
    if before["name"] != after["name"] or before["variant"] != after["variant"]:
        raise ValueError("image_identity_changed")
    if old_version[0] != new_version[0]:
        raise ValueError("major_upgrade")
    if new_version + (0,) * (4 - len(new_version)) < old_version + (0,) * (4 - len(old_version)):
        raise ValueError("version_downgrade")


def admit_archives(active: Path, candidate: Path) -> int:
    before, after = read_archive(active), read_archive(candidate)
    if before.keys() != after.keys():
        raise ValueError("source_set_changed")
    count = 0
    for name, old_entry in before.items():
        new_entry = after[name]
        if old_entry == new_entry:
            continue
        if old_entry[:3] != new_entry[:3] or re.fullmatch(r"services/[^/]+\.ya?ml", name) is None:
            raise ValueError("non_image_source_change")
        old, new = old_entry[3], new_entry[3]
        old_images, new_images = list(IMAGE_LINE.finditer(old)), list(IMAGE_LINE.finditer(new))
        if (len(old_images) != len(new_images) or not old_images
                or IMAGE_LINE.sub(rb"\g<prefix><image>\g<suffix>", old)
                != IMAGE_LINE.sub(rb"\g<prefix><image>\g<suffix>", new)):
            raise ValueError("non_image_compose_change")
        for left, right in zip(old_images, new_images):
            if left["image"] != right["image"]:
                admit_image(left["image"], right["image"])
                count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    policy = parser.add_mutually_exclusive_group(required=False)
    policy.add_argument("--policy", type=Path)
    policy.add_argument("--policy-json")
    parser.add_argument("--active-archive", type=Path)
    parser.add_argument("--candidate-archive", type=Path)
    args = parser.parse_args()
    try:
        if bool(args.active_archive) != bool(args.candidate_archive):
            raise ValueError("archive_pair_required")
        result = {}
        if args.policy or args.policy_json:
            settings = json.loads(args.policy.read_text() if args.policy else args.policy_json)
            result["window_open"] = window_open(settings)
        if args.active_archive:
            result["changed_images"] = admit_archives(args.active_archive, args.candidate_archive)
        if not result:
            raise ValueError("admission_request_missing")
        print(json.dumps(result))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, tarfile.TarError) as error:
        # Never render archive data, parser input, paths, or private exception text.
        reason = str(error) if type(error) is ValueError and str(error) in {
            "invalid_window", "timezone_required", "archive_shape", "archive_source_missing",
            "unversioned_or_prerelease_image", "image_identity_changed", "major_upgrade",
            "version_downgrade", "source_set_changed", "non_image_source_change",
            "non_image_compose_change", "archive_pair_required", "admission_request_missing",
        } else "invalid_admission_input"
        raise SystemExit(f"compose_upgrade=refused reason={reason}") from None


if __name__ == "__main__":
    main()
