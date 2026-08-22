#!/usr/bin/env python3
"""Build and apply an exact manifest for historical local backup cleanup."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Any

TIMESTAMP = r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}"
PREFIX = r"(?:backup|daily-backup|daily-local-backup)"
ARCHIVE = re.compile(rf"^(?:{PREFIX})-{TIMESTAMP}\.tar\.gz\.gpg$")
SIDECAR = re.compile(rf"^(?:{PREFIX})-{TIMESTAMP}\.tar\.gz\.gpg\.sha256$")
PARTIAL = re.compile(
    rf"^(?:\.(?:{PREFIX})-{TIMESTAMP}\.tar\.gz\.gpg(?:\.sha256)?\.partial\.\d+|"
    rf"(?:{PREFIX})-{TIMESTAMP}\.tar\.gz\.gpg(?:\.sha256)?\.partial)$"
)
KEEP = re.compile(rf"^daily-local-backup-{TIMESTAMP}\.tar\.gz\.gpg$")


def fail(reason: str) -> None:
    print(f"local_backup_cleanup=failed reason={reason}", file=sys.stderr)
    raise SystemExit(1)


def encoded_manifest(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(encoded_manifest(manifest)).hexdigest()


def checked_roots(paths: list[Path]) -> list[Path]:
    if len(paths) != 2:
        fail("path_count_invalid")
    try:
        roots = [path.resolve(strict=True) for path in paths]
    except OSError:
        fail("path_unavailable")
    if len(set(roots)) != 2:
        fail("path_set_invalid")
    devices: set[int] = set()
    for root in roots:
        try:
            metadata = root.lstat()
        except OSError:
            fail("path_unavailable")
        if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
            fail("path_invalid")
        if metadata.st_dev in devices:
            fail("filesystems_not_independent")
        devices.add(metadata.st_dev)
    return roots


def recognized(name: str) -> bool:
    return bool(ARCHIVE.fullmatch(name) or SIDECAR.fullmatch(name) or PARTIAL.fullmatch(name))


def build_manifest(roots: list[Path], keep_basename: str) -> dict[str, Any]:
    if not KEEP.fullmatch(keep_basename):
        fail("keep_basename_invalid")
    entries: list[dict[str, Any]] = []
    for root in roots:
        keep = root / keep_basename
        keep_sidecar = root / f"{keep_basename}.sha256"
        if not keep.is_file() or keep.is_symlink() or not keep_sidecar.is_file() or keep_sidecar.is_symlink():
            fail("validated_generation_missing")
        for item in root.iterdir():
            if not recognized(item.name) or item.name in {keep_basename, f"{keep_basename}.sha256"}:
                continue
            metadata = item.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                fail("recognized_entry_not_regular")
            entries.append(
                {
                    "root": str(root),
                    "name": item.name,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "size": metadata.st_size,
                    "mtime_ns": metadata.st_mtime_ns,
                }
            )
    entries.sort(key=lambda entry: (entry["root"], entry["name"]))
    return {
        "version": 1,
        "action": "delete-recognized-local-backups",
        "paths": [str(root) for root in roots],
        "keep_basename": keep_basename,
        "entries": entries,
    }


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    if not path.is_absolute():
        fail("manifest_path_not_absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as output:
            os.chmod(temporary, 0o600)
            output.write(encoded_manifest(manifest))
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
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        fail("manifest_read_error")
    if not isinstance(value, dict):
        fail("manifest_invalid")
    return value


def apply_manifest(manifest: dict[str, Any], roots: list[Path], keep_basename: str) -> None:
    expected = build_manifest(roots, keep_basename)
    if manifest != expected:
        fail("manifest_stale")
    for entry in manifest["entries"]:
        root = Path(entry["root"])
        target = root / entry["name"]
        if target.parent != root or not recognized(target.name):
            fail("manifest_entry_invalid")
        try:
            metadata = target.lstat()
        except OSError:
            fail("manifest_entry_unavailable")
        observed = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
        }
        if not stat.S_ISREG(metadata.st_mode) or target.is_symlink() or any(
            observed[key] != entry[key] for key in observed
        ):
            fail("manifest_entry_changed")
        target.unlink()


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--path", action="append", required=True, type=Path)
    parser.add_argument("--keep-basename", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approve-manifest-sha256")
    args = parser.parse_args()

    roots = checked_roots(args.path)
    if args.apply:
        manifest = load_manifest(args.manifest)
        digest = manifest_sha256(manifest)
        if args.approve_manifest_sha256 != digest:
            fail("manifest_approval_mismatch")
        apply_manifest(manifest, roots, args.keep_basename)
        print(f"local_backup_cleanup=applied entries={len(manifest['entries'])} manifest_sha256={digest}")
        return

    if args.approve_manifest_sha256:
        fail("approval_without_apply")
    manifest = build_manifest(roots, args.keep_basename)
    write_manifest(args.manifest, manifest)
    digest = manifest_sha256(manifest)
    print(f"local_backup_cleanup=dry-run entries={len(manifest['entries'])} manifest_sha256={digest}")


if __name__ == "__main__":
    main()
