#!/usr/bin/env python3
"""Safely extract a decrypted critical-data backup into an approved empty root."""

from argparse import ArgumentParser
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile

REQUIRED_CLASSES = (
    "vaultwarden-data",
    "omada-data",
    "hass-data",
    "wolf/cfg",
    "nextcloud-config",
    "nextcloud-custom-apps",
    "nextcloud-themes",
    ".env",
    ".ssh",
)
MAX_ARCHIVE_MEMBERS = 1_000_000
MAX_EXPANDED_BYTES = 200 * 1024 * 1024 * 1024


def fail(reason: str) -> None:
    status_file = os.environ.get("RECOVERY_STATUS_FILE", "")
    if re.fullmatch(r"/run/home-lab-recovery-[a-z0-9-]+", status_file):
        status_path = Path(status_file)
        status_path.write_text(f"recovery_restore=failed stage=extract reason={reason}\n")
        status_path.chmod(0o600)
    raise SystemExit(f"critical_restore=failed reason={reason}")


def safe_path(root: Path, member_name: str) -> tuple[Path, PurePosixPath]:
    archive_path = PurePosixPath(member_name)
    parts = archive_path.parts[1:] if archive_path.is_absolute() else archive_path.parts
    if not parts or ".." in parts:
        fail("unsafe_archive_path")
    relative = PurePosixPath(*parts)
    destination = root.joinpath(*relative.parts)
    if not destination.is_relative_to(root):
        fail("archive_path_escape")
    return destination, relative


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    args = parser.parse_args()

    archive_path = args.archive.resolve(strict=True)
    target = args.target.resolve(strict=True)
    if not target.is_dir() or any(target.iterdir()):
        fail("target_not_empty")

    observed: set[str] = set()
    written: set[str] = set()
    skipped_unsafe_symlinks: set[str] = set()
    extracted_files = 0
    member_count = 0
    expanded_bytes = 0
    directory_metadata: list[tuple[Path, int, int, int]] = []
    try:
        with archive_path.open("rb") as raw:
            with tarfile.open(fileobj=raw, mode="r|gz") as archive:
                for member in archive:
                    member_count += 1
                    if member_count > MAX_ARCHIVE_MEMBERS:
                        fail("archive_member_limit")
                    _, relative = safe_path(target, member.name)
                    relative_name = relative.as_posix()
                    observed.add(relative_name)
                    if relative.parts[0] != "backup":
                        fail("archive_root_mismatch")
                    if member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                        fail("unsupported_archive_member")
                    if member.isfile():
                        expanded_bytes += member.size
                        if expanded_bytes > MAX_EXPANDED_BYTES:
                            fail("archive_size_limit")
                    if not member.isdir():
                        if relative_name in written:
                            fail("duplicate_archive_destination")
                        written.add(relative_name)
                    if member.issym():
                        link = PurePosixPath(member.linkname)
                        normalized_target = PurePosixPath(
                            posixpath.normpath((relative.parent / link).as_posix())
                        )
                        if (
                            link.is_absolute()
                            or not normalized_target.parts
                            or normalized_target.parts[0] != "backup"
                            or ".." in normalized_target.parts
                        ):
                            skipped_unsafe_symlinks.add(relative_name)
                            observed.discard(relative_name)
                    elif not member.isdir() and not member.isfile():
                        fail("unsupported_archive_member")

            raw.seek(0)
            with tarfile.open(fileobj=raw, mode="r|gz") as archive:
                for member in archive:
                    destination, relative = safe_path(target, member.name)
                    if relative.as_posix() in skipped_unsafe_symlinks:
                        continue
                    if not destination.parent.resolve(strict=False).is_relative_to(target):
                        fail("archive_parent_escape")
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                        directory_metadata.append((destination, member.mode, member.uid, member.gid))
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if member.isfile():
                        source = archive.extractfile(member)
                        if source is None:
                            fail("unreadable_archive_member")
                        with destination.open("xb") as output:
                            shutil.copyfileobj(source, output)
                        extracted_files += 1
                    elif member.issym():
                        destination.symlink_to(member.linkname)
                    else:
                        fail("unsupported_archive_member")
                    if not member.issym():
                        os.chmod(destination, member.mode & 0o1777, follow_symlinks=False)
                    os.chown(destination, member.uid, member.gid, follow_symlinks=False)

        for destination, mode, uid, gid in sorted(
            directory_metadata, key=lambda entry: len(entry[0].parts), reverse=True
        ):
            os.chmod(destination, mode & 0o1777, follow_symlinks=False)
            os.chown(destination, uid, gid, follow_symlinks=False)
    except (tarfile.TarError, OSError, EOFError):
        fail("archive_integrity_or_extraction_error")

    for required in REQUIRED_CLASSES:
        required_path = f"backup/{required}"
        if not any(path == required_path or path.startswith(f"{required_path}/") for path in observed):
            fail("required_class_missing")
    print(
        f"critical_restore=verified files={extracted_files} classes={len(REQUIRED_CLASSES)} "
        f"skipped_unsafe_symlinks={len(skipped_unsafe_symlinks)}"
    )


if __name__ == "__main__":
    main()
