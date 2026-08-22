#!/usr/bin/env python3
"""Verify a complete decrypted backup stream and isolated SQLite restores.

The encrypted archive must be decrypted by an external GPG identity and piped to
stdin. This script never handles the private key or passphrase and emits only
non-secret hashes, counts, and policy labels.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import sys
import tarfile
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class DatabaseSpec:
    label: str
    archive_path: str


DATABASES = (
    DatabaseSpec("vaultwarden", "backup/vaultwarden-data/db.sqlite3"),
    DatabaseSpec("vikunja", "backup/vikunja-data/vikunja.db"),
    DatabaseSpec("openfit", "backup/openfit-data/openfit.db"),
    DatabaseSpec("karaoke", "backup/karaoke-eternal-data/database.sqlite3"),
    DatabaseSpec("home_assistant", "backup/hass-data/home-assistant_v2.db"),
    DatabaseSpec("frigate", "backup/frigate-data/frigate.db"),
)

REQUIRED_PATHS = {
    "production_environment": ("backup/.env",),
    "recovery_ssh": ("backup/.ssh/",),
    "audiobookshelf_config": ("backup/audiobookshelf-data/config/",),
    "authentik_postgresql": ("backup/authentik-data/postgresql/18/docker/PG_VERSION",),
    "authentik_files": (
        "backup/authentik-data/media/",
        "backup/authentik-data/custom-templates",
        "backup/authentik-data/certs/",
    ),
    "bookshelf_database": ("backup/bookshelf-data/readarr.db",),
    "calibre_config": ("backup/calibre-data/config/", "backup/calibre-data/plugins"),
    "calibre_web_database": ("backup/calibre-web-data/app.db",),
    "caro_database": ("backup/caro-tachidesk-data/database.mv.db",),
    "ddns_config": ("backup/ddns-updater-data/config.json",),
    "frigate_database": ("backup/frigate-data/frigate.db",),
    "gluetun_session": ("backup/gluetun-data/MAM.cookies",),
    "home_assistant_database": ("backup/hass-data/home-assistant_v2.db",),
    "jellyfin_database": ("backup/jellyfin-data/config/data/jellyfin.db",),
    "karaoke_database": ("backup/karaoke-eternal-data/database.sqlite3",),
    "litellm_credentials": ("backup/litellm-data/chatgpt/",),
    "mosquitto_state": ("backup/mosquitto-data/config/", "backup/mosquitto-data/data/"),
    "nextcloud_mariadb": (
        "backup/nextcloud-db-data/ibdata1",
        "backup/nextcloud-db-data/nextcloud/",
    ),
    "nextcloud_config": ("backup/nextcloud-config/",),
    "nextcloud_custom_apps": ("backup/nextcloud-custom-apps",),
    "nextcloud_themes": ("backup/nextcloud-themes/",),
    "omada_database": ("backup/omada-data/data/db/",),
    "openfit_database": ("backup/openfit-data/openfit.db",),
    "openfit_uploads": ("backup/openfit-data/uploads/",),
    "pihole_config": ("backup/pihole-data/pihole.toml", "backup/pihole-data/gravity.db"),
    "prowlarr_database": ("backup/prowlarr-data/prowlarr.db",),
    "qbittorrent_state": (
        "backup/qbittorrent-data/qBittorrent/qBittorrent.conf",
        "backup/qbittorrent-data/qBittorrent/BT_backup/",
    ),
    "radarr_database": ("backup/radarr-data/radarr.db",),
    "radarr_4k_database": ("backup/radarr-4k-data/radarr.db",),
    "recyclarr_config": ("backup/recyclarr-data/configs/", "backup/recyclarr-data/settings.yml"),
    "sabnzbd_state": ("backup/sabnzbd-data/sabnzbd.ini", "backup/sabnzbd-data/admin/"),
    "seerr_database": ("backup/seerr-data/db/",),
    "sonarr_database": ("backup/sonarr-data/sonarr.db",),
    "tachidesk_database": ("backup/tachidesk-data/database.mv.db",),
    "vaultwarden_database": ("backup/vaultwarden-data/db.sqlite3",),
    "vikunja_database": ("backup/vikunja-data/vikunja.db",),
    "wolf_config": ("backup/wolf/cfg/config.toml",),
    "wolf_profiles": (
        "backup/wolf/profile-data/paul/WolfES-DE/.config/retroarch/saves/",
        "backup/wolf/profile-data/paul/WolfES-DE/ES-DE/settings/",
    ),
    "zwave_state": ("backup/zwave-data/settings.json",),
}

FORBIDDEN_PATHS = {
    "calibre_books": re.compile(r"^backup/calibre-data/books(?:/|$)"),
    "caro_downloads": re.compile(r"^backup/caro-tachidesk-data/downloads(?:/|$)"),
    "nextcloud_user_files": re.compile(r"^backup/(?:nextcloud|nextcloud-data)(?:/|$)"),
    "mariadb_binlogs": re.compile(r"^backup/nextcloud-db-data/binlog\."),
    "authentik_postgresql_16": re.compile(r"^backup/authentik-data/postgresql-16(?:/|$)"),
    "jellyfin_derived": re.compile(
        r"^backup/jellyfin-data/(?:cache(?:/|$)|config/(?:metadata(?:/|$)|log(?:/|$)|data/(?:attachments|introskipper|subtitles)(?:/|$)))"
    ),
    "arr_derived": re.compile(
        r"^backup/(?:bookshelf|prowlarr|radarr|radarr-4k|sonarr)-data/(?:Backups|MediaCover|Sentry|logs)(?:/|$)"
    ),
    "tachidesk_runtime": re.compile(
        r"^backup/(?:caro-tachidesk|tachidesk)-data/(?:backups|bin|cache|downloads|logs|webUI)(?:/|$)"
    ),
    "pihole_query_history": re.compile(r"^backup/pihole-data/pihole-FTL\.db(?:-|$)"),
    "recyclarr_runtime": re.compile(
        r"^backup/recyclarr-data/(?:logs|repositories|resources|state)(?:/|$)"
    ),
    "omada_derived": re.compile(
        r"^backup/omada-data/(?:logs(?:/|$)|data/(?:device-firmware(?:/|$)|mongodb-preupgrade\.tar$))"
    ),
    "internal_backup_archives": re.compile(r"/(?:Backups|backups|config_backups|gravity_backups)(?:/|$)"),
    "application_caches": re.compile(r"/(?:\.[Cc]ache|[Cc]ache)(?:/|$)"),
    "logs": re.compile(r"/[Ll]ogs?(?:/|$)|\.log(?:\.[^/]+)?$"),
    "vaultwarden_icon_cache": re.compile(r"^backup/vaultwarden-data/icon_cache(?:/|$)"),
    "wolf_bulk": re.compile(
        r"^backup/wolf/profile-data/paul/WolfES-DE/(?:bioses|roms|\.local/share/Steam|ES-DE/themes)(?:/|$)"
    ),
    "removed_regenerable_roots": re.compile(
        r"^backup/(?:caddy-data|calibre-web-ingest|flaresolverr-data|nextcloud-redis-data)(?:/|$)"
    ),
}


def fail(message: str) -> None:
    print(f"backup_restore_verification=failed reason={message}", file=sys.stderr)
    raise SystemExit(1)


def safe_member_path(name: str) -> PurePosixPath:
    raw = name.removeprefix("/")
    parts = raw.split("/")
    while parts and parts[-1] == "":
        parts.pop()
    if not parts or any(part in {"", ".", ".."} for part in parts):
        fail("unsafe_archive_path")
    return PurePosixPath(*parts)


def safe_link_target(member_path: PurePosixPath, linkname: str) -> None:
    target = PurePosixPath(linkname)
    if target.is_absolute() or not target.parts:
        fail("unsafe_archive_link")
    resolved = list(member_path.parent.parts)
    for part in target.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                fail("unsafe_archive_link")
            resolved.pop()
        else:
            resolved.append(part)
    if not resolved or resolved[0] != "backup":
        fail("unsafe_archive_link")


def path_matches(observed: str, expected: str) -> bool:
    return observed == expected or (expected.endswith("/") and observed.startswith(expected))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--restore-root", required=True, type=Path)
    parser.add_argument("--expected-db-uid", type=int, default=0)
    parser.add_argument("--expected-db-gid", type=int, default=0)
    parser.add_argument("--expected-db-mode", default="0644")
    args = parser.parse_args()

    restore_root = args.restore_root.expanduser().resolve()
    if restore_root.exists():
        fail("restore_root_already_exists")
    restore_root.mkdir(parents=True, mode=0o700)

    expected_mode = int(args.expected_db_mode, 8)
    extraction_paths: dict[str, tuple[DatabaseSpec, str]] = {}
    for spec in DATABASES:
        extraction_paths[spec.archive_path] = (spec, Path(spec.archive_path).name)
        extraction_paths[f"{spec.archive_path}-wal"] = (spec, f"{Path(spec.archive_path).name}-wal")
        extraction_paths[f"{spec.archive_path}-shm"] = (spec, f"{Path(spec.archive_path).name}-shm")

    restored: dict[str, dict[str, Path]] = {spec.label: {} for spec in DATABASES}
    vaultwarden_metadata: dict[str, int] | None = None
    required_counts = {label: [0 for _ in expected] for label, expected in REQUIRED_PATHS.items()}
    forbidden_counts = {label: 0 for label in FORBIDDEN_PATHS}
    member_count = 0
    regular_file_count = 0
    total_uncompressed_bytes = 0
    path_stream_hash = hashlib.sha256()
    seen_regular_paths: set[str] = set()

    try:
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|gz") as archive:
            for member in archive:
                member_count += 1
                member_path = safe_member_path(member.name)
                normalized = member_path.as_posix()
                encoded = normalized.encode()
                path_stream_hash.update(len(encoded).to_bytes(8, "big"))
                path_stream_hash.update(encoded)

                if member.issym():
                    safe_link_target(member_path, member.linkname)
                elif member.islnk() or member.isdev() or member.isfifo():
                    fail("unsafe_archive_member_type")

                if member.isfile():
                    if normalized in seen_regular_paths:
                        fail("duplicate_regular_file_path")
                    seen_regular_paths.add(normalized)
                    regular_file_count += 1
                    total_uncompressed_bytes += member.size

                for label, expected_paths in REQUIRED_PATHS.items():
                    for index, expected in enumerate(expected_paths):
                        if path_matches(normalized, expected):
                            required_counts[label][index] += 1
                if not member.isdir():
                    for label, pattern in FORBIDDEN_PATHS.items():
                        if pattern.search(normalized):
                            forbidden_counts[label] += 1

                extraction = extraction_paths.get(normalized)
                if extraction is None or not member.isfile():
                    continue
                spec, filename = extraction
                if filename in restored[spec.label]:
                    fail("duplicate_sqlite_member")
                source = archive.extractfile(member)
                if source is None:
                    fail("unreadable_sqlite_member")
                destination_dir = restore_root / spec.label
                destination_dir.mkdir(mode=0o700, exist_ok=True)
                destination = destination_dir / filename
                with destination.open("xb") as output:
                    shutil.copyfileobj(source, output)
                destination.chmod(0o600)
                restored[spec.label][filename] = destination
                if normalized == "backup/vaultwarden-data/db.sqlite3":
                    vaultwarden_metadata = {
                        "uid": member.uid,
                        "gid": member.gid,
                        "mode": member.mode & 0o7777,
                        "bytes": member.size,
                    }
    except (tarfile.TarError, EOFError, OSError):
        fail("archive_integrity_error")

    missing_labels = [
        label for label, counts in required_counts.items() if any(count == 0 for count in counts)
    ]
    if missing_labels:
        fail("required_state_class_missing")
    forbidden_labels = sorted(
        label for label, count in forbidden_counts.items() if count > 0
    )
    if forbidden_labels:
        fail(f"excluded_state_class_present_{'-'.join(forbidden_labels)}")
    if vaultwarden_metadata is None:
        fail("vaultwarden_database_missing")
    if vaultwarden_metadata["uid"] != args.expected_db_uid:
        fail("vaultwarden_database_uid_mismatch")
    if vaultwarden_metadata["gid"] != args.expected_db_gid:
        fail("vaultwarden_database_gid_mismatch")
    if vaultwarden_metadata["mode"] != expected_mode:
        fail("vaultwarden_database_mode_mismatch")

    database_evidence: dict[str, dict[str, object]] = {}
    for spec in DATABASES:
        database = restored[spec.label].get(Path(spec.archive_path).name)
        if database is None:
            fail("sqlite_database_missing")
        try:
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
            connection.close()
        except sqlite3.DatabaseError:
            fail("sqlite_database_unreadable")
        if integrity_rows != [("ok",)]:
            fail("sqlite_integrity_error")
        database_evidence[spec.label] = {
            "bytes": database.stat().st_size,
            "sha256": sha256_file(database),
            "sqlite_integrity": "pass",
            "restored_sidecars": sorted(
                name for name in restored[spec.label] if name != database.name
            ),
        }

    print(
        json.dumps(
            {
                "archive_integrity": "pass",
                "safe_paths": "pass",
                "member_count": member_count,
                "regular_file_count": regular_file_count,
                "total_uncompressed_bytes": total_uncompressed_bytes,
                "member_path_stream_sha256": path_stream_hash.hexdigest(),
                "required_state_classes": {
                    label: {"status": "present", "matched_paths": sum(counts)}
                    for label, counts in sorted(required_counts.items())
                },
                "excluded_state_classes": {
                    label: {"status": "absent", "matched_paths": count}
                    for label, count in sorted(forbidden_counts.items())
                },
                "sqlite_databases": database_evidence,
                "vaultwarden_archive_metadata": {
                    "uid": vaultwarden_metadata["uid"],
                    "gid": vaultwarden_metadata["gid"],
                    "mode": f"{vaultwarden_metadata['mode']:04o}",
                    "bytes": vaultwarden_metadata["bytes"],
                },
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
