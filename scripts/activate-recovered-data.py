#!/usr/bin/env python3
"""Activate verified staged backup data only into fresh Compose volumes and binds."""

from argparse import ArgumentParser
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def fail(reason: str) -> None:
    print(f"recovery_activation=failed reason={reason}", file=sys.stderr)
    raise SystemExit(1)


def docker_json(arguments: list[str]) -> object:
    try:
        result = subprocess.run(
            ["docker", *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return json.loads(result.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        fail("docker_inspection_error")


def dotenv_paths(path: Path) -> dict[str, Path]:
    values: dict[str, Path] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line.lstrip().startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key == "GAMES_PATH":
            candidate = Path(value)
            if not candidate.is_absolute():
                fail("bind_path_not_absolute")
            values[key] = candidate
    if set(values) != {"GAMES_PATH"}:
        fail("required_bind_path_missing")
    if values["GAMES_PATH"] != Path("/mnt/games"):
        fail("games_path_outside_contract")
    return values


def require_empty(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if any(path.iterdir()):
        fail("bind_target_not_empty")


def clear_new_volume(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def copy_tree(source: Path, destination: Path) -> int:
    if not source.is_dir():
        fail("archive_source_missing")
    destination.mkdir(parents=True, exist_ok=True)
    copied = 0
    for source_path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        relative = source_path.relative_to(source)
        target_path = destination / relative
        stat = source_path.lstat()
        if source_path.is_symlink():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.symlink_to(os.readlink(source_path))
        elif source_path.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
        elif source_path.is_file():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, target_path, follow_symlinks=False)
            copied += 1
        else:
            fail("unsupported_staged_file")
        os.chown(target_path, stat.st_uid, stat.st_gid, follow_symlinks=False)
        if not source_path.is_symlink():
            os.chmod(target_path, stat.st_mode & 0o7777, follow_symlinks=False)
    source_stat = source.lstat()
    os.chown(destination, source_stat.st_uid, source_stat.st_gid)
    os.chmod(destination, source_stat.st_mode & 0o7777)
    return copied


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--staging-root", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--volume-inventory", required=True, type=Path)
    parser.add_argument("--project", default="docker-compose")
    parser.add_argument("--retain-existing-binds", action="store_true")
    parser.add_argument("--protected-external-data", required=True, type=Path)
    args = parser.parse_args()

    backup = args.staging_root.resolve(strict=True) / "backup"
    if not backup.is_dir():
        fail("backup_root_missing")
    paths = dotenv_paths(args.env_file.resolve(strict=True))
    protected_external_data = args.protected_external_data.resolve(strict=True)
    if protected_external_data != Path("/mnt/storage/media/nextcloud/data") or not protected_external_data.is_dir():
        fail("protected_external_data_identity")

    try:
        inventory = json.loads(args.volume_inventory.resolve(strict=True).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("volume_inventory_unreadable")
    records = inventory.get("volumes") if isinstance(inventory, dict) else None
    if not isinstance(inventory, dict) or inventory.get("schema") != 1 or inventory.get("project") != args.project or not isinstance(records, list):
        fail("volume_inventory_schema")

    expected_engine_names: set[str] = set()
    volumes: dict[str, Path] = {}
    for record in records:
        if not isinstance(record, dict):
            fail("volume_inventory_record")
        logical_name = record.get("logical_name")
        engine_name = record.get("engine_name")
        mountpoint = record.get("mountpoint")
        created_at = record.get("created_at")
        if (
            not isinstance(logical_name, str)
            or not isinstance(engine_name, str)
            or not isinstance(mountpoint, str)
            or not isinstance(created_at, str)
            or logical_name in volumes
            or engine_name in expected_engine_names
        ):
            fail("volume_inventory_identity")
        inspected = docker_json(["volume", "inspect", engine_name])
        if not isinstance(inspected, list) or len(inspected) != 1:
            fail("volume_inventory_inspection")
        current = inspected[0]
        labels = current.get("Labels") or {}
        if (
            current.get("Name") != engine_name
            or current.get("Mountpoint") != mountpoint
            or current.get("CreatedAt") != created_at
            or labels.get("com.docker.compose.project") != args.project
            or labels.get("com.docker.compose.volume") != logical_name
        ):
            fail("volume_inventory_changed")
        expected_engine_names.add(engine_name)
        volumes[logical_name] = Path(mountpoint)

    try:
        labeled_names = set(
            subprocess.run(
                [
                    "docker",
                    "volume",
                    "ls",
                    "--quiet",
                    "--filter",
                    f"label=com.docker.compose.project={args.project}",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            ).stdout.splitlines()
        )
    except subprocess.SubprocessError:
        fail("volume_inventory_error")
    if labeled_names != expected_engine_names:
        fail("unexpected_project_volume")
    if not volumes:
        fail("recovery_volumes_missing")

    copied_files = 0
    retained_binds = 0
    activated_sources: set[str] = set()
    for logical_name, destination in volumes.items():
        source = backup / logical_name
        if not source.exists():
            continue
        clear_new_volume(destination)
        copied_files += copy_tree(source, destination)
        activated_sources.add(logical_name)

    bind_mappings = {
        "hass-data": Path("/srv/home-lab-state/hass-data"),
        "nextcloud-config": Path("/srv/home-lab-state/nextcloud-config"),
        "nextcloud-custom-apps": Path("/srv/home-lab-state/nextcloud-custom-apps"),
        "nextcloud-themes": Path("/srv/home-lab-state/nextcloud-themes"),
        "wolf/cfg": paths["GAMES_PATH"] / "wolf/cfg",
        "wolf/profile-data": paths["GAMES_PATH"] / "wolf/profile-data",
        ".ssh": Path("/home/docker/.ssh"),
    }
    for destination in bind_mappings.values():
        resolved_destination = destination.absolute()
        if resolved_destination == protected_external_data or protected_external_data.is_relative_to(resolved_destination):
            fail("external_data_parent_restore_forbidden")
    for archive_name, destination in bind_mappings.items():
        source = backup.joinpath(*archive_name.split("/"))
        if destination.exists() and any(destination.iterdir()):
            if args.retain_existing_binds and archive_name in {"hass-data", "wolf/cfg", "wolf/profile-data"}:
                activated_sources.add(archive_name.split("/", 1)[0])
                retained_binds += 1
                continue
            fail("bind_target_not_empty")
        require_empty(destination)
        copied_files += copy_tree(source, destination)
        activated_sources.add(archive_name.split("/", 1)[0])

    allowed_top_level = set(volumes) | {"hass-data", "nextcloud-config", "nextcloud-custom-apps", "nextcloud-themes", "wolf", ".env", ".ssh"}
    observed_top_level = {path.name for path in backup.iterdir()}
    if observed_top_level - allowed_top_level:
        fail("unmodeled_archive_source")
    if not {
        "vaultwarden-data", "omada-data", "hass-data", "nextcloud-config",
        "nextcloud-custom-apps", "nextcloud-themes", "wolf", ".ssh"
    }.issubset(activated_sources):
        fail("critical_activation_missing")
    print(
        f"recovery_activation=verified files={copied_files} "
        f"volumes={len(volumes)} sources={len(activated_sources)} "
        f"retained_binds={retained_binds}"
    )


if __name__ == "__main__":
    main()
