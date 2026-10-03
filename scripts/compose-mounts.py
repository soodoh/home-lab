#!/usr/bin/env python3
"""Project live managed bind mounts to inode/metadata identities, never contents.

Compose hashes its model, not bind-mounted files. Native rsync and Ansible copy
preserve unchanged files and replace changed ones; this observation identifies
only the additional consumers needing recreation. Mutable app state is excluded.
"""
from __future__ import annotations

import argparse
import json
import stat
import subprocess
import sys
from pathlib import Path


def identity(path: Path) -> list:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return ["missing"]
    if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
        raise ValueError("managed_mount_type")
    value = [metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid,
             metadata.st_size if path.is_file() else 0]
    if path.is_dir():
        value.append({child.name: identity(child) for child in sorted(path.iterdir())})
    return value


def observe_mounts(services: dict, source_root: Path, credentials_root: Path) -> dict:
    observed = {}
    for service, mounts in services.items():
        observed[service] = {}
        for mount in mounts:
            if mount["Type"] != "bind":
                continue
            source = Path(mount["Source"])
            if not source.is_absolute() or ".." in source.parts:
                raise ValueError("mount_source")
            roots = (source_root, credentials_root)
            if not any(source == root or root in source.parents for root in roots):
                continue
            if mount["RW"]:
                raise ValueError("managed_mount_writable")
            # Refuse parent symlinks too: don't follow managed paths into app state.
            root = next(root for root in roots if source == root or root in source.parents)
            for parent in [source, *source.parents]:
                if parent.is_symlink():
                    raise ValueError("managed_mount_symlink")
                if parent == root:
                    break
            observed[service][str(source)] = identity(source)
    return observed


def run(arguments: list[str]) -> str:
    return subprocess.run(arguments, capture_output=True, text=True, check=True, timeout=60).stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--credentials-root", type=Path, required=True)
    arguments = parser.parse_args()
    ids = run(["/usr/bin/docker", "ps", "--all", "--quiet", "--filter",
               f"label=com.docker.compose.project={arguments.project}", "--filter",
               "label=com.docker.compose.oneoff=False"]).splitlines()
    if not ids:
        raise ValueError("project_missing")
    # Inspect only mounts and service name, never Config.Env or other private fields.
    template = '{{json .Mounts}} {{index .Config.Labels "com.docker.compose.service"}}'
    services = {}
    for line in run(["/usr/bin/docker", "inspect", "--format", template, *ids]).splitlines():
        raw, service = line.rsplit(" ", 1)
        if not service or service in services:
            raise ValueError("service_identity")
        services[service] = json.loads(raw)
    print(json.dumps(observe_mounts(services, arguments.source_root, arguments.credentials_root), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("compose_mount_observation=failed", file=sys.stderr)
        raise SystemExit(1)
