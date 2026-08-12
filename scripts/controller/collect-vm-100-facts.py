#!/usr/bin/env python3
"""Collect a secret-free, read-only VM 100 production fact document."""

from __future__ import annotations

from argparse import ArgumentParser
import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

FORMAT = "home-lab-vm-100-facts-v1"
AGE_RECIPIENT = re.compile(r"^age1[0-9a-z]+$")
LEGACY_VOLUMES = {"happier-data", "nzbget-data", "nzbhydra2-data"}
APPLICATIONS = ("authentik", "sonarr", "radarr", "radarr-4k", "prowlarr")
ROOTS = (
    ("docker-volumes", "/var/lib/docker/volumes", "copy", True),
    ("home-assistant", "/home/docker/hass", "copy", True),
    ("compose-deployment", "/srv/docker-compose", "regenerate", False),
    ("compose-runtime-inputs", "/etc/docker-compose", "regenerate", False),
    ("compose-controller-state", "/var/lib/docker-compose", "regenerate", False),
    ("home-backups", "/home/docker/backups", "pending", True),
    ("games-backups", "/mnt/games/backups", "pending", True),
    ("storage-backups", "/mnt/storage/backups", "pending", True),
    ("media", "/mnt/storage/media", "reuse", False),
    ("games", "/mnt/games", "reuse", False),
    ("wolf", "/mnt/games/wolf", "reuse", True),
)


def run(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()


def findmnt(path: str) -> dict[str, object]:
    value = json.loads(run(["/usr/bin/findmnt", "--json", "--target", path, "--output", "ID,SOURCE,FSTYPE,OPTIONS"]))
    filesystems = value.get("filesystems")
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise SystemExit(f"expected one mount for {path}")
    return filesystems[0]


def ext4_features(source: str) -> list[str]:
    if not source.startswith("/dev/"):
        raise SystemExit(f"ext4 source is not a block-device path: {source}")
    result = subprocess.run(["/usr/bin/tune2fs", "-l", source], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"unable to inspect ext4 features for {source}")
    for line in result.stdout.splitlines():
        if line.startswith("Filesystem features:"):
            features = sorted(line.split(":", 1)[1].split())
            if features:
                return features
    raise SystemExit(f"ext4 feature list is unavailable for {source}")


def root_fact(item: tuple[str, str, str, bool]) -> dict[str, object]:
    classification, path, disposition, measure_size = item
    path_stat = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(path_stat.st_mode):
        raise SystemExit(f"mutable root is not a directory: {path}")
    mount = findmnt(path)
    filesystem_stat = os.statvfs(path)
    source = str(mount["source"])
    size_bytes = None
    if measure_size:
        size_bytes = int(run(["/usr/bin/du", "-sx", "-B1", path]).split()[0])
    multiply_linked_file_count = None
    if disposition == "copy":
        multiply_linked_output = run([
            "/usr/bin/find", path, "-xdev", "-type", "f", "-links", "+1", "-printf", ".\n",
        ])
        multiply_linked_file_count = len(multiply_linked_output.splitlines()) if multiply_linked_output else 0
    return {
        "bytesAvailable": filesystem_stat.f_frsize * filesystem_stat.f_bavail,
        "bytesTotal": filesystem_stat.f_frsize * filesystem_stat.f_blocks,
        "class": classification,
        "disposition": disposition,
        "exists": True,
        "filesystem": mount["fstype"],
        "filesystemFeatures": ext4_features(source) if mount["fstype"] == "ext4" else [],
        "multiplyLinkedFileCount": multiply_linked_file_count,
        "gid": path_stat.st_gid,
        "mode": format(stat.S_IMODE(path_stat.st_mode), "04o"),
        "mountId": int(mount["id"]),
        "mountOptions": sorted(set(str(mount["options"]).split(","))),
        "path": path,
        "sizeBytes": size_bytes,
        "source": source,
        "uid": path_stat.st_uid,
    }


def docker_facts() -> dict[str, object]:
    info = json.loads(run(["/usr/bin/docker", "info", "--format", "{{json .}}"] ))
    volumes = []
    names = run(["/usr/bin/docker", "volume", "ls", "--filter", "label=com.docker.compose.project=docker-compose", "--format", "{{.Name}}"] ).splitlines()
    for name in sorted(names):
        inspected = json.loads(run(["/usr/bin/docker", "volume", "inspect", name]))[0]
        labels = inspected.get("Labels") or {}
        logical_name = labels.get("com.docker.compose.volume")
        expected_name = f"docker-compose_{logical_name}"
        if name != expected_name:
            raise SystemExit(f"volume engine name differs from Compose identity: {name}")
        volumes.append({
            "driver": inspected["Driver"],
            "engineName": name,
            "legacy": logical_name in LEGACY_VOLUMES,
            "logicalName": logical_name,
            "mountpoint": inspected["Mountpoint"],
        })
    backing = next((value for key, value in info.get("DriverStatus", []) if key == "Backing Filesystem"), "unknown")
    return {
        "backingFilesystem": backing,
        "declaredVolumeCount": 30,
        "legacyVolumeCount": len(LEGACY_VOLUMES),
        "observedProjectVolumeCount": len(volumes),
        "projectName": "docker-compose",
        "rootDir": info["DockerRootDir"],
        "storageDriver": info["Driver"],
        "volumes": volumes,
    }


def sops_facts() -> dict[str, object]:
    identity = Path("/etc/sops/age/keys.txt")
    identity_stat = identity.stat()
    recipient = run(["/usr/local/bin/age-keygen", "-y", str(identity)])
    if AGE_RECIPIENT.fullmatch(recipient) is None:
        raise SystemExit("age recipient is invalid")
    return {
        "identityGroup": run(["/usr/bin/id", "-gn", str(identity_stat.st_gid)]),
        "identityMode": format(stat.S_IMODE(identity_stat.st_mode), "04o"),
        "identityOwner": run(["/usr/bin/id", "-un", str(identity_stat.st_uid)]),
        "identityPath": str(identity),
        "independentRecoveryRecipient": False,
        "nixosRecipientStatus": "pending",
        "recipient": recipient,
        "roles": ["arch-runtime-decrypt", "externally-escrowed-recovery"],
    }


def identity_facts() -> dict[str, object]:
    fields = run(["/usr/bin/getent", "passwd", "docker"]).split(":")
    if len(fields) != 7:
        raise SystemExit("docker passwd record is invalid")
    groups = sorted(set(run(["/usr/bin/id", "-Gn", "docker"]).split()))
    return {
        "gid": int(fields[3]),
        "home": fields[5],
        "primaryGroup": run(["/usr/bin/id", "-gn", "docker"]),
        "shell": fields[6],
        "supplementaryGroups": groups,
        "uid": int(fields[2]),
        "user": fields[0],
    }


def parse_args() -> object:
    parser = ArgumentParser()
    parser.add_argument("--commit", required=True, type=str)
    parser.add_argument("--captured-at", type=str)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.commit) is None:
        raise SystemExit("commit must be a full Git object ID")
    captured_at = args.captured_at or datetime.datetime.now(datetime.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    facts = {
        "applications": [{"importIdentifiers": [], "inventoryStatus": "pending", "name": name} for name in APPLICATIONS],
        "authority": {"deploymentAuthority": "arch", "hostName": "archlinux", "networkIdentity": "docker-host", "vmid": 100},
        "capturedAt": captured_at,
        "controllerCommit": args.commit,
        "docker": docker_facts(),
        "findings": [
            {"code": "application-import-identifiers-pending", "message": "Application API inventory and import identifiers remain uncollected.", "severity": "blocker"},
            {"code": "independent-recovery-recipient-pending", "message": "The current runtime identity is externally escrowed, but no independent recovery age recipient exists.", "severity": "blocker"},
            {"code": "nixos-recipient-pending", "message": "A separate NixOS runtime recipient has not been generated or added to ciphertext.", "severity": "blocker"},
        ],
        "format": FORMAT,
        "identity": identity_facts(),
        "mutableRoots": [root_fact(item) for item in ROOTS],
        "sops": sops_facts(),
    }
    json.dump(facts, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
