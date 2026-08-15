#!/usr/bin/env python3
"""Shared fail-closed policy for the VM 100 Gate C data manifest."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any

FORMAT = "home-lab-vm-100-gate-c-manifest-v1"
COLLECTION_FORMAT = "home-lab-vm-100-gate-c-collection-v1"
CANDIDATE_INVENTORY_FORMAT = "home-lab-vm-100-candidate-volume-inventory-v1"
PROJECT = "docker-compose"
DOCKER_ROOT = "/var/lib/docker"
DESTINATION_ROOT = "/mnt/vm-100-candidate"
ISOLATED_DOCKER_HOST = "unix:///run/vm-100-candidate-docker/docker.sock"
ISOLATED_DOCKER_ROOT = f"{DESTINATION_ROOT}{DOCKER_ROOT}"
ISOLATED_DOCKER_EXEC_ROOT = "/run/vm-100-candidate-docker/exec"
ISOLATED_DOCKER_PIDFILE = "/run/vm-100-candidate-docker/docker.pid"
ISOLATED_DOCKER_ARGV = (
    "/usr/bin/dockerd", f"--host={ISOLATED_DOCKER_HOST}",
    f"--data-root={ISOLATED_DOCKER_ROOT}", f"--exec-root={ISOLATED_DOCKER_EXEC_ROOT}",
    f"--pidfile={ISOLATED_DOCKER_PIDFILE}",
    "--containerd=/run/vm-100-candidate-docker/containerd/containerd.sock",
    "--containerd-namespace=vm100-candidate",
    "--containerd-plugins-namespace=vm100-candidate-plugins",
    "--bridge=none", "--iptables=false", "--ip6tables=false", "--ip-forward=false",
    "--ip-masq=false", "--userland-proxy=false", "--live-restore=false",
)
CANDIDATE_PROFILE = "/nix/var/nix/profiles/system"
CANDIDATE_BY_ID = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2"
CANDIDATE_SERIAL = "QUAL-NIXOS-128G"
DISK_BYTES = 137438953472
CANDIDATE_INVENTORY_MAX_AGE_SECONDS = 3600
CANONICAL_SERVICES = frozenset({
    "audiobookshelf", "authentik-server", "authentik-worker", "bookshelf", "caddy",
    "calibre", "calibre-web-automated", "caro-tachidesk", "daily-local-backup",
    "ddns-updater", "flaresolverr", "frigate", "gluetun", "homeassistant",
    "jellyfin", "karaoke-eternal", "litellm", "mosquitto", "nextcloud",
    "nextcloud-db", "nextcloud-redis", "omada", "openfit", "pihole", "postgres",
    "prowlarr", "qbittorrent", "radarr", "radarr-4k", "recyclarr", "redis",
    "sabnzbd", "seerr", "sonarr", "tachidesk", "unpackerr", "vaultwarden",
    "vikunja", "weekly-remote-backup", "wolf", "zwave",
})
CANONICAL_VOLUMES = frozenset({
    "audiobookshelf-data", "authentik-data", "bookshelf-data", "caddy-data",
    "calibre-data", "calibre-web-data", "caro-tachidesk-data", "ddns-updater-data",
    "frigate-data", "gluetun-data", "jellyfin-data", "karaoke-eternal-data",
    "litellm-data", "mosquitto-data", "nextcloud-db-data", "omada-data",
    "openfit-data", "pihole-data", "prowlarr-data", "qbittorrent-data",
    "radarr-4k-data", "radarr-data", "recyclarr-data", "sabnzbd-data",
    "seerr-data", "sonarr-data", "tachidesk-data", "vaultwarden-data",
    "vikunja-data", "zwave-data",
})
LEGACY_VOLUMES = frozenset({"happier-data", "nzbget-data", "nzbhydra2-data"})
SAFE_VOLUME_LABELS = frozenset({
    "com.docker.compose.project", "com.docker.compose.volume",
    "com.docker.compose.version", "com.docker.compose.config-hash",
})
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
SAFE_CONTAINER_ID = re.compile(r"^(?:[0-9a-f]{12}|[0-9a-f]{64})$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./:@+-]{0,1023}$")
SAFE_TEXT = re.compile(r"^[A-Za-z0-9_./:@+ -]{0,255}$")
TOPLEVEL = re.compile(r"^/nix/store/[0-9a-z]{32}-[A-Za-z0-9][A-Za-z0-9+._?-]{0,199}$")
GENERATION_LINK = re.compile(r"^system-[1-9][0-9]*-link$")
NFS_SOURCE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9.-]{0,252}|[0-9A-Fa-f:]+):/[A-Za-z0-9_./@+-]{0,1023}$")
ANONYMOUS_VOLUME = re.compile(r"^/var/lib/docker/volumes/[0-9a-f]{64}/_data$")
ANONYMOUS_VOLUME_ALLOWLIST = frozenset({
    ("calibre-web-automated", "/cwa-book-ingest", False),
    ("flaresolverr", "/config", False),
    ("nextcloud-redis", "/data", False),
    ("wolf", "/run/user/wolf", False),
})
RUNTIME_TMPFS_ALLOWLIST = frozenset({
    ("frigate", "/tmp/cache", False),
    ("jellyfin", "/cache/transcodes", False),
})

CLASSIFICATIONS = (
    ("games", "/mnt/games", "reuse", "Existing games filesystem is reattached and is not copied to the candidate disk."),
    ("storage", "/mnt/storage", "reuse", "Existing storage mount is reused and is not copied to the candidate disk."),
    ("compose-artifact", "/srv/docker-compose", "regenerate", "Compose artifact files are rebuilt from the commit-bound artifact."),
    ("production-environment", "/etc/docker-compose/production.env", "regenerate", "Protected production environment material is reprovisioned without reading it into Gate C evidence."),
    ("sops-identities", "/etc/sops/age/keys.txt", "regenerate", "SOPS identities are independently provisioned and their contents are excluded from Gate C."),
    ("root-ssh", "/root/.ssh", "excluded", "Root SSH credentials are outside the direct-data migration scope."),
    ("runtime-state", "/run", "excluded", "Sockets and PID files are ephemeral runtime state."),
    ("device-tree", "/dev", "reuse", "Explicit Compose device-tree bind access is re-established from the NixOS host device namespace."),
    ("localtime", "/etc/localtime", "regenerate", "The host localtime link is regenerated by NixOS and explicitly rebound where declared."),
    ("zoneinfo", "/usr/share/zoneinfo", "regenerate", "The NixOS timezone database is regenerated and explicitly rebound where declared."),
    ("dbus-runtime", "/run/dbus", "excluded", "The host D-Bus runtime socket is ephemeral and only rebound where explicitly declared."),
    ("udev-runtime", "/run/udev", "excluded", "The host udev runtime database is ephemeral and only rebound where explicitly declared."),
    ("docker-socket", "/var/run/docker.sock", "excluded", "The Docker control socket is ephemeral and only rebound where explicitly declared."),
    ("docker-root-wholesale", "/var/lib/docker", "excluded", "The Docker data root is never copied wholesale; only approved named-volume data roots are copied."),
    ("anonymous-runtime-volumes", "/var/lib/docker/volumes", "regenerate", "Only the four exact allowlisted image-created anonymous runtime volumes are regenerated; they are never copied."),
    ("docker-images", "/var/lib/docker/image", "regenerate", "Docker image metadata is regenerated by pulling commit-bound images."),
    ("docker-overlay", "/var/lib/docker/overlay2", "regenerate", "Docker overlay layers are regenerated and are never copied as direct data."),
    ("docker-build-cache", "/var/lib/docker/buildkit", "regenerate", "Docker build cache is regenerated and is never copied as direct data."),
    ("home-backups", "/home/docker/backups", "excluded", "Encrypted backups remain excluded from recursive migration copy."),
    ("home-docker-ssh", "/home/docker/.ssh", "excluded", "Docker-user SSH credentials are outside the direct-data migration scope."),
    ("games-backups", "/mnt/games/backups", "excluded", "Encrypted games backups remain on the reused games filesystem."),
    ("storage-backups", "/mnt/storage/backups", "excluded", "Encrypted storage backups remain on the reused storage filesystem."),
)
BACKUP_PATHS = ("/home/docker/backups", "/mnt/games/backups", "/mnt/storage/backups")


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def parse_time(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ValueError(f"{label} timestamp is invalid")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError as error:
        raise ValueError(f"{label} timestamp is invalid") from error
    return parsed


def validate_freshness(collected_at: object, now: str, max_age_seconds: int, label: str = "collection") -> None:
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds < 1:
        raise ValueError("freshness maximum age is invalid")
    collected = parse_time(collected_at, label)
    current = parse_time(now, "current")
    age = (current - collected).total_seconds()
    if age < 0 or age > max_age_seconds:
        raise ValueError(f"{label} is stale or from the future")


def _safe_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not SAFE_PATH.fullmatch(value) or "//" in value or "/../" in value or value.endswith("/.."):
        raise ValueError(f"{label} is not a conservative absolute path")
    return value


def _safe_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not SAFE_NAME.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def project_desired_inventory(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("kind") != "desired" or raw.get("project_name") != PROJECT:
        raise ValueError("desired inventory kind or project differs")
    names = raw.get("volumes")
    if not isinstance(names, list) or any(not isinstance(name, str) for name in names) or set(names) != CANONICAL_VOLUMES or len(names) != 30:
        raise ValueError("desired inventory differs from the checked canonical 30-volume set")
    if raw.get("volume_count") != 30:
        raise ValueError("desired inventory volume count differs")
    services = raw.get("services")
    if not isinstance(services, dict) or set(services) != CANONICAL_SERVICES or raw.get("service_count") != 41:
        raise ValueError("desired inventory differs from the checked canonical 41-service set")
    service_mounts: list[dict[str, Any]] = []
    for service, detail in sorted(services.items()):
        _safe_name(service, "desired service")
        if not isinstance(detail, dict) or not isinstance(detail.get("binds"), list) or not isinstance(detail.get("volumes"), list):
            raise ValueError(f"desired mount inventory is incomplete for {service}")
        binds = []
        for mount in detail["binds"]:
            if not isinstance(mount, dict) or set(mount) != {"source", "target", "read_only"} or not isinstance(mount["read_only"], bool):
                raise ValueError(f"desired bind metadata is invalid for {service}")
            binds.append({"source": _safe_path(mount["source"], "desired bind source"), "target": _safe_path(mount["target"], "desired bind target"), "readOnly": mount["read_only"]})
        volumes = []
        for mount in detail["volumes"]:
            if not isinstance(mount, dict) or set(mount) != {"source", "target", "read_only"} or not isinstance(mount["read_only"], bool):
                raise ValueError(f"desired volume metadata is invalid for {service}")
            source = _safe_name(mount["source"], "desired logical volume")
            if source not in CANONICAL_VOLUMES:
                raise ValueError(f"desired service references undeclared volume {source}")
            volumes.append({"source": source, "target": _safe_path(mount["target"], "desired volume target"), "readOnly": mount["read_only"]})
        service_mounts.append({"service": service, "binds": sorted(binds, key=lambda x: canonical_bytes(x)), "volumes": sorted(volumes, key=lambda x: canonical_bytes(x))})
    return {"kind": "desired", "projectName": PROJECT, "volumeCount": 30, "volumes": sorted(CANONICAL_VOLUMES), "serviceMounts": service_mounts}


def desired_volume_names(desired: dict[str, Any]) -> list[str]:
    if set(desired) != {"kind", "projectName", "volumeCount", "volumes", "serviceMounts"} or desired.get("kind") != "desired" or desired.get("projectName") != PROJECT:
        raise ValueError("projected desired inventory envelope differs")
    names = desired.get("volumes")
    if desired.get("volumeCount") != 30 or not isinstance(names, list) or names != sorted(CANONICAL_VOLUMES):
        raise ValueError("projected desired inventory differs from the canonical set")
    # Re-validate the recursive shape without accepting unknown embedded fields.
    service_mounts = desired.get("serviceMounts")
    if not isinstance(service_mounts, list) or len(service_mounts) != 41:
        raise ValueError("projected desired inventory must contain exactly 41 services")
    service_names: set[str] = set()
    for service in service_mounts:
        if not isinstance(service, dict) or set(service) != {"service", "binds", "volumes"}:
            raise ValueError("projected desired service mount has unknown fields")
        service_name = _safe_name(service["service"], "desired service")
        if service_name in service_names:
            raise ValueError("projected desired inventory contains a duplicate service")
        service_names.add(service_name)
        for kind in ("binds", "volumes"):
            if not isinstance(service[kind], list):
                raise ValueError("projected desired mount list is invalid")
            for mount in service[kind]:
                if not isinstance(mount, dict) or set(mount) != {"source", "target", "readOnly"} or not isinstance(mount["readOnly"], bool):
                    raise ValueError("projected desired mount has unknown fields")
                _safe_path(mount["target"], "desired mount target")
                if kind == "binds": _safe_path(mount["source"], "desired bind source")
                elif _safe_name(mount["source"], "desired volume") not in CANONICAL_VOLUMES: raise ValueError("desired volume mount differs")
    if service_names != CANONICAL_SERVICES:
        raise ValueError("projected desired inventory differs from the checked canonical 41-service set")
    return list(names)


def expected_volume_names(desired: dict[str, Any]) -> list[str]:
    return sorted(set(desired_volume_names(desired)) | LEGACY_VOLUMES)


def project_runtime_inventory(raw: dict[str, Any], expected: list[str]) -> dict[str, Any]:
    if raw.get("kind") != "runtime" or raw.get("project_name") != PROJECT:
        raise ValueError("runtime inventory kind or project differs")
    values = raw.get("project_volumes")
    engines = sorted(f"{PROJECT}_{name}" for name in expected)
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values) or sorted(values) != engines or raw.get("project_volume_count") != 33:
        raise ValueError("runtime project-volume set differs from declared plus retained legacy volumes")
    return {"kind": "runtime", "projectName": PROJECT, "projectVolumeCount": 33, "projectVolumes": engines}


def validate_runtime_inventory(runtime: dict[str, Any], expected: list[str]) -> None:
    if set(runtime) != {"kind", "projectName", "projectVolumeCount", "projectVolumes"} or runtime.get("kind") != "runtime" or runtime.get("projectName") != PROJECT:
        raise ValueError("projected runtime inventory envelope differs")
    engines = sorted(f"{PROJECT}_{name}" for name in expected)
    if runtime.get("projectVolumeCount") != 33 or runtime.get("projectVolumes") != engines:
        raise ValueError("runtime project-volume set differs")


def volume_source(engine_name: str) -> str:
    return f"{DOCKER_ROOT}/volumes/{engine_name}/_data"


def volume_destination(engine_name: str) -> str:
    return f"{ISOLATED_DOCKER_ROOT}/volumes/{engine_name}/_data"


def host_destination() -> str:
    return f"{DESTINATION_ROOT}/home/docker/hass"


def write_argv(source: str, destination: str) -> list[str]:
    return ["rsync", "-aHAXSx", "--numeric-ids", "--delete", "--delete-delay", "--itemize-changes", "--", f"{source}/", f"{destination}/."]


def checksum_argv(source: str, destination: str) -> list[str]:
    return ["rsync", "-aHAXSx", "--numeric-ids", "--delete", "--delete-delay", "--dry-run", "--checksum", "--itemize-changes", "--", f"{source}/", f"{destination}/."]


def _contained(child: str, parent: str, *, allow_equal: bool = True) -> bool:
    child_path, parent_path = PurePosixPath(child), PurePosixPath(parent)
    if not child_path.is_absolute() or not parent_path.is_absolute() or ".." in child_path.parts or ".." in parent_path.parts:
        return False
    if child_path == parent_path:
        return allow_equal
    return parent_path in child_path.parents


def _validate_mount(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"device", "filesystem", "mountTarget", "mountId"}:
        raise ValueError(f"{label} mount identity is incomplete")
    filesystem = _safe_name(value["filesystem"], f"{label} filesystem")
    device = value["device"]
    if filesystem in {"nfs", "nfs4"}:
        if not isinstance(device, str) or not NFS_SOURCE.fullmatch(device) or "//" in device or "/../" in device or device.endswith("/.."):
            raise ValueError(f"{label} NFS mount source is invalid")
    elif not isinstance(device, str) or not device.startswith("/dev/"):
        raise ValueError(f"{label} mount device is not an absolute /dev path")
    else:
        _safe_path(device, f"{label} mount device")
    _safe_path(value["mountTarget"], f"{label} mount target")
    if not isinstance(value["mountId"], int) or isinstance(value["mountId"], bool) or value["mountId"] < 1:
        raise ValueError(f"{label} mount ID is invalid")


def validate_candidate_inventory(value: dict[str, Any], desired: dict[str, Any], expected_toplevel: str | None = None) -> None:
    required = {"format", "collectedAt", "candidateDisk", "candidateMount", "isolatedDockerHost", "isolatedDockerRoot", "isolatedDockerDaemonArgv", "systemProfile", "canonicalProductionMigrationToplevel", "volumes"}
    if set(value) != required or value.get("format") != CANDIDATE_INVENTORY_FORMAT:
        raise ValueError("candidate qualification inventory envelope differs")
    parse_time(value["collectedAt"], "candidate qualification")
    disk = value.get("candidateDisk")
    if not isinstance(disk, dict) or set(disk) != {"wholeDiskById", "serial", "sizeBytes"} or disk != {"wholeDiskById": CANDIDATE_BY_ID, "serial": CANDIDATE_SERIAL, "sizeBytes": DISK_BYTES}:
        raise ValueError("candidate qualification disk identity differs")
    mount = value.get("candidateMount")
    if not isinstance(mount, dict) or set(mount) != {"device", "filesystem", "target", "deviceAncestry"}:
        raise ValueError("candidate qualification mount identity differs")
    ancestry = mount.get("deviceAncestry")
    if mount.get("target") != DESTINATION_ROOT or not isinstance(mount.get("device"), str) or not str(mount["device"]).startswith("/dev/") or str(mount["device"]).startswith("/dev/disk/by-id/") or not isinstance(mount.get("filesystem"), str) or mount.get("filesystem") in {"tmpfs", "devtmpfs", "overlay"}:
        raise ValueError("candidate qualification mount is not a concrete block filesystem")
    if not isinstance(ancestry, list) or len(ancestry) < 2 or len(ancestry) > 8 or len(set(ancestry)) != len(ancestry) or ancestry[-1] != mount["device"] or any(not isinstance(item, str) or not item.startswith("/dev/") for item in ancestry):
        raise ValueError("candidate qualification mount ancestry differs")
    if value.get("isolatedDockerHost") != ISOLATED_DOCKER_HOST or value.get("isolatedDockerRoot") != ISOLATED_DOCKER_ROOT:
        raise ValueError("candidate qualification isolated Docker identity differs")
    if value.get("isolatedDockerDaemonArgv") != list(ISOLATED_DOCKER_ARGV):
        raise ValueError("candidate qualification isolated Docker daemon argv differs")
    toplevel = value.get("canonicalProductionMigrationToplevel")
    if not isinstance(toplevel, str) or not TOPLEVEL.fullmatch(toplevel) or (expected_toplevel is not None and toplevel != expected_toplevel):
        raise ValueError("candidate qualification toplevel differs")
    profile = value.get("systemProfile")
    if not isinstance(profile, dict):
        raise ValueError("candidate qualification system profile differs")
    profile_link_text = profile.get("profileLinkText")
    expected_profile = {
        "guestProfilePath": CANDIDATE_PROFILE,
        "hostProfilePath": f"{DESTINATION_ROOT}{CANDIDATE_PROFILE}",
        "profileLinkText": profile_link_text,
        "guestGenerationLinkPath": f"{PurePosixPath(CANDIDATE_PROFILE).parent}/{profile_link_text}",
        "hostGenerationLinkPath": f"{DESTINATION_ROOT}{PurePosixPath(CANDIDATE_PROFILE).parent}/{profile_link_text}",
        "generationLinkText": toplevel,
        "hostToplevelPath": f"{DESTINATION_ROOT}{toplevel}",
    }
    if not isinstance(profile_link_text, str) or not GENERATION_LINK.fullmatch(profile_link_text) or profile != expected_profile:
        raise ValueError("candidate qualification system profile chain differs")
    expected = expected_volume_names(desired)
    volumes = value.get("volumes")
    if not isinstance(volumes, list) or len(volumes) != 33:
        raise ValueError("candidate qualification must contain exactly 33 volumes")
    by_logical: dict[str, dict[str, Any]] = {}
    for volume in volumes:
        keys = {"logicalName", "engineName", "driver", "options", "hostMountpoint", "guestMountpoint", "composeLabels", "createdAt"}
        if not isinstance(volume, dict) or set(volume) != keys:
            raise ValueError("candidate qualification volume has unknown fields")
        name = _safe_name(volume["logicalName"], "candidate logical volume")
        engine = f"{PROJECT}_{name}"
        labels = volume["composeLabels"]
        if name in by_logical or name not in expected or volume["engineName"] != engine or volume["driver"] != "local" or volume["options"] != {} or volume["hostMountpoint"] != volume_destination(engine) or volume["guestMountpoint"] != volume_source(engine):
            raise ValueError("candidate qualification volume identity differs")
        if not isinstance(labels, dict) or not set(labels).issubset(SAFE_VOLUME_LABELS) or any(not isinstance(k, str) or not isinstance(v, str) or not SAFE_TEXT.fullmatch(v) for k, v in labels.items()):
            raise ValueError("candidate qualification volume labels are unsafe")
        if labels.get("com.docker.compose.project") != PROJECT or labels.get("com.docker.compose.volume") != name:
            raise ValueError("candidate qualification Compose labels differ")
        parse_time(volume["createdAt"], "candidate volume creation")
        by_logical[name] = volume
    if sorted(by_logical) != expected:
        raise ValueError("candidate qualification volume set differs")


def _validate_operational(metadata: object, desired: dict[str, Any]) -> None:
    if not isinstance(metadata, dict) or set(metadata) != {"containers", "writers", "timers", "mounts"}:
        raise ValueError("operational metadata is incomplete")
    containers = metadata["containers"]
    desired_services = {item["service"] for item in desired["serviceMounts"]}
    if not isinstance(containers, list) or len(containers) != 41 or len(desired_services) != 41: raise ValueError("container metadata must cover exactly 41 desired services")
    known = set(); observed_services: set[str] = set(); observed_ids: set[str] = set(); observed_names: set[str] = set()
    for item in containers:
        if not isinstance(item, dict) or set(item) != {"id", "name", "service", "running"} or not SAFE_CONTAINER_ID.fullmatch(str(item["id"])) or not isinstance(item["running"], bool):
            raise ValueError("container metadata has unknown or invalid fields")
        name = _safe_name(item["name"], "container name"); service = _safe_name(item["service"], "service name")
        if service in observed_services or item["id"] in observed_ids or name in observed_names: raise ValueError("container metadata contains a duplicate service, ID, or name")
        observed_services.add(service); observed_ids.add(item["id"]); observed_names.add(name); known.add((name, service))
    if observed_services != desired_services: raise ValueError("container metadata has missing or extra desired services")
    for key in ("mounts", "writers"):
        values = metadata[key]
        if not isinstance(values, list): raise ValueError(f"{key} metadata is invalid")
        for item in values:
            required = {"container", "service", "kind", "source", "destination", "readOnly", "logicalName"}
            if not isinstance(item, dict) or set(item) != required or not isinstance(item["readOnly"], bool) or item["kind"] not in ("bind", "volume", "anonymous-volume", "runtime-tmpfs"):
                raise ValueError(f"{key} metadata has unknown fields")
            _safe_name(item["container"], "mount container"); _safe_name(item["service"], "mount service")
            _safe_path(item["destination"], "mount destination")
            if (item["container"], item["service"]) not in known: raise ValueError("mount references an unknown container")
            if item["kind"] == "anonymous-volume":
                _safe_path(item["source"], "mount source")
                if item["logicalName"] is not None or (item["service"], item["destination"], item["readOnly"]) not in ANONYMOUS_VOLUME_ALLOWLIST or not ANONYMOUS_VOLUME.fullmatch(item["source"]):
                    raise ValueError("anonymous volume mount is not exactly allowlisted")
            elif item["kind"] == "runtime-tmpfs":
                if item["source"] != "" or item["logicalName"] is not None or (item["service"], item["destination"], item["readOnly"]) not in RUNTIME_TMPFS_ALLOWLIST:
                    raise ValueError("runtime tmpfs mount is not exactly allowlisted")
            elif item["kind"] == "volume":
                _safe_path(item["source"], "mount source"); _safe_name(item["logicalName"], "mount logical volume")
            else:
                _safe_path(item["source"], "mount source")
                if item["logicalName"] is not None: raise ValueError("bind mount has a logical volume")
        if key == "writers" and values != [item for item in metadata["mounts"] if item["kind"] != "runtime-tmpfs" and not item["readOnly"] and any(c["name"] == item["container"] and c["running"] for c in containers)]:
            raise ValueError("writer evidence is incomplete")
    expected_mounts = []
    for service in desired["serviceMounts"]:
        for item in service["binds"]:
            expected_mounts.append((service["service"], "bind", item["source"], item["target"], item["readOnly"], None))
        for item in service["volumes"]:
            expected_mounts.append((service["service"], "volume", volume_source(f"{PROJECT}_{item['source']}"), item["target"], item["readOnly"], item["source"]))
    observed_mounts = [(item["service"], item["kind"], item["source"], item["destination"], item["readOnly"], item["logicalName"]) for item in metadata["mounts"] if item["kind"] not in {"anonymous-volume", "runtime-tmpfs"}]
    if sorted(expected_mounts) != sorted(observed_mounts): raise ValueError("container mount evidence does not exactly match projected desired mounts")
    observed_anonymous = {(item["service"], item["destination"], item["readOnly"]) for item in metadata["mounts"] if item["kind"] == "anonymous-volume"}
    if observed_anonymous != ANONYMOUS_VOLUME_ALLOWLIST or sum(item["kind"] == "anonymous-volume" for item in metadata["mounts"]) != 4:
        raise ValueError("operational metadata must contain the exact four anonymous runtime volumes")
    observed_tmpfs = {(item["service"], item["destination"], item["readOnly"]) for item in metadata["mounts"] if item["kind"] == "runtime-tmpfs"}
    if observed_tmpfs != RUNTIME_TMPFS_ALLOWLIST or sum(item["kind"] == "runtime-tmpfs" for item in metadata["mounts"]) != 2:
        raise ValueError("operational metadata must contain the exact two regenerated runtime tmpfs mounts")
    timers = metadata["timers"]
    if not isinstance(timers, list): raise ValueError("timer metadata is invalid")
    for timer in timers:
        if not isinstance(timer, dict) or set(timer) != {"unit", "activates"}:
            raise ValueError("timer metadata has unknown fields")
        _safe_name(timer["unit"], "timer unit"); _safe_name(timer["activates"], "timer activation unit")


def validate_collection(collection: dict[str, Any], desired: dict[str, Any], runtime: dict[str, Any], *, expected_desired_sha256: str | None = None, expected_candidate_sha256: str | None = None, expected_toplevel: str | None = None) -> list[dict[str, Any]]:
    expected = expected_volume_names(desired)
    validate_runtime_inventory(runtime, expected)
    required = {"format", "collectedAt", "desiredInventorySha256", "runtimeInventorySha256", "candidateInventorySha256", "sourceDockerRoot", "candidateQualification", "candidate", "copyEntries", "backupEvidence", "operationalMetadata"}
    if set(collection) != required or collection.get("format") != COLLECTION_FORMAT:
        raise ValueError("collection envelope is incomplete")
    parse_time(collection.get("collectedAt"), "collection")
    if collection.get("desiredInventorySha256") != digest(desired) or collection.get("runtimeInventorySha256") != digest(runtime):
        raise ValueError("collection inventory digest binding differs")
    if expected_desired_sha256 is not None and (not SHA256.fullmatch(expected_desired_sha256) or digest(desired) != expected_desired_sha256):
        raise ValueError("independently expected desired inventory digest differs")
    qualification = collection.get("candidateQualification")
    if not isinstance(qualification, dict): raise ValueError("candidate qualification is absent")
    validate_candidate_inventory(qualification, desired, expected_toplevel)
    if collection.get("candidateInventorySha256") != digest(qualification) or (expected_candidate_sha256 is not None and digest(qualification) != expected_candidate_sha256):
        raise ValueError("candidate qualification digest binding differs")
    qualification_age = (parse_time(collection["collectedAt"], "collection") - parse_time(qualification["collectedAt"], "candidate qualification")).total_seconds()
    if qualification_age < 0 or qualification_age > CANDIDATE_INVENTORY_MAX_AGE_SECONDS:
        raise ValueError("candidate qualification is stale or from the future")
    if collection.get("sourceDockerRoot") != DOCKER_ROOT: raise ValueError("Docker data root differs")
    candidate = collection.get("candidate")
    candidate_keys = {"wholeDiskById", "wholeDiskDevice", "deviceAncestry", "serial", "sizeBytes", "destinationRoot", "device", "filesystem", "mountTarget", "mountId", "capacityBytes", "availableBytes", "reserveBytes"}
    if not isinstance(candidate, dict) or set(candidate) != candidate_keys: raise ValueError("candidate disk metadata is incomplete")
    if candidate["wholeDiskById"] != CANDIDATE_BY_ID or candidate["serial"] != CANDIDATE_SERIAL or candidate["sizeBytes"] != DISK_BYTES or candidate["destinationRoot"] != DESTINATION_ROOT or candidate["mountTarget"] != DESTINATION_ROOT:
        raise ValueError("candidate exact public identity or destination binding differs")
    ancestry = candidate["deviceAncestry"]
    if not isinstance(ancestry, list) or len(ancestry) < 2 or len(ancestry) > 8 or any(not isinstance(item, str) or not item.startswith("/dev/") for item in ancestry) or len(set(ancestry)) != len(ancestry) or ancestry[0] != candidate["wholeDiskDevice"] or ancestry[-1] != candidate["device"] or candidate["wholeDiskDevice"] == candidate["device"]:
        raise ValueError("candidate destination device ancestry does not prove strict descent from the whole disk")
    _safe_path(candidate["wholeDiskDevice"], "candidate whole-disk device")
    _validate_mount({key: candidate[key] for key in ("device", "filesystem", "mountTarget", "mountId")}, "candidate")
    if candidate["filesystem"] in {"tmpfs", "devtmpfs", "overlay"} or not str(candidate["device"]).startswith("/dev/"):
        raise ValueError("candidate destination is not a block filesystem")
    for field in ("capacityBytes", "reserveBytes"):
        if not isinstance(candidate[field], int) or isinstance(candidate[field], bool) or candidate[field] < 1: raise ValueError(f"candidate {field} is invalid")
    if not isinstance(candidate["availableBytes"], int) or isinstance(candidate["availableBytes"], bool) or not 0 <= candidate["availableBytes"] <= candidate["capacityBytes"] or candidate["capacityBytes"] > DISK_BYTES or candidate["reserveBytes"] >= candidate["capacityBytes"]:
        raise ValueError("candidate capacity is invalid")

    entries = collection.get("copyEntries")
    if not isinstance(entries, list) or len(entries) != 34: raise ValueError("collection must contain exactly 34 copy roots")
    volume_entries = [e for e in entries if isinstance(e, dict) and e.get("kind") == "docker-volume"]
    host_entries = [e for e in entries if isinstance(e, dict) and e.get("kind") == "host-path"]
    if len(volume_entries) != 33 or len(host_entries) != 1: raise ValueError("copy-entry kind counts differ")
    by_logical = {e.get("logicalName"): e for e in volume_entries}
    if len(by_logical) != 33 or sorted(by_logical) != expected: raise ValueError("copy-entry logical volume set differs")
    qualified = {v["logicalName"]: v for v in qualification["volumes"]}
    entry_keys = {"kind", "logicalName", "engineName", "legacy", "source", "destination", "sourceMount", "destinationMount", "driver", "options", "composeLabels", "candidateCreatedAt", "uid", "gid", "mode", "allocatedBytes", "apparentBytes", "inodeCount", "permittedDeletionRoot", "disposition"}
    sources: list[str] = []; destinations: list[str] = []; total_apparent = 0
    for name in expected:
        entry = by_logical[name]; engine = f"{PROJECT}_{name}"; q = qualified[name]
        if entry.get("engineName") != engine or entry.get("source") != volume_source(engine) or entry.get("destination") != volume_destination(engine) or entry.get("legacy") != (name in LEGACY_VOLUMES): raise ValueError(f"volume path or engine binding differs for {name}")
        if entry.get("driver") != q["driver"] or entry.get("options") != q["options"] or entry.get("composeLabels") != q["composeLabels"] or entry.get("candidateCreatedAt") != q["createdAt"]: raise ValueError(f"candidate Docker identity differs for {name}")
    host = host_entries[0]
    if host.get("logicalName") is not None or host.get("engineName") is not None or host.get("legacy") is not False or host.get("source") != "/home/docker/hass" or host.get("destination") != host_destination() or host.get("driver") is not None or host.get("options") != {} or host.get("composeLabels") != {} or host.get("candidateCreatedAt") is not None:
        raise ValueError("required Home Assistant host-path entry differs")
    for entry in entries:
        if set(entry) != entry_keys: raise ValueError("copy-entry metadata is incomplete or has unknown fields")
        source = _safe_path(entry["source"], "copy source"); destination = _safe_path(entry["destination"], "copy destination")
        if not _contained(destination, DESTINATION_ROOT, allow_equal=False) or entry["permittedDeletionRoot"] != destination or not _contained(entry["permittedDeletionRoot"], DESTINATION_ROOT, allow_equal=False): raise ValueError("permitted deletion root differs or escapes destination")
        if _contained(source, destination) or _contained(destination, source): raise ValueError("source and destination overlap")
        if entry["disposition"] != "copy" or not re.fullmatch(r"[0-7]{4}", str(entry["mode"])): raise ValueError("copy disposition or mode is invalid")
        for field in ("uid", "gid", "allocatedBytes", "apparentBytes"):
            if not isinstance(entry[field], int) or isinstance(entry[field], bool) or entry[field] < 0: raise ValueError(f"copy-entry {field} is invalid")
        if not isinstance(entry["inodeCount"], int) or isinstance(entry["inodeCount"], bool) or entry["inodeCount"] < 1: raise ValueError("copy-entry inode count is invalid")
        _validate_mount(entry["sourceMount"], "source"); _validate_mount(entry["destinationMount"], "destination")
        if entry["destinationMount"] != {key: candidate[key] for key in ("device", "filesystem", "mountTarget", "mountId")}: raise ValueError("copy destination mount differs from candidate")
        sources.append(source); destinations.append(destination); total_apparent += entry["apparentBytes"]
    for roots, label in ((sources, "source"), (destinations, "destination")):
        if len(set(roots)) != len(roots): raise ValueError(f"duplicate {label} copy root")
        for index, root in enumerate(roots):
            for other in roots[index + 1:]:
                if _contained(root, other) or _contained(other, root): raise ValueError(f"nested {label} copy roots")
    if total_apparent > candidate["availableBytes"] - candidate["reserveBytes"]: raise ValueError("candidate free space minus reserve is insufficient")
    backups = collection.get("backupEvidence")
    if not isinstance(backups, dict) or set(backups) != {"maxAgeSeconds", "replicas"} or not isinstance(backups["maxAgeSeconds"], int) or backups["maxAgeSeconds"] < 1 or not isinstance(backups["replicas"], list) or len(backups["replicas"]) != 3:
        raise ValueError("backup freshness evidence is incomplete")
    backup_keys = {"path", "archiveName", "sidecarName", "sha256", "sizeBytes", "mtime", "mount"}
    identities = set(); equality = set()
    for replica, path in zip(backups["replicas"], BACKUP_PATHS):
        if not isinstance(replica, dict) or set(replica) != backup_keys or replica["path"] != path: raise ValueError("backup replica projection differs")
        if not re.fullmatch(r"daily-local-backup-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.tar\.gz\.gpg", str(replica["archiveName"])) or replica["sidecarName"] != f"{replica['archiveName']}.sha256" or not SHA256.fullmatch(str(replica["sha256"])) or not isinstance(replica["sizeBytes"], int) or replica["sizeBytes"] < 1: raise ValueError("backup archive identity is invalid")
        mtime = parse_time(replica["mtime"], "backup")
        collected = parse_time(collection["collectedAt"], "collection")
        if not 0 <= (collected - mtime).total_seconds() <= backups["maxAgeSeconds"]: raise ValueError("backup archive is stale or from the future")
        backup_mount = replica["mount"]
        if not isinstance(backup_mount, dict) or set(backup_mount) != {"device", "filesystem", "filesystemUuid", "mountTarget", "mountId"}: raise ValueError("backup mount identity is incomplete")
        filesystem_uuid = backup_mount["filesystemUuid"]
        if filesystem_uuid is not None and (not isinstance(filesystem_uuid, str) or not re.fullmatch(r"[A-Fa-f0-9][A-Fa-f0-9-]{0,127}", filesystem_uuid)): raise ValueError("backup filesystem UUID is invalid")
        _validate_mount({key: backup_mount[key] for key in ("device", "filesystem", "mountTarget", "mountId")}, "backup")
        filesystem = backup_mount["filesystem"]
        if filesystem not in {"nfs", "nfs4"} and filesystem_uuid is None:
            raise ValueError("non-NFS backup filesystem UUID is required")
        identities.add(("uuid", filesystem_uuid.lower()) if filesystem_uuid is not None else ("device", backup_mount["device"]))
        equality.add((replica["archiveName"], replica["sha256"], replica["sizeBytes"]))
    if len(identities) != 3 or len(equality) != 1: raise ValueError("backup replicas are not equal or lack three distinct underlying filesystem/device identities")
    _validate_operational(collection.get("operationalMetadata"), desired)
    return entries


def validate_manifest(manifest: dict[str, Any], expected_commit: str | None = None, expected_artifact_sha256: str | None = None, expected_toplevel: str | None = None, expected_desired_sha256: str | None = None, expected_candidate_sha256: str | None = None, now: str | None = None, collection_max_age_seconds: int | None = None, expected_isolated_restore_evidence_sha256: str | None = None, expected_candidate_daemon_stop_evidence_sha256: str | None = None, expected_source_daemon_stability_evidence_sha256: str | None = None) -> None:
    top_keys = {"format", "version", "bindings", "inventories", "candidate", "sourceDockerRoot", "copyEntries", "classifications", "backupEvidence", "operationalMetadata"}
    if set(manifest) != top_keys or manifest.get("format") != FORMAT or manifest.get("version") != 1: raise ValueError("Gate C manifest envelope differs")
    inventories = manifest.get("inventories")
    if not isinstance(inventories, dict) or set(inventories) != {"desired", "runtime", "collection"} or not all(isinstance(v, dict) for v in inventories.values()): raise ValueError("embedded inventories are incomplete")
    desired, runtime, collection = inventories["desired"], inventories["runtime"], inventories["collection"]
    entries = validate_collection(collection, desired, runtime, expected_desired_sha256=expected_desired_sha256, expected_candidate_sha256=expected_candidate_sha256, expected_toplevel=expected_toplevel)
    bindings = manifest.get("bindings"); binding_keys = {"gitCommit", "composeArtifactSha256", "isolatedRestoreEvidenceSha256", "candidateDaemonStopEvidenceSha256", "sourceDaemonStabilityEvidenceSha256", "canonicalProductionMigrationToplevel", "desiredInventorySha256", "runtimeInventorySha256", "candidateInventorySha256", "collectionSha256", "collectedAt"}
    if not isinstance(bindings, dict) or set(bindings) != binding_keys: raise ValueError("manifest bindings are incomplete")
    if not COMMIT.fullmatch(str(bindings["gitCommit"])) or not SHA256.fullmatch(str(bindings["composeArtifactSha256"])) or not SHA256.fullmatch(str(bindings["isolatedRestoreEvidenceSha256"])) or not SHA256.fullmatch(str(bindings["candidateDaemonStopEvidenceSha256"])) or not SHA256.fullmatch(str(bindings["sourceDaemonStabilityEvidenceSha256"])) or not TOPLEVEL.fullmatch(str(bindings["canonicalProductionMigrationToplevel"])): raise ValueError("commit, artifact, external evidence, or toplevel binding is invalid")
    if bindings["desiredInventorySha256"] != digest(desired) or bindings["runtimeInventorySha256"] != digest(runtime) or bindings["candidateInventorySha256"] != digest(collection["candidateQualification"]) or bindings["collectionSha256"] != digest(collection): raise ValueError("manifest digest recomputation differs")
    if bindings["collectedAt"] != collection["collectedAt"] or bindings["canonicalProductionMigrationToplevel"] != collection["candidateQualification"]["canonicalProductionMigrationToplevel"]: raise ValueError("manifest timestamp or candidate toplevel projection differs")
    if expected_commit is not None and bindings["gitCommit"] != expected_commit: raise ValueError("pushed Git commit binding differs")
    if expected_artifact_sha256 is not None and bindings["composeArtifactSha256"] != expected_artifact_sha256: raise ValueError("Compose artifact binding differs")
    if expected_toplevel is not None and bindings["canonicalProductionMigrationToplevel"] != expected_toplevel: raise ValueError("canonical toplevel binding differs")
    if expected_isolated_restore_evidence_sha256 is not None and bindings["isolatedRestoreEvidenceSha256"] != expected_isolated_restore_evidence_sha256: raise ValueError("isolated restore evidence binding differs")
    if expected_candidate_daemon_stop_evidence_sha256 is not None and bindings["candidateDaemonStopEvidenceSha256"] != expected_candidate_daemon_stop_evidence_sha256: raise ValueError("candidate daemon stop evidence binding differs")
    if expected_source_daemon_stability_evidence_sha256 is not None and bindings["sourceDaemonStabilityEvidenceSha256"] != expected_source_daemon_stability_evidence_sha256: raise ValueError("source daemon stability evidence binding differs")
    if (now is None) != (collection_max_age_seconds is None): raise ValueError("collection freshness requires both current time and maximum age")
    if now is not None and collection_max_age_seconds is not None: validate_freshness(collection["collectedAt"], now, collection_max_age_seconds)
    if manifest["candidate"] != collection["candidate"] or manifest["sourceDockerRoot"] != collection["sourceDockerRoot"] or manifest["operationalMetadata"] != collection["operationalMetadata"] or manifest["backupEvidence"] != collection["backupEvidence"]: raise ValueError("manifest projection differs from collection")
    if not isinstance(manifest.get("copyEntries"), list) or len(manifest["copyEntries"]) != 34: raise ValueError("manifest copy-entry projection differs")
    for projected, collected in zip(manifest["copyEntries"], entries):
        base = dict(collected); base["writeArgv"] = write_argv(base["source"], base["destination"]); base["checksumArgv"] = checksum_argv(base["source"], base["destination"])
        if projected != base: raise ValueError(f"copy argv or collected metadata differs for {base['source']}")
    expected_classifications = [{"name": n, "path": p, "disposition": d, "reason": r} for n, p, d, r in CLASSIFICATIONS]
    if manifest.get("classifications") != expected_classifications: raise ValueError("reuse/regenerate/excluded classification policy differs")
