#!/usr/bin/env python3
"""Emit a secret-free desired or running Docker Compose model inventory."""

from argparse import ArgumentParser, Namespace
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any


def stable_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def desired_ports(ports: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        (
            {
                "host_ip": port.get("host_ip") or None,
                "published": str(port["published"]),
                "target": int(port["target"]),
                "protocol": port.get("protocol") or "tcp",
            }
            for port in ports
            if port.get("published") is not None
        ),
        key=lambda port: json.dumps(port, sort_keys=True),
    )


def runtime_ports(bindings: dict[str, object]) -> list[dict[str, object]]:
    ports = []
    for container_port, host_bindings in bindings.items():
        target_text, separator, protocol = container_port.partition("/")
        if not separator or not isinstance(host_bindings, list):
            continue
        for binding in host_bindings:
            if not isinstance(binding, dict) or not binding.get("HostPort"):
                continue
            ports.append(
                {
                    "host_ip": binding.get("HostIp") or None,
                    "published": str(binding["HostPort"]),
                    "target": int(target_text),
                    "protocol": protocol,
                }
            )
    return sorted(ports, key=lambda port: json.dumps(port, sort_keys=True))


DURATION_PATTERN = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
DURATION_FACTORS = {
    "ns": 1,
    "us": 1_000,
    "µs": 1_000,
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60_000_000_000,
    "h": 3_600_000_000_000,
}


def normalized_duration(value: object) -> object:
    if not isinstance(value, str):
        return value
    parts = DURATION_PATTERN.findall(value)
    if not parts or "".join(number + unit for number, unit in parts) != value:
        return value
    return int(sum(float(number) * DURATION_FACTORS[unit] for number, unit in parts))


def normalized_healthcheck(healthcheck: object) -> dict[str, object] | None:
    if not isinstance(healthcheck, dict):
        return None
    aliases = {
        "test": ("test", "Test"),
        "interval": ("interval", "Interval"),
        "timeout": ("timeout", "Timeout"),
        "retries": ("retries", "Retries"),
        "start_period": ("start_period", "StartPeriod"),
        "start_interval": ("start_interval", "StartInterval"),
    }
    normalized = {}
    for field, names in aliases.items():
        value = next((healthcheck[name] for name in names if name in healthcheck), None)
        if value not in (None, 0, "", []):
            normalized[field] = (
                normalized_duration(value)
                if field in {"interval", "timeout", "start_period", "start_interval"}
                else value
            )
    disabled = healthcheck.get("disable") is True or normalized.get("test") == ["NONE"]
    if disabled:
        return {"disable": True}
    return normalized or None


def healthcheck_field_hashes(healthcheck: object) -> dict[str, str]:
    normalized = normalized_healthcheck(healthcheck)
    if normalized is None:
        return {}
    return {field: stable_hash(value) for field, value in sorted(normalized.items())}


def mapped_bind_source(
    source: object, artifact_root: Path, bind_root_override: Path | None
) -> object:
    if not isinstance(source, str) or bind_root_override is None:
        return source
    try:
        relative_source = Path(source).resolve().relative_to(artifact_root)
    except ValueError:
        return source
    return str(bind_root_override.resolve() / relative_source)


def run_json(command: list[str]) -> Any:
    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return json.loads(result.stdout)


def normalize_desired_volume_source(source: object, declared: set[str], project_name: str) -> object:
    if not isinstance(source, str):
        return source
    prefix = f"{project_name}_"
    logical_name = source.removeprefix(prefix)
    return logical_name if source.startswith(prefix) and logical_name in declared else source


def desired_inventory(args: Namespace) -> dict[str, object]:
    artifact_root = args.artifact_root.resolve()
    model = run_json(
        [
            "/usr/bin/docker",
            "compose",
            "--project-name",
            args.project_name,
            "--project-directory",
            str(args.project_directory.resolve()),
            "--env-file",
            str(args.env_file.resolve()),
            "--file",
            str(artifact_root / "docker-compose.yml"),
            "config",
            "--format",
            "json",
        ]
    )

    declared_volume_names = set((model.get("volumes") or {}).keys())
    network_names = {
        name: definition.get("name", name)
        for name, definition in (model.get("networks") or {}).items()
    }
    services = {}
    for service_name, service in sorted(model.get("services", {}).items()):
        mounts = service.get("volumes") or []
        healthcheck = service.get("healthcheck")
        services[service_name] = {
            "image": service.get("image"),
            "ports": desired_ports(service.get("ports") or []),
            "binds": sorted(
                (
                    {
                        "source": mapped_bind_source(
                            mount.get("source"), artifact_root, args.bind_root_override
                        ),
                        "target": mount.get("target"),
                        "read_only": mount.get("read_only", False),
                    }
                    for mount in mounts
                    if mount.get("type") == "bind"
                ),
                key=lambda mount: json.dumps(mount, sort_keys=True),
            ),
            "volumes": sorted(
                (
                    {
                        "source": normalize_desired_volume_source(
                            mount.get("source"), declared_volume_names, args.project_name
                        ),
                        "target": mount.get("target"),
                        "read_only": mount.get("read_only", False),
                    }
                    for mount in mounts
                    if mount.get("type") == "volume"
                ),
                key=lambda mount: json.dumps(mount, sort_keys=True),
            ),
            "devices": sorted(
                (
                    {
                        "source": device.get("source"),
                        "target": device.get("target"),
                        "permissions": device.get("permissions"),
                    }
                    for device in service.get("devices") or []
                ),
                key=lambda device: json.dumps(device, sort_keys=True),
            ),
            "network_mode": service.get("network_mode"),
            "networks": sorted(
                network_names.get(name, name) for name in (service.get("networks") or {})
            ),
            "healthcheck_sha256": (
                stable_hash(normalized_healthcheck(healthcheck)) if healthcheck else None
            ),
            "healthcheck_fields_sha256": healthcheck_field_hashes(healthcheck),
        }

    volumes = sorted((model.get("volumes") or {}).keys())
    networks = {
        name: {
            "name": network.get("name"),
            "driver": network.get("driver"),
            "external": network.get("external", False),
        }
        for name, network in sorted((model.get("networks") or {}).items())
    }
    return {
        "kind": "desired",
        "project_name": args.project_name,
        "service_count": len(services),
        "volume_count": len(volumes),
        "services": services,
        "volumes": volumes,
        "networks": networks,
    }


def runtime_inventory(args: Namespace) -> dict[str, object]:
    ids_result = subprocess.run(
        [
            "/usr/bin/docker",
            "ps",
            "--all",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={args.project_name}",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    container_ids = [line for line in ids_result.stdout.splitlines() if line]
    inspected = run_json(["/usr/bin/docker", "inspect", *container_ids]) if container_ids else []

    container_services = {}
    for container in inspected:
        labels = container.get("Config", {}).get("Labels") or {}
        service_name = labels.get("com.docker.compose.service")
        if not service_name:
            continue
        container_id = container.get("Id") or ""
        container_name = (container.get("Name") or "").removeprefix("/")
        container_services[container_id] = service_name
        container_services[container_id[:12]] = service_name
        container_services[container_name] = service_name

    services = {}
    running_count = 0
    for container in inspected:
        labels = container.get("Config", {}).get("Labels") or {}
        service_name = labels.get("com.docker.compose.service")
        if not service_name:
            continue
        state = container.get("State") or {}
        if state.get("Running"):
            running_count += 1
        host_config = container.get("HostConfig") or {}
        mounts = container.get("Mounts") or []
        healthcheck = (container.get("Config") or {}).get("Healthcheck")
        network_settings = container.get("NetworkSettings") or {}
        runtime_networks = sorted((network_settings.get("Networks") or {}).keys())
        network_mode = host_config.get("NetworkMode")
        if isinstance(network_mode, str) and network_mode.startswith("container:"):
            target = network_mode.partition(":")[2]
            target_service = container_services.get(target)
            if target_service:
                network_mode = f"service:{target_service}"
        elif network_mode == "host":
            runtime_networks = []
        elif network_mode in runtime_networks:
            network_mode = None
        services[service_name] = {
            "container_name": (container.get("Name") or "").removeprefix("/"),
            "running": bool(state.get("Running")),
            "health": (state.get("Health") or {}).get("Status"),
            "image": (container.get("Config") or {}).get("Image"),
            "image_id": container.get("Image"),
            "ports": runtime_ports(host_config.get("PortBindings") or {}),
            "binds": sorted(
                (
                    {
                        "source": mount.get("Source"),
                        "target": mount.get("Destination"),
                        "read_only": not mount.get("RW", False),
                    }
                    for mount in mounts
                    if mount.get("Type") == "bind"
                ),
                key=lambda mount: json.dumps(mount, sort_keys=True),
            ),
            "volumes": sorted(
                (
                    {
                        "source": mount.get("Name"),
                        "target": mount.get("Destination"),
                        "read_only": not mount.get("RW", False),
                    }
                    for mount in mounts
                    if mount.get("Type") == "volume"
                ),
                key=lambda mount: json.dumps(mount, sort_keys=True),
            ),
            "devices": sorted(
                (
                    {
                        "source": device.get("PathOnHost"),
                        "target": device.get("PathInContainer"),
                        "permissions": device.get("CgroupPermissions"),
                    }
                    for device in host_config.get("Devices") or []
                ),
                key=lambda device: json.dumps(device, sort_keys=True),
            ),
            "network_mode": network_mode,
            "networks": runtime_networks,
            "healthcheck_sha256": (
                stable_hash(normalized_healthcheck(healthcheck)) if healthcheck else None
            ),
            "healthcheck_fields_sha256": healthcheck_field_hashes(healthcheck),
        }

    volume_result = subprocess.run(
        [
            "/usr/bin/docker",
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={args.project_name}",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    project_volumes = sorted(line for line in volume_result.stdout.splitlines() if line)
    return {
        "kind": "runtime",
        "project_name": args.project_name,
        "container_count": len(services),
        "running_count": running_count,
        "project_volume_count": len(project_volumes),
        "project_volumes": project_volumes,
        "services": dict(sorted(services.items())),
    }


def parse_args() -> Namespace:
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    desired = subparsers.add_parser("desired")
    desired.add_argument("--artifact-root", required=True, type=Path)
    desired.add_argument("--project-directory", required=True, type=Path)
    desired.add_argument("--env-file", required=True, type=Path)
    desired.add_argument("--project-name", default="docker-compose")
    desired.add_argument("--bind-root-override", type=Path)
    desired.add_argument("--output", type=Path)
    runtime = subparsers.add_parser("runtime")
    runtime.add_argument("--project-name", default="docker-compose")
    runtime.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    inventory = desired_inventory(args) if args.command == "desired" else runtime_inventory(args)
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        if args.output.exists():
            raise SystemExit("refusing to overwrite an existing inventory output")
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
