#!/usr/bin/env python3
"""Write a root-only, secret-free Docker Compose dry-run action plan."""

from argparse import ArgumentParser
import json
import os
from pathlib import Path
import re
import subprocess


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
ACTION_PATTERN = re.compile(
    r"Container\s+([a-z0-9-]+)\s+"
    r"(Creating|Created|Create|Recreated|Recreate|Removing|Removed|Remove|Starting|Started|Start|Stopping|Stopped|Stop)\b"
)


def compose_model(
    project_name: str,
    project_directory: Path,
    env_file: Path,
    compose_file: Path,
    override_file: Path | None,
    bind_root_override: Path | None,
) -> dict:
    command = [
        "/usr/bin/docker",
        "compose",
        "--project-name",
        project_name,
        "--project-directory",
        str(project_directory),
        "--env-file",
        str(env_file),
        "--file",
        str(compose_file),
    ]
    if override_file is not None:
        command.extend(["--file", str(override_file)])
    command.extend(["config", "--format", "json"])
    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    model = json.loads(result.stdout)
    if bind_root_override is None:
        return model
    project_root = project_directory.resolve()
    for service in (model.get("services") or {}).values():
        for mount in service.get("volumes") or []:
            if mount.get("type") != "bind" or not isinstance(mount.get("source"), str):
                continue
            try:
                relative = Path(mount["source"]).resolve().relative_to(project_root)
            except ValueError:
                continue
            mount["source"] = str(bind_root_override.resolve() / relative)
    return model


def compose_model_content(model: dict) -> str:
    return json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n"


def inspect_json(*arguments: str) -> list[dict]:
    result = subprocess.run(
        ["/usr/bin/docker", "inspect", *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def prepare_running_image_aliases(model: dict, project_name: str) -> list[str]:
    """Restore only missing aliases already used by the exact running service."""
    created_aliases: list[str] = []
    for service_name, service in (model.get("services") or {}).items():
        image_reference = service.get("image")
        if not isinstance(image_reference, str) or not image_reference:
            continue
        present = subprocess.run(
            ["/usr/bin/docker", "image", "inspect", image_reference],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if present.returncode == 0:
            continue
        containers = subprocess.run(
            [
                "/usr/bin/docker",
                "ps",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--filter",
                f"label=com.docker.compose.service={service_name}",
                "--format",
                "{{.ID}}",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.splitlines()
        if len(containers) != 1:
            continue
        container = inspect_json(containers[0])[0]
        if container.get("Config", {}).get("Image") != image_reference:
            continue
        image_id = container.get("Image")
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            continue
        subprocess.run(
            ["/usr/bin/docker", "image", "tag", image_id, image_reference],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        created_aliases.append(image_reference)
    return created_aliases


def remove_temporary_image_aliases(image_references: list[str]) -> None:
    for image_reference in reversed(image_references):
        subprocess.run(
            ["/usr/bin/docker", "image", "rm", image_reference],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )


def write_private_new_file(path: Path, content: str) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--project-directory", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--compose-file", required=True, type=Path)
    parser.add_argument("--override-file", type=Path)
    parser.add_argument("--bind-root-override", type=Path)
    parser.add_argument("--normalized-output", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    model = compose_model(
        args.project_name,
        args.project_directory,
        args.env_file,
        args.compose_file,
        args.override_file,
        args.bind_root_override,
    )
    dry_run_file = args.compose_file
    dry_run_project_directory = args.project_directory
    normalized_input = None
    if args.bind_root_override is not None:
        normalized_input = compose_model_content(model)
        dry_run_project_directory = args.bind_root_override
        if args.normalized_output is None:
            dry_run_file = Path("-")
        else:
            write_private_new_file(args.normalized_output, normalized_input)
            dry_run_file = args.normalized_output
            normalized_input = None

    created_aliases = prepare_running_image_aliases(model, args.project_name)
    try:
        dry_run_command = [
            "/usr/bin/docker",
            "compose",
            "--ansi",
            "never",
            "--dry-run",
            "--project-name",
            args.project_name,
            "--project-directory",
            str(dry_run_project_directory),
            "--env-file",
            str(args.env_file),
            "--file",
            str(dry_run_file),
        ]
        if args.override_file is not None and normalized_input is None:
            dry_run_command.extend(["--file", str(args.override_file)])
        dry_run_command.extend(["create", "--no-build", "--pull", "never"])
        result = subprocess.run(
            dry_run_command,
            check=False,
            input=normalized_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Docker Compose dry-run failed: {result.stderr.strip()}")
    finally:
        remove_temporary_image_aliases(created_aliases)

    output = ANSI_PATTERN.sub("", result.stdout + result.stderr)
    container_to_service = {
        service.get("container_name", service_name): service_name
        for service_name, service in (model.get("services") or {}).items()
    }
    raw_actions = ACTION_PATTERN.findall(output)
    unmapped_containers = {
        container_name
        for container_name, _action in raw_actions
        if container_name not in container_to_service
    }
    if unmapped_containers:
        raise RuntimeError(
            f"Docker Compose dry-run returned {len(unmapped_containers)} unmapped container names."
        )
    actions = [
        {"service": container_to_service[container_name], "action": action}
        for container_name, action in raw_actions
    ]
    report = {
        "recreate_services": sorted(
            {entry["service"] for entry in actions if entry["action"] == "Recreate"}
        ),
        "forbidden_actions": [
            entry
            for entry in actions
            if entry["action"] in {"Create", "Creating", "Created", "Remove", "Removing", "Removed"}
        ],
        "action_count": len(actions),
    }
    write_private_new_file(
        args.output,
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
    )


if __name__ == "__main__":
    main()
