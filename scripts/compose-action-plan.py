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


ACTION_CANONICAL_NAMES = {
    "Creating": "Create",
    "Created": "Create",
    "Create": "Create",
    "Recreated": "Recreate",
    "Recreate": "Recreate",
    "Removing": "Remove",
    "Removed": "Remove",
    "Remove": "Remove",
    "Starting": "Start",
    "Started": "Start",
    "Start": "Start",
    "Stopping": "Stop",
    "Stopped": "Stop",
    "Stop": "Stop",
}


def canonical_actions(raw_actions: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return sorted({(container, ACTION_CANONICAL_NAMES[action]) for container, action in raw_actions})


def compose_operation_arguments(
    operation: str, no_deps: bool, requested_services: list[str]
) -> list[str]:
    if operation == "up":
        if not requested_services:
            raise RuntimeError("--operation up requires at least one exact --service")
        arguments = ["up", "--detach", "--no-build", "--pull", "never"]
        if no_deps:
            arguments.append("--no-deps")
        return [*arguments, *requested_services]
    if no_deps:
        raise RuntimeError("--no-deps is valid only with --operation up")
    return ["create", "--no-build", "--pull", "never", *requested_services]


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
            mount["source"] = str(bind_root_override.absolute() / relative)
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


def review_actions(value: dict, candidate: dict, runtime: dict, tool_sha256: str) -> dict:
    """Synthetic progress grammar ONLY. This does not qualify any native Compose output.

    Exact mappings are supplied claims; never infer generated names or dependency closure.
    All unknown/error text is discarded from the summary, not treated as a native no-op.
    Legacy collectors and their alias mutations below are deliberately not called.
    """
    import hashlib
    def digest(item):
        return hashlib.sha256(json.dumps(item, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    fields = {'generation_sha256', 'runtime_sha256', 'tool_sha256', 'grammar', 'exit_code',
              'truncated', 'stdout', 'stderr', 'requested_roots', 'mappings'}
    if (not isinstance(value, dict) or set(value) != fields
            or value['generation_sha256'] != digest(candidate)
            or value['runtime_sha256'] != digest(runtime) or value['tool_sha256'] != tool_sha256
            or type(value['exit_code']) is not int or not -255 <= value['exit_code'] <= 255
            or type(value['truncated']) is not bool
            or not all(isinstance(value[k], str) and len(value[k]) <= 65536 for k in ('stdout', 'stderr', 'grammar'))):
        raise ValueError('invalid action review bindings or shape')
    roots = value['requested_roots']
    if (not isinstance(roots, list) or len(roots) > 256
            or any(not isinstance(s, str) or s not in candidate['model']['services'] for s in roots)
            or len(set(roots)) != len(roots)):
        raise ValueError('invalid requested roots')
    mappings = value['mappings']
    if not isinstance(mappings, list) or len(mappings) > 1024:
        raise ValueError('invalid action mapping count')
    mapped = {}; identities = set()
    actual = {('Container', row['name']): {'kind': 'Container', 'name': row['name'], 'id': row['id'], 'service': row['service']}
              for row in runtime['containers']}
    actual.update({(row['kind'].capitalize(), row['name']): {'kind': row['kind'].capitalize(),
                   'name': row['name'], 'id': row['id'], 'service': None} for row in runtime['resources']})
    actual_ids = {(row['kind'], row['id']): key for key, row in actual.items()}
    image_associations = {}
    for image in candidate['images']:
        image_associations.setdefault(image['reference'], set()).add(image['image_id'])
    for container in runtime['containers']:
        image_associations.setdefault(container['image_reference'], set()).add(container['image_id'])
    services = set(candidate['model']['services']) | {row['service'] for row in runtime['containers']}
    kinds = {'Container', 'Network', 'Volume', 'Image', 'Preparation'}
    for row in mappings:
        if (not isinstance(row, dict) or set(row) != {'kind', 'name', 'id', 'service'}
                or not isinstance(row['kind'], str) or row['kind'] not in kinds
                or any(not isinstance(row[k], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,239}', row[k])
                       for k in ('name', 'id'))
                or (row['kind'] == 'Container' and (not isinstance(row['service'], str)
                    or row['service'] not in services))
                or (row['kind'] != 'Container' and row['service'] is not None)):
            raise ValueError('invalid action resource mapping')
        key = (row['kind'], row['name'])
        identity = (row['kind'], row['id'])
        if key in mapped or (row['kind'] != 'Image' and identity in identities):
            raise ValueError('duplicate action resource identity')
        if row['kind'] == 'Image':
            if row['id'] not in image_associations.get(row['name'], set()):
                raise ValueError('action mapping image generation identity mismatch')
        elif ((key in actual and row != actual[key]) or (identity in actual_ids and actual_ids[identity] != key)):
            raise ValueError('action mapping runtime identity mismatch')
        mapped[key] = row
        identities.add(identity)
    blockers = {'native-grammar-unqualified'}
    if any(key not in actual and key[0] != 'Image' for key in mapped):
        blockers.add('unobserved-resource-mapping')
    if value['exit_code'] != 0 or value['truncated'] or value['stderr']:
        blockers.add('failed-truncated-or-error-action-output')
    records = {}
    actions = {**ACTION_CANONICAL_NAMES, 'Recreating': 'Recreate',
               'Pulling': 'Pull', 'Pulled': 'Pull', 'Pull': 'Pull',
               'Building': 'Build', 'Built': 'Build', 'Build': 'Build',
               'Retagging': 'Retag', 'Retagged': 'Retag', 'Retag': 'Retag',
               'Preparing': 'Prepare', 'Prepared': 'Prepare', 'Prepare': 'Prepare'}
    allowed = {'Container': {'Create', 'Recreate', 'Start', 'Stop', 'Remove'},
               'Network': {'Create', 'Remove'}, 'Volume': {'Create', 'Remove'},
               'Image': {'Pull', 'Build', 'Retag', 'Remove'}, 'Preparation': {'Prepare'}}
    if value['grammar'] != 'synthetic-progress-v1':
        blockers.add('unknown-action-grammar')
    else:
        lines = value['stdout'].splitlines()
        if len(lines) > 2048:
            raise ValueError('action output line limit exceeded')
        for line in lines:
            match = re.fullmatch(r'(Container|Network|Volume|Image|Preparation) ([A-Za-z0-9][A-Za-z0-9_.:/@-]{0,239}) ([A-Za-z]+)', line)
            if match is None:
                blockers.add('unknown-action-output')
                continue
            kind, name, action = match.groups()
            canonical = actions.get(action)
            row = mapped.get((kind, name))
            if row is None or canonical not in allowed[kind]:
                blockers.add('unmapped-or-unknown-action')
                continue
            records[(kind, name, canonical)] = {**row, 'action': canonical}
    rows = [records[key] for key in sorted(records)]
    if any(r['kind'] != 'Container' or r['action'] in ('Create', 'Remove') for r in rows):
        blockers.add('resource-or-preparation-effects-require-review')
    return {'records': rows, 'requested_roots': roots,
            'affected_services': sorted({r['service'] for r in rows if r['service'] is not None}),
            'native_qualified': False, 'native_noop': False, 'blockers': sorted(blockers)}


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--project-directory", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--compose-file", required=True, type=Path)
    parser.add_argument("--override-file", type=Path)
    parser.add_argument("--bind-root-override", type=Path)
    parser.add_argument("--normalized-output", type=Path)
    parser.add_argument("--operation", choices=["create", "up"], default="create")
    parser.add_argument("--no-deps", action="store_true")
    parser.add_argument("--service", action="append", default=[])
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
    requested_services = sorted(set(args.service))
    unknown_services = sorted(set(requested_services) - set(model.get("services") or {}))
    if unknown_services:
        raise RuntimeError(f"Unknown requested Compose services: {len(unknown_services)}")
    operation_arguments = compose_operation_arguments(
        args.operation, args.no_deps, requested_services
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
        dry_run_command.extend(operation_arguments)
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
    actions_by_container = canonical_actions(raw_actions)
    unmapped_containers = {
        container_name
        for container_name, _action in actions_by_container
        if container_name not in container_to_service
    }
    if unmapped_containers:
        raise RuntimeError(
            f"Docker Compose dry-run returned {len(unmapped_containers)} unmapped container names."
        )
    actions = [
        {"service": container_to_service[container_name], "action": action}
        for container_name, action in actions_by_container
    ]
    report = {
        "recreate_services": sorted(
            {entry["service"] for entry in actions if entry["action"] == "Recreate"}
        ),
        "forbidden_actions": [
            entry for entry in actions if entry["action"] in {"Create", "Remove"}
        ],
        "action_count": len(actions),
        "action_services": sorted({entry["service"] for entry in actions}),
        "start_services": sorted(
            {entry["service"] for entry in actions if entry["action"] == "Start"}
        ),
        "stop_services": sorted(
            {entry["service"] for entry in actions if entry["action"] == "Stop"}
        ),
        "operation": args.operation,
        "dependency_mode": "isolated" if args.no_deps else "complete",
        "requested_services": requested_services,
    }
    write_private_new_file(
        args.output,
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
    )


if __name__ == "__main__":
    main()
