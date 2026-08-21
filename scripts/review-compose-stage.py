#!/usr/bin/env python3
"""Review staged Compose and runtime inventories without exposing environment data."""

from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
import re
import subprocess

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("inventory root must be an object")
    return value


def environment_entries(path: Path) -> tuple[list[str], list[str]]:
    keys = []
    values = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise SystemExit("runtime environment contains an invalid assignment")
        keys.append(key)
        if value:
            values.append(value)
    return keys, values


def write_report(path: Path, report: dict[str, object]) -> None:
    path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def service_differences(
    desired_services: dict[str, object], runtime_services: dict[str, object], field: str
) -> dict[str, object]:
    differences = {}
    for service_name in sorted(set(desired_services) & set(runtime_services)):
        desired_service = desired_services[service_name]
        runtime_service = runtime_services[service_name]
        if not isinstance(desired_service, dict) or not isinstance(runtime_service, dict):
            raise SystemExit("service inventory entry must be an object")
        desired_value = desired_service.get(field)
        runtime_value = runtime_service.get(field)
        if field == "volumes" and isinstance(desired_value, list) and isinstance(runtime_value, list):
            desired_targets = {
                mount.get("target") for mount in desired_value if isinstance(mount, dict)
            }
            runtime_value = [
                mount
                for mount in runtime_value
                if isinstance(mount, dict) and mount.get("target") in desired_targets
            ]
        if desired_value != runtime_value:
            differences[service_name] = {
                "desired": desired_value,
                "runtime": runtime_value,
            }
    return differences


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--desired", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--project-directory", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--override-file", type=Path)
    parser.add_argument("--project-name", default="docker-compose")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    desired = load_json(args.desired)
    runtime = load_json(args.runtime)
    if desired.get("kind") != "desired" or runtime.get("kind") != "runtime":
        raise SystemExit("inventory kinds are invalid")
    if desired.get("project_name") != args.project_name or runtime.get("project_name") != args.project_name:
        raise SystemExit("inventory project name differs from the required project")
    desired_services = desired.get("services")
    runtime_services = runtime.get("services")
    if not isinstance(desired_services, dict) or not isinstance(runtime_services, dict):
        raise SystemExit("service inventory is invalid")

    command = [
        "/usr/bin/docker",
        "compose",
        "--dry-run",
        "--project-name",
        args.project_name,
        "--project-directory",
        str(args.project_directory.resolve()),
        "--env-file",
        str(args.env_file.resolve()),
        "--file",
        str(args.artifact_root.resolve() / "docker-compose.yml"),
    ]
    if args.override_file is not None:
        command.extend(["--file", str(args.override_file.resolve())])
    command.extend(["create", "--no-build", "--pull", "never"])
    dry_run = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    dry_run_output = ANSI_PATTERN.sub("", dry_run.stdout + dry_run.stderr)
    env_keys, env_values = environment_entries(args.env_file)
    matched_key_count = sum(
        re.search(rf"(?<![A-Za-z0-9_]){re.escape(key)}\\s*=", dry_run_output) is not None
        for key in env_keys
    )
    matched_long_values = {
        value for value in env_values if len(value) >= 12 and value in dry_run_output
    }
    safe_dry_run_output = dry_run_output
    redacted_value_occurrence_count = 0
    for value in sorted(matched_long_values, key=len, reverse=True):
        redacted_value_occurrence_count += safe_dry_run_output.count(value)
        safe_dry_run_output = safe_dry_run_output.replace(value, "<redacted-env-value>")
    dry_run_lines = [line for line in safe_dry_run_output.splitlines() if line]
    if matched_key_count:
        write_report(
            args.output,
            {
                "status": "blocked",
                "reason": "environment_assignment_guard",
                "matched_key_count": matched_key_count,
                "redacted_value_count": len(matched_long_values),
                "redacted_value_occurrence_count": redacted_value_occurrence_count,
                "dry_run_line_count": len(dry_run_lines),
                "dry_run_sha256": hashlib.sha256(dry_run_output.encode()).hexdigest(),
            },
        )
        return

    desired_names = set(desired_services)
    runtime_names = set(runtime_services)
    compared_fields = (
        "image",
        "ports",
        "binds",
        "volumes",
        "devices",
        "network_mode",
        "networks",
        "healthcheck_sha256",
        "healthcheck_fields_sha256",
    )
    differences = {
        field: service_differences(desired_services, runtime_services, field)
        for field in compared_fields
    }
    report = {
        "status": "pass",
        "project_name": args.project_name,
        "desired_service_count": desired.get("service_count"),
        "runtime_container_count": runtime.get("container_count"),
        "runtime_running_count": runtime.get("running_count"),
        "desired_volume_count": desired.get("volume_count"),
        "runtime_project_volume_count": runtime.get("project_volume_count"),
        "missing_runtime_services": sorted(desired_names - runtime_names),
        "unexpected_runtime_services": sorted(runtime_names - desired_names),
        "difference_counts": {
            field: len(field_differences)
            for field, field_differences in differences.items()
        },
        "differences": differences,
        "dry_run": {
            "line_count": len(dry_run_lines),
            "sha256": hashlib.sha256(dry_run_output.encode()).hexdigest(),
            "redacted_value_count": len(matched_long_values),
            "redacted_value_occurrence_count": redacted_value_occurrence_count,
            "lines": dry_run_lines,
        },
    }
    write_report(args.output, report)


if __name__ == "__main__":
    main()
