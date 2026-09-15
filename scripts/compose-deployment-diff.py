#!/usr/bin/env python3
"""Combine secret-free Compose inventories and dry-run actions into a deploy plan."""

from argparse import ArgumentParser
import json
from pathlib import Path


def load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("plan input must be a JSON object")
    return value


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--desired", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--actions", required=True, type=Path)
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--current-root", required=True, type=Path)
    parser.add_argument("--candidate-hash", required=True)
    parser.add_argument("--deployed-hash", required=True)
    parser.add_argument("--canary-service", required=True)
    parser.add_argument("--canary-path", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    desired = load_object(args.desired)
    runtime = load_object(args.runtime)
    actions = load_object(args.actions)
    if desired.get("kind") != "desired" or runtime.get("kind") != "runtime":
        raise SystemExit("inventory kinds are invalid")
    if desired.get("project_name") != runtime.get("project_name"):
        raise SystemExit("inventory project names differ")
    desired_services = desired.get("services")
    runtime_services = runtime.get("services")
    recreate_services = actions.get("recreate_services")
    forbidden_actions = actions.get("forbidden_actions")
    if not isinstance(desired_services, dict) or not isinstance(runtime_services, dict):
        raise SystemExit("inventory services are invalid")
    if not isinstance(recreate_services, list) or not isinstance(forbidden_actions, list):
        raise SystemExit("action plan is invalid")

    desired_names = set(desired_services)
    runtime_names = set(runtime_services)
    image_services = []
    stateful_services = []
    for service_name in sorted(desired_names & runtime_names):
        desired_service = desired_services[service_name]
        runtime_service = runtime_services[service_name]
        if not isinstance(desired_service, dict) or not isinstance(runtime_service, dict):
            raise SystemExit("service inventory entry is invalid")
        if desired_service.get("image") != runtime_service.get("image"):
            image_services.append(service_name)
        volumes = desired_service.get("volumes")
        if service_name in recreate_services and isinstance(volumes, list) and volumes:
            stateful_services.append(service_name)

    candidate_paths = {
        path.relative_to(args.candidate_root).as_posix(): path.read_bytes()
        for path in args.candidate_root.rglob("*")
        if path.is_file()
    }
    current_paths = {
        path.relative_to(args.current_root).as_posix(): path.read_bytes()
        for path in args.current_root.rglob("*")
        if path.is_file()
    }
    changed_paths = sorted(
        path
        for path in set(candidate_paths) | set(current_paths)
        if candidate_paths.get(path) != current_paths.get(path)
    )

    canary_eligible = (
        args.candidate_hash != args.deployed_hash
        and image_services == [args.canary_service]
        and sorted(set(recreate_services)) == [args.canary_service]
        and not stateful_services
        and not forbidden_actions
        and desired_names == runtime_names
        and changed_paths == [args.canary_path]
    )
    artifact_only_eligible = (
        args.candidate_hash != args.deployed_hash
        and not recreate_services
        and not image_services
        and not forbidden_actions
        and desired_names == runtime_names
        and bool(changed_paths)
        and all(path.startswith("scripts/") for path in changed_paths)
    )

    report = {
        "candidate_hash": args.candidate_hash,
        "deployed_hash": args.deployed_hash,
        "has_changes": args.candidate_hash != args.deployed_hash,
        "recreate_services": sorted(set(recreate_services)),
        "image_services": image_services,
        "stateful_recreate_services": stateful_services,
        "missing_runtime_services": sorted(desired_names - runtime_names),
        "unexpected_runtime_services": sorted(runtime_names - desired_names),
        "forbidden_actions": forbidden_actions,
        "changed_paths": changed_paths,
        "manual_only_paths": [
            path for path in changed_paths if path.startswith("services/data/")
        ],
        "canary_service": args.canary_service,
        "canary_path": args.canary_path,
        "canary_eligible": canary_eligible,
        "artifact_only_eligible": artifact_only_eligible,
    }
    args.output.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)


if __name__ == "__main__":
    main()
