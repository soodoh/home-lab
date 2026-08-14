#!/usr/bin/env python3
"""Capture and verify current/previous Compose images before destructive pruning."""

from argparse import ArgumentParser, Namespace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


def fail(reason: str) -> None:
    print(f"compose_image_lock=failed reason={reason}", file=sys.stderr)
    raise SystemExit(1)


def docker_json(arguments: list[str]) -> Any:
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


def capture(args: Namespace) -> None:
    try:
        containers = subprocess.run(
            [
                "docker",
                "ps",
                "--all",
                "--quiet",
                "--filter",
                f"label=com.docker.compose.project={args.project}",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.splitlines()
    except subprocess.SubprocessError:
        fail("container_inventory_error")

    images: dict[str, dict[str, Any]] = {}
    if containers:
        inspected = docker_json(["inspect", *containers])
        for container in inspected:
            labels = container.get("Config", {}).get("Labels", {}) or {}
            service = labels.get("com.docker.compose.service")
            image_id = container.get("Image")
            reference = container.get("Config", {}).get("Image")
            if not service or not image_id or not reference:
                fail("compose_identity_missing")
            if service in images:
                fail("duplicate_compose_service")
            image = docker_json(["image", "inspect", image_id])[0]
            images[service] = {
                "service": service,
                "reference": reference,
                "image_id": image_id,
                "repo_digests": sorted(image.get("RepoDigests") or []),
            }

    document = {
        "schema": 1,
        "project": args.project,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "images": [images[name] for name in sorted(images)],
    }
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile("w", dir=output.parent, delete=False) as stream:
        json.dump(document, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        temporary = Path(stream.name)
    temporary.chmod(0o600)
    temporary.replace(output)
    print(f"compose_image_lock=captured services={len(images)}")


def read_lock(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail(f"{label}_lock_unreadable")
    if document.get("schema") != 1 or not isinstance(document.get("images"), list):
        fail(f"{label}_lock_schema")
    return document["images"]


def verify(args: Namespace) -> None:
    current = read_lock(args.current, "current")
    previous = read_lock(args.previous, "previous")
    if not current:
        fail("current_lock_empty")
    if not previous:
        fail("previous_lock_empty")

    checked_ids: set[str] = set()
    checked_digests: set[str] = set()
    for lock_name, records in (("current", current), ("previous", previous)):
        services: set[str] = set()
        for record in records:
            service = record.get("service")
            image_id = record.get("image_id")
            digests = record.get("repo_digests")
            if (
                not isinstance(service, str)
                or not isinstance(image_id, str)
                or not image_id.startswith("sha256:")
                or not isinstance(digests, list)
                or not digests
            ):
                fail(f"{lock_name}_record_schema")
            if service in services:
                fail(f"{lock_name}_duplicate_service")
            services.add(service)
            if image_id not in checked_ids:
                docker_json(["image", "inspect", image_id])
                checked_ids.add(image_id)
            for digest in digests:
                if not isinstance(digest, str) or "@sha256:" not in digest:
                    fail(f"{lock_name}_digest_schema")
                if args.check_registry and digest not in checked_digests:
                    try:
                        subprocess.run(
                            ["docker", "manifest", "inspect", digest],
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    except subprocess.SubprocessError:
                        fail("registry_digest_unavailable")
                    checked_digests.add(digest)

    print(
        "compose_image_lock=verified "
        f"current_services={len(current)} previous_services={len(previous)} "
        f"local_images={len(checked_ids)} registry_digests={len(checked_digests)}"
    )


def activate(args: Namespace) -> None:
    records = read_lock(args.lock, "activation")
    activated = 0
    for record in records:
        reference = record.get("reference")
        image_id = record.get("image_id")
        if (
            not isinstance(reference, str)
            or not reference
            or not isinstance(image_id, str)
            or not image_id.startswith("sha256:")
        ):
            fail("activation_record_schema")
        docker_json(["image", "inspect", image_id])
        if "@sha256:" in reference:
            continue
        try:
            subprocess.run(
                ["docker", "image", "tag", image_id, reference],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.SubprocessError:
            fail("rollback_reference_activation_error")
        activated += 1
    print(f"compose_image_lock=activated references={activated}")


def difference(args: Namespace) -> None:
    current = {record["service"]: record for record in read_lock(args.current, "current")}
    previous = {record["service"]: record for record in read_lock(args.previous, "previous")}
    if set(current) != set(previous):
        fail("image_lock_service_set_changed")
    changed = sorted(
        service
        for service in current
        if current[service].get("image_id") != previous[service].get("image_id")
    )
    print(json.dumps(changed, separators=(",", ":")))


def prune(args: Namespace) -> None:
    verify(args)
    records = read_lock(args.current, "current") + read_lock(args.previous, "previous")
    image_ids = sorted({record["image_id"] for record in records})
    protection_containers: list[str] = []
    try:
        for index, image_id in enumerate(image_ids):
            result = subprocess.run(
                [
                    "docker",
                    "create",
                    "--label",
                    "home-lab.prune-protection=true",
                    "--name",
                    f"home-lab-prune-protection-{index}",
                    image_id,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            protection_containers.append(result.stdout.strip())
        subprocess.run(
            ["docker", "image", "prune", "--all", "--force", "--filter", f"until={args.until}"],
            check=True,
        )
    except subprocess.SubprocessError:
        fail("protected_image_prune_error")
    finally:
        if protection_containers:
            subprocess.run(
                ["docker", "container", "rm", "--force", *protection_containers],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    print(f"compose_image_lock=pruned protected_images={len(image_ids)}")

def main() -> None:
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--output", type=Path, required=True)
    capture_parser.add_argument("--project", default="docker-compose")
    capture_parser.set_defaults(handler=capture)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--current", type=Path, required=True)
    verify_parser.add_argument("--previous", type=Path, required=True)
    verify_parser.add_argument("--check-registry", action="store_true")
    verify_parser.set_defaults(handler=verify)

    activate_parser = subparsers.add_parser("activate")
    activate_parser.add_argument("--lock", type=Path, required=True)
    activate_parser.set_defaults(handler=activate)

    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("--current", type=Path, required=True)
    diff_parser.add_argument("--previous", type=Path, required=True)
    diff_parser.set_defaults(handler=difference)

    prune_parser = subparsers.add_parser("prune")
    prune_parser.add_argument("--current", type=Path, required=True)
    prune_parser.add_argument("--previous", type=Path, required=True)
    prune_parser.add_argument("--check-registry", action="store_true")
    prune_parser.add_argument("--until", default="168h")
    prune_parser.set_defaults(handler=prune)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
