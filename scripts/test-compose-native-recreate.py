#!/usr/bin/env python3
"""Opt-in disposable regression for Compose 2.26 forced replacement settling.

This test creates and removes two Alpine containers and one private Docker network.
It never pulls images. Callers must provide an exact Compose 2.26.1 binary, an
already-local image, and the explicitly approved non-production Docker context.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path


def run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def compose_command(binary: Path, project: str, root: Path) -> list[str]:
    return [
        str(binary),
        "--project-name",
        project,
        "--project-directory",
        str(root),
        "--file",
        str(root / "compose.yml"),
    ]


def dry_run_actions(binary: Path, project: str, root: Path) -> str:
    result = run(
        compose_command(binary, project, root)
        + ["--dry-run", "up", "--detach", "--no-build", "--pull", "never"]
    )
    return result.stdout + result.stderr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-binary", type=Path, required=True)
    parser.add_argument("--approved-context", required=True)
    parser.add_argument("--image", default="alpine:3.22")
    args = parser.parse_args()

    binary = args.compose_binary.expanduser().resolve(strict=True)
    if not binary.is_file() or binary.is_symlink():
        raise SystemExit("compose binary must be a regular non-symlink file")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.approved_context):
        raise SystemExit("approved context has an invalid name")

    actual_context = run(["docker", "context", "show"]).stdout.strip()
    if actual_context != args.approved_context:
        raise SystemExit(
            f"refusing Docker context {actual_context!r}; expected {args.approved_context!r}"
        )
    version = run([str(binary), "version", "--short"]).stdout.strip()
    if version != "2.26.1":
        raise SystemExit(f"Compose 2.26.1 is required, found {version!r}")
    run(["docker", "image", "inspect", args.image])

    project = f"home-lab-compose-recreate-{uuid.uuid4().hex[:12]}"
    root = Path(tempfile.mkdtemp(prefix="home-lab-compose-recreate-"))
    compose = compose_command(binary, project, root)
    try:
        (root / "compose.yml").write_text(
            "\n".join(
                [
                    "services:",
                    "  dependency:",
                    f"    image: {args.image}",
                    '    command: ["sleep", "infinity"]',
                    "    healthcheck:",
                    '      test: ["CMD", "true"]',
                    "      interval: 1s",
                    "      timeout: 1s",
                    "      retries: 5",
                    "  canary:",
                    f"    image: {args.image}",
                    f"    container_name: {project}-canary",
                    '    command: ["sleep", "infinity"]',
                    "    depends_on:",
                    "      dependency:",
                    "        condition: service_healthy",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        run(compose + ["up", "--detach", "--no-build", "--pull", "never", "--wait"])
        dependency_name = f"{project}-dependency-1"
        dependency_before = run(
            ["docker", "inspect", "--format", "{{.Id}}", dependency_name]
        ).stdout.strip()

        run(
            compose
            + [
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "--no-deps",
                "--force-recreate",
                "--wait",
                "canary",
            ]
        )
        red_output = dry_run_actions(binary, project, root)
        if not re.search(r"Container .*canary\s+Recreate", red_output):
            raise SystemExit("fixture did not reproduce the Compose 2.26 replacement drift")

        run(
            compose
            + [
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "--wait",
                "canary",
            ]
        )
        dependency_after = run(
            ["docker", "inspect", "--format", "{{.Id}}", dependency_name]
        ).stdout.strip()
        if dependency_before != dependency_after:
            raise SystemExit("dependency-aware auto convergence recreated the dependency")

        green_output = dry_run_actions(binary, project, root)
        if re.search(r"Container .* (Recreate|Starting)", green_output):
            raise SystemExit("replacement drift remained after dependency-aware auto convergence")
        print(
            json.dumps(
                {
                    "compose_version": version,
                    "context": actual_context,
                    "dependency_recreated": False,
                    "initial_replacement_drift": True,
                    "post_settle_idempotent": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    finally:
        subprocess.run(
            compose + ["down", "--remove-orphans", "--volumes"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
