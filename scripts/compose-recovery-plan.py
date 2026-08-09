#!/usr/bin/env python3
"""Derive a secret-free identity for an approved first Compose recovery."""

from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REQUIRED_CLASSES = (
    "vaultwarden-data",
    "omada-data",
    "hass-data",
    "wolf/cfg",
    ".env",
    ".ssh",
)
RECOVERY_ROOT = Path("/srv/home-lab-recovery")


def fail(reason: str) -> None:
    print(f"compose_recovery_plan=failed reason={reason}", file=sys.stderr)
    raise SystemExit(1)


def run(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            arguments,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return result.stdout
    except subprocess.SubprocessError:
        fail("docker_command_error")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--artifact-hash", required=True)
    parser.add_argument("--backup-source", choices=("local", "remote"), required=True)
    parser.add_argument("--backup-id-sha256", required=True)
    parser.add_argument("--backup-sha256", required=True)
    parser.add_argument("--backup-version-id-sha256", default="")
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--current-dir", required=True, type=Path)
    parser.add_argument("--runtime-env", required=True, type=Path)
    parser.add_argument("--staged-dir", required=True, type=Path)
    parser.add_argument("--staged-env", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--retain-existing-binds", action="store_true")
    parser.add_argument("--retained-bind-review-confirmed", action="store_true")
    args = parser.parse_args()

    if len(args.artifact_hash) != 64 or any(
        character not in "0123456789abcdef" for character in args.artifact_hash
    ):
        fail("artifact_hash_invalid")
    for name, value in (
        ("backup_id_sha256", args.backup_id_sha256),
        ("backup_sha256", args.backup_sha256),
    ):
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            fail(f"{name}_invalid")
    if args.backup_source == "remote":
        if len(args.backup_version_id_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in args.backup_version_id_sha256
        ):
            fail("backup_version_id_sha256_invalid")
    elif args.backup_version_id_sha256:
        fail("local_backup_has_remote_version")
    if args.retain_existing_binds and not args.retained_bind_review_confirmed:
        fail("retained_bind_review_missing")
    target = args.target.resolve(strict=True)
    if not target.is_relative_to(RECOVERY_ROOT):
        fail("target_outside_recovery_root")
    backup = target / "backup"
    if not backup.is_dir():
        fail("backup_root_missing")
    if args.current_dir.exists() or args.runtime_env.exists():
        fail("active_deployment_exists")
    if not args.staged_dir.is_dir() or not args.staged_env.is_file():
        fail("staged_artifact_missing")
    for required in REQUIRED_CLASSES:
        if not backup.joinpath(*required.split("/")).exists():
            fail("critical_class_missing")

    label = f"label=com.docker.compose.project={args.project}"
    if run(["docker", "volume", "ls", "--quiet", "--filter", label]).splitlines():
        fail("project_volume_exists")
    if run(["docker", "container", "ls", "--all", "--quiet", "--filter", label]).splitlines():
        fail("project_container_exists")

    model = run(
        [
            "docker",
            "compose",
            "--project-name",
            args.project,
            "--project-directory",
            str(args.staged_dir),
            "--env-file",
            str(args.staged_env),
            "--file",
            str(args.staged_dir / "docker-compose.yml"),
            "config",
            "--format",
            "json",
        ]
    )
    try:
        canonical_model = json.dumps(json.loads(model), sort_keys=True, separators=(",", ":"))
    except json.JSONDecodeError:
        fail("compose_model_invalid")

    plan = {
        "artifact_sha256": args.artifact_hash,
        "backup_ciphertext_sha256": args.backup_sha256,
        "backup_id_sha256": args.backup_id_sha256,
        "backup_source": args.backup_source,
        "backup_version_id_sha256": args.backup_version_id_sha256 or None,
        "compose_model_sha256": digest(canonical_model),
        "critical_classes": REQUIRED_CLASSES,
        "retain_existing_binds": args.retain_existing_binds,
        "retained_bind_review_confirmed": args.retained_bind_review_confirmed,
        "target_sha256": digest(str(target)),
        "version": 2,
    }
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    print(f"compose_recovery_plan_sha256={digest(encoded)}")


if __name__ == "__main__":
    main()
