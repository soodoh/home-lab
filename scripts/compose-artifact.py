#!/usr/bin/env python3
"""Build and hash the deterministic Docker Compose deployment artifact."""

from argparse import ArgumentParser, Namespace
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys

FORMAT_MARKER = b"docker-compose-artifact-v1\0"
EXPLICIT_PATHS = {
    ".sops.yaml",
    "docker-compose.yml",
    "scripts/check-sops-env.py",
    "scripts/compose-artifact.py",
    "scripts/compose-image-lock.py",
    "scripts/compose-model-inventory.py",
    "scripts/materialize-compose-secret-files.py",
    "scripts/restore-dotenv-layout.py",
    "secrets/production.env.keys",
    "secrets/production.env.layout.json",
    "secrets/production.sops.env",
}


def is_selected(path: str) -> bool:
    candidate = PurePosixPath(path)
    if path in EXPLICIT_PATHS:
        return True
    if len(candidate.parts) == 2 and candidate.parts[0] == "services":
        return candidate.suffix == ".yml"
    return len(candidate.parts) >= 3 and candidate.parts[:2] == ("services", "data")


def reject_unsafe_path(path: str) -> None:
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise SystemExit("artifact contains an unsafe path")
    if path.endswith(".env") and path != "secrets/production.sops.env":
        raise SystemExit("artifact selection includes a plaintext environment path")
    lowered = path.lower()
    if any(token in lowered for token in ("private-key", "secret-key", "keys.txt")):
        raise SystemExit("artifact selection includes a private-key candidate")


def git_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def filesystem_paths(root: Path) -> list[str]:
    return [
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    ]


def selected_paths(root: Path, require_git_tracked: bool) -> list[str]:
    candidates = git_paths(root) if require_git_tracked else filesystem_paths(root)
    selected = sorted(path for path in candidates if is_selected(path))
    if not selected:
        raise SystemExit("artifact selection is empty")
    if not EXPLICIT_PATHS.issubset(selected):
        raise SystemExit("artifact is missing a required explicit path")
    for path in selected:
        reject_unsafe_path(path)
        source = root / path
        if not source.exists() and not source.is_symlink():
            raise SystemExit("artifact contains a missing path")
    return selected


def path_bytes(root: Path, relative_path: str) -> bytes:
    path = root / relative_path
    if path.is_symlink():
        return os.readlink(path).encode()
    return path.read_bytes()


def artifact_hash(root: Path, paths: list[str]) -> str:
    digest = hashlib.sha256(FORMAT_MARKER)
    for relative_path in paths:
        encoded_path = relative_path.encode()
        content = path_bytes(root, relative_path)
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def copy_artifact(root: Path, destination: Path, paths: list[str]) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit("artifact destination must be absent or empty")
    destination.mkdir(parents=True, exist_ok=True)
    for relative_path in paths:
        source = root / relative_path
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
            continue
        shutil.copyfile(source, target)
        source_mode = stat.S_IMODE(source.stat().st_mode)
        target.chmod(source_mode)


def parse_args() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--no-git", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--null", action="store_true")
    subparsers.add_parser("hash")
    copy_parser = subparsers.add_parser("copy")
    copy_parser.add_argument("destination", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    paths = selected_paths(root, require_git_tracked=not args.no_git)

    if args.command == "list":
        separator = "\0" if args.null else "\n"
        sys.stdout.write(separator.join(paths) + separator)
        return
    if args.command == "hash":
        print(artifact_hash(root, paths))
        return
    if args.command == "copy":
        destination = args.destination.resolve()
        copy_artifact(root, destination, paths)
        copied_paths = selected_paths(destination, require_git_tracked=False)
        if copied_paths != paths:
            raise SystemExit("copied artifact path set differs from the source")
        source_hash = artifact_hash(root, paths)
        if artifact_hash(destination, copied_paths) != source_hash:
            raise SystemExit("copied artifact hash differs from the source")
        print(source_hash)
        return
    raise SystemExit("unsupported artifact command")


if __name__ == "__main__":
    main()
