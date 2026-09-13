#!/usr/bin/env python3
"""Build and hash the deterministic Docker Compose deployment artifact."""

from argparse import ArgumentParser, Namespace
import hashlib
import json
import re
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys

FORMAT_MARKER = b"docker-compose-artifact-v1\0"
MANIFEST_FORMAT = "compose-artifact-manifest-v1"
# Implicit exact parents, including the root, are LOCAL PRIVATE package metadata.
# This is not the root-owned layout of a future native deployment.
PACKAGE_LAYOUT = "local-private-parents-0700-v1"
MAX_FILES = 256
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TREE_BYTES = 32 * 1024 * 1024
GIT_PREFIX = ["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false"]
GIT_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/", "LANG": "C", "LC_ALL": "C",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
    "GIT_ALLOW_PROTOCOL": "",
}
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
        GIT_PREFIX + ["ls-files", "-z"],
        env=GIT_ENV,
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


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def manifest_identity(entries: list[dict]) -> str:
    return hashlib.sha256(canonical({"format": MANIFEST_FORMAT, "layout": PACKAGE_LAYOUT, "entries": entries})).hexdigest()


def strict_path(name: str) -> None:
    if (not isinstance(name, str) or not 1 <= len(name) <= 240
            or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name)
            or any(part in (".", "..") for part in name.split("/"))):
        raise ValueError("unsafe artifact path")
    try:
        reject_unsafe_path(name)
    except SystemExit as exc:
        raise ValueError("unsafe artifact path") from exc


def open_directory(path: Path) -> int:
    """Open an existing directory without following any pathname component."""
    path = path.absolute()
    if ".." in path.parts:
        raise ValueError("unsafe directory path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def file_identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def source_identities(root: Path, paths: list[str]) -> dict:
    identities = {}
    for name in paths:
        strict_path(name)
        parent = open_directory((root / name).parent)
        try:
            identities[name] = file_identity(os.stat((root / name).name, dir_fd=parent, follow_symlinks=False))
        finally:
            os.close(parent)
    return identities


def bounded_read(path: Path, limit: int = MAX_FILE_BYTES) -> tuple[bytes, int]:
    parent = open_directory(path.parent)
    fd = None
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or mode not in (0o600, 0o644, 0o700, 0o755) or before.st_size > limit):
            raise ValueError("unsafe file type, links, mode or byte limit")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        if file_identity(before) != file_identity(os.fstat(fd)):
            raise ValueError("source changed before read")
        chunks = []
        count = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if count > limit:
                raise ValueError("file byte limit exceeded")
            chunks.append(chunk)
        after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if file_identity(before) != file_identity(os.fstat(fd)) or file_identity(before) != file_identity(after):
            raise ValueError("source changed during read")
        return b"".join(chunks), mode
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def strict_snapshot(root: Path, paths: list[str]) -> tuple[dict, dict[str, bytes]]:
    """Seal regular artifact inputs separately from the historical content hash."""
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_FILES:
        raise ValueError("artifact entry limit exceeded")
    for name in paths:
        strict_path(name)
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate artifact paths")
    entries = []
    buffers = {}
    total = 0
    legacy = hashlib.sha256(FORMAT_MARKER)
    for name in sorted(paths):
        data, mode = bounded_read(root / name)
        total += len(data)
        if total > MAX_TREE_BYTES:
            raise ValueError("artifact tree byte limit exceeded")
        buffers[name] = data
        entries.append({"path": name, "type": "file", "mode": f"{mode:04o}",
                        "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        encoded = name.encode()
        legacy.update(len(encoded).to_bytes(8, "big") + encoded)
        legacy.update(len(data).to_bytes(8, "big") + data)
    return {"format": MANIFEST_FORMAT, "layout": PACKAGE_LAYOUT, "entries": entries,
            "sha256": manifest_identity(entries), "legacy_sha256": legacy.hexdigest()}, buffers


def validate_manifest(value: object) -> dict:
    if (not isinstance(value, dict)
            or set(value) != {"format", "layout", "entries", "sha256", "legacy_sha256"}
            or value["format"] != MANIFEST_FORMAT or value["layout"] != PACKAGE_LAYOUT
            or not isinstance(value["entries"], list)
            or not 1 <= len(value["entries"]) <= MAX_FILES):
        raise ValueError("invalid artifact manifest")
    names = []
    total = 0
    for entry in value["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "type", "mode", "size", "sha256"}:
            raise ValueError("invalid manifest entry fields")
        strict_path(entry["path"])
        if (entry["type"] != "file" or entry["mode"] not in ("0600", "0644", "0700", "0755")
                or type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_FILE_BYTES
                or not isinstance(entry["sha256"], str) or not re.fullmatch('[0-9a-f]{64}', entry["sha256"])):
            raise ValueError("invalid manifest entry")
        total += entry["size"]
        names.append(entry["path"])
    if names != sorted(set(names)) or total > MAX_TREE_BYTES:
        raise ValueError("duplicate, unsorted or excessive manifest entries")
    if any(parent.as_posix() in set(names) for name in names for parent in PurePosixPath(name).parents):
        raise ValueError("manifest file/directory collision")
    if (not isinstance(value["legacy_sha256"], str)
            or not re.fullmatch('[0-9a-f]{64}', value["legacy_sha256"])
            or value["sha256"] != manifest_identity(value["entries"])):
        raise ValueError("manifest identity mismatch")
    return value


def verify_tree(root: Path, manifest: dict) -> None:
    """Inspect only declared artifact directories; reject extras before descent/read."""
    validate_manifest(manifest)
    files = {e["path"] for e in manifest["entries"]}
    directories = {p.as_posix() for name in files for p in PurePosixPath(name).parents if p.as_posix() != '.'}
    found = set()
    count = 0

    def visit(directory: Path, relative: str) -> None:
        nonlocal count
        fd = open_directory(directory)
        try:
            info = os.fstat(fd)
            if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
                raise ValueError("invalid local package directory mode or owner")
            with os.scandir(fd) as children:
                for child in children:
                    count += 1
                    if count > MAX_FILES * 16:
                        raise ValueError("artifact tree entry limit exceeded")
                    name = relative + child.name
                    if name in directories and child.is_dir(follow_symlinks=False):
                        visit(directory / child.name, name + '/')
                    elif name in files and child.is_file(follow_symlinks=False):
                        found.add(name)
                    else:
                        raise ValueError("unexpected or unsafe artifact path")
        finally:
            os.close(fd)

    visit(root, '')
    if found != files or strict_snapshot(root, sorted(files))[0] != manifest:
        raise ValueError("missing or changed artifact entries")


STACK_PATHS = {f"services/{name}.yml" for name in (
    "openfit", "apps", "hass", "gaming", "nextcloud", "servarr", "authentik", "infra")}


def validate_policy(policy: object) -> dict:
    if (not isinstance(policy, dict) or set(policy) != {"version", "assets"}
            or type(policy["version"]) is not int or policy["version"] != 1
            or not isinstance(policy["assets"], list) or not 1 <= len(policy["assets"]) <= 64):
        raise ValueError("invalid compose_deployment policy")
    selectors = []
    for asset in policy["assets"]:
        if not isinstance(asset, dict):
            raise ValueError("invalid asset declaration")
        host = asset.get("disposition") == "host-consumed"
        if set(asset) != ({"path", "kind", "disposition", "host"} if host else {"path", "kind", "disposition"}):
            raise ValueError("invalid asset declaration fields")
        strict_path(asset["path"])
        if (not asset["path"].startswith("services/data/")
                or asset["kind"] not in ("file", "directory")
                or asset["disposition"] not in ("compose-bind", "host-consumed", "retained-only")):
            raise ValueError("invalid asset declaration scope")
        if host:
            value = asset["host"]
            if (asset["kind"] != "file" or not isinstance(value, dict)
                    or set(value) != {"consumer", "destination", "adoption"}
                    or not isinstance(value["consumer"], str)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value["consumer"])
                    or value["adoption"] not in ("pending-review", "out-of-domain")
                    or not isinstance(value["destination"], str)
                    or not re.fullmatch(r"/(?:[A-Za-z0-9_. -]+/)*[A-Za-z0-9_. -]+", value["destination"])
                    or len(value["destination"]) > 240
                    or any(p in (".", "..") for p in value["destination"].split("/"))):
                raise ValueError("invalid host-consumer declaration")
        for earlier in selectors:
            if (asset["path"] == earlier["path"]
                    or (earlier["kind"] == "directory" and asset["path"].startswith(earlier["path"] + "/"))
                    or (asset["kind"] == "directory" and earlier["path"].startswith(asset["path"] + "/"))):
                raise ValueError("duplicate or ambiguous asset selectors")
        selectors.append(asset)
    return policy


def asset_policy(path: str, policy: dict) -> dict | None:
    return next((a for a in policy["assets"] if path == a["path"] or
                 (a["kind"] == "directory" and path.startswith(a["path"] + "/"))), None)


def strict_selected_paths(tracked: list[str], policy: dict) -> list[str]:
    validate_policy(policy)
    if len(tracked) != len(set(tracked)) or len(tracked) > 4096:
        raise ValueError("duplicate or excessive tracked paths")
    selected = []
    for name in tracked:
        if is_selected(name):
            strict_path(name)
            if name not in EXPLICIT_PATHS | STACK_PATHS and asset_policy(name, policy) is None:
                raise ValueError("blocked: unselected tracked asset requires policy review")
            declaration = asset_policy(name, policy)
            if declaration and declaration['kind'] == 'directory' and name == declaration['path']:
                raise ValueError('directory selector resolved to a file')
            selected.append(name)
    required = EXPLICIT_PATHS | STACK_PATHS | {a["path"] for a in policy["assets"] if a["kind"] == "file"}
    if not required.issubset(selected):
        raise ValueError("missing required selected paths")
    if not 1 <= len(selected) <= MAX_FILES:
        raise ValueError("artifact entry limit exceeded")
    return sorted(selected)


def exclusive_directory(path: Path) -> None:
    parent = open_directory(path.parent)
    try:
        info = os.fstat(parent)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError("output parent must be private and owned")
        os.mkdir(path.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)


def exclusive_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    if len(data) > MAX_TREE_BYTES:
        raise ValueError("output byte limit exceeded")
    parent = open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
    finally:
        os.close(parent)


def strict_copy(destination: Path, manifest: dict, buffers: dict[str, bytes]) -> None:
    validate_manifest(manifest)
    names = {e["path"] for e in manifest["entries"]}
    if set(buffers) != names or any(
            not isinstance(buffers[e["path"]], bytes) or len(buffers[e["path"]]) != e["size"]
            or hashlib.sha256(buffers[e["path"]]).hexdigest() != e["sha256"] for e in manifest["entries"]):
        raise ValueError("copy buffers differ from manifest")
    exclusive_directory(destination)
    directories = {p.as_posix() for name in names for p in PurePosixPath(name).parents if p.as_posix() != '.'}
    for name in sorted(directories, key=lambda name: (name.count('/'), name)):
        exclusive_directory(destination / name)
    for entry in manifest["entries"]:
        exclusive_file(destination / entry["path"], buffers[entry["path"]], int(entry["mode"], 8))


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
