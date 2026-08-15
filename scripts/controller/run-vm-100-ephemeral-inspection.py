#!/usr/bin/env python3
"""Run one fail-closed, inspection-only ephemeral /nix session inside Arch."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
from types import ModuleType
from typing import Any


def _load_helper_from_bytes(module_name: str, source_path: Path, source_bytes: bytes) -> ModuleType:
    module = ModuleType(module_name)
    module.__file__ = str(source_path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        exec(compile(source_bytes, str(source_path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


HELPER_SOURCE = Path(__file__).resolve().with_name("vm_100_ephemeral.py")
_HELPER_BYTES = HELPER_SOURCE.read_bytes()
_EARLY_HELPER_SHA256 = hashlib.sha256(_HELPER_BYTES).hexdigest()
if __name__ == "__main__" and "--help" not in sys.argv:
    positions = [index for index, item in enumerate(sys.argv) if item == "--expected-helper-sha256"]
    if (len(positions) != 1 or positions[0] + 1 >= len(sys.argv)
            or sys.argv[positions[0] + 1] != _EARLY_HELPER_SHA256):
        print("run-vm-100-ephemeral-inspection: helper preflight failed", file=sys.stderr)
        raise SystemExit(1)

_load_helper_from_bytes("vm_100_ephemeral", HELPER_SOURCE, _HELPER_BYTES)
from vm_100_ephemeral import (
    BY_ID, CLEANUP_EVIDENCE_FORMAT, COMPOSE_ARTIFACT_SHA256, INSPECTION_EVIDENCE_FORMAT,
    LIVE_MODE, NIX_VERSION, PROTECTED_DISKS_FORMAT, PUBLIC_KEY, QUALIFICATION_CONFIRMATION,
    QUALIFICATION_MODE, SHA256, canonical_bytes, build_qualification_evidence, descriptor_metrics, load_canonical,
    open_protected, require_absent_nix, select_bootstrap_executables, sha256_bytes, validate_cleanup, validate_disk_snapshot,
    validate_export_request, validate_host_attestation, validate_host_attested_qualification,
    validate_import_observation, validate_inspection_evidence,
    validate_inspection_request, validate_live_qualification, validate_manifest,
    validate_qualification, validate_qualification_request, validate_resources, validate_tar_descriptor,
)

TOOLS = {
    "findmnt": "/usr/bin/findmnt", "fuser": "/usr/bin/fuser", "lsblk": "/usr/bin/lsblk",
    "mount": "/usr/bin/mount", "tar": "/usr/bin/tar", "umount": "/usr/bin/umount",
    "unshare": "/usr/bin/unshare", "wipefs": "/usr/bin/wipefs",
}
CLEAN_ENV = {"HOME": "/root", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NIX_REMOTE": "local", "PATH": "/usr/bin:/bin"}
NIX = Path("/nix")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
PRODUCT_UUID = Path("/sys/class/dmi/id/product_uuid")
PERSISTENT_NIX_PATHS = (
    Path("/etc/nix"), Path("/root/.config/nix"), Path("/root/.nix-profile"), Path("/root/.nix-defexpr"),
    Path("/root/.nix-channels"), Path("/etc/profiles/per-user/root"), Path("/usr/lib/nix/plugins"),
    Path("/usr/lib64/nix/plugins"), Path("/usr/local/lib/nix/plugins"),
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--export-request", required=True, type=Path)
    parser.add_argument("--protected-disks", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bootstrap", required=True, type=Path)
    parser.add_argument("--export", required=True, dest="export_path", type=Path)
    parser.add_argument("--qualification-evidence", type=Path)
    parser.add_argument("--host-attestation", type=Path)
    parser.add_argument("--qualification-request", type=Path)
    parser.add_argument("--qualification-confirmation")
    parser.add_argument("--expected-qualification-product-uuid-sha256")
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-bootstrap-sha256", required=True)
    parser.add_argument("--expected-bootstrap-store-path", required=True)
    parser.add_argument("--expected-export-sha256", required=True)
    parser.add_argument("--expected-qualification-evidence-sha256")
    parser.add_argument("--expected-host-attestation-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-flake-lock-sha256", required=True)
    parser.add_argument("--expected-compose-artifact-sha256", required=True)
    parser.add_argument("--expected-installer-path", required=True)
    parser.add_argument("--expected-toplevel", required=True)
    parser.add_argument("--expected-trusted-public-key", required=True)
    parser.add_argument("--expected-exporter-sha256", required=True)
    parser.add_argument("--expected-runner-sha256", required=True)
    parser.add_argument("--expected-helper-sha256", required=True)
    return parser.parse_args()


def nix_environment(runtime: Path, trusted_public_key: str) -> dict[str, str]:
    config = runtime / "config/nix/empty.conf"
    return {
        "HOME": str(runtime / "home"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "NIX_CONFIG": "\n".join((
            "builders =", "experimental-features = nix-command", "plugin-files =",
            "require-sigs = true", "substituters =",
            f"trusted-public-keys = {trusted_public_key}", "trusted-substituters =",
        )) + "\n",
        "NIX_PATH": "", "NIX_REMOTE": "local", "NIX_USER_CONF_FILES": str(config),
        "PATH": "/usr/bin:/bin", "TMPDIR": str(runtime / "tmp"),
        "XDG_CACHE_HOME": str(runtime / "cache"), "XDG_CONFIG_HOME": str(runtime / "config"),
    }


def reject_persistent_nix_configuration() -> None:
    if any(os.path.lexists(path) for path in PERSISTENT_NIX_PATHS):
        raise ValueError("persistent host Nix configuration, profile, or plugin path is present")


class MountObservationError(ValueError):
    def __init__(self, message: str, mounted: bool):
        super().__init__(message)
        self.mounted = mounted


def validate_mount_result(result: subprocess.CompletedProcess[bytes]) -> bool:
    mounted = result.returncode == 0
    if not mounted:
        try:
            mounted = tmpfs_mounted()
        except Exception:
            mounted = True
    if result.returncode != 0 or result.stdout != b"" or result.stderr != b"":
        raise MountObservationError("bounded executable /nix tmpfs mount failed or emitted diagnostics", mounted)
    return True


def command(name: str, argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([TOOLS[name], *argv], check=check, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLEAN_ENV)


def json_command(name: str, argv: list[str]) -> dict[str, Any]:
    result = command(name, argv)
    if result.stderr:
        raise ValueError(f"{name} observation emitted diagnostics")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError(f"{name} observation is not an object")
    return value


def base_device(source: str) -> str:
    current = str(Path(source).resolve(strict=True))
    for _ in range(32):
        value = json_command("lsblk", ["--bytes", "--json", "--nodeps", "--output", "PATH,PKNAME", current])
        devices = value.get("blockdevices")
        if not isinstance(devices, list) or len(devices) != 1 or not isinstance(devices[0], dict):
            raise ValueError("mounted source device ancestry is ambiguous")
        parent = devices[0].get("pkname")
        if not parent:
            return current
        current = str(Path("/dev") / str(parent))
    raise ValueError("mounted source device ancestry is cyclic")


def mounted_base_devices() -> set[str]:
    value = json_command("findmnt", ["--json", "--output", "SOURCE"])
    filesystems = value.get("filesystems")
    if not isinstance(filesystems, list):
        raise ValueError("mount observation is malformed")
    result: set[str] = set()
    pending = list(filesystems)
    while pending:
        item = pending.pop()
        if not isinstance(item, dict) or not isinstance(item.get("children", []), list):
            raise ValueError("mount observation is malformed")
        source = item.get("source")
        if isinstance(source, str) and source.startswith("/dev/"):
            result.add(base_device(source.split("[", 1)[0]))
        pending.extend(item.get("children", []))
    return result


def observe_disk(by_id: str, games_device: str) -> dict[str, Any]:
    if not Path(by_id).is_symlink() or not Path(games_device).is_symlink():
        raise ValueError("candidate or protected games by-id is unavailable")
    candidate_link = Path(by_id)
    games_link = Path(games_device)
    resolved = str(candidate_link.resolve(strict=True))
    games_resolved = str(games_link.resolve(strict=True))
    if not stat.S_ISBLK(Path(resolved).stat().st_mode) or not stat.S_ISBLK(Path(games_resolved).stat().st_mode):
        raise ValueError("candidate or protected games by-id does not resolve to a block device")
    observed = json_command("lsblk", ["--bytes", "--json", "--output", "PATH,TYPE,SIZE,SERIAL,MOUNTPOINTS,FSTYPE", resolved])
    devices = observed.get("blockdevices")
    if not isinstance(devices, list) or len(devices) != 1 or not isinstance(devices[0], dict):
        raise ValueError("candidate observation is ambiguous")
    disk = devices[0]
    if disk.get("path") != resolved:
        raise ValueError("lsblk did not report the exact resolved candidate device")
    wipe = json_command("wipefs", ["--json", "--output", "DEVICE,OFFSET,TYPE,UUID,LABEL", resolved])
    signatures = wipe.get("signatures")
    if not isinstance(signatures, list):
        raise ValueError("wipefs observation is malformed")
    holders_path = Path("/sys/class/block") / Path(resolved).name / "holders"
    holders = sorted(item.name for item in holders_path.iterdir())
    fuser = command("fuser", [resolved], check=False)
    if fuser.returncode != 1 or fuser.stdout != b"" or fuser.stderr != b"":
        raise ValueError("candidate no-opener observation differs or emitted diagnostics")
    if str(candidate_link.resolve(strict=True)) != resolved or str(games_link.resolve(strict=True)) != games_resolved:
        raise ValueError("candidate or protected games by-id changed during exact resolved-device observation")
    snapshot = {
        "byId": by_id, "children": disk.get("children") or [],
        "formatted": bool(signatures) or disk.get("fstype") not in (None, ""), "holders": holders,
        "mounted": any(item not in (None, "") for item in (disk.get("mountpoints") or [])), "openers": [],
        "resolved": resolved, "serial": disk.get("serial"), "sizeBytes": disk.get("size"), "type": disk.get("type"),
    }
    validated = validate_disk_snapshot(snapshot, games_resolved, mounted_base_devices())
    if str(candidate_link.resolve(strict=True)) != resolved or str(games_link.resolve(strict=True)) != games_resolved:
        raise ValueError("candidate or protected games by-id changed after exact resolved-device observation")
    return validated


def daemon_absent() -> bool:
    if Path("/nix/var/nix/daemon-socket/socket").exists():
        return False
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if (proc / "comm").read_text(encoding="ascii").strip() == "nix-daemon":
                return False
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return True


def boot_id() -> str:
    value = BOOT_ID.read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-f-]{36}", value) is None:
        raise ValueError("boot ID is invalid")
    return value


def product_uuid() -> str:
    value = PRODUCT_UUID.read_text(encoding="ascii").strip().lower()
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value) is None:
        raise ValueError("disposable product UUID observation is invalid")
    return value


def mem_available() -> int:
    values = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if ":" in line:
            key, raw = line.split(":", 1)
            values[key] = raw.strip()
    match = re.fullmatch(r"([0-9]+) kB", values.get("MemAvailable", ""))
    if match is None:
        raise ValueError("MemAvailable is unavailable")
    return int(match.group(1)) * 1024


def require_tmpfs_inodes(path: Path, required: int) -> None:
    available = os.statvfs(path).f_favail
    if available < required:
        raise ValueError("mounted ephemeral Nix tmpfs has insufficient inodes")


def directory_identity(descriptor: int) -> tuple[int, int, int, int, int]:
    value = os.fstat(descriptor)
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def open_private_output(root: Path) -> tuple[int, tuple[int, int, int, int, int]]:
    if not root.is_absolute():
        raise ValueError("output root path must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in root.parts[1:]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        value = os.fstat(descriptor)
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_gid != 0
                or stat.S_IMODE(value.st_mode) != 0o700 or value.st_nlink < 1 or os.listdir(descriptor) != []):
            raise ValueError("output root must be an existing empty root-owned mode-0700 directory")
        return descriptor, directory_identity(descriptor)
    except Exception:
        os.close(descriptor)
        raise


def verify_private_output(root: Path, descriptor: int, identity: tuple[int, int, int, int, int], expected_names: set[str]) -> None:
    if directory_identity(descriptor) != identity or set(os.listdir(descriptor)) != expected_names:
        raise ValueError("pinned output directory identity, metadata, or entries changed")
    reopened = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in root.parts[1:]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=reopened)
            os.close(reopened)
            reopened = next_descriptor
        if directory_identity(reopened) != identity:
            raise ValueError("output pathname no longer resolves to pinned directory")
    finally:
        os.close(reopened)


def write_evidence(directory: int, name: str, value: dict[str, Any]) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(descriptor, "wb") as output:
        output.write(canonical_bytes(value) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    os.fsync(directory)


def verify_import(nix: str, manifest: dict[str, Any], imported_paths: set[str], environment: dict[str, str]) -> None:
    expected = {item["path"] for item in manifest["closure"]}
    if imported_paths != expected:
        raise ValueError("nix-store import output differs from the exact closure")
    roots = [manifest["installerPath"], manifest["toplevel"], *manifest["bootstrapPaths"]]
    recursive_result = subprocess.run([nix, "path-info", "--recursive", "--json", "--json-format", "1", "--sigs", *roots], check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    if recursive_result.returncode != 0 or recursive_result.stderr:
        raise ValueError("pinned Nix recursive path-info failed or emitted diagnostics")
    try:
        recursive_info = json.loads(recursive_result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("pinned Nix recursive path-info returned malformed JSON") from error
    if not isinstance(recursive_info, dict):
        raise ValueError("pinned Nix recursive path-info returned an ambiguous value")
    observed = set(recursive_info)
    physical = {str(item) for item in Path("/nix/store").iterdir() if item.name != ".links"}
    validate_import_observation(expected, observed, physical, True)
    by_path = {item["path"]: item for item in manifest["closure"]}
    signer = manifest["trustedKeyName"]
    if set(recursive_info) != expected:
        raise ValueError("imported recursive path-info set differs")
    for path in sorted(expected):
        entry = by_path[path]
        info = recursive_info[path]
        if (not isinstance(info, dict) or info.get("narHash") != entry["narHash"] or info.get("narSize") != entry["narSize"]
                or sorted(info.get("references", [])) != entry["references"] or sorted(info.get("signatures", [])) != entry["signatures"]
                or not any(item.startswith(signer + ":") for item in info.get("signatures", []))):
            raise ValueError("imported closure path-info hash, references, size, or signature differs")
    result = subprocess.run([nix, "store", "verify", "--quiet", "--sigs-needed", "1", *sorted(expected)], check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    validate_import_observation(expected, observed, physical, result.returncode == 0 and result.stdout == b"" and result.stderr == b"")


def copy_descriptor(source: int, directory: Path, name: str, expected: dict[str, object]) -> int:
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        output = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    before = os.fstat(source)
    digest = hashlib.sha256()
    size = 0
    os.lseek(source, 0, os.SEEK_SET)
    try:
        while chunk := os.read(source, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                view = view[written:]
        os.fsync(output)
        os.fchmod(output, 0o400)
        after = os.fstat(source)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("protected transport input changed while copied")
        metrics = {"bytes": size, "sha256": digest.hexdigest()}
        if metrics != expected:
            raise ValueError("consumed transport bytes differ from exact manifest metrics")
        os.lseek(output, 0, os.SEEK_SET)
        if descriptor_metrics(output, "immutable tmpfs transport copy") != expected:
            raise ValueError("immutable tmpfs transport copy differs after fsync")
        return output
    except Exception:
        os.close(output)
        raise


def write_transport_input(directory: Path, name: str, raw: bytes) -> Path:
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)
    return directory / name


def process_group_absent(process: subprocess.Popen[bytes] | None) -> bool:
    if process is None:
        return True
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def tmpfs_mounted() -> bool:
    result = command("findmnt", ["--noheadings", "--mountpoint", "/nix"], check=False)
    if result.returncode == 0 and result.stdout != b"" and result.stderr == b"":
        return True
    if result.returncode == 1 and result.stdout == b"" and result.stderr == b"":
        return False
    raise ValueError("/nix mount observation is ambiguous or emitted diagnostics")


def tmpfs_absent() -> bool:
    try:
        return not tmpfs_mounted()
    except Exception:
        return False


def main() -> None:
    args = arguments()
    os.umask(0o077)
    session_mode = LIVE_MODE
    inspection: dict[str, Any] = {
        "bootIdStable": False, "candidate": None, "candidateIdentityStable": False, "cleanupEvidence": "cleanup-evidence.json",
        "commit": args.expected_commit, "format": INSPECTION_EVIDENCE_FORMAT, "helperSha256": args.expected_helper_sha256, "importVerified": False,
        "installerExitCode": None, "manifestSha256": args.expected_manifest_sha256, "mode": session_mode, "result": "failed",
    }
    before_boot: str | None = None
    child: subprocess.Popen[bytes] | None = None
    mounted = False
    created = False
    failure: Exception | None = None
    output_safe = False
    output_descriptor: int | None = None
    output_identity: tuple[int, int, int, int, int] | None = None
    bootstrap_source: int | None = None
    export_source: int | None = None
    bootstrap_copy: int | None = None
    export_copy: int | None = None
    bootstrap_metric: dict[str, object] | None = None
    export_metric: dict[str, object] | None = None
    qualification_request_raw: bytes | None = None
    qualification_product_uuid: str | None = None
    host_attestation_sha256: str | None = None
    manifest: dict[str, Any] | None = None
    try:
        if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("runner requires root on exact x86_64-linux")
        if any(name.startswith("NIX_") or name == "VM100_CANDIDATE_INSTALL_CONFIRMED" for name in os.environ):
            raise ValueError("Nix or installation environment injection is forbidden")
        for path in TOOLS.values():
            if not Path(path).is_file() or not os.access(path, os.X_OK):
                raise ValueError("a fixed runner executable is unavailable")
        if PUBLIC_KEY.fullmatch(args.expected_trusted_public_key or "") is None or SHA256.fullmatch(args.expected_host_attestation_sha256 or "") is None:
            raise ValueError("independently expected trusted public key or host-attestation hash is invalid")
        script_root = Path(__file__).resolve().parent
        actual_runner_sha = sha256_bytes(Path(__file__).read_bytes())
        actual_exporter_sha = sha256_bytes((script_root / "export-vm-100-ephemeral-inspection.py").read_bytes())
        actual_helper_sha = sha256_bytes(_HELPER_BYTES)
        if (SHA256.fullmatch(args.expected_runner_sha256 or "") is None or SHA256.fullmatch(args.expected_exporter_sha256 or "") is None
                or SHA256.fullmatch(args.expected_helper_sha256 or "") is None or actual_runner_sha != args.expected_runner_sha256
                or actual_exporter_sha != args.expected_exporter_sha256 or actual_helper_sha != args.expected_helper_sha256
                or actual_helper_sha != _EARLY_HELPER_SHA256):
            raise ValueError("independently expected exporter, runner, or helper hash differs")
        output_descriptor, output_identity = open_private_output(args.output_root)
        output_safe = True
        before_boot = boot_id()
        reject_persistent_nix_configuration()
        protected_inputs = [args.request, args.export_request, args.protected_disks, args.manifest, args.bootstrap, args.export_path]
        if args.qualification_evidence is not None:
            protected_inputs.append(args.qualification_evidence)
        if args.host_attestation is not None:
            protected_inputs.append(args.host_attestation)
        if args.qualification_request is not None:
            protected_inputs.append(args.qualification_request)
        if any(not item.is_absolute() for item in protected_inputs):
            raise ValueError("every protected input path must be absolute")
        request, request_raw = load_canonical(args.request, "inspection request", owner=0, maximum=16 * 1024)
        request = validate_inspection_request(request)
        export_request, export_request_raw = load_canonical(args.export_request, "export request", owner=0, maximum=64 * 1024)
        export_request = validate_export_request(export_request)
        session_mode = export_request["mode"]
        inspection["mode"] = session_mode
        protected, protected_raw = load_canonical(args.protected_disks, "protected disk input", owner=0, maximum=16 * 1024)
        if (set(protected) != {"format", "gamesDevice"} or protected["format"] != PROTECTED_DISKS_FORMAT
                or not isinstance(protected["gamesDevice"], str) or BY_ID.fullmatch(protected["gamesDevice"]) is None):
            raise ValueError("protected disk input shape differs")
        manifest_value, manifest_raw = load_canonical(args.manifest, "export manifest", owner=0)
        manifest = validate_manifest(manifest_value)
        manifest_sha = sha256_bytes(manifest_raw)
        if SHA256.fullmatch(args.expected_manifest_sha256 or "") is None or manifest_sha != args.expected_manifest_sha256:
            raise ValueError("manifest exact SHA-256 differs")
        if manifest["mode"] != session_mode or manifest["requestSha256"] != sha256_bytes(export_request_raw) or manifest["inspectionRequestSha256"] != sha256_bytes(request_raw):
            raise ValueError("manifest does not bind the exact mode and canonical requests")
        independently_expected = {
            "commit": args.expected_commit, "flakeLockSha256": args.expected_flake_lock_sha256,
            "composeArtifactSha256": args.expected_compose_artifact_sha256, "installerPath": args.expected_installer_path,
            "toplevel": args.expected_toplevel, "trustedPublicKey": args.expected_trusted_public_key,
            "helperSha256": args.expected_helper_sha256,
            "bootstrapStorePath": args.expected_bootstrap_store_path,
            "qualificationHostAttestationSha256": args.expected_host_attestation_sha256,
        }
        if any(manifest[key] != value for key, value in independently_expected.items()) or args.expected_compose_artifact_sha256 != COMPOSE_ARTIFACT_SHA256:
            raise ValueError("independent expected source, store, or trust identity differs")
        for key, manifest_key in (("commit", "commit"), ("flakeLockSha256", "flakeLockSha256"), ("composeArtifactSha256", "composeArtifactSha256"), ("installerPath", "installerPath"), ("candidateToplevel", "toplevel"), ("qualificationEvidenceSha256", "qualificationEvidenceSha256"), ("qualificationHostAttestationSha256", "qualificationHostAttestationSha256"), ("helperSha256", "helperSha256"), ("bootstrapStorePath", "bootstrapStorePath"), ("trustedPublicKey", "trustedPublicKey")):
            if export_request[key] != manifest[manifest_key]:
                raise ValueError("export request and manifest identities differ")
        if (export_request["bootstrapStorePath"] != args.expected_bootstrap_store_path
                or export_request["bootstrapStorePath"] not in manifest["bootstrapPaths"]):
            raise ValueError("independently expected export bootstrap root is absent from manifest bootstrap closure")
        bootstrap_source = open_protected(args.bootstrap, "bootstrap archive", owner=0)
        export_source = open_protected(args.export_path, "closure export", owner=0)
        bootstrap_metric = descriptor_metrics(bootstrap_source, "bootstrap archive")
        export_metric = descriptor_metrics(export_source, "closure export")
        if (bootstrap_metric["sha256"] != args.expected_bootstrap_sha256 or export_metric["sha256"] != args.expected_export_sha256
                or bootstrap_metric != manifest["artifacts"]["bootstrap"] or export_metric != manifest["artifacts"]["export"]):
            raise ValueError("protected transport descriptors differ from independent and manifest byte identities")
        if session_mode == QUALIFICATION_MODE:
            if (args.qualification_evidence is not None or args.expected_qualification_evidence_sha256 is not None
                    or args.qualification_request is None or args.host_attestation is None
                    or args.qualification_confirmation != QUALIFICATION_CONFIRMATION
                    or args.expected_qualification_product_uuid_sha256 is None
                    or SHA256.fullmatch(args.expected_qualification_product_uuid_sha256) is None):
                raise ValueError("qualification mode requires only the explicit disposable VMID 9900 qualification controls")
            qualification_request, qualification_request_raw = load_canonical(args.qualification_request, "qualification request", owner=0, maximum=16 * 1024)
            qualification_request = validate_qualification_request(qualification_request)
            host_attestation, host_attestation_raw = load_canonical(args.host_attestation, "qualification host attestation", owner=0, maximum=64 * 1024)
            host_attestation = validate_host_attestation(host_attestation)
            host_attestation_sha256 = sha256_bytes(host_attestation_raw)
            observed_product_uuid = product_uuid()
            validate_host_attested_qualification(qualification_request, host_attestation, observed_product_uuid, host_attestation_sha256, args.expected_host_attestation_sha256, manifest)
            if (sha256_bytes(observed_product_uuid.encode()) != args.expected_qualification_product_uuid_sha256
                    or qualification_request["confirmation"] != args.qualification_confirmation):
                raise ValueError("host-attested VMID 9900 identity, guest observation, or explicit confirmation differs")
            qualification_product_uuid = observed_product_uuid
        else:
            if (args.qualification_evidence is None or args.expected_qualification_evidence_sha256 is None
                    or args.qualification_request is not None or args.host_attestation is not None or args.qualification_confirmation is not None
                    or args.expected_qualification_product_uuid_sha256 is not None):
                raise ValueError("live inspection requires exact prior qualification evidence and forbids qualification controls")
            qualification, qualification_raw = load_canonical(args.qualification_evidence, "qualification evidence", owner=0, maximum=64 * 1024)
            qualification = validate_qualification(qualification)
            qualification_sha = sha256_bytes(qualification_raw)
            if (qualification_sha != args.expected_qualification_evidence_sha256
                    or qualification_sha != manifest["qualificationEvidenceSha256"]):
                raise ValueError("live inspection qualification evidence byte hash differs")
            validate_live_qualification(qualification, manifest, args.expected_exporter_sha256, args.expected_runner_sha256, args.expected_trusted_public_key)
        require_absent_nix(NIX)
        if not daemon_absent():
            raise ValueError("a Nix daemon or socket is present")
        resources = manifest["resources"]
        # The persistent root may be an inode-less filesystem such as Btrfs.
        # Memory is checked before disk observation; tmpfs inode capacity is
        # checked against the mounted filesystem itself below.
        validate_resources(manifest, mem_available(), resources["requiredInodes"])
        first_disk = observe_disk(request["device"], protected["gamesDevice"])
        inspection["candidate"] = {
            "blank": True, "byId": first_disk["byId"], "holdersAbsent": True, "mountedSourcesDistinct": True,
            "openersAbsent": True, "protectedGamesDistinct": True, "resolved": first_disk["resolved"],
            "serial": first_disk["serial"], "sizeBytes": first_disk["sizeBytes"],
        }
        NIX.mkdir(mode=0o755)
        created = True
        option = f"rw,nosuid,nodev,exec,size={resources['tmpfsBytes']},nr_inodes={resources['requiredInodes'] + 1},mode=0755"
        mount_result = command("mount", ["-t", "tmpfs", "-o", option, "tmpfs", "/nix"], check=False)
        try:
            mounted = validate_mount_result(mount_result)
        except MountObservationError as error:
            mounted = error.mounted
            raise
        require_tmpfs_inodes(NIX, resources["requiredInodes"])
        transport = NIX / ".transport"
        transport.mkdir(mode=0o700)
        runtime = NIX / ".runtime"
        for path in (runtime, runtime / "home", runtime / "tmp", runtime / "cache", runtime / "config", runtime / "config/nix"):
            path.mkdir(mode=0o700)
        empty_config = runtime / "config/nix/empty.conf"
        empty_config.write_bytes(b"")
        empty_config.chmod(0o400)
        isolated_nix_env = nix_environment(runtime, args.expected_trusted_public_key)
        bootstrap_copy = copy_descriptor(bootstrap_source, transport, "bootstrap.tar", manifest["artifacts"]["bootstrap"])
        export_copy = copy_descriptor(export_source, transport, "closure.export", manifest["artifacts"]["export"])
        os.close(bootstrap_source); bootstrap_source = None
        os.close(export_source); export_source = None
        validate_tar_descriptor(bootstrap_copy, set(manifest["bootstrapPaths"]))
        os.lseek(bootstrap_copy, 0, os.SEEK_SET)
        tar_result = subprocess.run(
            [TOOLS["tar"], "--extract", "--file", f"/proc/self/fd/{bootstrap_copy}", "--directory", "/", "--numeric-owner", "--same-owner", "--no-overwrite-dir"],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLEAN_ENV, pass_fds=(bootstrap_copy,),
        )
        if tar_result.returncode != 0 or tar_result.stdout or tar_result.stderr:
            raise ValueError("validated descriptor-backed bootstrap extraction failed or emitted diagnostics")
        nix, nix_store = select_bootstrap_executables(manifest["bootstrapStorePath"], manifest["bootstrapPaths"])
        if (not Path(nix).is_file() or not Path(nix_store).is_file()
                or not os.access(nix, os.X_OK) or not os.access(nix_store, os.X_OK)):
            raise ValueError("exact bound bootstrap store path does not provide executable nix and nix-store")
        version = subprocess.run([nix, "--version"], check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=isolated_nix_env)
        if version.returncode != 0 or version.stdout != f"nix (Nix) {NIX_VERSION}\n".encode() or version.stderr:
            raise ValueError("literal bootstrap Nix version differs")
        init = subprocess.run([nix_store, "--init"], check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=isolated_nix_env)
        if init.returncode != 0 or init.stdout or init.stderr:
            raise ValueError("ephemeral local Nix database initialization failed or emitted diagnostics")
        os.lseek(export_copy, 0, os.SEEK_SET)
        with os.fdopen(os.dup(export_copy), "rb") as source:
            imported = subprocess.run([nix_store, "--option", "require-sigs", "true", "--option", "trusted-public-keys", args.expected_trusted_public_key, "--import"], check=False, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=isolated_nix_env)
        if imported.returncode != 0 or imported.stderr:
            raise ValueError("signed descriptor-backed closure import failed or emitted diagnostics")
        imported_paths = set(imported.stdout.decode("utf-8", "strict").splitlines())
        verify_import(nix, manifest, imported_paths, isolated_nix_env)
        inspection["importVerified"] = True
        if boot_id() != before_boot or observe_disk(request["device"], protected["gamesDevice"]) != first_disk:
            raise ValueError("boot ID or candidate identity changed before inspection invocation")
        inspection["candidateIdentityStable"] = True
        installer = manifest["installerPath"] + "/bin/vm-100-candidate-install"
        if not Path(installer).is_file() or not os.access(installer, os.X_OK):
            raise ValueError("literal installer is unavailable after exact import")
        request_copy = write_transport_input(transport, "inspection-request.json", request_raw)
        protected_copy = write_transport_input(transport, "protected-disks.json", protected_raw)
        handoff_raw = canonical_bytes({
            "bootIdSha256": sha256_bytes(before_boot.encode()), "device": request["device"],
            "format": "home-lab-vm-100-ephemeral-inspection-handoff-v1", "mode": "inspect",
            "resolvedDevice": first_disk["resolved"], "serial": first_disk["serial"], "sizeBytes": first_disk["sizeBytes"],
        }) + b"\n"
        handoff_copy = write_transport_input(transport, "inspection-handoff.json", handoff_raw)
        child = subprocess.Popen(
            [TOOLS["unshare"], "--net", "--", installer, "--request", str(request_copy), "--protected-disk-input", str(protected_copy), "--inspection-handoff", str(handoff_copy)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=isolated_nix_env, start_new_session=True,
        )
        stdout, stderr = child.communicate(timeout=60)
        inspection["installerExitCode"] = child.returncode
        if child.returncode != 0 or stderr or stdout != f"vm-100-candidate-install=inspection-passed device={request['device']}\n".encode():
            raise ValueError("literal inspection-only installer invocation failed")
        if boot_id() != before_boot or observe_disk(request["device"], protected["gamesDevice"]) != first_disk:
            raise ValueError("boot ID or candidate identity changed during inspection")
        inspection["bootIdStable"] = True
        inspection["result"] = "passed"
    except Exception as error:
        failure = error
    finally:
        for descriptor_name in ("bootstrap_source", "export_source", "bootstrap_copy", "export_copy"):
            descriptor = locals()[descriptor_name]
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if child is not None and not process_group_absent(child):
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            if not process_group_absent(child):
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        child_group_absent = process_group_absent(child)
        if mounted:
            result = command("umount", ["--", "/nix"], check=False)
            if result.returncode == 0 and result.stdout == b"" and result.stderr == b"":
                mounted = False
        tmpfs_unmounted = tmpfs_absent() if created else True
        if created and tmpfs_unmounted:
            try:
                NIX.rmdir()
            except OSError:
                pass
        nix_absent = not os.path.lexists(NIX)
        try:
            boot_stable = before_boot is not None and boot_id() == before_boot
        except Exception:
            boot_stable = False
        cleanup = {
            "bootIdStable": boot_stable, "childProcessGroupAbsent": child_group_absent,
            "format": CLEANUP_EVIDENCE_FORMAT, "nixAbsent": nix_absent,
            "result": "passed" if boot_stable and child_group_absent and nix_absent and tmpfs_unmounted else "failed",
            "temporaryPathsAbsent": nix_absent, "tmpfsUnmounted": tmpfs_unmounted,
        }
        evidence_valid = True
        qualification: dict[str, Any] | None = None
        try:
            validate_inspection_evidence(inspection)
            validate_cleanup(cleanup)
            if (session_mode == QUALIFICATION_MODE and failure is None and inspection["result"] == "passed"
                    and cleanup["result"] == "passed" and manifest is not None and bootstrap_metric is not None
                    and export_metric is not None and qualification_request_raw is not None and qualification_product_uuid is not None
                    and host_attestation_sha256 is not None):
                qualification = build_qualification_evidence(
                    manifest=manifest, inspection_passed=True, cleanup_passed=True,
                    bootstrap_sha256=str(bootstrap_metric["sha256"]), export_sha256=str(export_metric["sha256"]),
                    exporter_sha256=args.expected_exporter_sha256, helper_sha256=args.expected_helper_sha256,
                    runner_sha256=args.expected_runner_sha256,
                    trusted_public_key=args.expected_trusted_public_key, product_uuid=qualification_product_uuid,
                    qualification_request_sha256=sha256_bytes(qualification_request_raw),
                    host_attestation_sha256=host_attestation_sha256,
                    observed_at=dt.datetime.now(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    manifest_sha256=args.expected_manifest_sha256,
                )
        except Exception as evidence_error:
            evidence_valid = False
            if failure is None:
                failure = evidence_error
        if output_safe and evidence_valid and output_descriptor is not None and output_identity is not None:
            try:
                verify_private_output(args.output_root, output_descriptor, output_identity, set())
                write_evidence(output_descriptor, "inspection-evidence.json", inspection)
                write_evidence(output_descriptor, "cleanup-evidence.json", cleanup)
                published = {"inspection-evidence.json", "cleanup-evidence.json"}
                if qualification is not None:
                    write_evidence(output_descriptor, "qualification-evidence.json", qualification)
                    published.add("qualification-evidence.json")
                verify_private_output(args.output_root, output_descriptor, output_identity, published)
            except Exception as evidence_error:
                if failure is None:
                    failure = evidence_error
        if output_descriptor is not None:
            try:
                os.close(output_descriptor)
            except OSError:
                pass
        if cleanup["result"] != "passed" and failure is None:
            failure = ValueError("ephemeral Nix cleanup proof failed")
    if failure is not None:
        print("run-vm-100-ephemeral-inspection: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
    print(f"inspection_evidence={args.output_root / 'inspection-evidence.json'}")
    print(f"cleanup_evidence={args.output_root / 'cleanup-evidence.json'}")
    if session_mode == QUALIFICATION_MODE:
        print(f"qualification_evidence={args.output_root / 'qualification-evidence.json'}")


if __name__ == "__main__":
    main()
