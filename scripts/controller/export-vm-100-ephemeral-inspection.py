#!/usr/bin/env python3
"""Build and export one exact signed x86_64 VM 100 inspection closure.

This runs only on the Proxmox x86_64 builder. It never reads secret values and
creates only mode-0600 artifacts in an already-private output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
from types import ModuleType


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
        print("export-vm-100-ephemeral-inspection: helper preflight failed", file=sys.stderr)
        raise SystemExit(1)

_load_helper_from_bytes("vm_100_ephemeral", HELPER_SOURCE, _HELPER_BYTES)
from vm_100_ephemeral import (
    COMPOSE_ARTIFACT_SHA256, EXPORT_EVIDENCE_FORMAT, EXPORT_MANIFEST_FORMAT,
    INSTALL_ATTRIBUTE, NIX_VERSION, SYSTEM, TOPLEVEL_ATTRIBUTE, canonical_bytes, load_canonical, open_protected,
    sha256_bytes, validate_export_evidence, validate_export_request, validate_host_attestation,
    validate_inspection_request, validate_manifest,
)

NIX = "/nix/var/nix/profiles/default/bin/nix"
NIX_STORE = "/nix/var/nix/profiles/default/bin/nix-store"
GIT = "/usr/bin/git"
TAR = "/usr/bin/tar"
FIND = "/usr/bin/find"
SIGNING_KEY = Path("/var/lib/home-lab/protected/vm-100-closure-signing-key")
ENV = {"HOME": "/root", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/nix/var/nix/profiles/default/bin:/usr/bin:/bin"}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source-root", required=True, type=Path)
    result.add_argument("--request", required=True, type=Path)
    result.add_argument("--inspection-request", required=True, type=Path)
    result.add_argument("--host-attestation", required=True, type=Path)
    result.add_argument("--output-root", required=True, type=Path)
    result.add_argument("--expected-commit", required=True)
    result.add_argument("--expected-flake-lock-sha256", required=True)
    result.add_argument("--expected-compose-artifact-sha256", required=True)
    result.add_argument("--expected-installer-path", required=True)
    result.add_argument("--expected-toplevel", required=True)
    result.add_argument("--expected-bootstrap-store-path", required=True)
    result.add_argument("--expected-trusted-public-key", required=True)
    result.add_argument("--expected-host-attestation-sha256", required=True)
    result.add_argument("--expected-helper-sha256", required=True)
    return result


def run(argv: list[str], *, input_file=None) -> bytes:
    result = subprocess.run(argv, check=True, stdin=input_file or subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if result.stderr:
        # Build diagnostics can reveal local paths and are intentionally not copied to evidence.
        raise ValueError("fixed exporter command emitted diagnostics")
    return result.stdout


def one_line(argv: list[str]) -> str:
    raw = run(argv)
    stripped = raw[:-1] if raw.endswith(b"\n") else raw
    if not stripped or b"\n" in stripped:
        raise ValueError("fixed exporter query returned an ambiguous result")
    return stripped.decode("utf-8", "strict")


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def assert_private_output(root: Path) -> None:
    value = root.stat(follow_symlinks=False)
    if not root.is_absolute() or not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_gid != 0 or stat.S_IMODE(value.st_mode) != 0o700:
        raise ValueError("output root must be an existing root-owned mode-0700 directory")
    if any(root.iterdir()):
        raise ValueError("output root must be empty")


def write_exclusive(root: Path, name: str, raw: bytes) -> Path:
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)
    return root / name


def query_closure(roots: list[str], signer: str) -> list[dict[str, object]]:
    raw = run([NIX, "path-info", "--recursive", "--json", "--json-format", "1", "--sigs", *roots])
    try:
        observed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("pinned Nix path-info returned malformed JSON") from error
    if not isinstance(observed, dict) or not observed:
        raise ValueError("pinned Nix path-info returned an empty or ambiguous closure")
    closure = set(observed)
    entries = []
    for path in sorted(closure):
        info = observed[path]
        if not isinstance(info, dict):
            raise ValueError("pinned Nix path-info entry is malformed")
        references = sorted(info.get("references", []))
        signatures = sorted(info.get("signatures", []))
        nar_hash = info.get("narHash")
        nar_size = info.get("narSize")
        if (not signatures or not any(item.startswith(signer + ":") for item in signatures)
                or not isinstance(nar_hash, str) or not isinstance(nar_size, int)):
            raise ValueError("closure path lacks exact hash, size, or trusted signature")
        entries.append({"narHash": nar_hash, "narSize": nar_size, "path": path, "references": references, "registrationSize": nar_size, "signatures": signatures})
    if any(not set(entry["references"]).issubset(closure) for entry in entries):
        raise ValueError("recursive closure query is incomplete")
    return entries


def main() -> None:
    args = parser().parse_args()
    os.umask(0o077)
    helper_sha256 = sha256_bytes(_HELPER_BYTES)
    if helper_sha256 != _EARLY_HELPER_SHA256 or helper_sha256 != args.expected_helper_sha256:
        raise ValueError("helper source identity changed after early preflight")
    if os.geteuid() != 0 or platform.machine() != "x86_64" or platform.system() != "Linux":
        raise ValueError("exporter requires root on x86_64-linux")
    for executable in (NIX, NIX_STORE, GIT, TAR, FIND):
        if not Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise ValueError("a fixed exporter executable is unavailable")
    signing_descriptor = open_protected(SIGNING_KEY, "fixed closure signing key", owner=0, maximum=64 * 1024)
    if one_line([NIX, "--version"]) != f"nix (Nix) {NIX_VERSION}" or one_line([NIX, "eval", "--raw", "--impure", "--expr", "builtins.currentSystem"]) != SYSTEM:
        raise ValueError("fixed Nix version or builder system differs")
    source = args.source_root.resolve(strict=True)
    output_root = args.output_root.resolve(strict=True)
    if source == output_root or source in output_root.parents or output_root in source.parents:
        raise ValueError("protected export output must not overlap the exact source checkout")
    assert_private_output(args.output_root)
    if not args.request.is_absolute() or not args.inspection_request.is_absolute() or not args.host_attestation.is_absolute():
        raise ValueError("protected request and host-attestation paths must be absolute")
    request, request_raw = load_canonical(args.request, "export request", owner=0, maximum=64 * 1024)
    request = validate_export_request(request)
    inspection_request, inspection_request_raw = load_canonical(args.inspection_request, "inspection request", owner=0, maximum=16 * 1024)
    validate_inspection_request(inspection_request)
    host_attestation, host_attestation_raw = load_canonical(args.host_attestation, "qualification host attestation", owner=0, maximum=64 * 1024)
    validate_host_attestation(host_attestation)
    host_attestation_sha256 = sha256_bytes(host_attestation_raw)
    exact = {
        "commit": args.expected_commit, "flakeLockSha256": args.expected_flake_lock_sha256,
        "composeArtifactSha256": args.expected_compose_artifact_sha256,
        "installerPath": args.expected_installer_path, "candidateToplevel": args.expected_toplevel,
        "bootstrapStorePath": args.expected_bootstrap_store_path, "trustedPublicKey": args.expected_trusted_public_key,
        "qualificationHostAttestationSha256": args.expected_host_attestation_sha256,
        "helperSha256": args.expected_helper_sha256,
    }
    if (any(request[key] != value for key, value in exact.items()) or host_attestation_sha256 != args.expected_host_attestation_sha256
            or host_attestation_sha256 != request["qualificationHostAttestationSha256"]
            or host_attestation["commit"] != request["commit"]):
        raise ValueError("independent exporter or host-attestation expectations differ from canonical request")
    if request["installerAttribute"] != INSTALL_ATTRIBUTE or request["toplevelAttribute"] != TOPLEVEL_ATTRIBUTE or request["system"] != SYSTEM or args.expected_compose_artifact_sha256 != COMPOSE_ARTIFACT_SHA256:
        raise ValueError("fixed exporter identity differs")
    head = one_line([GIT, "-C", str(source), "rev-parse", "HEAD"])
    upstream = one_line([GIT, "-C", str(source), "rev-parse", "refs/remotes/origin/main"])
    status = run([GIT, "-C", str(source), "status", "--porcelain"])
    if head != request["commit"] or upstream != request["commit"] or status != b"":
        raise ValueError("source is not the exact clean pushed commit")
    if file_sha(source / "nix/flake.lock") != request["flakeLockSha256"]:
        raise ValueError("flake.lock SHA-256 differs")
    artifact = (source / "nix/compose-artifact.sha256").read_text(encoding="ascii")
    if artifact != COMPOSE_ARTIFACT_SHA256 + "\n":
        raise ValueError("tracked Compose artifact freshness identity differs")
    flake = f"path:{source / 'nix'}"
    common = ["--no-link", "--print-out-paths", "--offline", "--no-substitute", "--quiet"]
    installer = one_line([NIX, "build", f"{flake}#{INSTALL_ATTRIBUTE}", *common])
    toplevel = one_line([NIX, "build", f"{flake}#{TOPLEVEL_ATTRIBUTE}", *common])
    if installer != request["installerPath"] or toplevel != request["candidateToplevel"]:
        raise ValueError("built installer or candidate toplevel differs from the exact request")
    bootstrap = request["bootstrapStorePath"]
    if one_line([NIX_STORE, "--query", "--resolve", bootstrap]) != bootstrap:
        raise ValueError("bootstrap store path is not valid")
    signer = request["trustedPublicKey"].split(":", 1)[0]
    # Sign every recursively referenced path with the fixed protected key. The
    # key value is never read by Python, printed, or serialized.
    signing_before = os.fstat(signing_descriptor)
    try:
        sign = subprocess.run([NIX, "store", "sign", "--quiet", "--recursive", "--key-file", f"/proc/self/fd/{signing_descriptor}", bootstrap, installer, toplevel], check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, pass_fds=(signing_descriptor,))
        signing_after = os.fstat(signing_descriptor)
    finally:
        os.close(signing_descriptor)
    if (signing_before.st_dev, signing_before.st_ino, signing_before.st_mode, signing_before.st_uid, signing_before.st_gid, signing_before.st_nlink, signing_before.st_size, signing_before.st_mtime_ns, signing_before.st_ctime_ns) != (signing_after.st_dev, signing_after.st_ino, signing_after.st_mode, signing_after.st_uid, signing_after.st_gid, signing_after.st_nlink, signing_after.st_size, signing_after.st_mtime_ns, signing_after.st_ctime_ns):
        raise ValueError("fixed closure signing key changed during signing")
    if sign.returncode != 0 or sign.stdout or sign.stderr:
        raise ValueError("fixed descriptor-backed recursive closure signing failed")
    entries = query_closure([bootstrap, installer, toplevel], signer)
    paths = {entry["path"] for entry in entries}
    bootstrap_paths = sorted(run([NIX_STORE, "--query", "--requisites", bootstrap]).decode().splitlines())
    if not set(bootstrap_paths).issubset(paths):
        raise ValueError("bootstrap closure is not part of complete export")
    bootstrap_tar = args.output_root / "bootstrap.tar"
    relative = [item.removeprefix("/") for item in bootstrap_paths]
    tar_result = subprocess.run([TAR, "--sort=name", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner", "--format=gnu", "--hard-dereference", "--create", "--file", str(bootstrap_tar), "--directory=/", *relative], check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if tar_result.returncode != 0 or tar_result.stdout or tar_result.stderr:
        raise ValueError("deterministic bootstrap tar creation failed or emitted diagnostics")
    bootstrap_tar.chmod(0o600)
    export_path = args.output_root / "closure.export"
    with export_path.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        export_result = subprocess.run([NIX_STORE, "--export", *sorted(paths)], check=False, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.PIPE, env=ENV)
        if export_result.returncode != 0 or export_result.stderr:
            raise ValueError("complete closure export failed or emitted diagnostics")
        output.flush(); os.fsync(output.fileno())
    # Count fixed find output records directly; no shell or executable override is involved.
    found = run([FIND, *sorted(paths), "-xdev", "-printf", "."])
    inode_count = len(found)
    closure_bytes = sum(int(item["registrationSize"]) for item in entries)
    bootstrap_size = bootstrap_tar.stat().st_size
    export_size = export_path.stat().st_size
    tmpfs_bytes = closure_bytes * 3 + bootstrap_size + export_size + 512 * 1024 * 1024
    # Reassert the exact source after every build/export operation before evidence.
    final_head = one_line([GIT, "-C", str(source), "rev-parse", "HEAD"])
    final_upstream = one_line([GIT, "-C", str(source), "rev-parse", "refs/remotes/origin/main"])
    final_status = run([GIT, "-C", str(source), "status", "--porcelain"])
    if (final_head != request["commit"] or final_upstream != request["commit"] or final_status != b""
            or file_sha(source / "nix/flake.lock") != request["flakeLockSha256"]
            or (source / "nix/compose-artifact.sha256").read_text(encoding="ascii") != COMPOSE_ARTIFACT_SHA256 + "\n"):
        raise ValueError("source identity changed during exact export")
    manifest = {
        "artifacts": {
            "bootstrap": {"bytes": bootstrap_size, "sha256": file_sha(bootstrap_tar)},
            "export": {"bytes": export_size, "sha256": file_sha(export_path)},
        },
        "bootstrapPaths": bootstrap_paths,
        "bootstrapStorePath": bootstrap,
        "closure": entries,
        "closureBytes": closure_bytes,
        "commit": request["commit"],
        "composeArtifactSha256": request["composeArtifactSha256"],
        "flakeLockSha256": request["flakeLockSha256"],
        "format": EXPORT_MANIFEST_FORMAT,
        "helperSha256": helper_sha256,
        "inspectionRequestSha256": sha256_bytes(inspection_request_raw),
        "installerAttribute": INSTALL_ATTRIBUTE,
        "installerPath": installer,
        "mode": request["mode"],
        "nixVersion": NIX_VERSION,
        "qualificationEvidenceSha256": request["qualificationEvidenceSha256"],
        "qualificationHostAttestationSha256": host_attestation_sha256,
        "requestSha256": sha256_bytes(request_raw),
        "resources": {"headroomBytes": 2 * 1024 ** 3, "requiredInodes": inode_count * 2 + 65536, "tmpfsBytes": tmpfs_bytes},
        "system": SYSTEM,
        "toplevel": toplevel,
        "toplevelAttribute": TOPLEVEL_ATTRIBUTE,
        "trustedKeyName": signer,
        "trustedPublicKey": request["trustedPublicKey"],
    }
    validate_manifest(manifest)
    manifest_raw = canonical_bytes(manifest) + b"\n"
    manifest_path = write_exclusive(args.output_root, "manifest.json", manifest_raw)
    evidence = {
        "artifacts": {
            "bootstrap": manifest["artifacts"]["bootstrap"], "export": manifest["artifacts"]["export"],
            "manifest": {"bytes": len(manifest_raw), "sha256": sha256_bytes(manifest_raw)},
        },
        "closurePathCount": len(entries), "commit": request["commit"], "format": EXPORT_EVIDENCE_FORMAT,
        "helperSha256": helper_sha256, "mode": request["mode"], "qualificationHostAttestationSha256": host_attestation_sha256,
        "requestSha256": sha256_bytes(request_raw), "result": "passed", "system": SYSTEM,
    }
    validate_export_evidence(evidence)
    write_exclusive(args.output_root, "export-evidence.json", canonical_bytes(evidence) + b"\n")
    # The fixed successful output contains paths only, never signatures, keys, or protected values.
    print(f"manifest={manifest_path}")
    print(f"bootstrap={bootstrap_tar}")
    print(f"export={export_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("export-vm-100-ephemeral-inspection: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
