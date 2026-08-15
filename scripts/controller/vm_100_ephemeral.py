#!/usr/bin/env python3
"""Strict, secret-free contracts for VM 100 ephemeral Nix inspection."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any, BinaryIO

EXPORT_REQUEST_FORMAT = "home-lab-vm-100-ephemeral-export-request-v4"
EXPORT_MANIFEST_FORMAT = "home-lab-vm-100-ephemeral-export-manifest-v5"
EXPORT_EVIDENCE_FORMAT = "home-lab-vm-100-ephemeral-export-evidence-v4"
QUALIFICATION_REQUEST_FORMAT = "home-lab-vm-100-ephemeral-qualification-request-v2"
HOST_ATTESTATION_FORMAT = "home-lab-vm-100-ephemeral-host-attestation-v1"
QUALIFICATION_FORMAT = "home-lab-vm-100-ephemeral-qualification-v4"
INSPECTION_EVIDENCE_FORMAT = "home-lab-vm-100-ephemeral-inspection-evidence-v3"
CLEANUP_EVIDENCE_FORMAT = "home-lab-vm-100-ephemeral-cleanup-evidence-v2"
PROTECTED_DISKS_FORMAT = "home-lab-vm-100-protected-disks-v1"
INSTALL_REQUEST_FORMAT = "home-lab-vm-100-candidate-install-v1"
SYSTEM = "x86_64-linux"
LIVE_MODE = "live-inspect"
QUALIFICATION_MODE = "qualification"
QUALIFICATION_CONFIRMATION = "qualify-disposable-vmid-9900-inspection-only"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
STORE_PATH = re.compile(r"^/nix/store/[0-9a-df-np-sv-z]{32}-[^/\x00]+$")
NAR_HASH = re.compile(r"^sha256-[A-Za-z0-9+/=]+$")
BY_ID = re.compile(r"^/dev/disk/by-id/[A-Za-z0-9._:+-]+$")
PUBLIC_KEY = re.compile(r"^[A-Za-z0-9._-]+:[A-Za-z0-9+/=]+$")
INSTALL_ATTRIBUTE = "packages.x86_64-linux.vm-100-candidate-install"
TOPLEVEL_ATTRIBUTE = "nixosConfigurations.vm-100-candidate.config.system.build.toplevel"
COMPOSE_ARTIFACT_SHA256 = "aa550bfd004366bf85f58b661ed26d2a3ba3b72d5f01e4286b6d05117352f086"
EXPECTED_SIZE = 137438953472
EXPECTED_SERIAL = "QUAL-NIXOS-128G"
NIX_VERSION = "2.34.8"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fail(message: str) -> None:
    raise ValueError(message)


def exact_keys(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} shape differs")
    return value


def open_protected(path: Path, label: str, *, owner: int | None = None, maximum: int | None = None) -> int:
    """Open an absolute protected input through no-follow directory descriptors."""
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        fail(f"{label} path must be absolute")
    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    expected_owner = os.geteuid() if owner is None else owner
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != expected_owner
            or (owner is not None and metadata.st_gid != owner) or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1 or (maximum is not None and metadata.st_size > maximum)):
        os.close(descriptor)
        fail(f"{label} metadata differs")
    return descriptor


def descriptor_bytes(descriptor: int, label: str, maximum: int) -> bytes:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > maximum:
            fail(f"{label} is too large")
    after = os.fstat(descriptor)
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        fail(f"{label} changed while read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def descriptor_metrics(descriptor: int, label: str) -> dict[str, int | str]:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    after = os.fstat(descriptor)
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        fail(f"{label} changed while hashed")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return {"bytes": size, "sha256": digest.hexdigest()}


def read_protected(path: Path, label: str, *, owner: int | None = None, maximum: int = 64 * 1024 * 1024) -> bytes:
    descriptor = open_protected(path, label, owner=owner, maximum=maximum)
    try:
        return descriptor_bytes(descriptor, label, maximum)
    finally:
        os.close(descriptor)


def load_canonical(path: Path, label: str, **kwargs: Any) -> tuple[dict[str, Any], bytes]:
    raw = read_protected(path, label, **kwargs)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"{label} is not JSON") from error
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        fail(f"{label} is not canonical JSON")
    return value, raw


def load_canonical_descriptor(descriptor: int, label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    raw = descriptor_bytes(descriptor, label, maximum)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"{label} is not JSON") from error
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        fail(f"{label} is not canonical JSON")
    return value, raw


def validate_inspection_request(value: object) -> dict[str, Any]:
    request = exact_keys(value, {"approvedSerial", "device", "format", "mode", "observedSizeBytes"}, "inspection request")
    if (request["format"] != INSTALL_REQUEST_FORMAT or request["mode"] != "inspect"
            or request["approvedSerial"] != EXPECTED_SERIAL or request["observedSizeBytes"] != EXPECTED_SIZE
            or request["device"] != "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2"):
        fail("only the exact canonical inspect request is permitted")
    return request


def validate_qualification_request(value: object) -> dict[str, Any]:
    request = exact_keys(value, {"confirmation", "disposableProductUuid", "disposableVmId", "format", "hostAttestationSha256", "mode"}, "qualification request")
    if (request["format"] != QUALIFICATION_REQUEST_FORMAT or request["mode"] != QUALIFICATION_MODE
            or request["confirmation"] != QUALIFICATION_CONFIRMATION or request["disposableVmId"] != 9900
            or not isinstance(request["disposableProductUuid"], str) or UUID.fullmatch(request["disposableProductUuid"]) is None
            or SHA256.fullmatch(request["hostAttestationSha256"] or "") is None):
        fail("qualification request does not identify the confirmed disposable VMID 9900")
    return request


def validate_host_attestation(value: object) -> dict[str, Any]:
    keys = {"bios", "candidateSerial", "candidateSizeBytes", "collectedAt", "commit", "format", "machine", "productUuid", "pveConfigSha256", "result", "vmId"}
    attestation = exact_keys(value, keys, "qualification host attestation")
    if (attestation["format"] != HOST_ATTESTATION_FORMAT or attestation["vmId"] != 9900
            or attestation["bios"] != "seabios" or attestation["machine"] != "q35"
            or attestation["candidateSerial"] != EXPECTED_SERIAL or attestation["candidateSizeBytes"] != EXPECTED_SIZE
            or attestation["result"] != "passed" or UUID.fullmatch(attestation["productUuid"] or "") is None
            or COMMIT.fullmatch(attestation["commit"] or "") is None or SHA256.fullmatch(attestation["pveConfigSha256"] or "") is None
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", attestation["collectedAt"] or "") is None):
        fail("host attestation does not bind exact VMID 9900 SeaBIOS/q35/candidate identity")
    return attestation


def validate_host_attested_qualification(qualification_request: dict[str, Any], host_attestation: dict[str, Any],
                                         observed_product_uuid: str, host_attestation_sha256: str,
                                         independently_expected_sha256: str, manifest: dict[str, Any]) -> None:
    validate_qualification_request(qualification_request)
    validate_host_attestation(host_attestation)
    if (host_attestation_sha256 != independently_expected_sha256
            or host_attestation_sha256 != manifest["qualificationHostAttestationSha256"]
            or qualification_request["hostAttestationSha256"] != host_attestation_sha256
            or host_attestation["productUuid"] != observed_product_uuid
            or qualification_request["disposableProductUuid"] != observed_product_uuid
            or host_attestation["commit"] != manifest["commit"]):
        fail("qualification requires independently hashed host attestation matching guest observation")


def validate_export_request(value: object) -> dict[str, Any]:
    keys = {
        "bootstrapStorePath", "candidateToplevel", "commit", "composeArtifactSha256", "flakeLockSha256",
        "format", "helperSha256", "installerAttribute", "installerPath", "mode", "nixVersion", "qualificationEvidenceSha256",
        "qualificationHostAttestationSha256", "system", "toplevelAttribute", "trustedPublicKey",
    }
    request = exact_keys(value, keys, "export request")
    if (request["format"] != EXPORT_REQUEST_FORMAT or request["mode"] not in {LIVE_MODE, QUALIFICATION_MODE}
            or request["system"] != SYSTEM or request["nixVersion"] != NIX_VERSION):
        fail("export request mode, format, or system differs")
    if COMMIT.fullmatch(request["commit"] or "") is None or SHA256.fullmatch(request["flakeLockSha256"] or "") is None:
        fail("export request source identity is invalid")
    if SHA256.fullmatch(request["helperSha256"] or "") is None:
        fail("export request helper hash is invalid")
    if request["composeArtifactSha256"] != COMPOSE_ARTIFACT_SHA256:
        fail("export request Compose artifact differs")
    if request["installerAttribute"] != INSTALL_ATTRIBUTE or request["toplevelAttribute"] != TOPLEVEL_ATTRIBUTE:
        fail("export request attributes differ")
    for key in ("bootstrapStorePath", "candidateToplevel", "installerPath"):
        if not isinstance(request[key], str) or STORE_PATH.fullmatch(request[key]) is None:
            fail(f"export request {key} is not an exact store path")
    qualification = request["qualificationEvidenceSha256"]
    if request["mode"] == QUALIFICATION_MODE:
        if qualification is not None:
            fail("qualification export cannot claim prior qualification evidence")
    elif not isinstance(qualification, str) or SHA256.fullmatch(qualification) is None or qualification == "0" * 64:
        fail("live inspection requires a non-placeholder qualification evidence hash")
    if SHA256.fullmatch(request["qualificationHostAttestationSha256"] or "") is None:
        fail("export request host-attestation hash is invalid")
    key = request["trustedPublicKey"]
    if not isinstance(key, str) or PUBLIC_KEY.fullmatch(key) is None:
        fail("trusted public key is invalid")
    return request


def select_bootstrap_executables(bootstrap_store_path: str, bootstrap_paths: list[str]) -> tuple[str, str]:
    if (STORE_PATH.fullmatch(bootstrap_store_path or "") is None or bootstrap_store_path not in bootstrap_paths
            or bootstrap_paths != sorted(set(bootstrap_paths))):
        fail("exact bootstrap store path is absent from complete bootstrap closure")
    return (bootstrap_store_path + "/bin/nix", bootstrap_store_path + "/bin/nix-store")


def validate_closure_entry(value: object) -> dict[str, Any]:
    entry = exact_keys(value, {"narHash", "narSize", "path", "references", "registrationSize", "signatures"}, "closure entry")
    if not isinstance(entry["path"], str) or STORE_PATH.fullmatch(entry["path"]) is None:
        fail("closure path is invalid")
    references = entry["references"]
    if not isinstance(references, list) or references != sorted(set(references)) or any(STORE_PATH.fullmatch(item or "") is None for item in references):
        fail("closure references are invalid")
    if not isinstance(entry["narHash"], str) or NAR_HASH.fullmatch(entry["narHash"]) is None:
        fail("closure NAR hash is invalid")
    if any(not isinstance(entry[key], int) or isinstance(entry[key], bool) or entry[key] < 0 for key in ("narSize", "registrationSize")):
        fail("closure sizes are invalid")
    signatures = entry["signatures"]
    if not isinstance(signatures, list) or not signatures or signatures != sorted(set(signatures)) or any(not isinstance(item, str) or ":" not in item for item in signatures):
        fail("every closure path must have a signature")
    return entry


def validate_manifest(value: object) -> dict[str, Any]:
    keys = {
        "artifacts", "bootstrapPaths", "bootstrapStorePath", "closure", "closureBytes", "commit", "composeArtifactSha256",
        "flakeLockSha256", "format", "helperSha256", "inspectionRequestSha256", "installerAttribute", "installerPath", "mode",
        "nixVersion", "qualificationEvidenceSha256", "qualificationHostAttestationSha256", "requestSha256",
        "resources", "system", "toplevel", "toplevelAttribute",
        "trustedKeyName", "trustedPublicKey",
    }
    manifest = exact_keys(value, keys, "export manifest")
    if (manifest["format"] != EXPORT_MANIFEST_FORMAT or manifest["system"] != SYSTEM or manifest["nixVersion"] != NIX_VERSION
            or manifest["mode"] not in {LIVE_MODE, QUALIFICATION_MODE}):
        fail("export manifest format, mode, or system differs")
    if (COMMIT.fullmatch(manifest["commit"] or "") is None or SHA256.fullmatch(manifest["flakeLockSha256"] or "") is None
            or SHA256.fullmatch(manifest["requestSha256"] or "") is None or SHA256.fullmatch(manifest["inspectionRequestSha256"] or "") is None
            or SHA256.fullmatch(manifest["helperSha256"] or "") is None):
        fail("export manifest source hashes are invalid")
    qualification = manifest["qualificationEvidenceSha256"]
    if manifest["mode"] == QUALIFICATION_MODE:
        if qualification is not None:
            fail("qualification manifest cannot claim prior qualification")
    elif not isinstance(qualification, str) or SHA256.fullmatch(qualification) is None or qualification == "0" * 64:
        fail("live manifest qualification gate is invalid")
    if (manifest["composeArtifactSha256"] != COMPOSE_ARTIFACT_SHA256 or manifest["installerAttribute"] != INSTALL_ATTRIBUTE
            or manifest["toplevelAttribute"] != TOPLEVEL_ATTRIBUTE or SHA256.fullmatch(manifest["qualificationHostAttestationSha256"] or "") is None):
        fail("export manifest fixed identities differ")
    closure = manifest["closure"]
    if not isinstance(closure, list) or not closure:
        fail("export closure is empty")
    entries = [validate_closure_entry(item) for item in closure]
    paths = [item["path"] for item in entries]
    if paths != sorted(set(paths)):
        fail("export closure paths must be unique and sorted")
    path_set = set(paths)
    if any(not set(item["references"]).issubset(path_set) for item in entries):
        fail("export closure is not reference-complete")
    if manifest["installerPath"] not in path_set or manifest["toplevel"] not in path_set:
        fail("export closure omits installer or toplevel")
    bootstrap = manifest["bootstrapPaths"]
    if (not isinstance(bootstrap, list) or not bootstrap or bootstrap != sorted(set(bootstrap))
            or not set(bootstrap).issubset(path_set) or manifest["bootstrapStorePath"] not in bootstrap
            or STORE_PATH.fullmatch(manifest["bootstrapStorePath"] or "") is None):
        fail("bootstrap closure is invalid")
    signer = manifest["trustedKeyName"]
    public_key = manifest["trustedPublicKey"]
    if (not isinstance(signer, str) or not signer or not isinstance(public_key, str) or not public_key.startswith(signer + ":")
            or PUBLIC_KEY.fullmatch(public_key) is None
            or any(not any(signature.startswith(signer + ":") for signature in item["signatures"]) for item in entries)):
        fail("closure contains an unsigned or untrusted path")
    calculated = sum(item["registrationSize"] for item in entries)
    if manifest["closureBytes"] != calculated:
        fail("closure byte total differs")
    artifacts = exact_keys(manifest["artifacts"], {"bootstrap", "export"}, "manifest artifacts")
    for name in ("bootstrap", "export"):
        metric = exact_keys(artifacts[name], {"bytes", "sha256"}, f"{name} metrics")
        if not isinstance(metric["bytes"], int) or metric["bytes"] <= 0 or SHA256.fullmatch(metric["sha256"] or "") is None:
            fail(f"{name} metrics are invalid")
    resources = exact_keys(manifest["resources"], {"headroomBytes", "requiredInodes", "tmpfsBytes"}, "manifest resources")
    if any(not isinstance(resources[key], int) or isinstance(resources[key], bool) or resources[key] <= 0 for key in resources):
        fail("manifest resources are invalid")
    artifact_bytes = artifacts["bootstrap"]["bytes"] + artifacts["export"]["bytes"]
    if resources["tmpfsBytes"] < calculated * 2 + artifact_bytes or resources["headroomBytes"] < 1024 ** 3 or resources["requiredInodes"] < len(paths):
        fail("manifest resource bounds are not conservative")
    return manifest


def validate_qualification(value: object) -> dict[str, Any]:
    keys = {
        "architecture", "bootstrapImportPassed", "bootstrapSha256", "cleanupPassed", "closureVerificationPassed",
        "commit", "disposableProductUuidSha256", "disposableVmId", "exportSha256", "exporterSha256", "format",
        "helperSha256", "hostAttestationSha256", "installerPath", "manifestSha256", "nixVersion", "observedAt",
        "qualificationRequestSha256", "result", "runnerSha256",
        "toplevel", "trustedPublicKeySha256",
    }
    qualification = exact_keys(value, keys, "qualification evidence")
    if (qualification["architecture"] != SYSTEM or qualification["format"] != QUALIFICATION_FORMAT or qualification["nixVersion"] != NIX_VERSION
            or qualification["result"] != "passed" or qualification["disposableVmId"] != 9900
            or qualification["bootstrapImportPassed"] is not True or qualification["closureVerificationPassed"] is not True
            or qualification["cleanupPassed"] is not True or SHA256.fullmatch(qualification["disposableProductUuidSha256"] or "") is None
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", qualification["observedAt"] or "") is None
            or COMMIT.fullmatch(qualification["commit"] or "") is None):
        fail("qualification evidence does not attest a successful disposable VMID 9900 inspection")
    for key in ("bootstrapSha256", "exportSha256", "exporterSha256", "helperSha256", "hostAttestationSha256", "manifestSha256", "qualificationRequestSha256", "runnerSha256", "trustedPublicKeySha256"):
        if SHA256.fullmatch(qualification[key] or "") is None:
            fail("qualification evidence hash is invalid")
    for key in ("installerPath", "toplevel"):
        if STORE_PATH.fullmatch(qualification[key] or "") is None:
            fail("qualification evidence store path is invalid")
    return qualification


def build_qualification_evidence(*, manifest: dict[str, Any], inspection_passed: bool, cleanup_passed: bool,
                                 bootstrap_sha256: str, export_sha256: str, exporter_sha256: str,
                                 helper_sha256: str, runner_sha256: str, trusted_public_key: str, product_uuid: str,
                                 qualification_request_sha256: str, host_attestation_sha256: str,
                                 observed_at: str, manifest_sha256: str) -> dict[str, Any]:
    if (manifest["mode"] != QUALIFICATION_MODE or not inspection_passed or not cleanup_passed
            or UUID.fullmatch(product_uuid or "") is None or PUBLIC_KEY.fullmatch(trusted_public_key or "") is None):
        fail("qualification evidence requires a completed, exact qualification-mode inspection and cleanup")
    evidence = {
        "architecture": SYSTEM, "bootstrapImportPassed": True, "bootstrapSha256": bootstrap_sha256,
        "cleanupPassed": True, "closureVerificationPassed": True, "commit": manifest["commit"],
        "disposableProductUuidSha256": sha256_bytes(product_uuid.encode()), "disposableVmId": 9900,
        "exportSha256": export_sha256, "exporterSha256": exporter_sha256, "format": QUALIFICATION_FORMAT,
        "helperSha256": helper_sha256, "hostAttestationSha256": host_attestation_sha256,
        "installerPath": manifest["installerPath"],
        "manifestSha256": manifest_sha256, "nixVersion": NIX_VERSION, "observedAt": observed_at,
        "qualificationRequestSha256": qualification_request_sha256, "result": "passed",
        "runnerSha256": runner_sha256, "toplevel": manifest["toplevel"],
        "trustedPublicKeySha256": sha256_bytes(trusted_public_key.encode()),
    }
    return validate_qualification(evidence)


def validate_live_qualification(qualification: dict[str, Any], manifest: dict[str, Any], exporter_sha256: str, runner_sha256: str, trusted_public_key: str) -> None:
    validate_qualification(qualification)
    expected = {
        "bootstrapSha256": manifest["artifacts"]["bootstrap"]["sha256"],
        "commit": manifest["commit"], "exportSha256": manifest["artifacts"]["export"]["sha256"],
        "helperSha256": manifest["helperSha256"],
        "hostAttestationSha256": manifest["qualificationHostAttestationSha256"],
        "exporterSha256": exporter_sha256, "installerPath": manifest["installerPath"],
        "runnerSha256": runner_sha256, "toplevel": manifest["toplevel"],
        "trustedPublicKeySha256": sha256_bytes(trusted_public_key.encode()),
    }
    if any(qualification[key] != value for key, value in expected.items()):
        fail("qualification evidence does not authorize this exact closure, trust key, exporter, and runner")


def validate_tar_file(source: BinaryIO, allowed_store_paths: set[str]) -> int:
    count = 0
    with tarfile.open(fileobj=source, mode="r:") as archive:
        for member in archive:
            count += 1
            if count > 10_000_000:
                fail("bootstrap archive has too many members")
            name = member.name[2:] if member.name.startswith("./") else member.name
            original = PurePosixPath(name)
            if original.is_absolute() or ".." in original.parts:
                fail("bootstrap archive member escapes /nix/store")
            pure = PurePosixPath("/") / original
            if len(pure.parts) < 4 or pure.parts[1:3] != ("nix", "store"):
                fail("bootstrap archive member escapes /nix/store")
            store_root = "/" + "/".join(pure.parts[1:4])
            if store_root not in allowed_store_paths:
                fail("bootstrap archive contains a path outside its declared closure")
            if member.ischr() or member.isblk() or member.isfifo() or member.issparse() or member.isdev() or member.islnk():
                fail("bootstrap archive contains an unsafe special or hard-link member")
            if member.issym():
                target = PurePosixPath(member.linkname)
                resolved = target if target.is_absolute() else pure.parent / target
                normalized: list[str] = []
                for part in resolved.parts:
                    if part in ("", "/", "."):
                        continue
                    if part == "..":
                        if not normalized:
                            fail("bootstrap symlink escapes archive")
                        normalized.pop()
                    else:
                        normalized.append(part)
                if len(normalized) < 3 or normalized[:2] != ["nix", "store"] or "/" + "/".join(normalized[:3]) not in allowed_store_paths:
                    fail("bootstrap symlink escapes its declared closure")
    if count == 0:
        fail("bootstrap archive is empty")
    return count


def validate_tar_descriptor(descriptor: int, allowed_store_paths: set[str]) -> int:
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb", closefd=True) as source:
        result = validate_tar_file(source, allowed_store_paths)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return result


def validate_tar(path: Path, allowed_store_paths: set[str]) -> int:
    with path.open("rb") as source:
        return validate_tar_file(source, allowed_store_paths)


def validate_disk_snapshot(value: object, protected_games_resolved: str, mounted_devices: set[str]) -> dict[str, Any]:
    disk = exact_keys(value, {"byId", "children", "formatted", "holders", "mounted", "openers", "resolved", "serial", "sizeBytes", "type"}, "candidate disk snapshot")
    if disk["byId"] != "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2" or disk["type"] != "disk" or disk["serial"] != EXPECTED_SERIAL or disk["sizeBytes"] != EXPECTED_SIZE:
        fail("candidate disk identity differs")
    if not isinstance(disk["resolved"], str) or not disk["resolved"].startswith("/dev/") or disk["resolved"] == protected_games_resolved or disk["resolved"] in mounted_devices:
        fail("candidate disk aliases a protected or mounted device")
    if disk["children"] != [] or disk["formatted"] is not False or disk["mounted"] is not False or disk["holders"] != [] or disk["openers"] != []:
        fail("candidate disk is not blank, unmounted, holder-free, and unopened")
    return disk


def validate_resources(manifest: dict[str, Any], memory_available: int, available_inodes: int) -> None:
    resources = manifest["resources"]
    if memory_available < resources["tmpfsBytes"] + resources["headroomBytes"]:
        fail("insufficient MemAvailable for bounded ephemeral Nix store")
    if available_inodes < resources["requiredInodes"]:
        fail("insufficient inodes for bounded ephemeral Nix store")


def validate_import_observation(expected: set[str], recursive: set[str], physical: set[str], contents_verified: bool) -> None:
    if recursive != expected or physical != expected:
        fail("imported closure contains an extra or missing path")
    if not contents_verified:
        fail("imported closure content verification failed")


def require_absent_nix(path: Path) -> None:
    if os.path.lexists(path):
        fail("/nix must not preexist, including as an empty directory or symlink")


def validate_export_evidence(value: object) -> dict[str, Any]:
    evidence = exact_keys(value, {"artifacts", "closurePathCount", "commit", "format", "helperSha256", "mode", "qualificationHostAttestationSha256", "requestSha256", "result", "system"}, "export evidence")
    if (evidence["format"] != EXPORT_EVIDENCE_FORMAT or evidence["result"] != "passed" or evidence["system"] != SYSTEM
            or evidence["mode"] not in {LIVE_MODE, QUALIFICATION_MODE} or COMMIT.fullmatch(evidence["commit"] or "") is None
            or SHA256.fullmatch(evidence["requestSha256"] or "") is None or SHA256.fullmatch(evidence["helperSha256"] or "") is None
            or SHA256.fullmatch(evidence["qualificationHostAttestationSha256"] or "") is None
            or not isinstance(evidence["closurePathCount"], int)
            or evidence["closurePathCount"] <= 0):
        fail("export evidence differs")
    artifacts = exact_keys(evidence["artifacts"], {"bootstrap", "export", "manifest"}, "export evidence artifacts")
    for metric in artifacts.values():
        metric = exact_keys(metric, {"bytes", "sha256"}, "export evidence artifact")
        if not isinstance(metric["bytes"], int) or metric["bytes"] <= 0 or SHA256.fullmatch(metric["sha256"] or "") is None:
            fail("export evidence artifact metrics differ")
    return evidence


def validate_inspection_evidence(value: object) -> dict[str, Any]:
    keys = {"bootIdStable", "candidate", "candidateIdentityStable", "cleanupEvidence", "commit", "format", "helperSha256", "importVerified", "installerExitCode", "manifestSha256", "mode", "result"}
    evidence = exact_keys(value, keys, "inspection evidence")
    if (evidence["format"] != INSPECTION_EVIDENCE_FORMAT or evidence["mode"] not in {LIVE_MODE, QUALIFICATION_MODE}
            or evidence["cleanupEvidence"] != "cleanup-evidence.json" or evidence["result"] not in {"passed", "failed"}
            or COMMIT.fullmatch(evidence["commit"] or "") is None or SHA256.fullmatch(evidence["manifestSha256"] or "") is None
            or SHA256.fullmatch(evidence["helperSha256"] or "") is None):
        fail("inspection evidence differs")
    candidate = evidence["candidate"]
    if candidate is not None:
        candidate = exact_keys(candidate, {"blank", "byId", "holdersAbsent", "mountedSourcesDistinct", "openersAbsent", "protectedGamesDistinct", "resolved", "serial", "sizeBytes"}, "inspection candidate evidence")
        if (candidate["byId"] != "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2" or candidate["serial"] != EXPECTED_SERIAL
                or candidate["sizeBytes"] != EXPECTED_SIZE or not isinstance(candidate["resolved"], str) or not candidate["resolved"].startswith("/dev/")
                or any(candidate[key] is not True for key in ("blank", "holdersAbsent", "mountedSourcesDistinct", "openersAbsent", "protectedGamesDistinct"))):
            fail("inspection candidate evidence differs")
    passed = evidence["bootIdStable"] is True and evidence["candidateIdentityStable"] is True and evidence["importVerified"] is True and evidence["installerExitCode"] == 0 and candidate is not None
    if (evidence["result"] == "passed") != passed:
        fail("inspection evidence contradicts inspection observations")
    return evidence


def validate_cleanup(value: object) -> dict[str, Any]:
    cleanup = exact_keys(value, {"bootIdStable", "childProcessGroupAbsent", "format", "nixAbsent", "result", "temporaryPathsAbsent", "tmpfsUnmounted"}, "cleanup evidence")
    passed = all(cleanup.get(key) is True for key in ("bootIdStable", "childProcessGroupAbsent", "nixAbsent", "temporaryPathsAbsent", "tmpfsUnmounted"))
    if cleanup["format"] != CLEANUP_EVIDENCE_FORMAT or cleanup["result"] not in {"passed", "failed"} or (cleanup["result"] == "passed") != passed:
        fail("cleanup evidence contradicts cleanup observations")
    return cleanup
