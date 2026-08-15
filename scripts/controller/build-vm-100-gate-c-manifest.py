#!/usr/bin/env python3
"""Build and strictly validate a canonical VM 100 Gate C manifest."""

from __future__ import annotations

from argparse import ArgumentParser
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from vm_100_gate_c import (
    CLASSIFICATIONS, FORMAT, canonical_bytes, checksum_argv, digest,
    expected_volume_names, project_desired_inventory, project_runtime_inventory,
    validate_collection, validate_manifest, write_argv,
)


def parse_args() -> object:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--desired-inventory", required=True, type=Path); parser.add_argument("--expected-desired-inventory-sha256", required=True)
    parser.add_argument("--runtime-inventory", required=True, type=Path); parser.add_argument("--collection", required=True, type=Path)
    parser.add_argument("--expected-candidate-inventory-sha256", required=True)
    parser.add_argument("--isolated-restore-evidence-sha256", required=True)
    parser.add_argument("--candidate-daemon-stop-evidence-sha256", required=True)
    parser.add_argument("--source-daemon-stability-evidence-sha256", required=True)
    parser.add_argument("--commit", required=True); parser.add_argument("--compose-artifact-sha256", required=True); parser.add_argument("--canonical-toplevel", required=True)
    parser.add_argument("--now", required=True); parser.add_argument("--collection-max-age-seconds", required=True, type=int)
    parser.add_argument("--output-root", required=True, type=Path); parser.add_argument("--output-name", required=True)
    return parser.parse_args()


def load_object(path: Path, label: str) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict): raise SystemExit(f"{label} must be a JSON object")
    return value


def schema_validate(encoded: bytes) -> None:
    helper = Path(__file__).with_name("validate-vm-100-gate-c-schema.js")
    with tempfile.NamedTemporaryFile(prefix="vm-100-gate-c-", suffix=".json") as temporary:
        temporary.write(encoded); temporary.flush(); subprocess.run(["node", str(helper), temporary.name], check=True, stdout=subprocess.DEVNULL)


def protected_output(root: Path, name: str, encoded: bytes) -> None:
    if not root.is_absolute() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.json", name): raise SystemExit("output root/name is invalid")
    try: value = root.stat(follow_symlinks=False)
    except FileNotFoundError as error: raise SystemExit("dedicated output root must already exist") from error
    if root.is_symlink() or not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) & 0o077: raise SystemExit("output root must be owned, private, and not a symlink")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current.is_symlink(): raise SystemExit("output root has a symlink path component")
    directory_fd = os.open(root.resolve(strict=True), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded); output.flush(); os.fsync(output.fileno())
        os.fsync(directory_fd)
    finally: os.close(directory_fd)


def main() -> None:
    args = parse_args(); os.umask(0o077)
    if re.fullmatch(r"[0-9a-f]{40}", args.commit) is None or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (args.compose_artifact_sha256, args.isolated_restore_evidence_sha256, args.candidate_daemon_stop_evidence_sha256, args.source_daemon_stability_evidence_sha256)): raise SystemExit("commit, Compose artifact, or external evidence digest is invalid")
    desired = project_desired_inventory(load_object(args.desired_inventory, "desired inventory"))
    runtime = project_runtime_inventory(load_object(args.runtime_inventory, "runtime inventory"), expected_volume_names(desired))
    collection = load_object(args.collection, "collection")
    entries = validate_collection(collection, desired, runtime, expected_desired_sha256=args.expected_desired_inventory_sha256, expected_candidate_sha256=args.expected_candidate_inventory_sha256, expected_toplevel=args.canonical_toplevel)
    projected_entries = []
    for entry in entries:
        projected = dict(entry); projected["writeArgv"] = write_argv(str(entry["source"]), str(entry["destination"])); projected["checksumArgv"] = checksum_argv(str(entry["source"]), str(entry["destination"])); projected_entries.append(projected)
    manifest = {
        "format": FORMAT, "version": 1,
        "bindings": {"gitCommit": args.commit, "composeArtifactSha256": args.compose_artifact_sha256, "isolatedRestoreEvidenceSha256": args.isolated_restore_evidence_sha256, "candidateDaemonStopEvidenceSha256": args.candidate_daemon_stop_evidence_sha256, "sourceDaemonStabilityEvidenceSha256": args.source_daemon_stability_evidence_sha256, "canonicalProductionMigrationToplevel": args.canonical_toplevel, "desiredInventorySha256": digest(desired), "runtimeInventorySha256": digest(runtime), "candidateInventorySha256": collection["candidateInventorySha256"], "collectionSha256": digest(collection), "collectedAt": collection["collectedAt"]},
        "inventories": {"desired": desired, "runtime": runtime, "collection": collection},
        "candidate": collection["candidate"], "sourceDockerRoot": collection["sourceDockerRoot"], "copyEntries": projected_entries,
        "classifications": [{"name": name, "path": path, "disposition": disposition, "reason": reason} for name, path, disposition, reason in CLASSIFICATIONS],
        "backupEvidence": collection["backupEvidence"], "operationalMetadata": collection["operationalMetadata"],
    }
    validate_manifest(manifest, args.commit, args.compose_artifact_sha256, args.canonical_toplevel, args.expected_desired_inventory_sha256, args.expected_candidate_inventory_sha256, args.now, args.collection_max_age_seconds, args.isolated_restore_evidence_sha256, args.candidate_daemon_stop_evidence_sha256, args.source_daemon_stability_evidence_sha256)
    encoded = canonical_bytes(manifest) + b"\n"; schema_validate(encoded); protected_output(args.output_root, args.output_name, encoded)
    print("vm_100_gate_c_manifest=built")


if __name__ == "__main__": main()
