#!/usr/bin/env python3
"""Independently validate VM 100 transfer evidence against its exact manifest."""

from __future__ import annotations

from argparse import ArgumentParser
import importlib.util
from pathlib import Path
import re
import subprocess
from typing import Any

from vm_100_execution import load_canonical_object, sha256_bytes
from vm_100_gate_c import validate_manifest

CLOSED_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def import_transfer() -> Any:
    path = Path(__file__).resolve().with_name("vm-100-data-transfer.py")
    spec = importlib.util.spec_from_file_location("vm100_data_transfer_validator", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot import transfer semantic validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--node-command", default="/usr/bin/node")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.expected_manifest_sha256) is None:
        raise SystemExit("expected manifest SHA-256 is invalid")
    manifest, manifest_raw = load_canonical_object(args.manifest, "Gate C manifest")
    evidence, _ = load_canonical_object(args.evidence, "data transfer evidence")
    if sha256_bytes(manifest_raw) != args.expected_manifest_sha256:
        raise SystemExit("exact manifest file SHA-256 differs")
    root = Path(__file__).resolve().parent
    subprocess.run([args.node_command, str(root / "validate-vm-100-gate-c-schema.js"), str(args.manifest)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLOSED_ENV)
    subprocess.run([args.node_command, str(root / "validate-vm-100-execution-schema.js"), "data-transfer", str(args.evidence)], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLOSED_ENV)
    validate_manifest(manifest)
    transfer = import_transfer()
    transfer.validate_evidence(evidence, manifest, args.expected_manifest_sha256)
    print("vm_100_data_transfer_evidence=manifest-bound-valid")


if __name__ == "__main__":
    main()
