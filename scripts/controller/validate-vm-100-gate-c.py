#!/usr/bin/env python3
"""Fail-closed validation for a VM 100 Gate C direct-data manifest."""

from __future__ import annotations

from argparse import ArgumentParser
import json
from pathlib import Path
import re
import subprocess

from vm_100_gate_c import canonical_bytes, validate_manifest


def parse_args() -> object:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--expected-commit", required=True); parser.add_argument("--expected-compose-artifact-sha256", required=True)
    parser.add_argument("--expected-canonical-toplevel", required=True); parser.add_argument("--expected-desired-inventory-sha256", required=True)
    parser.add_argument("--expected-candidate-inventory-sha256", required=True)
    parser.add_argument("--expected-isolated-restore-evidence-sha256", required=True)
    parser.add_argument("--expected-candidate-daemon-stop-evidence-sha256", required=True)
    parser.add_argument("--expected-source-daemon-stability-evidence-sha256", required=True); parser.add_argument("--now", required=True)
    parser.add_argument("--collection-max-age-seconds", required=True, type=int)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_commit) is None: raise SystemExit("expected commit must be a full Git object ID")
    for label, value in (("Compose artifact", args.expected_compose_artifact_sha256), ("desired inventory", args.expected_desired_inventory_sha256), ("candidate inventory", args.expected_candidate_inventory_sha256), ("isolated restore evidence", args.expected_isolated_restore_evidence_sha256), ("candidate daemon stop evidence", args.expected_candidate_daemon_stop_evidence_sha256), ("source daemon stability evidence", args.expected_source_daemon_stability_evidence_sha256)):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None: raise SystemExit(f"expected {label} SHA-256 is invalid")
    raw = args.manifest.read_bytes(); document = json.loads(raw)
    if not isinstance(document, dict): raise SystemExit("Gate C manifest must be a JSON object")
    if raw != canonical_bytes(document) + b"\n": raise SystemExit("Gate C manifest is not canonical JSON")
    schema_helper = Path(__file__).with_name("validate-vm-100-gate-c-schema.js")
    subprocess.run(["node", str(schema_helper), str(args.manifest)], check=True)
    validate_manifest(document, args.expected_commit, args.expected_compose_artifact_sha256, args.expected_canonical_toplevel, args.expected_desired_inventory_sha256, args.expected_candidate_inventory_sha256, args.now, args.collection_max_age_seconds, args.expected_isolated_restore_evidence_sha256, args.expected_candidate_daemon_stop_evidence_sha256, args.expected_source_daemon_stability_evidence_sha256)
    print("vm_100_gate_c_manifest=verified")


if __name__ == "__main__": main()
