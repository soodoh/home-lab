#!/usr/bin/env python3
"""Validate the retained evidence for the completed disposable LXC qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

LOCKFILE = Path("infrastructure/tofu/proxmox-lxc-qualification/.terraform.lock.hcl")
PROVIDER_SOURCE = "registry.opentofu.org/bpg/proxmox"
EVIDENCE_OPERATIONS = [
    "create",
    "probe-protected-delete",
    "verify-protected",
    "unprotect",
    "delete",
    "verify-empty",
]


class EvidenceError(ValueError):
    """Raised when retained qualification evidence violates an invariant."""


def locked_provider(lockfile: Path) -> tuple[str, str]:
    try:
        text = lockfile.read_text()
    except OSError as error:
        raise EvidenceError("the provider lock evidence is unavailable") from error
    provider = re.search(
        r'^provider "([^"]+)" \{.*?^  version     = "([^"]+)"$',
        text,
        re.MULTILINE | re.DOTALL,
    )
    if provider is None or provider.group(1) != PROVIDER_SOURCE:
        raise EvidenceError("the pinned provider evidence is invalid")
    return provider.group(1), provider.group(2)


def validate_evidence(evidence: Any, lockfile: Path) -> None:
    expected_keys = {
        "version",
        "qualification_tooling_commit",
        "provider",
        "runs",
        "final_proof",
        "protected_identifiers_included",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_keys:
        raise EvidenceError("qualification evidence fields are invalid")
    commit = evidence.get("qualification_tooling_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise EvidenceError("qualification tooling commit evidence is invalid")
    if evidence.get("version") != 1 or evidence.get("protected_identifiers_included") is not False:
        raise EvidenceError("qualification evidence version or identifier declaration is invalid")

    provider_source, provider_version = locked_provider(lockfile)
    expected_provider = {
        "source": provider_source,
        "version": provider_version,
        "lock_sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest(),
    }
    if evidence.get("provider") != expected_provider:
        raise EvidenceError("qualification provider evidence does not match the pinned lock")

    runs = evidence.get("runs")
    if not isinstance(runs, list) or len(runs) != len(EVIDENCE_OPERATIONS):
        raise EvidenceError("qualification evidence does not record exactly six runs")
    run_ids: list[str] = []
    for run, operation in zip(runs, EVIDENCE_OPERATIONS, strict=True):
        if not isinstance(run, dict) or set(run) != {"operation", "run_id"}:
            raise EvidenceError("qualification run evidence fields are invalid")
        run_id = run.get("run_id")
        if run.get("operation") != operation or not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]*", run_id):
            raise EvidenceError("qualification evidence operation sequence is invalid")
        run_ids.append(run_id)
    if len(set(run_ids)) != len(run_ids):
        raise EvidenceError("qualification evidence reuses a run ID")

    expected_final = {
        "operation": "verify-empty",
        "run_id": run_ids[-1],
        "state": "empty",
        "plan": "no-op",
        "api": "absent",
        "volumes": "absent",
        "backend_lock": "absent",
    }
    if evidence.get("final_proof") != expected_final:
        raise EvidenceError("qualification final empty/no-op proof is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-json", type=Path, required=True)
    parser.add_argument("--provider-lockfile", type=Path, default=LOCKFILE)
    args = parser.parse_args()
    try:
        validate_evidence(json.loads(args.evidence_json.read_text()), args.provider_lockfile)
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"LXC qualification evidence validation failed: {error}", file=sys.stderr)
        return 1
    print("qualification run evidence and final proof are exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
