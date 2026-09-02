#!/usr/bin/env python3
"""Unit tests for lifecycle-aware Proxmox access evidence."""

from __future__ import annotations

import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import tempfile
import time
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("proxmox_access_evidence", ROOT / "scripts/controller/proxmox-access-evidence.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class AccessEvidenceTests(unittest.TestCase):
    def test_root_key_evidence_treats_final_absence_as_complete_empty_input(self) -> None:
        source = inspect.getsource(MODULE.root_key_evidence)
        self.assertIn("except FileNotFoundError: lines=[]", source)

    def test_pending_state_requires_steady_noop(self) -> None:
        result = subprocess.CompletedProcess([], 0, stdout=b"[tailscale]\nNo changes\n", stderr=b"")
        with mock.patch.object(MODULE, "access_cutover_state", return_value="pending"):
            proof = MODULE.controller_plan_proof(result, time.time() - 1)
        self.assertTrue(proof["live_plan_noop"])
        self.assertFalse(proof["expected_retirement_drift"])

    def test_ready_state_accepts_only_exact_retirement_drift(self) -> None:
        targets = ["/etc/sudoers.d/tofu-apply", "/etc/sudoers.d/tofu-plan"]
        plan = {"planSha256": "a" * 64, "status": "blocked", "applyEligible": False, "actions": [],
                "blockers": [{"code": "manual-remediation-required", "domain": "audit-absence", "target": target} for target in targets],
                "findings": [{"code": "unexpected-presence", "domain": "audit-absence", "target": target} for target in targets]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); plans = root / ".reconcile/plans"; plans.mkdir(parents=True)
            (plans / f"{'a' * 64}.json").write_text(json.dumps(plan))
            result = subprocess.CompletedProcess([], 66, stdout=b"expected blocked plan\n", stderr=b"")
            with mock.patch.object(MODULE, "ROOT", root), mock.patch.object(MODULE, "access_cutover_state", return_value="ready"):
                proof = MODULE.controller_plan_proof(result, time.time() - 1)
        self.assertTrue(proof["expected_retirement_drift"])
        self.assertEqual(proof["retirement_drift_targets"], targets)
        self.assertEqual(proof["controller_plan_sha256"], "a" * 64)

    def test_ready_state_accepts_exact_final_access_drift(self) -> None:
        ssh = "/etc/ssh/sshd_config.d/60-home-lab.conf"
        plan = {"planSha256": "c" * 64, "status": "blocked", "applyEligible": False, "actions": [],
                "blockers": [
                    {"code": "review-required", "domain": "managed-files", "target": ssh},
                    {"code": "private-observation-mismatch", "domain": "protected-access", "target": "protected-access"},
                ],
                "findings": [{"code": "desired-state-drift", "domain": "managed-files", "target": ssh}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); plans = root / ".reconcile/plans"; plans.mkdir(parents=True)
            (plans / f"{'c' * 64}.json").write_text(json.dumps(plan))
            result = subprocess.CompletedProcess([], 66, stdout=b"expected final access drift\n", stderr=b"")
            with mock.patch.object(MODULE, "ROOT", root), mock.patch.object(MODULE, "access_cutover_state", return_value="ready"):
                proof = MODULE.controller_plan_proof(result, time.time() - 1)
        self.assertEqual(proof["retirement_drift_targets"], [ssh, "protected-access"])
        self.assertTrue(proof["expected_retirement_drift"])

    def test_ready_state_accepts_final_noop(self) -> None:
        result = subprocess.CompletedProcess([], 0, stdout=b"[tailscale]\nNo changes\n", stderr=b"")
        with mock.patch.object(MODULE, "access_cutover_state", return_value="ready"):
            proof = MODULE.controller_plan_proof(result, time.time() - 1)
        self.assertFalse(proof["expected_retirement_drift"])

    def test_ready_state_rejects_extra_drift(self) -> None:
        result = subprocess.CompletedProcess([], 66, stdout=b"blocked\n", stderr=b"")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); plans = root / ".reconcile/plans"; plans.mkdir(parents=True)
            plan = {"planSha256": "b" * 64, "status": "blocked", "applyEligible": False, "actions": [],
                    "blockers": [{"code": "manual-remediation-required", "domain": "audit-absence", "target": "/unexpected"}], "findings": []}
            (plans / f"{'b' * 64}.json").write_text(json.dumps(plan))
            with mock.patch.object(MODULE, "ROOT", root), mock.patch.object(MODULE, "access_cutover_state", return_value="ready"):
                with self.assertRaises(SystemExit):
                    MODULE.controller_plan_proof(result, time.time() - 1)


if __name__ == "__main__":
    unittest.main()
