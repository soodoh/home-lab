#!/usr/bin/env python3
"""Unit tests for exact tofu SSH identity retirement planning."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("tofu_identity_retirement", ROOT / "scripts/controller/proxmox-tofu-identity-retirement.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def contract(state: str) -> bytes:
    return f"""lifecycle:
  hosts:
    proxmox:
      access_cutover:
        state: {state}
        retire_identities:
          - tofu-plan
          - tofu-apply
      domain_handoffs:
        package_set:
          state: transferred
""".encode()


def observation() -> dict:
    paths = {}
    for index, path in enumerate(sorted({*MODULE.RETAINED_HOST_ASSETS, *sum(MODULE.HOST_ASSETS.values(), ())}), 1):
        paths[path] = {"exists": True, "uid": 0, "gid": 0, "mode": "0600", "regular": True,
                       "directory": False, "symlink": False, "nlink": 1, "size": index, "sha256": f"{index:064x}"}
    return {
        "accounts": {
            "tofu-plan": {"exists": True, "uid": 1001, "gid": 1001, "home": "/home/tofu-plan", "shell": "/bin/bash", "gecos": "", "groups": ["tofu-plan"], "password_locked": True, "active_pids": []},
            "tofu-apply": {"exists": True, "uid": 1002, "gid": 1002, "home": "/home/tofu-apply", "shell": "/usr/local/libexec/home-lab/proxmox-apply-transport", "gecos": "", "groups": ["tofu-apply"], "password_locked": True, "active_pids": []},
        },
        "groups": {"tofu-plan": {"exists": True, "gid": 1001, "members": []}, "tofu-apply": {"exists": True, "gid": 1002, "members": []}},
        "locks": [], "paths": paths,
    }


class RetirementPlanTests(unittest.TestCase):
    def build(self, state: str = "pending", evidence: dict | None = None) -> list[dict]:
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "identity"; public = Path(directory) / "identity.pub"
            private.write_text("private\n"); private.chmod(0o600); public.write_text("public\n")
            controller = {name: [str(private), str(public)] for name in MODULE.IDENTITIES}
            return MODULE.build_plans("a" * 40, contract(state), evidence or observation(), controller,
                                      datetime(2026, 4, 3, 12, 0, tzinfo=timezone.utc))

    def test_builds_four_separate_unauthorized_plans(self) -> None:
        plans = self.build()
        self.assertEqual([item["sequence"] for item in plans], [1, 2, 3, 4])
        self.assertEqual([item["kind"] for item in plans], [
            "host-tofu-plan-retirement", "host-tofu-apply-retirement",
            "controller-tofu-plan-credential-retirement", "controller-tofu-apply-credential-retirement",
        ])
        self.assertTrue(all(item["authorized"] is False for item in plans))
        self.assertTrue(all(item["access_cutover_state"] == "pending" for item in plans))
        self.assertTrue(all("access-cutover-state-not-ready" in item["blockers"] for item in plans[:2]))
        self.assertTrue(all("separate-authorization-required" in item["blockers"] for item in plans))

    def test_host_plans_are_exact_and_exclude_retained_authorities(self) -> None:
        plans = self.build("ready")
        self.assertNotIn("access-cutover-state-not-ready", plans[0]["blockers"])
        self.assertEqual(set(plans[0]["before"]["assets"]), set(MODULE.HOST_ASSETS["tofu-plan"]))
        self.assertEqual(set(plans[1]["before"]["assets"]), set(MODULE.HOST_ASSETS["tofu-apply"]))
        self.assertNotIn("/usr/local/libexec/home-lab/proxmox-private-preparer", plans[1]["after"]["assets"])
        self.assertEqual(plans[0]["explicit_exclusions"]["pve_api_identities"], ["root@pam!tofu-plan", "root@pam!tofu-apply"])
        self.assertEqual(set(plans[0]["retained_host_assets_before"]), set(MODULE.RETAINED_HOST_ASSETS))
        self.assertEqual(plans[0]["after"]["account"], {"exists": False})
        self.assertEqual(plans[1]["after"]["group"], {"exists": False})

    def test_active_identity_process_blocks_host_transaction(self) -> None:
        evidence = observation(); evidence["accounts"]["tofu-apply"]["active_pids"] = [42]
        plans = self.build("ready", evidence)
        self.assertNotIn("identity-has-active-processes", plans[0]["blockers"])
        self.assertIn("identity-has-active-processes", plans[1]["blockers"])

    def test_controller_credentials_follow_host_receipts(self) -> None:
        plans = self.build("ready")
        self.assertIn("host-tofu-plan-retirement-receipt-required", plans[2]["blockers"])
        self.assertIn("host-tofu-apply-retirement-receipt-required", plans[3]["blockers"])
        self.assertTrue(all(metadata["sha256"] for metadata in plans[2]["before"].values()))
        self.assertEqual(plans[2]["host_retirement_plan_sha256"], MODULE.sha(MODULE.canonical(plans[0])))
        self.assertEqual(plans[3]["host_retirement_plan_sha256"], MODULE.sha(MODULE.canonical(plans[1])))

    def test_authorization_binds_plan_and_console_evidence(self) -> None:
        now = datetime.now(timezone.utc); expires = (now + timedelta(minutes=20)).isoformat().replace("+00:00", "Z")
        requirements = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
        plan = {"kind": "host-tofu-plan-retirement", "commit": "a" * 40, "contract_sha256": "b" * 64,
                "inventory_sha256": "e" * 64, "host_key_fingerprint": MODULE.HOST_KEY_FINGERPRINT,
                "expires_at": expires, "blockers": requirements}
        evidence = {"format": "home-lab-proxmox-access-evidence-v1", "commit": "a" * 40,
                    "contract_sha256": "b" * 64, "inventory_sha256": "e" * 64,
                    "host_key_fingerprint": MODULE.HOST_KEY_FINGERPRINT, "expires_at": expires}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory); plan_path = output / "plan.json"; evidence_path = output / "evidence.json"
            confirmation = f"authorize-proxmox-host-tofu-plan-retirement-{'c' * 64}-{'d' * 64}"
            with mock.patch.object(MODULE, "OUTPUT", output), mock.patch.object(MODULE, "load_local_plan", return_value=(plan, b"plan\n", "c" * 64, "tofu-plan")), \
                 mock.patch.object(MODULE, "load_local_evidence", return_value=(evidence, b"evidence\n", "d" * 64)), \
                 mock.patch.object(MODULE, "stage_authorized_bundle", return_value={"plan": "/staged/plan"}), \
                 mock.patch.dict(os.environ, {"PROXMOX_TOFU_RETIREMENT_AUTHORIZATION_CONFIRMED": confirmation}):
                MODULE.authorize(plan_path, evidence_path)
            saved = list(output.glob("authorization-tofu-plan-*.json"))
            self.assertEqual(len(saved), 1)
            authorization = json.loads(saved[0].read_bytes())
            self.assertTrue(authorization["authorized"])
            self.assertEqual(authorization["plan_sha256"], "c" * 64)
            self.assertEqual(authorization["console_evidence_sha256"], "d" * 64)
            self.assertEqual(authorization["accepted_requirements"], requirements)
            self.assertEqual(authorization["inventory_sha256"], "e" * 64)
            self.assertEqual(authorization["host_key_fingerprint"], MODULE.HOST_KEY_FINGERPRINT)

    def test_controller_credentials_require_committed_matching_host_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory); private = output / "plan-key"; public = output / "plan-key.pub"
            private.write_bytes(b"private\n"); private.chmod(0o600); public.write_bytes(b"public\n"); public.chmod(0o644)
            before = {str(path): MODULE.local_metadata(path) for path in (private, public)}
            plan = {"kind": "controller-tofu-plan-credential-retirement", "before": before,
                    "after": {path: {"exists": False} for path in before},
                    "host_retirement_plan_sha256": "a" * 64,
                    "blockers": ["host-tofu-plan-retirement-receipt-required", "controller-recovery-attestation-required", "separate-authorization-required"]}
            host_receipt = {"format": "home-lab-proxmox-tofu-retirement-host-receipt-v1", "status": "committed",
                            "identity": "tofu-plan", "plan_sha256": "a" * 64}
            confirmation = f"retire-controller-tofu-plan-credentials-{'b' * 64}-{'c' * 64}"
            with mock.patch.object(MODULE, "OUTPUT", output), mock.patch.object(MODULE, "load_controller_plan", return_value=(plan, b"plan\n", "b" * 64, "tofu-plan")), \
                 mock.patch.object(MODULE, "fetch_host_receipt", return_value=(host_receipt, b"receipt\n", "c" * 64, output / "host.json")), \
                 mock.patch.dict(os.environ, {"PROXMOX_TOFU_RETIREMENT_CONFIRMED": confirmation}):
                MODULE.retire_controller_credentials(output / "controller-plan.json")
            self.assertFalse(private.exists()); self.assertFalse(public.exists())
            receipts = list((output / "controller-journals" / ("b" * 64)).glob("receipt.json"))
            self.assertEqual(len(receipts), 1)
            self.assertEqual(json.loads(receipts[0].read_bytes())["status"], "committed")


if __name__ == "__main__":
    unittest.main()
