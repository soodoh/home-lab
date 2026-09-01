#!/usr/bin/env python3
"""Unit tests for exact tofu SSH identity retirement planning."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import tempfile
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


if __name__ == "__main__":
    unittest.main()
