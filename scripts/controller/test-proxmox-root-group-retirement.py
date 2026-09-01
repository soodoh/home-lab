#!/usr/bin/env python3
"""Unit tests for exact Proxmox root supplementary-group retirement plans."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("root_group_retirement", ROOT / "scripts/controller/proxmox-root-group-retirement.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def contract(state: str = "ready") -> bytes:
    return f"""lifecycle:
  hosts:
    proxmox:
      access_cutover:
        state: {state}
        retire_root_supplementary_groups:
          - apex
      domain_handoffs:
        package_set:
          state: transferred
""".encode()


def observation() -> dict:
    return {"root": {"exists": True, "gid": 0, "home": "/root", "shell": "/bin/bash", "groups": ["apex", "root"]},
            "apex": {"exists": True, "gid": 1000, "members": ["root"]},
            "database_records": {"/etc/group": {"count": 1, "sha256": "a" * 64},
                                 "/etc/gshadow": {"count": 1, "sha256": "b" * 64}},
            "locks": [], "paths": {path: {"exists": True, "sha256": "c" * 64} for path in MODULE.RETAINED},
            "pve_tokens": [{"privsep": 1, "tokenid": "tofu-apply"}, {"privsep": 1, "tokenid": "tofu-plan"}]}


class RootGroupRetirementTests(unittest.TestCase):
    def test_ready_plan_removes_only_membership(self) -> None:
        plan = MODULE.build_plan("a" * 40, contract(), observation(), datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertEqual(plan["target_group"], "apex")
        self.assertEqual(plan["after"], {"root_groups": ["root"], "apex": {"exists": True, "gid": 1000, "members": []}})
        self.assertFalse(plan["explicit_exclusions"]["delete_apex_group"])
        self.assertTrue(plan["explicit_exclusions"]["root_authorized_keys"])
        self.assertEqual(plan["retained_pve_tokens"], observation()["pve_tokens"])
        self.assertEqual(plan["blockers"], ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"])
        self.assertFalse(plan["authorized"])

    def test_pending_state_remains_blocked(self) -> None:
        plan = MODULE.build_plan("a" * 40, contract("pending"), observation(), datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertIn("access-cutover-state-not-ready", plan["blockers"])

    def test_divergent_membership_is_not_plannable(self) -> None:
        evidence = observation(); evidence["apex"]["members"] = ["someone-else"]
        plan = MODULE.build_plan("a" * 40, contract(), evidence, datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertIn("root-apex-membership-differs", plan["blockers"])


if __name__ == "__main__":
    unittest.main()
