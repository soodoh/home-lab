#!/usr/bin/env python3
"""Unit tests for exact obsolete Proxmox root-key retirement planning."""
from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("obsolete_root_key", ROOT / "scripts/controller/proxmox-obsolete-root-key-retirement.py")
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)


def contract() -> bytes:
    return (ROOT / "infrastructure/contract/home-lab.yml").read_bytes()


def observation(fingerprints: list[str]) -> dict:
    paths = {}
    for path, expected in MODULE.RETAINED_METADATA.items():
        paths[path] = {"exists": True, "size": 1, **expected, **({"sha256": "a" * 64} if expected["regular"] else {})}
    records = [{"index": index, "line": f"key-{index}\n", "line_sha256": "c" * 64, "fingerprint": value} for index, value in enumerate(fingerprints)]
    raw = "".join(item["line"] for item in records).encode()
    paths[MODULE.KEY_PATH] = {"exists": True, "uid": 0, "gid": 33, "mode": "0600", "regular": True, "directory": False, "symlink": False, "nlink": 1, "size": len(raw), "sha256": MODULE.sha(raw)}
    return {"paths": paths, "key_bytes_hex": raw.hex(), "key_records": records, "locks": [], "root_groups": ["root"], "apex": {"exists": True, "gid": 1000, "members": []}, "tofu_absent": True, "sshd": {"fixed": True}, "pve_tokens": MODULE.EXPECTED_TOKENS}


class ObsoleteRootKeyPlanTests(unittest.TestCase):
    def test_exact_six_key_state_plans_only_two_obsolete_fingerprints(self) -> None:
        evidence = observation(list(MODULE.EXPECTED_ATTRIBUTIONS))
        after = {"metadata": {**evidence["paths"][MODULE.KEY_PATH], "size": 4, "sha256": "d" * 64}, "bytes_hex": "00", "records": []}
        with mock.patch.object(MODULE, "after_snapshot", return_value=after):
            plan = MODULE.build_plan("a" * 40, contract(), evidence, datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertEqual(plan["actions"], [{"kind": "remove-obsolete-root-key-lines", "path": MODULE.KEY_PATH, "fingerprints": MODULE.TARGET_FINGERPRINTS}])
        self.assertEqual(plan["findings"], [])
        self.assertEqual(plan["blockers"], ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"])

    def test_exact_retained_four_key_state_is_final_noop(self) -> None:
        evidence = observation(MODULE.RETAINED_FINGERPRINTS)
        plan = MODULE.build_plan("a" * 40, contract(), evidence, datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertEqual((plan["actions"], plan["blockers"], plan["findings"]), ([], [], []))

    def test_extra_duplicate_or_unattributed_key_fails_closed(self) -> None:
        fingerprints = list(MODULE.EXPECTED_ATTRIBUTIONS) + [MODULE.TARGET_FINGERPRINTS[0], "SHA256:unattributed"]
        evidence = observation(fingerprints)
        plan = MODULE.build_plan("a" * 40, contract(), evidence, datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertIn("duplicate-root-key-fingerprint", plan["findings"])
        self.assertIn("root-key-set-differs", plan["findings"])
        self.assertEqual(plan["actions"], [])

    def test_after_snapshot_preserves_blank_lines_and_newline_shape(self) -> None:
        raw = b"retain-one\n\ntarget\nretain-two"
        before = {"metadata": {"size": len(raw), "sha256": MODULE.sha(raw)}, "bytes_hex": raw.hex(), "records": [
            {"index": 0, "line": "retain-one\n", "fingerprint": MODULE.RETAINED_FINGERPRINTS[0]},
            {"index": 2, "line": "target\n", "fingerprint": MODULE.TARGET_FINGERPRINTS[0]},
            {"index": 3, "line": "retain-two", "fingerprint": MODULE.RETAINED_FINGERPRINTS[1]},
        ]}
        with mock.patch.object(MODULE, "parse_authorized_keys", return_value=[]):
            after = MODULE.after_snapshot(before)
        self.assertEqual(bytes.fromhex(after["bytes_hex"]), b"retain-one\n\nretain-two")

    def test_contract_must_bind_exact_two_target_labels(self) -> None:
        raw = contract().replace(b"obsolete-proxmox-root-identity", b"personal-laptop", 1)
        evidence = observation(list(MODULE.EXPECTED_ATTRIBUTIONS))
        with mock.patch.object(MODULE, "after_snapshot", return_value={}):
            plan = MODULE.build_plan("a" * 40, raw, evidence, datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertIn("root-key-attribution-policy-differs", plan["findings"])
        self.assertEqual(plan["actions"], [])


if __name__ == "__main__": unittest.main()
