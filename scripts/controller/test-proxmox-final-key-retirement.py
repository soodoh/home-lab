#!/usr/bin/env python3
import importlib.util
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "final_keys", ROOT / "scripts/controller/proxmox-final-key-retirement.py"
)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def obs(state="present"):
    paths = {p: {"exists": False} for p in M.AUTHORIZED_KEY_CATALOG}
    for p, (uid, gid, mode) in M.RETAINED.items():
        paths[p] = {
            "exists": True,
            "uid": uid,
            "gid": gid,
            "mode": mode,
            "regular": True,
            "symlink": False,
            "nlink": 1,
            "sha256": "a" * 64,
            "bytes_hex": "00",
            "size": 1,
        }
    for path, content in M.SUDO_CONTENT.items():
        raw = content.encode()
        paths[path].update(
            {"bytes_hex": raw.hex(), "sha256": M.sha(raw), "size": len(raw)}
        )
    for path, source in M.TRANSPORT_SOURCES.items():
        raw = (M.ROOT / source).read_bytes()
        paths[path].update(
            {"bytes_hex": raw.hex(), "sha256": M.sha(raw), "size": len(raw)}
        )
    return {
        "paths": paths,
        "locks": [],
        "accounts": {
            **M.RETAINED_ACCOUNTS,
            **{
                name: {
                    "exists": False,
                    "group_exists": False,
                    "home_exists": False,
                    "sudo_exists": False,
                }
                for name in M.RETIRED_ACCOUNTS
            },
        },
        "tokens": M.TOKENS,
        "sshd": M.SSHD_BEFORE,
        "root_groups": ["root"],
        "apex": {"gid": 1000, "members": []},
        "state": state,
    }


class Tests(unittest.TestCase):
    def build(self, o, present=False):
        with (
            mock.patch.object(
                M,
                "recovery_proof",
                return_value={"commit": M.RECOVERY_COMMIT, "sha256": M.RECOVERY_SHA},
            ),
            mock.patch.object(M, "expected_present", return_value=present),
        ):
            return M.build_plan(
                "a" * 40,
                M.CONTRACT.read_bytes(),
                o,
                datetime(2026, 1, 1, tzinfo=timezone.utc),
            )

    def test_exact_present_state_plans_only_three_paths(self):
        o = obs()
        o["paths"].update({p: {"exists": True} for p in M.PATHS})
        v = self.build(o, True)
        self.assertEqual(
            v["actions"],
            [{"kind": "remove-final-conventional-key-paths", "paths": list(M.PATHS)}],
        )
        self.assertEqual(v["findings"], [])

    def test_exact_absence_is_noop(self):
        v = self.build(obs())
        self.assertEqual((v["actions"], v["findings"], v["blockers"]), ([], [], []))

    def test_exact_absence_remains_noop_after_openssh_tightening(self):
        o = obs()
        o["sshd"] = M.SSHD_FINAL
        v = self.build(o)
        self.assertEqual((v["actions"], v["findings"], v["blockers"]), ([], [], []))

    def test_exact_absence_noop_does_not_require_recovery_proof(self):
        with mock.patch.object(M, "recovery_proof", side_effect=AssertionError("must not run")), mock.patch.object(M, "expected_present", return_value=False):
            value = M.build_plan("a" * 40, M.CONTRACT.read_bytes(), obs(), datetime(2030, 1, 1, tzinfo=timezone.utc))
        self.assertEqual((value["actions"], value["findings"], value["blockers"]), ([], [], []))

    def test_real_pinned_recovery_receipt_passes_at_controlled_valid_time(self):
        completed = 1788312098
        proof = M.recovery_proof(datetime.fromtimestamp(completed + 60, timezone.utc))
        self.assertEqual(proof["repository_id"], M.RECOVERY_REPOSITORY_ID)
        self.assertEqual(proof["snapshot_id"], M.RECOVERY_SNAPSHOT_ID)

    def test_partial_absence_fails_closed(self):
        o = obs()
        o["paths"][M.ROOT_KEY] = {"exists": True}
        v = self.build(o)
        self.assertIn("conventional-key-state-differs", v["findings"])
        self.assertEqual(v["actions"], [])

    def test_authorized_key_catalog_covers_both_names_for_every_account(self):
        for name in ("root", *M.ACCOUNT_NAMES):
            home = "/root" if name == "root" else f"/home/{name}"
            self.assertIn(f"{home}/.ssh/authorized_keys", M.AUTHORIZED_KEY_CATALOG)
            self.assertIn(f"{home}/.ssh/authorized_keys2", M.AUTHORIZED_KEY_CATALOG)

    def test_access_evidence_rejects_unbounded_or_noncanonical_input(self):
        plan = {"commit": "a", "contract_sha256": "b", "inventory_sha256": "c"}
        with self.assertRaises(SystemExit):
            M.validate_access_evidence({}, b"{}\n" + b" " * 262145, plan, [])
        with self.assertRaises(SystemExit):
            M.validate_access_evidence(
                {"unexpected": True}, b'{"unexpected": true}\n', plan, []
            )

    def test_recovery_timestamp_rejects_older_than_contract_limit(self):
        now = datetime(2026, 9, 2, tzinfo=timezone.utc)
        with self.assertRaises(SystemExit):
            M.validate_recovery_timestamp(int((now.timestamp() - 91 * 86400)), now)

    def test_recovery_proof_requires_exact_bound_digest(self):
        with mock.patch.object(M, "RECOVERY_SHA", "0" * 64):
            with self.assertRaises(SystemExit):
                M.recovery_proof()


if __name__ == "__main__":
    unittest.main()
