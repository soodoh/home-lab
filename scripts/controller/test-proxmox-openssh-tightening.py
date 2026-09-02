#!/usr/bin/env python3
import importlib.util
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "openssh", ROOT / "scripts/controller/proxmox-openssh-tightening.py"
)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def observation(raw):
    meta = {
        "exists": True,
        "uid": 0,
        "gid": 0,
        "mode": "0644",
        "regular": True,
        "symlink": False,
        "nlink": 1,
        "size": len(raw),
        "sha256": M.sha(raw),
        "bytes_hex": raw.hex(),
    }
    paths = {
        M.CONFIG: meta,
        **{p: {"exists": False} for p in M.B.AUTHORIZED_KEY_CATALOG},
    }
    for p, (uid, gid, mode) in M.RETAINED.items():
        paths[p] = {
            "exists": True,
            "uid": uid,
            "gid": gid,
            "mode": mode,
            "regular": True,
            "symlink": False,
            "nlink": 1,
            "size": 1,
            "sha256": "a" * 64,
            "bytes_hex": "00",
        }
    for path, content in M.B.SUDO_CONTENT.items():
        content_raw = content.encode()
        paths[path].update(
            {
                "bytes_hex": content_raw.hex(),
                "sha256": M.sha(content_raw),
                "size": len(content_raw),
            }
        )
    for path, source in M.B.TRANSPORT_SOURCES.items():
        content_raw = (M.B.ROOT / source).read_bytes()
        paths[path].update(
            {
                "bytes_hex": content_raw.hex(),
                "sha256": M.sha(content_raw),
                "size": len(content_raw),
            }
        )
    return {
        "paths": paths,
        "effective": M.final_effective() if raw == M.DESIRED else {"legacy": True},
        "service_active": True,
        "service_enabled": True,
        "locks": [],
        "accounts": {
            **M.B.RETAINED_ACCOUNTS,
            **{
                name: {
                    "exists": False,
                    "group_exists": False,
                    "home_exists": False,
                    "sudo_exists": False,
                }
                for name in M.B.RETIRED_ACCOUNTS
            },
        },
        "final_key_receipt": {
            "path": "/receipt",
            "sha256": "b" * 64,
            "plan_sha256": "c" * 64,
            "committed_at": "2026-01-01T00:00:00Z",
        },
        "tokens": M.B.TOKENS,
        "root_groups": ["root"],
        "apex": {"gid": 1000, "members": []},
    }


class Tests(unittest.TestCase):
    def test_committed_final_key_receipt_requires_canonical_matching_state(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        digest = "a" * 64
        receipt = {
            "status": "committed",
            "plan_sha256": digest,
            "mutation_started_at": now.isoformat().replace("+00:00", "Z"),
            "mutated_at": now.isoformat().replace("+00:00", "Z"),
            "watchdog_deadline": now.isoformat().replace("+00:00", "Z"),
            "watchdog_seconds": 900,
            "format": "home-lab-proxmox-final-key-retirement-receipt-v1",
            "canary_sha256": "b" * 64,
            "committed_at": now.isoformat().replace("+00:00", "Z"),
        }
        raw = M.canonical(receipt)
        value = {
            "watchdog_units": [],
            "receipts": [
                {
                    "path": f"/var/lib/home-lab/final-key-retirement/{digest}/receipt.json",
                    "receipt_hex": raw.hex(),
                    "receipt_sha256": M.sha(raw),
                    "state_hex": raw.hex(),
                    "state_sha256": M.sha(raw),
                }
            ],
        }
        self.assertEqual(M.validate_final_key_receipt(value)["plan_sha256"], digest)
        value["receipts"][0]["state_hex"] = M.canonical(
            {**receipt, "status": "awaiting-canary"}
        ).hex()
        with self.assertRaises(SystemExit):
            M.validate_final_key_receipt(value)

    def test_legacy_dropin_plans_only_reload_transaction(self):
        v = M.build_plan(
            "a" * 40,
            M.CONTRACT.read_bytes(),
            observation(b"legacy\n"),
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(
            v["actions"],
            [
                {
                    "kind": "tighten-openssh-drop-in",
                    "path": M.CONFIG,
                    "reload_service": "ssh.service",
                }
            ],
        )
        self.assertEqual(v["findings"], [])

    def test_exact_final_policy_is_noop(self):
        v = M.build_plan(
            "a" * 40,
            M.CONTRACT.read_bytes(),
            observation(M.DESIRED),
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual((v["actions"], v["findings"], v["blockers"]), ([], [], []))

    def test_any_conventional_key_blocks_transaction(self):
        o = observation(b"legacy\n")
        o["paths"][M.B.ROOT_KEY] = {"exists": True}
        v = M.build_plan(
            "a" * 40,
            M.CONTRACT.read_bytes(),
            o,
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.assertIn("final-key-absence-or-ssh-service-differs", v["findings"])
        self.assertEqual(v["actions"], [])

    def test_desired_content_omits_allowusers(self):
        self.assertNotIn(b"AllowUsers", M.DESIRED)


if __name__ == "__main__":
    unittest.main()
