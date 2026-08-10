#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
PARSER_PATH = REPOSITORY / "scripts/controller/parse-zpool-status.py"
SPEC = importlib.util.spec_from_file_location("parse_zpool_status", PARSER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load ZFS status parser")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ZpoolStatusParserTests(unittest.TestCase):
    def fixture(self, name: str) -> str:
        return (REPOSITORY / "scripts/controller/fixtures" / name).read_text()

    def test_exact_online_mirrors(self) -> None:
        result = MODULE.parse_status(self.fixture("zpool-status-online.txt"), "storage")
        self.assertEqual(result["pool"], {"name": "storage", "state": "ONLINE"})
        self.assertEqual(len(result["mirrors"]), 6)
        self.assertTrue(all(len(mirror["leaves"]) == 2 for mirror in result["mirrors"]))
        self.assertTrue(all(mirror["state"] == "ONLINE" for mirror in result["mirrors"]))
        self.assertEqual(result["unexpected_data"], [])
        self.assertTrue(all(entries == [] for entries in result["extras"].values()))

    def test_reports_resilver_and_cache(self) -> None:
        result = MODULE.parse_status(self.fixture("zpool-status-resilver-cache.txt"), "storage")
        self.assertIn("resilver in progress", result["scan"])
        self.assertEqual(result["extras"]["cache"][0]["name"], "/dev/disk/by-id/unexpected-cache")

    def test_rejects_wrong_pool(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected pool"):
            MODULE.parse_status(self.fixture("zpool-status-online.txt"), "other")


if __name__ == "__main__":
    unittest.main()
