#!/usr/bin/env python3
"""Tests for generic recovery-group selection."""

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery_scope", ROOT / "scripts/recovery-scope.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RecoveryScopeTests(unittest.TestCase):
    def test_groups_cover_the_complete_restic_path_set(self):
        scope = module.load_scope(ROOT / "recovery/groups.json")
        selected = module.resolve(scope, ["all"])
        files_from = set((ROOT / "services/data/restic/files-from").read_text().splitlines())
        self.assertEqual(set(selected["paths"]), files_from)
        self.assertEqual(len(selected["services"]), 38)

    def test_partial_group_includes_common_inputs(self):
        scope = module.load_scope(ROOT / "recovery/groups.json")
        selected = module.resolve(scope, ["nextcloud"])
        self.assertEqual(selected["groups"], ["nextcloud"])
        self.assertEqual(
            selected["services"],
            ["nextcloud", "nextcloud-cron", "nextcloud-db", "nextcloud-redis"],
        )
        self.assertIn("/etc/docker-compose/production.env", selected["paths"])
        self.assertIn("/srv/home-lab-state/nextcloud-db-data", selected["paths"])
        self.assertNotIn("/srv/home-lab-state/vaultwarden-data", selected["paths"])

    def test_unknown_or_mixed_selection_is_rejected(self):
        scope = module.load_scope(ROOT / "recovery/groups.json")
        with self.assertRaisesRegex(ValueError, "unknown or mixed"):
            module.resolve(scope, ["missing"])
        with self.assertRaisesRegex(ValueError, "unknown or mixed"):
            module.resolve(scope, ["all", "nextcloud"])

    def test_scope_has_only_public_selection_metadata(self):
        value = json.loads((ROOT / "recovery/groups.json").read_text())
        self.assertEqual(value["version"], 1)
        self.assertEqual(set(value), {"version", "common_paths", "groups"})


if __name__ == "__main__":
    unittest.main()
