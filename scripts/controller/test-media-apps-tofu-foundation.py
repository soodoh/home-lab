#!/usr/bin/env python3

import json
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "infrastructure" / "tofu" / "media-apps"
DESIRED = json.loads((ROOT / "desired.json").read_text())
IMPORTS = json.loads((REPO / "infrastructure" / "applications" / "vm-100-application-imports.json").read_text())


class MediaAppsTofuFoundationTests(unittest.TestCase):
    def test_desired_objects_match_approved_imports(self) -> None:
        expected = {
            item["resourceAddress"]: item
            for item in IMPORTS["imports"]
            if item["root"] == "media-apps"
        }
        actual = {}
        groups = [
            ("sonarrRootFolders", "sonarr_root_folder.root_folders", "root-folder"),
            ("radarrRootFolders", "radarr_root_folder.root_folders", "root-folder"),
            ("radarr4kRootFolders", "radarr_root_folder.root_folders_4k", "root-folder"),
            ("prowlarrTags", "prowlarr_tag.tags", "tag"),
            ("prowlarrSyncProfiles", "prowlarr_sync_profile.sync_profiles", "sync-profile"),
        ]
        for group, address, resource_class in groups:
            for key, value in DESIRED[group].items():
                actual[f'{address}["{key}"]'] = (str(value["importId"]), resource_class)

        self.assertEqual(set(actual), set(expected))
        self.assertEqual(len(actual), 9)
        for address, (import_id, resource_class) in actual.items():
            self.assertEqual(expected[address]["importId"], import_id)
            self.assertEqual(expected[address]["class"], resource_class)

    def test_recyclarr_and_secret_bearing_resources_are_absent(self) -> None:
        serialized = json.dumps(DESIRED, sort_keys=True)
        for forbidden in (
            "api_key",
            "custom_format",
            "download_client",
            "import_list",
            "indexer",
            "password",
            "quality_profile",
            "token",
        ):
            self.assertNotIn(forbidden, serialized.lower())

    def test_root_is_disabled_import_first_and_ephemeral(self) -> None:
        versions = (ROOT / "versions.tf").read_text()
        variables = (ROOT / "variables.tf").read_text()
        main = (ROOT / "main.tf").read_text()

        for version in ("= 3.4.2", "= 2.4.0", "= 3.2.1"):
            self.assertIn(f'version = "{version}"', versions)
        self.assertIn('key          = "home-lab/media-apps/tofu.tfstate"', versions)
        self.assertIn("default     = false", variables)
        self.assertEqual(variables.count("ephemeral = true"), 4)
        self.assertEqual(variables.count("sensitive = true"), 4)
        self.assertEqual(main.count("prevent_destroy = true"), 5)
        self.assertEqual(main.count("import {"), 5)
        self.assertIn("provider = radarr.radarr_4k", main)

    def test_source_hash_matches_inventory_manifest(self) -> None:
        self.assertEqual(DESIRED["sourceInventory"]["sha256"], IMPORTS["evidence"]["arrInventorySha256"])


if __name__ == "__main__":
    unittest.main()
