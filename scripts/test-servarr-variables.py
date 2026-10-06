#!/usr/bin/env python3
"""Behavior checks for protected Arr provider input preparation."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("inputs", Path(__file__).with_name("prepare-servarr-variables.py"))
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)


class ProviderInputTest(unittest.TestCase):
    def test_combines_only_expected_values(self):
        production = {f"{name}_API_KEY": name for name in inputs.KEYS}
        production["RADARR_URL"] = "http://gluetun:7878"
        clients = {"qbittorrent_username": "admin", "qbittorrent_password": "long secret", "sabnzbd_api_key": "key"}
        additional = {"root_folders": {"sonarr": {"7": "/data/media/tv"}}, "indexers": {"5": {"cookie": "protected"}, "8": {"mamId": "synthetic-mam-id"}}}
        result = inputs.build_inputs(production, clients, additional)
        self.assertEqual(result["radarr_4k_api_key"], "RADARR_4K")
        self.assertEqual(result["indexer_secrets"]["5"]["cookie"], "protected")
        self.assertEqual(result["indexer_secrets"]["8"]["mamId"], "synthetic-mam-id")
        self.assertNotIn("MEDIA_PATH", result)
        self.assertEqual(result["radarr_internal_url"], "http://gluetun:7878")
        self.assertEqual(len(result), 10)

    def test_refuses_missing_values(self):
        with self.assertRaises(KeyError):
            inputs.build_inputs({}, {}, {})

    def test_requires_fresh_owned_mode_0700_directory(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            path.chmod(0o700)
            inputs.require_private_session(path)
            path.chmod(0o755)
            with self.assertRaises(ValueError):
                inputs.require_private_session(path)
            path.chmod(0o700)
            link = path / "symlink"
            link.symlink_to(path, target_is_directory=True)
            with self.assertRaises(ValueError):
                inputs.require_private_session(link)
            os.utime(path, (0, 0))
            with self.assertRaises(ValueError):
                inputs.require_private_session(path)


if __name__ == "__main__":
    unittest.main()
