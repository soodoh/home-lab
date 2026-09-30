#!/usr/bin/env python3
"""Offline tests for the protected two-source Compose validation adapter."""

import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check-compose-with-sops.py"
spec = importlib.util.spec_from_file_location("compose_with_sops", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MergeTests(unittest.TestCase):
    def test_appends_one_client_id_and_secret(self):
        result = module.merged_env("BASE=synthetic\n", "synthetic-id", "s" * 48)
        self.assertEqual(result.count("VAULTWARDEN_SSO_CLIENT_ID="), 1)
        self.assertEqual(result.count("VAULTWARDEN_SSO_CLIENT_SECRET="), 1)
        self.assertTrue(result.endswith("\n"))

    def test_rejects_duplicate_or_unsafe_values(self):
        for source, client_id, secret in (
            ("VAULTWARDEN_SSO_CLIENT_ID=old\n", "id", "s" * 48),
            ("VAULTWARDEN_SSO_CLIENT_SECRET=old\n", "id", "s" * 48),
            ("BASE=synthetic", "id", "s" * 48),
            ("BASE=synthetic\n", "unsafe=id", "s" * 48),
            ("BASE=synthetic\n", "id", "${OTHER}" + "s" * 48),
        ):
            with self.subTest(source=source, client_id=client_id):
                with self.assertRaises(ValueError):
                    module.merged_env(source, client_id, secret)


if __name__ == "__main__":
    unittest.main()
