#!/usr/bin/env python3
"""Behavior tests for least-privilege Compose interpolation selection."""

import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check-compose-with-sops.py"
spec = importlib.util.spec_from_file_location("compose_with_sops", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EnvironmentTests(unittest.TestCase):
    def test_keeps_native_serialization_and_drops_unselected_secrets(self):
        line = 'BASE="synthetic\\nquoted\\\"\\$value"'
        result = module.render_environment("# Native SOPS comment\n\n" + line + "\nAPI_KEY=synthetic-private\n", "synthetic-id", ["BASE"])
        self.assertEqual(result, line + "\nVAULTWARDEN_SSO_CLIENT_ID=synthetic-id\n")
        self.assertNotIn("synthetic-private", result)
        self.assertNotIn("SSO_CLIENT_SECRET", result)

    def test_rejects_duplicate_or_unsafe_inputs_without_echoing_values(self):
        for source, client_id, keys in (
            ("VAULTWARDEN_SSO_CLIENT_ID=old\n", "id", []),
            ("VAULTWARDEN_SSO_CLIENT_SECRET=old\n", "id", []),
            ("BASE=synthetic", "id", ["BASE"]),
            ("BASE=synthetic\n", "unsafe=id", ["BASE"]),
            ("BASE=synthetic\n", "id", ["MISSING"]),
            ("BASE=one\nBASE=two\n", "id", ["BASE"]),
            ("BASE=synthetic\n", "id", ["BASE", "BASE"]),
            ("BASE=synthetic\n", "id", ["BASE\nOTHER"]),
            ("BASE=synthetic\nvalue-continuation\n", "id", ["BASE"]),
        ):
            with self.subTest(client_id=client_id, keys=keys):
                with self.assertRaises(ValueError) as raised:
                    module.render_environment(source, client_id, keys)
                self.assertNotIn("synthetic", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
