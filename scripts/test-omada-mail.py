#!/usr/bin/env python3
"""Exercise the native jq contract with synthetic credentials only."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
INPUT = {
    "schema_version": 1,
    "smtp": {
        "host": "smtp.protonmail.ch", "port": 587, "security": "starttls",
        "username": "fixture@example.com", "sender": "fixture@example.com",
        "password": "synthetic-'quoted'-$token=with\\backslash",
    },
    "recipients": ["recipient@example.com"],
}


class OmadaMailInputTests(unittest.TestCase):
    def validate(self, value, accepted):
        result = subprocess.run(
            ["jq", "-e", "-f", str(ROOT / "scripts/omada-mail-input.jq")],
            input=json.dumps(value), capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0 if accepted else 1)
        self.assertEqual(result.stdout.strip(), "true" if accepted else "false")
        self.assertEqual(result.stderr, "")

    def test_accepts_exact_literal_credentials(self):
        self.validate(INPUT, True)

    def test_accepts_another_provider_with_implicit_tls(self):
        value = deepcopy(INPUT)
        value["smtp"].update(host="smtp.example.com", port=465, security="tls")
        self.validate(value, True)

    def test_rejects_wrong_shapes_without_printing_values(self):
        for value in [None, [], "synthetic-secret", {}, {**INPUT, "unknown": True}]:
            with self.subTest(shape=type(value).__name__):
                self.validate(value, False)
        for key in INPUT:
            value = deepcopy(INPUT)
            del value[key]
            self.validate(value, False)

    def test_rejects_incomplete_or_unsafe_smtp_fields(self):
        bad = {
            "host": ["", "https://smtp.example.com", "host\nheader", "user@host"],
            "port": ["587", 0, 65536, 587.5, True],
            "security": ["none", "ssl", ""],
            "username": ["", "user\rheader", 123],
            "password": ["", "synthetic\nsecret", "synthetic\x00secret", None],
            "sender": ["", "not-email", "a@example.com\nBcc:other@example.com"],
        }
        for field, values in bad.items():
            for invalid in values:
                value = deepcopy(INPUT)
                value["smtp"][field] = invalid
                with self.subTest(field=field):
                    self.validate(value, False)

    def test_rejects_incompatible_proton_settings(self):
        for changes in [{"port": 465}, {"security": "tls"}, {"sender": "other@example.com"}]:
            value = deepcopy(INPUT)
            value["smtp"].update(changes)
            self.validate(value, False)

    def test_rejects_missing_invalid_or_duplicate_recipients(self):
        for recipients in [[], "recipient@example.com", [None], ["bad"],
                           ["r@example.com", "r@example.com"]]:
            value = deepcopy(INPUT)
            value["recipients"] = recipients
            self.validate(value, False)


if __name__ == "__main__":
    unittest.main()
