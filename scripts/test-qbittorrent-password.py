#!/usr/bin/env python3
"""Behavioral checks for the pinned qBittorrent password verifier."""

import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "qbit_password", Path(__file__).with_name("check-qbittorrent-password.py")
)
qbit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qbit)


class PasswordCheck(unittest.TestCase):
    def setUp(self):
        salt = bytes(range(16))
        key = hashlib.pbkdf2_hmac("sha512", b"correct horse", salt, 100000, 64)
        value = base64.b64encode(salt).decode() + ":" + base64.b64encode(key).decode()
        self.conf = '[Preferences]\nWebUI\\Username=operator\nWebUI\\Password_PBKDF2="@ByteArray(' + value + ')"\n'

    def test_matching_username_and_password(self):
        self.assertTrue(qbit.matches(self.conf, "operator", "correct horse"))

    def migrated_conf(self):
        # qBittorrent 5.3 migrates Preferences/WebUI/* to WebUI/*, without
        # changing the PBKDF2 encoding or parameters.
        return self.conf.replace('[Preferences]', '[WebUI]').replace('WebUI\\', '')

    def test_migrated_webui_credentials(self):
        conf = self.migrated_conf()
        self.assertTrue(qbit.matches(conf, 'operator', 'correct horse'))
        self.assertFalse(qbit.matches(conf, 'operator', 'other'))
        self.assertFalse(qbit.matches(conf, 'other', 'correct horse'))

    def test_partial_migration_fails_closed(self):
        for conf in (
            self.migrated_conf().replace('Username=operator\n', ''),
            self.conf.replace('WebUI\\Username=operator\n', '') + '[WebUI]\nUsername=operator\n',
        ):
            with self.subTest(conf=conf), self.assertRaises(ValueError):
                qbit.matches(conf, 'operator', 'correct horse')

    def test_multiple_credential_locations_fail_closed(self):
        for conf in (self.conf + self.migrated_conf(), self.conf + '[WebUI]\nUsername=operator\n'):
            with self.subTest(conf=conf), self.assertRaises(ValueError):
                qbit.matches(conf, 'operator', 'correct horse')

    def test_migrated_unknown_encoding_fails_closed(self):
        with self.assertRaises(ValueError):
            qbit.matches(self.migrated_conf().replace('@ByteArray(', '@Other('), 'operator', 'correct horse')

    def test_other_credentials_do_not_match(self):
        self.assertFalse(qbit.matches(self.conf, "operator", "other"))
        self.assertFalse(qbit.matches(self.conf, "other", "correct horse"))

    def test_unknown_encoding_fails_closed(self):
        with self.assertRaises(ValueError):
            qbit.matches(self.conf.replace("@ByteArray(", "@Other("), "operator", "correct horse")
        with self.assertRaises(ValueError):
            qbit.matches(self.conf.replace("WebUI\\Password_PBKDF2", "WebUI\\Other"), "operator", "correct horse")


if __name__ == "__main__":
    unittest.main()
