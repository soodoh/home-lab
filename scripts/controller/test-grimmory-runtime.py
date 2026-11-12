#!/usr/bin/env python3
"""Settings qualification against the isolated BookDrop fixture's pinned stack.

The Ansible fixture owns startup, Linux bind permissions and teardown. This test
uses only its loopback endpoint and synthetic administrator/settings; no SOPS or
production application data. Run through ansible/tests/grimmory-bookdrop.yml.
"""

import argparse
import importlib.util
import os
from pathlib import Path
import unittest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('grimmory_contract', Path(__file__).with_name('test-grimmory.py'))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
ENDPOINT = None


@unittest.skipUnless(os.environ.get('GRIMMORY_RUNTIME_TEST') == '1', 'explicit isolated-container qualification required')
class PinnedRuntimeTests(unittest.TestCase):
    run_native = contract.NativeAuthenticationTests.run_native

    def test_native_config_tree_and_settings_api(self):
        self.assertIsNotNone(ENDPOINT, 'requires the isolated fixture endpoint')
        with contract.api_server() as (discovery, _):
            first = self.run_native(ENDPOINT, initialize=True, discovery_url=discovery + '/discovery')
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            second = self.run_native(ENDPOINT, discovery_url=discovery + '/discovery')
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertRegex(second.stdout, r'changed=0\s')
            rotated = self.run_native(ENDPOINT, secret='synthetic-runtime-rotation', discovery_url=discovery + '/discovery')
            self.assertEqual(rotated.returncode, 0, rotated.stdout + rotated.stderr)


def endpoint(value):
    url = urlsplit(value)
    if (url.scheme != 'http' or url.hostname != '127.0.0.1' or not url.port
            or url.username or url.password or url.path or url.query or url.fragment):
        raise argparse.ArgumentTypeError('requires an isolated loopback endpoint')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True, type=endpoint)
    args, remaining = parser.parse_known_args()
    ENDPOINT = args.endpoint
    unittest.main(argv=[__file__, *remaining])
