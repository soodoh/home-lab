#!/usr/bin/env python3
"""Check the read-only collector's reviewed-versus-sealed hardware gate."""

import json
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "infrastructure/host-lifecycle/proxmox/protected-collector-template.py"


class ReviewedHardwareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = TEMPLATE.read_text().replace("'@PROTECTED_SPEC@'", repr(json.dumps({})))
        namespace = {"__name__": "protected_collector_fixture"}
        exec(compile(source, str(TEMPLATE), "exec"), namespace)
        cls.matches = staticmethod(namespace["reviewed_hardware_matches"])

    def setUp(self) -> None:
        self.expected = {
            "gamesDiskIdentity": "/dev/disk/by-id/test-games-disk",
            "usbMappings": [
                {"mapping": "zigbee-cp210x", "port": "1-6", "serial": "test-zigbee-serial"},
                {"mapping": "zwave-cp210x", "port": "1-7", "serial": "test-zwave-serial"},
            ],
        }
        self.sealed = dict(self.expected)

    def test_exact_reviewed_identity_matches(self) -> None:
        self.assertTrue(self.matches(self.sealed, self.expected))

    def test_disk_usb_port_and_serial_changes_are_refused(self) -> None:
        for change in ("gamesDiskIdentity", "port", "serial"):
            with self.subTest(change=change):
                desired = json.loads(json.dumps(self.expected))
                if change == "gamesDiskIdentity":
                    desired[change] = "/dev/disk/by-id/test-other-disk"
                else:
                    desired["usbMappings"][0][change] = "1-8" if change == "port" else "test-other-serial"
                self.assertFalse(self.matches(self.sealed, desired))

    def test_invalid_or_extra_desired_fields_refuse(self) -> None:
        for desired in (
            {**self.expected, "unreviewed": "value"},
            {**self.expected, "gamesDiskIdentity": "/dev/sda"},
            {**self.expected, "usbMappings": self.expected["usbMappings"][:1]},
            {**self.expected, "usbMappings": [{**self.expected["usbMappings"][0], "port": "bad"},
                                                self.expected["usbMappings"][1]]},
        ):
            with self.subTest(desired=desired):
                with self.assertRaises(ValueError):
                    self.matches(self.sealed, desired)


if __name__ == "__main__":
    unittest.main()
