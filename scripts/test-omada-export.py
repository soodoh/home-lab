#!/usr/bin/env python3
"""Focused tests for the fresh Omada observation projection."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = Path(__file__).with_name("export-omada-state.py")
SPEC = importlib.util.spec_from_file_location("export_omada_state", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


class FakeOmada:
    controller_id = "controller-id"
    controller_version = "6.3.0.45"

    def __init__(self) -> None:
        self.responses: dict[str, list[dict[str, Any]]] = {
            "/controller-id/api/v2/sites": [
                {"id": "other-site", "name": "Other"},
                {"id": "site-id", "name": "Selected"},
            ],
            "/controller-id/api/v2/sites/site-id/setting/lan/networks": [
                {
                    "id": "network-id",
                    "name": "Default",
                    "vlan": 1,
                    "gatewaySubnet": "192.0.2.1/24",
                    "dhcpSettings": {
                        "enable": True,
                        "ipaddrStart": "192.0.2.10",
                        "ipaddrEnd": "192.0.2.99",
                    },
                }
            ],
            "/controller-id/api/v2/sites/site-id/setting/service/dhcp": [
                {
                    "netId": "network-id",
                    "clientName": "second",
                    "mac": "aa:bb:cc:dd:ee:02",
                    "ip": "192.0.2.12",
                    "status": False,
                },
                {
                    "netId": "another-network",
                    "name": "excluded",
                    "mac": "aa:bb:cc:dd:ee:03",
                    "ip": "192.0.2.13",
                    "status": True,
                },
                {
                    "netId": "network-id",
                    "name": "first",
                    "mac": "AA-BB-CC-DD-EE-01",
                    "ip": "192.0.2.11",
                    "status": True,
                },
            ],
            "/controller-id/api/v2/sites/site-id/setting/transmission/portForwardings": [
                {
                    "id": "forward-2",
                    "name": "combined",
                    "status": False,
                    "interfaceWanPortId": ["wan-1"],
                    "externalPort": "8000-8010",
                    "forwardIp": "192.0.2.22",
                    "forwardPort": "8000-8010",
                    "protocol": 0,
                    "dMZ": False,
                },
                {
                    "id": "forward-1",
                    "name": "https",
                    "status": True,
                    "interfaceWanPortId": ["wan-1", "wan-2"],
                    "externalPort": "443",
                    "forwardIp": "192.0.2.21",
                    "forwardPort": "8443",
                    "protocol": 1,
                    "dMZ": False,
                },
            ],
        }

    def list_all(self, path: str) -> list[dict[str, Any]]:
        return self.responses[path]


class OmadaExportTests(unittest.TestCase):
    def test_root_admits_only_fresh_selected_domain_exports(self) -> None:
        source = (ROOT / "infrastructure/tofu/omada/main.tf").read_text()
        for required in (
            "local.export.site.name == var.omada_domain.site_name",
            "local.export.network.name == var.omada_domain.network_name",
            'timeadd(plantimestamp(), "-15m")',
            "timecmp(local.export.exported_at, plantimestamp()) <= 0",
            "length(local.export.port_forwards) > 0",
            "to = omada_port_forward.port_forward[each.key]",
        ):
            self.assertIn(required, source)

    def test_projects_exact_selected_live_domain(self) -> None:
        value = EXPORTER.build_export(FakeOmada(), "Selected", "Default")

        self.assertEqual(value["controller_version"], "6.3.0.45")
        self.assertEqual(value["site"], {"id": "site-id", "name": "Selected"})
        self.assertEqual(value["network"]["id"], "network-id")
        self.assertEqual(
            [reservation["mac"] for reservation in value["reservations"]],
            ["AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"],
        )
        self.assertEqual(
            [reservation["enable"] for reservation in value["reservations"]],
            [True, False],
        )
        self.assertEqual(
            [port_forward["id"] for port_forward in value["port_forwards"]],
            ["forward-1", "forward-2"],
        )
        self.assertEqual(
            value["port_forwards"][0],
            {
                "id": "forward-1",
                "name": "https",
                "enable": True,
                "external_port": "443",
                "forward_ip": "192.0.2.21",
                "forward_port": "8443",
                "protocol": "tcp",
                "wan_port_ids": ["wan-1", "wan-2"],
                "dmz": False,
            },
        )
        self.assertEqual(value["port_forwards"][1]["protocol"], "tcp_udp")

    def test_refuses_an_unknown_site(self) -> None:
        with self.assertRaisesRegex(SystemExit, "exactly one Omada site"):
            EXPORTER.build_export(FakeOmada(), "Missing", "Default")

    def test_normalizes_supported_mac_formats(self) -> None:
        self.assertEqual(EXPORTER.normalize_mac("aabb.ccdd.eeff"), "AA-BB-CC-DD-EE-FF")
        with self.assertRaisesRegex(SystemExit, "invalid MAC"):
            EXPORTER.normalize_mac("not-a-mac")

    def test_refuses_invalid_port_forward_protocols_and_bindings(self) -> None:
        value = FakeOmada().responses[
            "/controller-id/api/v2/sites/site-id/setting/transmission/portForwardings"
        ][0].copy()
        value["protocol"] = 3
        with self.assertRaisesRegex(SystemExit, "invalid protocol"):
            EXPORTER.normalize_port_forward(value)

        value["protocol"] = 2
        value["interfaceWanPortId"] = []
        with self.assertRaisesRegex(SystemExit, "invalid WAN port bindings"):
            EXPORTER.normalize_port_forward(value)


if __name__ == "__main__":
    unittest.main()
