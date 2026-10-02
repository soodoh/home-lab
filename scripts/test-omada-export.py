#!/usr/bin/env python3
"""Focused tests for the fresh Omada observation projection."""

from __future__ import annotations

import importlib.util
import json
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
            "/controller-id/api/v2/sites/site-id/setting/wlans": [
                {"id": "group-id", "name": "Default"},
            ],
            "/controller-id/api/v2/sites/site-id/setting/wlans/group-id/ssids": [
                {"id": "ssid-id", "name": "Selected WLAN", "pskSetting": {"securityKey": "do-not-export"}},
            ],
            "/controller-id/api/v2/sites/site-id/devices": [
                {"type": "gateway", "mac": "AA:BB:CC:DD:EE:FF", "password": "do-not-export"},
                {"type": "ap", "mac": "AA:BB:CC:DD:EE:00"},
            ],
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
                        "options": [{"code": 42, "type": 1, "value": "192.0.2.30"}],
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
    def test_committed_desired_settings_have_stable_ownership_keys(self) -> None:
        desired = json.loads((ROOT / "infrastructure/tofu/omada/desired.json").read_text())
        domain = json.loads((ROOT / "infrastructure/tofu/omada/domain.auto.tfvars.json").read_text())
        self.assertEqual(set(desired), {
            "network", "reservations", "port_forwards", "wireless_networks", "gateway",
            "upnp", "ssh_settings", "snmp", "site_settings", "attack_defense", "iptv",
            "notification_settings",
        })
        self.assertEqual(desired["network"]["name"], domain["omada_domain"]["network_name"])
        self.assertEqual(set(desired["network"]), {
            "name", "vlan_id", "gateway_subnet", "dhcp_enabled", "dhcp_start", "dhcp_end", "dhcp_options",
            "isolation", "igmp_snoop_enable", "ipv6", "dhcp_dns_mode", "dhcp_lease_time",
        })
        self.assertEqual(desired["network"]["dhcp_options"], [
            {"code": 138, "value": "192.168.0.100"},
        ])
        self.assertTrue(desired["reservations"])
        self.assertTrue(desired["port_forwards"])
        for mac, reservation in desired["reservations"].items():
            self.assertEqual(mac, mac.lower())
            self.assertEqual(len(mac.split(":")), 6)
            self.assertEqual(set(reservation), {"name", "ip", "enable"})
        for rule_id, forward in desired["port_forwards"].items():
            self.assertTrue(rule_id)
            self.assertEqual(set(forward), {
                "name", "enable", "external_port", "forward_ip", "forward_port",
                "protocol", "wan_port_ids", "dmz",
            })
            self.assertTrue(forward["wan_port_ids"])

    def test_projects_exact_selected_live_domain(self) -> None:
        value = EXPORTER.build_export(FakeOmada(), "Selected", "Default")

        self.assertEqual(value["controller_version"], "6.3.0.45")
        self.assertEqual(value["site"], {"id": "site-id", "name": "Selected"})
        self.assertEqual(value["network"]["id"], "network-id")
        self.assertEqual(value["wireless_networks"], [
            {"id": "ssid-id", "wlan_group_id": "group-id", "name": "Selected WLAN"},
        ])
        self.assertEqual(value["gateway"], {"mac": "AA-BB-CC-DD-EE-FF"})
        self.assertNotIn("do-not-export", json.dumps(value))
        self.assertEqual(value["network"]["dhcp_options"], [
            {"code": 42, "type": 1, "value": "192.0.2.30"},
        ])
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

    def test_projects_every_group_and_ssid_without_filtering_extra_identities(self) -> None:
        client = FakeOmada()
        base = "/controller-id/api/v2/sites/site-id/setting/wlans"
        client.responses[base].append({"id": "extra-group", "name": "Extra"})
        client.responses[f"{base}/extra-group/ssids"] = [
            {"id": "extra-ssid", "name": "Extra SSID"},
        ]
        value = EXPORTER.build_export(client, "Selected", "Default")
        self.assertEqual(value["wireless_networks"], [
            {"id": "extra-ssid", "wlan_group_id": "extra-group", "name": "Extra SSID"},
            {"id": "ssid-id", "wlan_group_id": "group-id", "name": "Selected WLAN"},
        ])
        client.responses[f"{base}/extra-group/ssids"][0].pop("id")
        with self.assertRaisesRegex(SystemExit, "missing id"):
            EXPORTER.build_export(client, "Selected", "Default")

    def test_refuses_missing_or_ambiguous_gateway(self) -> None:
        client = FakeOmada()
        path = "/controller-id/api/v2/sites/site-id/devices"
        client.responses[path] = []
        with self.assertRaisesRegex(SystemExit, "exactly one managed gateway"):
            EXPORTER.build_export(client, "Selected", "Default")
        client.responses[path] = [{"type": "gateway", "mac": "AA:BB:CC:DD:EE:FF"}] * 2
        with self.assertRaisesRegex(SystemExit, "exactly one managed gateway"):
            EXPORTER.build_export(client, "Selected", "Default")

    def test_list_accepts_bare_and_paginated_native_responses(self) -> None:
        client = EXPORTER.Omada.__new__(EXPORTER.Omada)
        pages = iter([{"data": [{"id": "first"}], "totalRows": 2},
                      {"data": [{"id": "second"}], "totalRows": 2}])
        client.request = lambda *args: next(pages)
        self.assertEqual(client.list_all("/list"), [{"id": "first"}, {"id": "second"}])
        client.request = lambda *args: [{"id": "bare"}]
        self.assertEqual(client.list_all("/list"), [{"id": "bare"}])
        client.request = lambda *args: {"data": [{"id": "unpaginated"}], "maxSsids2G": 16}
        self.assertEqual(client.list_all("/list"), [{"id": "unpaginated"}])
        for malformed in [[None], {"data": [None], "totalRows": 1}, {}]:
            client.request = lambda *args: malformed
            with self.assertRaisesRegex(SystemExit, "unexpected shape"):
                client.list_all("/list")

    def test_refuses_unverifiable_or_truncated_pagination(self) -> None:
        client = EXPORTER.Omada.__new__(EXPORTER.Omada)
        for malformed in [{"data": [{}], "currentPage": 1}, {"data": [{}], "totalRows": 0},
                          {"data": [], "totalRows": 1}]:
            client.request = lambda *args: malformed
            with self.assertRaisesRegex(SystemExit, "incomplete inventory"):
                client.list_all("/list")

    def test_refuses_an_unknown_site(self) -> None:
        with self.assertRaisesRegex(SystemExit, "exactly one Omada site"):
            EXPORTER.build_export(FakeOmada(), "Missing", "Default")

    def test_refuses_unmanaged_networks_and_reservations(self) -> None:
        client = FakeOmada()
        base = "/controller-id/api/v2/sites/site-id"
        client.responses[f"{base}/setting/lan/networks"].append({"id": "other", "name": "Other"})
        with self.assertRaisesRegex(SystemExit, "exactly the managed network"):
            EXPORTER.build_export(client, "Selected", "Default")

        client = FakeOmada()
        client.responses[f"{base}/setting/service/dhcp"].append({
            "netId": "other", "name": "unmanaged", "mac": "AA-BB-CC-DD-EE-03",
            "ip": "192.0.2.13", "status": True,
        })
        with self.assertRaisesRegex(SystemExit, "outside the managed network"):
            EXPORTER.build_export(client, "Selected", "Default")

    def test_refuses_invalid_dhcp_options(self) -> None:
        client = FakeOmada()
        network = client.responses["/controller-id/api/v2/sites/site-id/setting/lan/networks"][0]
        network["dhcpSettings"]["options"] = [{"code": 138, "value": "192.0.2.30"}]
        with self.assertRaisesRegex(SystemExit, "invalid DHCP options"):
            EXPORTER.build_export(client, "Selected", "Default")

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
