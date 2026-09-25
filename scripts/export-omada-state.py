#!/usr/bin/env python3
"""Read the adopted Omada LAN, DHCP reservations, and port forwards."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse


class RoutedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, connect_host: str, port: int, context: ssl.SSLContext):
        super().__init__(host, port=port, context=context, timeout=30)
        self.connect_host = connect_host

    def connect(self) -> None:
        raw = socket.create_connection((self.connect_host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class Omada:
    def __init__(self, url: str, connect_host: str, username: str, password: str):
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/"):
            raise SystemExit("OMADA_URL must be an HTTPS origin without a path")
        context = ssl.create_default_context()
        self.connection = RoutedHTTPSConnection(
            parsed.hostname, connect_host, parsed.port or 443, context
        )
        self.cookie = ""
        self.token = ""
        info = self.request("GET", "/api/info", authenticated=False)
        self.controller_id = required_string(info, "omadacId")
        self.controller_version = required_string(info, "controllerVer")
        login = self.request(
            "POST",
            f"/{self.controller_id}/api/v2/login",
            {"username": username, "password": password},
            authenticated=False,
        )
        self.token = required_string(login, "token")

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None, *, authenticated: bool = True
    ) -> Any:
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Csrf-Token"] = self.token
            if self.cookie:
                headers["Cookie"] = self.cookie
        payload = json.dumps(body, separators=(",", ":")) if body is not None else None
        self.connection.request(method, path, body=payload, headers=headers)
        response = self.connection.getresponse()
        raw = response.read()
        if response.status < 200 or response.status >= 300:
            raise SystemExit(f"Omada HTTP request failed with status {response.status}")
        cookies = SimpleCookie()
        for value in response.headers.get_all("Set-Cookie", []):
            cookies.load(value)
        if cookies:
            self.cookie = "; ".join(f"{key}={morsel.value}" for key, morsel in cookies.items())
        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError as error:
            raise SystemExit("Omada returned invalid JSON") from error
        if envelope.get("errorCode") != 0:
            raise SystemExit(f"Omada API request failed with code {envelope.get('errorCode')}")
        return envelope.get("result")

    def list_all(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            query = urlencode({"currentPage": page, "currentPageSize": 100})
            result = self.request("GET", f"{path}?{query}")
            if not isinstance(result, dict) or not isinstance(result.get("data"), list):
                raise SystemExit("Omada list response has an unexpected shape")
            chunk = result["data"]
            items.extend(chunk)
            total = result.get("totalRows")
            if not chunk or not isinstance(total, int) or len(items) >= total:
                return items
            page += 1


def required_string(value: Any, key: str) -> str:
    if not isinstance(value, dict) or not isinstance(value.get(key), str) or not value[key]:
        raise SystemExit(f"Omada response is missing {key}")
    return value[key]


def normalize_mac(value: Any) -> str:
    if not isinstance(value, str):
        raise SystemExit("Omada reservation has an invalid MAC")
    compact = value.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(compact) != 12 or any(character not in "0123456789ABCDEF" for character in compact):
        raise SystemExit("Omada reservation has an invalid MAC")
    return "-".join(compact[index : index + 2] for index in range(0, 12, 2))


def normalize_port_forward(value: dict[str, Any]) -> dict[str, Any]:
    protocols = {0: "tcp_udp", 1: "tcp", 2: "udp"}
    protocol = value.get("protocol")
    if protocol not in protocols:
        raise SystemExit("Omada port forward has an invalid protocol")
    wan_port_ids = value.get("interfaceWanPortId")
    if not isinstance(wan_port_ids, list) or not wan_port_ids or not all(
        isinstance(port_id, str) and port_id for port_id in wan_port_ids
    ):
        raise SystemExit("Omada port forward has invalid WAN port bindings")
    if not isinstance(value.get("status"), bool) or not isinstance(value.get("dMZ"), bool):
        raise SystemExit("Omada port forward has invalid boolean settings")
    return {
        "id": required_string(value, "id"),
        "name": required_string(value, "name"),
        "enable": value["status"],
        "external_port": required_string(value, "externalPort"),
        "forward_ip": required_string(value, "forwardIp"),
        "forward_port": required_string(value, "forwardPort"),
        "protocol": protocols[protocol],
        "wan_port_ids": wan_port_ids,
        "dmz": value["dMZ"],
    }


def build_export(client: Omada, site_name: str, network_name: str) -> dict[str, Any]:
    sites = client.list_all(f"/{client.controller_id}/api/v2/sites")
    matching_sites = [site for site in sites if site.get("name") == site_name]
    if len(matching_sites) != 1:
        raise SystemExit("exactly one Omada site must match --site")
    site = matching_sites[0]
    site_id = required_string(site, "id")
    canonical_site_name = required_string(site, "name")

    base = f"/{client.controller_id}/api/v2/sites/{site_id}"
    networks = client.list_all(f"{base}/setting/lan/networks")
    matching_networks = [network for network in networks if network.get("name") == network_name]
    if len(networks) != 1 or len(matching_networks) != 1:
        raise SystemExit("the selected Omada site must contain exactly the managed network")
    network = matching_networks[0]
    network_id = required_string(network, "id")
    dhcp = network.get("dhcpSettings")
    if not isinstance(dhcp, dict):
        raise SystemExit("Omada network is missing DHCP settings")

    reservations = client.list_all(f"{base}/setting/service/dhcp")
    selected_reservations = [reservation for reservation in reservations if reservation.get("netId") == network_id]
    if len(selected_reservations) != len(reservations):
        raise SystemExit("the selected Omada site has reservations outside the managed network")
    port_forwards = client.list_all(f"{base}/setting/transmission/portForwardings")
    export = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "controller_version": client.controller_version,
        "site": {"id": site_id, "name": canonical_site_name},
        "network": {
            "id": network_id,
            "name": required_string(network, "name"),
            "vlan_id": network.get("vlan"),
            "gateway_subnet": required_string(network, "gatewaySubnet"),
            "dhcp_enabled": dhcp.get("enable"),
            "dhcp_start": required_string(dhcp, "ipaddrStart"),
            "dhcp_end": required_string(dhcp, "ipaddrEnd"),
        },
        "reservations": sorted(
            (
                {
                    "name": reservation.get("name") or reservation.get("clientName") or "unnamed",
                    "mac": normalize_mac(reservation.get("mac")),
                    "ip": required_string(reservation, "ip"),
                    "enable": reservation.get("status") is True,
                }
                for reservation in selected_reservations
            ),
            key=lambda reservation: reservation["mac"],
        ),
        "port_forwards": sorted(
            (normalize_port_forward(port_forward) for port_forward in port_forwards),
            key=lambda port_forward: port_forward["id"],
        ),
    }
    if not isinstance(export["network"]["vlan_id"], int):
        raise SystemExit("Omada network VLAN is invalid")
    return export


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--connect-host", required=True)
    parser.add_argument("--site", required=True)
    parser.add_argument("--network", required=True)
    args = parser.parse_args()

    url = os.environ.get("OMADA_URL", "")
    username = os.environ.get("OMADA_USERNAME", "")
    password = os.environ.get("OMADA_PASSWORD", "")
    if not url or not username or not password:
        raise SystemExit("OMADA_URL, OMADA_USERNAME, and OMADA_PASSWORD are required")

    client = Omada(url, args.connect_host, username, password)
    export = build_export(client, args.site, args.network)
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile("w", dir=output.parent, delete=False) as temporary:
        json.dump(export, temporary, indent=2)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    temporary_path.chmod(0o600)
    temporary_path.replace(output)
    print(
        "omada_export=created "
        f"reservations={len(export['reservations'])} "
        f"port_forwards={len(export['port_forwards'])}"
    )


if __name__ == "__main__":
    main()
