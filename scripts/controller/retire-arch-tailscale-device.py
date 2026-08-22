#!/usr/bin/env python3
"""Delete only the exact retained Arch Tailscale device after retirement acceptance."""

from __future__ import annotations

from argparse import ArgumentParser
import json
from pathlib import Path
import stat
from typing import Any
from urllib import error, parse, request

TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"
DEVICES_URL = "https://api.tailscale.com/api/v2/tailnet/-/devices"
DEVICE_URL = "https://api.tailscale.com/api/v2/device/{device_id}"
ARCH_DEVICE = {
    "id": "5011652268534622",
    "hostname": "docker-host",
    "name": "docker-host.tailea1a78.ts.net",
    "addresses": ["100.111.210.72", "fd7a:115c:a1e0::234:d249"],
    "tags": ["tag:docker-host"],
}
DEBIAN_DEVICE = {
    "id": "6762069159616123",
    "hostname": "docker-host-debian",
    "name": "docker-host-debian.tailea1a78.ts.net",
    "addresses": ["100.116.163.42", "fd7a:115c:a1e0::5634:a32b"],
    "tags": ["tag:docker-host"],
}
CONFIRMATION = "retire-exact-arch-tailscale-device"


def fail(reason: str) -> None:
    raise SystemExit(f"arch_tailscale_retirement=failed reason={reason}")


def api_request(method: str, url: str, access_token: str) -> dict[str, Any] | None:
    value = request.Request(url, headers={"Authorization": f"Bearer {access_token}"}, method=method)
    with request.urlopen(value, timeout=30) as response:
        content = response.read()
        if method == "DELETE":
            if response.status not in (200, 204):
                fail("device_delete_status")
            return None
        document = json.loads(content)
        if not isinstance(document, dict):
            fail("api_response_invalid")
        return document


def exact_device(device: object, expected: dict[str, object]) -> bool:
    return isinstance(device, dict) and all(device.get(key) == value for key, value in expected.items())


def list_devices(access_token: str) -> list[object]:
    document = api_request("GET", DEVICES_URL, access_token)
    devices = document.get("devices") if document is not None else None
    if not isinstance(devices, list):
        fail("device_list_invalid")
    return devices


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--config-dir", type=Path, default=Path.home() / ".config/home-lab/controller")
    parser.add_argument("--approve-device-id", required=True)
    parser.add_argument("--confirmation", required=True)
    args = parser.parse_args()
    if args.approve_device_id != ARCH_DEVICE["id"] or args.confirmation != CONFIRMATION:
        fail("approval_differs")

    config_dir = args.config_dir.expanduser().resolve()
    credentials_path = config_dir / "tailscale-cutover-credentials.json"
    if (
        not config_dir.is_dir()
        or config_dir.is_symlink()
        or stat.S_IMODE(config_dir.stat().st_mode) != 0o700
        or not credentials_path.is_file()
        or credentials_path.is_symlink()
        or stat.S_IMODE(credentials_path.stat().st_mode) != 0o600
    ):
        fail("controller_credentials_unsafe")

    try:
        credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
        body = parse.urlencode({
            "client_id": credentials["TAILSCALE_OAUTH_CLIENT_ID"],
            "client_secret": credentials["TAILSCALE_OAUTH_CLIENT_SECRET"],
        }).encode()
        token_request = request.Request(
            TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with request.urlopen(token_request, timeout=30) as response:
            access_token = json.loads(response.read())["access_token"]

        devices = list_devices(access_token)
        arch_matches = [device for device in devices if exact_device(device, ARCH_DEVICE)]
        debian_matches = [device for device in devices if exact_device(device, DEBIAN_DEVICE)]
        if len(arch_matches) != 1 or len(debian_matches) != 1:
            fail("exact_devices_not_found")
        if arch_matches[0].get("authorized") is not True or debian_matches[0].get("authorized") is not True:
            fail("device_authorization_differs")

        api_request("DELETE", DEVICE_URL.format(device_id=ARCH_DEVICE["id"]), access_token)
        devices = list_devices(access_token)
        if any(isinstance(device, dict) and device.get("id") == ARCH_DEVICE["id"] for device in devices):
            fail("arch_device_still_present")
        if sum(exact_device(device, DEBIAN_DEVICE) for device in devices) != 1:
            fail("debian_device_changed")
    except (KeyError, json.JSONDecodeError, error.URLError, TimeoutError):
        fail("api_request_failed")
    print(f"arch_tailscale_retirement=deleted device_id={ARCH_DEVICE['id']}")


if __name__ == "__main__":
    main()
