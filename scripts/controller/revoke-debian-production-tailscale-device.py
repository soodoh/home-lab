#!/usr/bin/env python3
"""Delete a failed Debian cutover node from Tailscale using protected controller credentials."""

from argparse import ArgumentParser
import json
from pathlib import Path
import stat
from typing import Any
from urllib import error, parse, request

TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"
DEVICES_URL = "https://api.tailscale.com/api/v2/tailnet/-/devices"
DEVICE_URL = "https://api.tailscale.com/api/v2/device/{device_id}"
EXPECTED_HOSTNAME = "docker-host-debian"
EXPECTED_TAG = "tag:docker-host"


def fail(reason: str) -> None:
    raise SystemExit(f"tailscale_cutover_revoke=failed reason={reason}")


def api_request(method: str, url: str, access_token: str, body: bytes | None = None) -> dict[str, Any] | None:
    api_request_object = request.Request(
        url,
        data=body,
        headers={"Authorization": f"Bearer {access_token}"},
        method=method,
    )
    with request.urlopen(api_request_object, timeout=30) as response:
        content = response.read()
        if method == "DELETE":
            if response.status not in (200, 204):
                fail("device_delete_status")
            return None
        document = json.loads(content)
        if not isinstance(document, dict):
            fail("tailscale_api_response_invalid")
        return document


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--config-dir", type=Path, default=Path.home() / ".config/home-lab/controller")
    parser.add_argument("--device-id")
    parser.add_argument("--hostname", default=EXPECTED_HOSTNAME)
    args = parser.parse_args()
    if args.device_id is not None and (not args.device_id.startswith("n") or not args.device_id.isalnum()):
        fail("device_id_invalid")
    if args.hostname != EXPECTED_HOSTNAME:
        fail("hostname_not_allowed")

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
        token_body = parse.urlencode(
            {
                "client_id": credentials["TAILSCALE_OAUTH_CLIENT_ID"],
                "client_secret": credentials["TAILSCALE_OAUTH_CLIENT_SECRET"],
            }
        ).encode()
        with request.urlopen(
            request.Request(
                TOKEN_URL,
                data=token_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            ),
            timeout=30,
        ) as response:
            access_token = json.loads(response.read())["access_token"]

        device_id = args.device_id
        if device_id is None:
            devices_document = api_request("GET", DEVICES_URL, access_token)
            devices = devices_document.get("devices") if devices_document is not None else None
            if not isinstance(devices, list):
                fail("device_list_invalid")
            matches = [
                device
                for device in devices
                if isinstance(device, dict)
                and device.get("hostname") == EXPECTED_HOSTNAME
                and EXPECTED_TAG in (device.get("tags") or [])
            ]
            if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
                fail("expected_device_not_found")
            device_id = matches[0]["id"]

        api_request("DELETE", DEVICE_URL.format(device_id=device_id), access_token)
    except (KeyError, json.JSONDecodeError, error.URLError, TimeoutError):
        fail("tailscale_api_request_failed")
    print(f"tailscale_cutover_revoke=deleted device_id={device_id}")


if __name__ == "__main__":
    main()
