#!/usr/bin/env python3
"""Create a one-use Tailscale key and retain it only as Debian-recipient age ciphertext."""

from argparse import ArgumentParser
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any
from urllib import error, parse, request

RECIPIENT = "age1atumjua6hxyls6z8v20tsgy72304x72lqjstwmwzqy5ma4txyfsse7xakv"
TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"
KEY_URL = "https://api.tailscale.com/api/v2/tailnet/-/keys"
DESCRIPTION = "debian production cutover"
TAG = "tag:docker-host"
EXPIRY_SECONDS = 86400


def fail(reason: str) -> None:
    raise SystemExit(f"tailscale_cutover_key=failed reason={reason}")


def read_credentials(config_dir: Path) -> tuple[str, str]:
    path = config_dir / "tailscale-cutover-credentials.json"
    if (
        not config_dir.is_dir()
        or config_dir.is_symlink()
        or stat.S_IMODE(config_dir.stat().st_mode) != 0o700
        or not path.is_file()
        or path.is_symlink()
        or stat.S_IMODE(path.stat().st_mode) != 0o600
    ):
        fail("controller_credentials_unsafe")
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("controller_credentials_unreadable")
    client_id = values.get("TAILSCALE_OAUTH_CLIENT_ID")
    client_secret = values.get("TAILSCALE_OAUTH_CLIENT_SECRET")
    if not isinstance(client_id, str) or not client_id or not isinstance(client_secret, str) or not client_secret:
        fail("tailscale_oauth_credentials_absent")
    return client_id, client_secret


def post(url: str, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    try:
        with request.urlopen(request.Request(url, data=body, headers=headers, method="POST"), timeout=30) as response:
            document = json.loads(response.read())
    except (error.URLError, TimeoutError, json.JSONDecodeError):
        fail("tailscale_api_request_failed")
    if not isinstance(document, dict):
        fail("tailscale_api_response_invalid")
    return document


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--config-dir", type=Path, default=Path.home() / ".config/home-lab/controller")
    parser.add_argument("--output-encrypted", type=Path, required=True)
    parser.add_argument("--output-metadata", type=Path, required=True)
    args = parser.parse_args()

    encrypted = args.output_encrypted.resolve()
    metadata = args.output_metadata.resolve()
    if encrypted == metadata or encrypted.exists() or encrypted.is_symlink() or metadata.exists() or metadata.is_symlink():
        fail("output_requires_reconciliation")

    client_id, client_secret = read_credentials(args.config_dir.expanduser().resolve())
    token_response = post(
        TOKEN_URL,
        parse.urlencode({"client_id": client_id, "client_secret": client_secret}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    access_token = token_response.get("access_token")
    if not isinstance(access_token, str) or not access_token.startswith("tskey-"):
        fail("oauth_token_invalid")

    key_request = {
        "keyType": "auth",
        "description": DESCRIPTION,
        "expirySeconds": EXPIRY_SECONDS,
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": False,
                    "ephemeral": False,
                    "preauthorized": True,
                    "tags": [TAG],
                }
            }
        },
    }
    key_response = post(
        KEY_URL,
        json.dumps(key_request, separators=(",", ":")).encode(),
        {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    auth_key = key_response.pop("key", None)
    key_id = key_response.get("id")
    if (
        not isinstance(auth_key, str)
        or not auth_key.startswith("tskey-auth-")
        or not isinstance(key_id, str)
        or not key_id
        or key_response.get("keyType") != "auth"
    ):
        fail("auth_key_response_invalid")

    encrypted.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{encrypted.name}.", dir=encrypted.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.chmod(0o600)
        subprocess.run(
            ["age", "--encrypt", "--recipient", RECIPIENT, "--output", str(temporary)],
            input=(auth_key + "\n").encode(),
            check=True,
            stdout=subprocess.DEVNULL,
        )
        ciphertext = temporary.read_bytes()
        if not ciphertext.startswith(b"age-encryption.org/v1\n"):
            fail("age_ciphertext_invalid")
        temporary.replace(encrypted)
        encrypted.chmod(0o600)
    except (OSError, subprocess.SubprocessError):
        fail("age_encryption_failed")
    finally:
        temporary.unlink(missing_ok=True)

    metadata_document = {
        "schemaVersion": 1,
        "format": "home-lab-debian-production-tailscale-key-v1",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "keyId": key_id,
        "keyType": "auth",
        "description": DESCRIPTION,
        "expirySeconds": EXPIRY_SECONDS,
        "expires": key_response.get("expires"),
        "reusable": False,
        "ephemeral": False,
        "preauthorized": True,
        "tags": [TAG],
        "recipient": RECIPIENT,
        "encryptedPath": encrypted.relative_to(Path.cwd()).as_posix(),
        "encryptedSha256": hashlib.sha256(encrypted.read_bytes()).hexdigest(),
        "plaintextRetained": False,
    }
    atomic_write(metadata, (json.dumps(metadata_document, indent=2, sort_keys=True) + "\n").encode(), 0o644)
    print(f"tailscale_cutover_key=encrypted key_id={key_id} expires={key_response.get('expires')}")


if __name__ == "__main__":
    main()
