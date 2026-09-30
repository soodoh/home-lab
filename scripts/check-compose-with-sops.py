#!/usr/bin/env python3
"""Validate Compose with the same two encrypted OIDC inputs as deployment."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
OIDC_KEYS = ("VAULTWARDEN_SSO_CLIENT_ID", "VAULTWARDEN_SSO_CLIENT_SECRET")


def merged_env(production: str, client_id: str, client_secret: str) -> str:
    if not production.endswith("\n"):
        raise ValueError("Production dotenv must end in a newline")
    if any(re.search(rf"(?m)^{key}=", production) for key in OIDC_KEYS):
        raise ValueError("Vaultwarden OIDC credentials must have only one encrypted source")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", client_id):
        raise ValueError("Invalid OIDC client ID")
    if not re.fullmatch(r"[A-Za-z0-9_-]{48,}", client_secret):
        raise ValueError("OIDC client secret cannot be represented safely in dotenv")
    return production + f"VAULTWARDEN_SSO_CLIENT_ID={client_id}\nVAULTWARDEN_SSO_CLIENT_SECRET={client_secret}\n"


def decrypt(path: Path, output_type: str) -> str:
    result = subprocess.run(
        ["sops", "--decrypt", "--output-type", output_type, str(path)],
        capture_output=True,
    )
    if result.returncode:
        raise ValueError("Protected SOPS input is unavailable")
    return result.stdout.decode()


def main() -> None:
    if not os.environ.get("SOPS_AGE_KEY_FILE"):
        raise ValueError("SOPS_AGE_KEY_FILE is required")
    credentials = json.loads(decrypt(ROOT / "infrastructure/tofu/authentik/client-secrets.sops.json", "json"))
    desired = json.loads((ROOT / "infrastructure/tofu/authentik/desired.json").read_text())
    content = merged_env(
        decrypt(ROOT / "secrets/production.sops.yaml", "dotenv"),
        desired["oauthProviders"]["47"]["client_id"],
        credentials["oauthProviders"]["47"]["client_secret"],
    )
    with tempfile.TemporaryDirectory(prefix="compose-validation-") as directory:
        path = Path(directory) / "production.env"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(content)
        environment = os.environ.copy()
        for key in re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)=", content):
            environment.pop(key, None)
        result = subprocess.run(
            ["docker", "compose", "--env-file", str(path), "config", "--quiet"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
        )
        if result.returncode:
            raise ValueError("Compose validation failed; resolved settings withheld")
    print("compose_configuration=valid")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError) as exc:
        raise SystemExit(str(exc)) from None
