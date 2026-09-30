#!/usr/bin/env python3
"""Quietly validate Compose with its declared interpolation inputs, not secrets."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
OIDC_KEYS = ("VAULTWARDEN_SSO_CLIENT_ID", "VAULTWARDEN_SSO_CLIENT_SECRET")


def render_environment(production: str, client_id: str, keys: list[str]) -> str:
    """Filter native SOPS dotenv serialization without re-encoding any value."""
    if not production.endswith("\n"):
        raise ValueError("Production dotenv must end in a newline")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", client_id):
        raise ValueError("Invalid OIDC client ID")
    if len(keys) != len(set(keys)) or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) for k in keys):
        raise ValueError("Invalid interpolation key selection")
    lines = {}
    for line in production.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if not match or match[1] in lines:
            raise ValueError("Invalid or duplicate native dotenv entry")
        lines[match[1]] = line
    if any(key in lines or key in keys for key in OIDC_KEYS):
        raise ValueError("Vaultwarden OIDC credentials must have only one encrypted source")
    if any(key not in lines for key in keys):
        raise ValueError("A declared interpolation input is missing")
    return "\n".join(lines[key] for key in keys) + f"\nVAULTWARDEN_SSO_CLIENT_ID={client_id}\n"


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
    bindings = json.loads((ROOT / "services/credentials.json").read_text())
    desired = json.loads((ROOT / "infrastructure/tofu/authentik/desired.json").read_text())
    production = decrypt(ROOT / "secrets/production.sops.yaml", "dotenv")
    content = render_environment(production, desired["oauthProviders"]["47"]["client_id"], bindings["environment_keys"])
    with tempfile.TemporaryDirectory(prefix="compose-validation-") as directory:
        path = Path(directory) / "production.env"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(content)
        environment = os.environ.copy()
        for key in re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)=", production):
            environment.pop(key, None)
        for key in OIDC_KEYS:
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
