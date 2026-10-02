#!/usr/bin/env python3
"""Refuse an Authentik plan whose identity cannot read managed secret material."""

import json
import os
from pathlib import Path
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def check(base_url: str, token: str, certificate_ids: tuple[str, ...] = ()) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    reads = [
        (f"providers/oauth2/{provider_id}/", "client_secret", f"OAuth provider {provider_id}")
        for provider_id in ("15", "21", "37", "47")
    ] + [
        (f"crypto/certificatekeypairs/{certificate_id}/view_private_key/", "data", f"signing certificate {certificate_id}")
        for certificate_id in certificate_ids
    ]
    for path, field, label in reads:
        request = urllib.request.Request(
            f"{base_url}/api/v3/{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with opener.open(request, timeout=10) as response:
                document = json.load(response)
        except (OSError, ValueError) as exc:
            if isinstance(exc, urllib.error.HTTPError):
                exc.close()
            raise SystemExit(f"Cannot read Authentik {label}") from None
        value = document.get(field) if isinstance(document, dict) else None
        if not isinstance(value, str) or not value.strip() or (
            field == "data" and not value.lstrip().startswith((
                "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
            ))
        ):
            raise SystemExit(f"Authentik identity cannot read {label} {field}")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    desired = json.loads((root / "infrastructure/tofu/authentik/desired.json").read_text())
    check(
        os.environ["AUTHENTIK_URL"],
        os.environ["AUTHENTIK_TOKEN"],
        tuple(certificate["pk"] for certificate in desired["signingCertificates"].values()),
    )
