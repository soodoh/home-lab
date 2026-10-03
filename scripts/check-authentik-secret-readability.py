#!/usr/bin/env python3
"""Check secret reads and provider-non-round-tripping login settings before a plan."""

import json
import os
from pathlib import Path
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def read_document(opener, base_url: str, token: str, path: str, label: str):
    request = urllib.request.Request(
        f"{base_url}/api/v3/{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with opener.open(request, timeout=10) as response:
            return json.load(response)
    except (OSError, ValueError) as exc:
        if isinstance(exc, urllib.error.HTTPError):
            exc.close()
        raise SystemExit(f"Cannot read Authentik {label}") from None


def check(
    base_url: str, token: str, certificate_ids: tuple[str, ...] = (),
    login_bindings: tuple[tuple[str, str, str], ...] = (),
    oauth_providers: dict | None = None,
) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    providers = oauth_providers if oauth_providers is not None else {
        key: {"pk": int(key)} for key in ("15", "21", "37", "47")
    }
    provider_ids = []
    for key, provider in providers.items():
        pk = provider["pk"]
        if pk is None:
            # A create-only declaration has no observed ID. Discover by the
            # reviewed client ID on every plan, including after its first apply.
            document = read_document(opener, base_url, token, "providers/oauth2/?page_size=1000", "OAuth inventory")
            if not isinstance(document, dict) or not isinstance(document.get("results"), list):
                raise SystemExit("Cannot read complete Authentik OAuth inventory")
            pagination = document.get("pagination", document)
            if pagination.get("next") or pagination.get("count", len(document["results"])) != len(document["results"]):
                raise SystemExit("Cannot read complete Authentik OAuth inventory")
            matches = [item for item in document["results"] if item.get("client_id") == provider["client_id"]]
            if len(matches) > 1:
                raise SystemExit(f"Ambiguous Authentik OAuth client {key}")
            if not matches:
                continue
            pk = matches[0].get("pk")
        if not isinstance(pk, int) or isinstance(pk, bool) or pk < 1:
            raise SystemExit(f"Invalid Authentik OAuth provider ID for {key}")
        provider_ids.append(str(pk))
    reads = [
        (f"providers/oauth2/{provider_id}/", "client_secret", f"OAuth provider {provider_id}")
        for provider_id in provider_ids
    ] + [
        (f"crypto/certificatekeypairs/{certificate_id}/view_private_key/", "data", f"signing certificate {certificate_id}")
        for certificate_id in certificate_ids
    ]
    for path, field, label in reads:
        document = read_document(opener, base_url, token, path, label)
        value = document.get(field) if isinstance(document, dict) else None
        if not isinstance(value, str) or not value.strip() or (
            field == "data" and not value.lstrip().startswith((
                "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----",
            ))
        ):
            raise SystemExit(f"Authentik identity cannot read {label} {field}")
    for pk, network, geoip in login_bindings:
        label = f"login stage {pk}"
        document = read_document(opener, base_url, token, f"stages/user_login/{pk}/", label)
        if not isinstance(document, dict) or document.get("network_binding") != network or document.get("geoip_binding") != geoip:
            raise SystemExit(f"Authentik {label} binding drift; refuse plan")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    desired = json.loads((root / "infrastructure/tofu/authentik/desired.json").read_text())
    check(
        os.environ["AUTHENTIK_URL"],
        os.environ["AUTHENTIK_TOKEN"],
        tuple(certificate["pk"] for certificate in desired["signingCertificates"].values()),
        tuple((stage["pk"], stage["network_binding"], stage["geoip_binding"]) for stage in desired["userLoginStages"].values()),
        desired["oauthProviders"],
    )
