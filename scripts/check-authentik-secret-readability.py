#!/usr/bin/env python3
"""Refuse an Authentik plan whose identity cannot read managed OAuth secrets."""

import json
import os
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def check(base_url: str, token: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    for provider_id in ("15", "21", "37", "47"):
        request = urllib.request.Request(
            f"{base_url}/api/v3/providers/oauth2/{provider_id}/",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with opener.open(request, timeout=10) as response:
                provider = json.load(response)
        except (OSError, ValueError) as exc:
            if isinstance(exc, urllib.error.HTTPError):
                exc.close()
            raise SystemExit(f"Cannot read Authentik OAuth provider {provider_id}") from None
        if not isinstance(provider, dict) or not isinstance(provider.get("client_secret"), str) or not provider["client_secret"]:
            raise SystemExit(f"Authentik identity cannot read OAuth provider {provider_id} client_secret")


if __name__ == "__main__":
    check(os.environ["AUTHENTIK_URL"], os.environ["AUTHENTIK_TOKEN"])
