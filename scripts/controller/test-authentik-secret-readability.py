#!/usr/bin/env python3
"""Offline behavior tests for the Authentik secret-material plan preflight."""

import importlib.util
import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import unittest

MODULE = Path(__file__).resolve().parents[1] / "check-authentik-secret-readability.py"
spec = importlib.util.spec_from_file_location("authentik_secret_readability", MODULE)
readability = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readability)


@contextmanager
def api_server(mode):
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            paths.append(self.path)
            if self.headers.get("Authorization") != "Bearer synthetic-token":
                self.send_error(401)
                return
            if mode == "denied":
                self.send_error(403)
                return
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "https://example.invalid/")
                self.end_headers()
                return
            if self.path == "/api/v3/providers/oauth2/?page_size=1000":
                matches = [] if mode == "new-absent" else [{"pk": 99, "client_id": "synthetic-new-client"}]
                if mode == "new-duplicate":
                    matches.append({"pk": 100, "client_id": "synthetic-new-client"})
                body = {"pagination": {"count": len(matches), "next": 2 if mode == "new-paginated" else 0}, "results": matches}
            elif self.path == "/api/v3/crypto/certificatekeypairs/?page_size=1000":
                matches = [] if mode == "cert-absent" else [{"pk": "11111111-1111-1111-1111-111111111111", "name": "Synthetic signing"}]
                if mode == "cert-duplicate":
                    matches.append({"pk": "22222222-2222-2222-2222-222222222222", "name": "Synthetic signing"})
                if mode == "cert-invalid-id":
                    matches[0]["pk"] = None
                body = {"pagination": {"count": len(matches) + (1 if mode == "cert-incomplete" else 0), "next": 2 if mode == "cert-paginated" else 0}, "results": matches}
            elif self.path.startswith("/api/v3/stages/user_login/"):
                body = {
                    "network_binding": "bind_asn" if mode == "binding-drift" else "no_binding",
                    "geoip_binding": "no_binding",
                }
            elif self.path.endswith("/view_private_key/"):
                if mode == "key-denied":
                    self.send_error(403)
                    return
                body = {"data": {"key-masked": "", "key-obfuscated": "<redacted>"}.get(
                    mode, "-----BEGIN PRIVATE KEY-----\nsynthetic-key",
                )}
            else:
                provider_id = self.path.rstrip("/").split("/")[-1]
                body = {"pk": int(provider_id)}
                if not ((mode == "masked" and provider_id == "37") or (mode == "new-masked" and provider_id == "99")):
                    body["client_secret"] = "synthetic-secret"
            response = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", paths
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class ReadabilityTests(unittest.TestCase):
    def test_all_managed_secrets_are_readable(self):
        with api_server("complete") as (url, paths):
            readability.check(url, "synthetic-token")
        self.assertEqual(paths, [f"/api/v3/providers/oauth2/{i}/" for i in (15, 21, 37, 47)])

    def test_create_only_provider_is_discovered_again_after_apply(self):
        providers = {"new": {"pk": None, "client_id": "synthetic-new-client"}}
        with api_server("new-absent") as (url, paths):
            readability.check(url, "synthetic-token", oauth_providers=providers)
        self.assertEqual(paths, ["/api/v3/providers/oauth2/?page_size=1000"])
        with api_server("complete") as (url, paths):
            readability.check(url, "synthetic-token", oauth_providers=providers)
        self.assertEqual(paths[-1], "/api/v3/providers/oauth2/99/")
        for mode in ("new-masked", "new-duplicate", "new-paginated"):
            with self.subTest(mode=mode), api_server(mode) as (url, paths):
                with self.assertRaises(SystemExit) as caught:
                    readability.check(url, "synthetic-token", oauth_providers=providers)
                self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_create_only_signer_is_discovered_and_private_key_required_after_apply(self):
        certificates = {"new": {"pk": None, "name": "Synthetic signing"}}
        with api_server("cert-absent") as (url, paths):
            readability.check(url, "synthetic-token", oauth_providers={}, signing_certificates=certificates)
        self.assertEqual(paths, ["/api/v3/crypto/certificatekeypairs/?page_size=1000"])
        with api_server("complete") as (url, paths):
            readability.check(url, "synthetic-token", oauth_providers={}, signing_certificates=certificates)
        self.assertEqual(paths[-1], "/api/v3/crypto/certificatekeypairs/11111111-1111-1111-1111-111111111111/view_private_key/")
        for mode in ("cert-duplicate", "cert-paginated", "cert-incomplete", "cert-invalid-id", "key-denied", "key-masked", "key-obfuscated"):
            with self.subTest(mode=mode), api_server(mode) as (url, paths):
                with self.assertRaises(SystemExit) as caught:
                    readability.check(url, "synthetic-token", oauth_providers={}, signing_certificates=certificates)
                self.assertNotIn("synthetic-key", str(caught.exception))

    def test_masked_secret_refuses_plan_without_printing_value(self):
        with api_server("masked") as (url, paths):
            with self.assertRaises(SystemExit) as caught:
                readability.check(url, "synthetic-token")
        self.assertIn("provider 37 client_secret", str(caught.exception))
        self.assertNotIn("synthetic-secret", str(caught.exception))
        self.assertEqual(len(paths), 3)

    def test_signing_key_read_is_required_when_managed(self):
        with api_server("complete") as (url, paths):
            readability.check(url, "synthetic-token", ("synthetic-certificate",))
        self.assertEqual(len(paths), 5)
        self.assertEqual(paths[-1], "/api/v3/crypto/certificatekeypairs/synthetic-certificate/view_private_key/")

    def test_unreadable_signing_key_refuses_plan_without_key_output(self):
        for mode in ("key-denied", "key-masked", "key-obfuscated"):
            with self.subTest(mode=mode), api_server(mode) as (url, paths):
                with self.assertRaises(SystemExit) as caught:
                    readability.check(url, "synthetic-token", ("synthetic-certificate",))
                self.assertIn("signing certificate synthetic-certificate", str(caught.exception))
                self.assertNotIn("synthetic-key", str(caught.exception))
                self.assertEqual(len(paths), 5)

    def test_login_binding_reader_gap_is_checked_independently(self):
        expected = (("synthetic-login", "no_binding", "no_binding"),)
        with api_server("complete") as (url, paths):
            readability.check(url, "synthetic-token", login_bindings=expected)
        self.assertEqual(paths[-1], "/api/v3/stages/user_login/synthetic-login/")
        with api_server("binding-drift") as (url, paths):
            with self.assertRaisesRegex(SystemExit, "binding drift; refuse plan"):
                readability.check(url, "synthetic-token", login_bindings=expected)

    def test_denied_and_redirected_reads_fail_closed(self):
        for mode in ("denied", "redirect"):
            with self.subTest(mode=mode), api_server(mode) as (url, paths):
                with self.assertRaises(SystemExit) as caught:
                    readability.check(url, "synthetic-token")
                self.assertIn("provider 15", str(caught.exception))
                self.assertEqual(len(paths), 1)


if __name__ == "__main__":
    unittest.main()
