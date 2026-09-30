#!/usr/bin/env python3
"""Offline behavior tests for the Authentik OAuth plan preflight."""

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
            provider_id = self.path.rstrip("/").split("/")[-1]
            body = {"pk": int(provider_id)}
            if mode != "masked" or provider_id != "37":
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

    def test_masked_secret_refuses_plan_without_printing_value(self):
        with api_server("masked") as (url, paths):
            with self.assertRaises(SystemExit) as caught:
                readability.check(url, "synthetic-token")
        self.assertIn("provider 37 client_secret", str(caught.exception))
        self.assertNotIn("synthetic-secret", str(caught.exception))
        self.assertEqual(len(paths), 3)

    def test_denied_and_redirected_reads_fail_closed(self):
        for mode in ("denied", "redirect"):
            with self.subTest(mode=mode), api_server(mode) as (url, paths):
                with self.assertRaises(SystemExit) as caught:
                    readability.check(url, "synthetic-token")
                self.assertIn("provider 15", str(caught.exception))
                self.assertEqual(len(paths), 1)


if __name__ == "__main__":
    unittest.main()
