#!/usr/bin/env python3
"""Run the native Ansible API tasks against an isolated TLS controller fixture.

Only the authority-loading seam is supplied with synthetic values; HTTP, TLS,
check mode, JSON serialization, comparisons and write tasks are real Ansible.
"""

from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "synthetic-SMTP-'quoted'-$token=with\\backslash"
LOGIN_PASSWORD = "synthetic-controller-login-secret"
CSRF = "synthetic-csrf-secret"
COOKIE = "synthetic-session-cookie-secret"
DESIRED = {
    "schema_version": 1,
    "smtp": {
        "host": "smtp.protonmail.ch", "port": 587, "security": "starttls",
        "username": "fixture@example.com", "sender": "fixture@example.com", "password": TOKEN,
    },
    "recipients": ["recipient@example.com"],
}
SMTP = {
    "smtpEnable": True, "smtpServer": "smtp.protonmail.ch", "port": 587,
    "sslEnable": False, "authEnable": True, "username": "fixture@example.com",
    "password": TOKEN, "senderAddress": "fixture@example.com",
}
NOTIFICATIONS = {
    "alertEmailSetting": {"alertEmailEnable": False, "delayEnable": True, "delay": 17},
    "eventEmailSetting": {"eventEmailEnable": False, "delayEnable": False, "delay": 0},
    "webhookSetting": {"webhookEnable": False, "webhookId": "keep-this-webhook"},
    "resource": {"controllerOwned": True},
    "alertNotifications": [{"key": "DHCP_EXHAUSTED", "email": False, "webhook": True,
                            "enable": True, "level": "warning", "unmodelled": [1, 2]}],
    "eventNotifications": [{"key": "DEVICE_ADOPTED", "email": True, "webhook": False, "enable": False}],
    # Native recipients are derived from independently configured accounts.
    "recipients": [{"email": "recipient@example.com"}],
    "futureSetting": {"preserve": "nested-value"},
}
BASE = "/fixture-controller/api/v2"
SMTP_PATH = BASE + "/global/settings/mail-server"
NOTIFICATION_PATH = BASE + "/sites/fixture-site/logs/notification"


class Controller:
    def __init__(self):
        self.smtp = {"smtpEnable": False, "sslEnable": False, "authEnable": False, "password": "old-token"}
        self.notifications = deepcopy(NOTIFICATIONS)
        self.version = "6.3.0.45"
        self.sites = [{"id": "fixture-site", "name": "Fixture home"}]
        self.requests = []
        self.drift_on_reread = False
        self.notification_reads = 0
        self.fail_smtp_write = False
        self.corrupt_during_smtp_write = False
        self.redirect_info = False

    def in_sync(self):
        self.smtp = deepcopy(SMTP)
        self.notifications["recipients"] = [{"email": "recipient@example.com"}]

    def respond(self, method, path, body):
        if method == "GET" and path == "/api/info":
            return {"controllerVer": self.version, "omadacId": "fixture-controller"}
        if method == "GET" and path == BASE + "/sites":
            return {"data": self.sites, "totalRows": len(self.sites)}
        if method == "GET" and path == SMTP_PATH:
            return {**self.smtp, "password": "********"}
        if method == "GET" and path == NOTIFICATION_PATH:
            self.notification_reads += 1
            if self.drift_on_reread and self.notification_reads == 2:
                self.notifications["alertNotifications"][0]["email"] = True
            return deepcopy(self.notifications)
        if method == "PATCH" and path == SMTP_PATH:
            if self.fail_smtp_write:
                return None
            self.smtp = deepcopy(body)
            if self.corrupt_during_smtp_write:
                self.notifications["eventEmailSetting"]["eventEmailEnable"] = True
            return {}
        if method == "PATCH" and path == NOTIFICATION_PATH:
            # The real controller accepts the PATCH but ignores this read-only
            # projection; only account email/alert settings change recipients.
            recipients = deepcopy(self.notifications["recipients"])
            self.notifications = deepcopy(body)
            self.notifications["resource"] = {"controllerOwned": True}
            self.notifications["recipients"] = recipients
            return {}
        if method == "POST" and path == BASE + "/settings/test-mail":
            # Native UI tests reread form settings with the stored-password mask,
            # not the desired token as a transient test credential.
            if body != {**self.smtp, "password": "********", "receiver": "recipient@example.com"}:
                return None
            if self.smtp["password"] != TOKEN:
                return None
            return {}
        return None


class MailConvergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="omada-native-mail-test-")
        cls.work = Path(cls.temporary.name)
        cls.cert = cls.work / "server.pem"
        cls.key = cls.work / "server.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(cls.key), "-out", str(cls.cert),
        ], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @contextmanager
    def controller(self, state):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def handle_request(self):
                path = urlparse(self.path).path
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                state.requests.append((self.command, path, deepcopy(body)))
                if state.redirect_info and path == "/api/info":
                    self.send_response(302)
                    self.send_header("Location", "/untrusted-redirect-target")
                    self.end_headers()
                    return
                if self.command == "POST" and path == BASE + "/login":
                    valid = body == {"username": "fixture-admin", "password": LOGIN_PASSWORD}
                    result = {"token": CSRF} if valid else None
                else:
                    valid = path == "/api/info" or (
                        self.headers.get("Csrf-Token") == CSRF and
                        self.headers.get("Cookie") == "TPOMADA_SESSIONID=" + COOKIE
                    )
                    result = state.respond(self.command, path, body) if valid else None
                response = json.dumps({"errorCode": 0 if result is not None else -1001,
                                       "result": result, "errorMessage": "" if result is not None else TOKEN}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                if path == BASE + "/login" and valid:
                    self.send_header("Set-Cookie", "TPOMADA_SESSIONID=" + COOKIE + "; Secure; HttpOnly; Path=/")
                self.end_headers()
                self.wfile.write(response)

            do_GET = handle_request
            do_POST = handle_request
            do_PATCH = handle_request

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield "https://localhost:" + str(server.server_port)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def run_role(self, state, *, check=False, approved=True, send_test=False, rotate=False,
                 observe=False, trusted=True, origin_mismatch=False, desired=None, success=True):
        with self.controller(state) as endpoint, tempfile.TemporaryDirectory(dir=self.work) as directory:
            run = Path(directory)
            variables = {
                "ansible_become": False,
                "ansible_python_interpreter": shutil.which("python3"),
                "omada_mail_controller_root": str(ROOT),
                "omada_mail_ca_path": str(self.cert) if trusted else "",
                "omada_mail_apply_confirmed": approved,
                "omada_mail_observe_only": observe,
                "omada_mail_rotate_credentials": rotate,
                "omada_mail_send_test": send_test,
                "omada_mail_domain": {"endpoint": endpoint, "controller_version": "6.3.0.45", "site_name": "Fixture home"},
                "omada_mail_credentials": {
                    "OMADA_URL": "https://other.example.com" if origin_mismatch else endpoint,
                    "OMADA_USERNAME": "fixture-admin", "OMADA_PASSWORD": LOGIN_PASSWORD,
                },
                "omada_mail_desired": DESIRED if desired is None else desired,
            }
            inputs = run / "inputs.json"
            inputs.write_text(json.dumps(variables))
            inputs.chmod(0o600)
            play = run / "play.yml"
            play.write_text(json.dumps([{
                "name": "Exercise native Omada mail behavior", "hosts": "localhost", "gather_facts": False,
                "tasks": [{"name": "Run the unchanged native API task seam",
                           "ansible.builtin.import_role": {"name": "omada_mail", "tasks_from": "controller"}}],
            }]))
            environment = {**os.environ, "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
                           "ANSIBLE_LOCAL_TEMP": str(run / "ansible"), "ANSIBLE_NOCOLOR": "1"}
            command = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(play), "-e", "@" + str(inputs)]
            if check:
                command.append("--check")
            result = subprocess.run(command, env=environment, cwd=ROOT, capture_output=True, text=True, timeout=120)
            output = result.stdout + result.stderr
            for secret in (TOKEN, LOGIN_PASSWORD, CSRF, COOKIE):
                for representation in (secret, json.dumps(secret)[1:-1]):
                    self.assertNotIn(representation, output, "Secret leaked in native Ansible output")
            self.assertEqual(result.returncode == 0, success, output)
            return output

    @staticmethod
    def mutations(state):
        return [(method, path, body) for method, path, body in state.requests
                if method == "PATCH" or (method == "POST" and path != BASE + "/login")]

    def test_check_and_observer_cannot_write_or_send_even_with_mutating_flags(self):
        for flags in [{"check": True}, {"observe": True}]:
            state = Controller()
            self.run_role(state, send_test=True, rotate=True, approved=True, **flags)
            self.assertTrue(state.requests)
            self.assertEqual(self.mutations(state), [])
            self.assertEqual(state.notifications, NOTIFICATIONS)

    def test_approval_and_origin_mismatch_fail_before_any_request(self):
        for flags in [{"approved": False}, {"origin_mismatch": True}]:
            state = Controller()
            self.run_role(state, success=False, **flags)
            self.assertEqual(state.requests, [])

    def test_untrusted_tls_and_redirects_fail_closed(self):
        state = Controller()
        self.run_role(state, trusted=False, success=False)
        self.assertEqual(state.requests, [])
        state = Controller()
        state.redirect_info = True
        self.run_role(state, success=False)
        self.assertEqual([(m, p) for m, p, _ in state.requests], [("GET", "/api/info")])

    def test_wrong_version_and_ambiguous_site_fail_before_settings_writes(self):
        state = Controller()
        state.version = "unqualified-version"
        self.run_role(state, success=False)
        self.assertEqual(self.mutations(state), [])
        state = Controller()
        state.sites.append({"id": "other-site", "name": "Fixture home"})
        self.run_role(state, success=False)
        self.assertEqual(self.mutations(state), [])

    def test_missing_account_recipients_block_before_any_mutation(self):
        for synchronized_smtp in [False, True]:
            state = Controller()
            if synchronized_smtp:
                state.smtp = deepcopy(SMTP)
            state.notifications["recipients"] = []
            smtp_before = deepcopy(state.smtp)
            notifications_before = deepcopy(state.notifications)
            self.run_role(state, send_test=True, success=False)
            self.assertEqual(self.mutations(state), [])
            self.assertEqual(state.smtp, smtp_before)
            self.assertEqual(state.notifications, notifications_before)

    def test_initial_apply_serializes_token_preserves_notifications_and_is_idempotent(self):
        state = Controller()
        self.run_role(state, send_test=True)
        self.assertEqual(state.smtp, SMTP)
        self.assertEqual(state.notifications, NOTIFICATIONS)
        mutations = self.mutations(state)
        self.assertEqual([(m, p) for m, p, _ in mutations], [
            ("PATCH", SMTP_PATH), ("POST", BASE + "/settings/test-mail"),
        ])
        self.assertEqual(mutations[1][2]["password"], "********")
        state.requests.clear()
        output = self.run_role(state)
        self.assertEqual(self.mutations(state), [])
        self.assertIn("unavailable_masked_by_controller", output)

    def test_unexpected_account_destinations_are_not_changed(self):
        state = Controller()
        state.notifications["recipients"].append({"email": "independent-owner@example.com"})
        before = deepcopy(state.notifications)
        self.run_role(state, send_test=True, success=False)
        self.assertEqual(self.mutations(state), [])
        self.assertEqual(state.notifications, before)

    def test_missing_recipients_are_reported_by_observer_and_refuse_preview(self):
        state = Controller()
        state.smtp = deepcopy(SMTP)
        state.notifications["recipients"] = []
        output = self.run_role(state, observe=True)
        self.assertIn('"recipient_prerequisite_met": false', output)
        self.assertIn("administrator_accounts", output)
        self.assertEqual(self.mutations(state), [])
        self.run_role(state, check=True, send_test=True, rotate=True, success=False)
        self.assertEqual(self.mutations(state), [])
        self.assertEqual(state.smtp, SMTP)

    def test_token_only_rotation_requires_its_flag_and_tests_saved_credentials(self):
        state = Controller()
        state.in_sync()
        state.smtp["password"] = "different-stored-token"
        self.run_role(state)
        self.assertEqual(self.mutations(state), [])
        state.requests.clear()
        self.run_role(state, rotate=True, send_test=True)
        self.assertEqual(state.smtp["password"], TOKEN)
        self.assertEqual([(m, p) for m, p, _ in self.mutations(state)], [
            ("PATCH", SMTP_PATH), ("POST", BASE + "/settings/test-mail"),
        ])

    def test_unexpected_document_shapes_and_smtp_fields_fail_before_writes(self):
        for invalid in ["not-a-list", {"key": "not-a-list"}]:
            state = Controller()
            state.notifications["alertNotifications"] = invalid
            self.run_role(state, success=False)
            self.assertEqual(self.mutations(state), [])
        state = Controller()
        state.smtp["unknownSetting"] = "must-not-be-dropped"
        self.run_role(state, success=False)
        self.assertEqual(self.mutations(state), [])

    def test_concurrent_edit_is_not_overwritten(self):
        state = Controller()
        state.drift_on_reread = True
        self.run_role(state, success=False)
        self.assertEqual(self.mutations(state), [])
        self.assertTrue(state.notifications["alertNotifications"][0]["email"])

    def test_api_error_does_not_continue_with_recipient_writes_or_send_email(self):
        state = Controller()
        state.fail_smtp_write = True
        self.run_role(state, send_test=True, success=False)
        self.assertEqual([(m, p) for m, p, _ in self.mutations(state)], [("PATCH", SMTP_PATH)])

    def test_persistence_corruption_is_detected_before_test_submission(self):
        state = Controller()
        state.corrupt_during_smtp_write = True
        self.run_role(state, send_test=True, success=False)
        self.assertEqual([(m, p) for m, p, _ in self.mutations(state)], [
            ("PATCH", SMTP_PATH),
        ])

    def test_implicit_tls_and_invalid_input_contract(self):
        state = Controller()
        desired = deepcopy(DESIRED)
        desired["smtp"].update(host="smtp.example.com", port=465, security="tls")
        self.run_role(state, desired=desired)
        self.assertTrue(state.smtp["sslEnable"])
        for changes in [{"password": "\nunsafe"}, {"password": "x" * 129}, {"password": "unicode-\u2603"}, {"security": "none"}]:
            state = Controller()
            desired = deepcopy(DESIRED)
            desired["smtp"].update(changes)
            self.run_role(state, desired=desired, success=False)
            self.assertEqual(state.requests, [])


if __name__ == "__main__":
    unittest.main()
