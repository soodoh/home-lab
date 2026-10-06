#!/usr/bin/env python3
"""Exercise the MAM hook in its pinned Alpine image without network or real cookies."""

from pathlib import Path
import re
import subprocess
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parent.parent
IMAGE = re.search(r"  gluetun:\n    image: (\S+)", (ROOT / "services/servarr.yml").read_text())[1]
SCRIPT = ROOT / "services/data/gluetun/mam_seedbox.sh"

FIXTURE = """
mkdir -p /gluetun /tmp/gluetun /fixture /usr/local/bin /scripts /run/secrets
printf '192.0.2.1\\n' >/tmp/gluetun/ip
printf 'bootstrap-cookie' >/run/secrets/mam_initial_id
digest=$(printf 'bootstrap-cookie' | sha256sum)
printf '# MAM bootstrap: %s\\n.myanonamouse.net\\tTRUE\\t/\\tTRUE\\t0\\tmam_id\\tsynthetic-cookie\\n' "${digest%% *}" >/gluetun/MAM.cookies
printf '{"Success":false,"msg":"Last change too recent"}\\n' >/fixture/response
cat >/usr/local/bin/curl <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -b) shift; input=$1 ;;
    -c) shift; output=$1 ;;
  esac
  shift
done
used=$(awk -F '\\t' '$6 == "mam_id" { print $7 }' "$input")
printf '%s\\n' "$used" >>/fixture/used-cookies
printf 'request\\n' >>/fixture/requests
while [ -f /fixture/hold-request ]; do /bin/sleep 0.05; done
if [ -f /fixture/transport-error ]; then exit 7; fi
printf '.myanonamouse.net\\tTRUE\\t/\\tTRUE\\t0\\tmam_id\\trefreshed-cookie\\n' >"$output"
if [ -f /fixture/empty-cookie ]; then : >"$output"; fi
if [ -f /fixture/reject-cookie ] && [ "$used" = "$(cat /fixture/reject-cookie)" ]; then
  printf '{"Success":false,"msg":"Invalid session"}\\n'
else
  cat /fixture/response
fi
EOF
cat >/usr/local/bin/sleep <<'EOF'
#!/bin/sh
printf '%s\\n' "$1" >>/fixture/sleeps
while [ ! -f /fixture/wake ]; do /bin/sleep 0.05; done
EOF
chmod +x /usr/local/bin/curl /usr/local/bin/sleep
"""


class SeedboxHook(unittest.TestCase):
    def setUp(self):
        self.container = "mam-test-" + uuid.uuid4().hex[:12]
        self.addCleanup(self.remove_container)
        self.docker(
            "run", "-d", "--name", self.container, "--network", "none",
            "--entrypoint", "/bin/sh",
            IMAGE, "-c", "while :; do /bin/sleep 3600; done",
        )
        self.shell(FIXTURE)
        self.docker("cp", str(SCRIPT), f"{self.container}:/scripts/mam_seedbox.sh")

    def docker(self, *args, **kwargs):
        return subprocess.run(
            ["docker", *args], text=True, capture_output=True, check=True,
            timeout=60, **kwargs,
        ).stdout

    def remove_container(self):
        subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, timeout=20)

    def shell(self, script):
        return self.docker("exec", "-i", self.container, "sh", "-s", input=script)

    def hook(self, max_retries=3, expected_status=0):
        result = subprocess.run(
            ["docker", "exec", "-e", f"MAM_MAX_COOLDOWN_RETRIES={max_retries}",
             self.container, "sh", "/scripts/mam_seedbox.sh"],
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def lines(self, filename):
        return self.shell(f"test ! -f /fixture/{filename} || cat /fixture/{filename}").splitlines()

    def wait_lines(self, filename, count):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            lines = self.lines(filename)
            if len(lines) >= count:
                return lines
            time.sleep(0.05)
        self.fail(f"expected {count} lines in {filename}, got {lines}")

    def test_container_restart_cannot_leave_retry_locked(self):
        self.assertIn("scheduling retry attempt 1/3", self.hook())
        self.wait_lines("sleeps", 1)
        self.docker("restart", "--time", "0", self.container)
        self.assertIn("scheduling retry attempt 1/3", self.hook())
        self.assertEqual(self.wait_lines("sleeps", 2), ["3900", "3900"])

    def test_active_retry_excludes_duplicate(self):
        self.hook()
        self.wait_lines("sleeps", 1)
        self.assertIn("already scheduled", self.hook())
        self.assertEqual(self.lines("sleeps"), ["3900"])

    def test_retry_refreshes_cookie_after_success(self):
        self.hook()
        self.wait_lines("sleeps", 1)
        self.shell("printf '{\"Success\":true,\"msg\":\"Completed\"}' >/fixture/response; touch /fixture/wake")
        self.wait_lines("requests", 2)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if "refreshed-cookie" in self.shell("cat /gluetun/MAM.cookies"):
                return
            time.sleep(0.05)
        self.fail("successful retry did not persist its refreshed cookie")

    def test_retry_chain_releases_lock_and_stops_at_limit(self):
        self.shell("touch /fixture/wake")
        self.hook(max_retries=2)
        self.wait_lines("requests", 3)
        self.assertEqual(self.wait_lines("sleeps", 2), ["3900", "3900"])
        time.sleep(0.2)
        self.assertEqual(len(self.lines("requests")), 3)

    def success_response(self):
        self.shell("printf '{\"Success\":true,\"msg\":\"Completed\"}' >/fixture/response")

    def cookie(self):
        return self.shell("cat /gluetun/MAM.cookies")

    def test_missing_jar_bootstraps_and_retains_refreshed_cookie_after_restart(self):
        self.success_response()
        self.shell("rm /gluetun/MAM.cookies")
        self.assertIn("Initializing session", self.hook())
        self.assertEqual(self.lines("used-cookies"), ["bootstrap-cookie"])
        self.assertIn("refreshed-cookie", self.cookie())
        self.assertEqual(self.shell("stat -c %a /gluetun/MAM.cookies").strip(), "600")
        self.docker("restart", "--time", "0", self.container)
        self.hook()
        self.assertEqual(self.lines("used-cookies"), ["bootstrap-cookie", "refreshed-cookie"])

    def test_cooldown_during_bootstrap_preserves_jar_until_successful_retry(self):
        self.shell("printf replacement-bootstrap >/run/secrets/mam_initial_id")
        before = self.cookie()
        self.hook()
        self.wait_lines("sleeps", 1)
        self.assertEqual(self.cookie(), before)
        self.assertEqual(self.lines("used-cookies"), ["replacement-bootstrap"])
        self.success_response()
        self.shell("touch /fixture/wake")
        self.wait_lines("requests", 2)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if "refreshed-cookie" in self.cookie():
                self.hook()
                self.assertEqual(self.lines("used-cookies"),
                                 ["replacement-bootstrap", "replacement-bootstrap", "refreshed-cookie"])
                return
            time.sleep(0.05)
        self.fail("bootstrap retry did not publish its refreshed cookie")

    def test_invalid_initial_session_is_attempted_once_without_creating_jar(self):
        self.shell("rm /gluetun/MAM.cookies; printf '{\"Success\":false,\"msg\":\"No Session Cookie\"}' >/fixture/response")
        self.hook(expected_status=1)
        self.assertEqual(self.lines("used-cookies"), ["bootstrap-cookie"])
        self.assertEqual(self.shell("test ! -e /gluetun/MAM.cookies && printf absent"), "absent")

    def test_http_only_cookie_is_preserved_for_request(self):
        self.success_response()
        self.shell("sed -i 's/^\\.myanonamouse.net/#HttpOnly_.myanonamouse.net/' /gluetun/MAM.cookies")
        self.hook()
        self.assertEqual(self.lines("used-cookies"), ["synthetic-cookie"])

    def test_source_rotation_and_legacy_jar_reset_once(self):
        self.success_response()
        self.shell("printf 'replacement-bootstrap' >/run/secrets/mam_initial_id")
        self.hook()
        self.hook()
        self.assertEqual(self.lines("used-cookies"), ["replacement-bootstrap", "refreshed-cookie"])
        # A pre-bootstrap jar has no generation tag and must adopt SOPS once.
        self.shell("printf '.myanonamouse.net\\tTRUE\\t/\\tTRUE\\t0\\tmam_id\\tlegacy-cookie\\n' >/gluetun/MAM.cookies")
        self.hook()
        self.assertEqual(self.lines("used-cookies")[-1], "replacement-bootstrap")

    def test_session_rejection_recovers_once_with_bootstrap(self):
        self.success_response()
        self.shell("printf synthetic-cookie >/fixture/reject-cookie")
        self.assertIn("trying the bootstrap credential once", self.hook())
        self.assertEqual(self.lines("used-cookies"), ["synthetic-cookie", "bootstrap-cookie"])
        self.assertIn("refreshed-cookie", self.cookie())

    def test_rejected_bootstrap_preserves_jar_and_does_not_loop(self):
        self.shell("printf '{\"Success\":false,\"msg\":\"Invalid session\"}' >/fixture/response")
        before = self.cookie()
        self.assertIn("update the MAM ID", self.hook(expected_status=1))
        self.assertEqual(self.lines("used-cookies"), ["synthetic-cookie", "bootstrap-cookie"])
        self.assertEqual(self.cookie(), before)
        self.assertEqual(self.lines("sleeps"), [])

    def test_rotation_failure_preserves_existing_jar(self):
        self.shell("printf replacement-bootstrap >/run/secrets/mam_initial_id; touch /fixture/transport-error")
        before = self.cookie()
        self.hook(expected_status=1)
        self.assertEqual(self.cookie(), before)
        self.assertEqual(self.lines("used-cookies"), ["replacement-bootstrap"])

    def test_transport_and_unexpected_errors_never_rebootstrap(self):
        before = self.cookie()
        self.shell("touch /fixture/transport-error")
        self.hook(expected_status=1)
        self.assertEqual(self.cookie(), before)
        self.shell("rm /fixture/transport-error; printf '{\"Success\":false,\"msg\":\"synthetic-secret-do-not-log\"}' >/fixture/response")
        output = self.hook(expected_status=1)
        self.assertNotIn("synthetic-secret-do-not-log", output)
        self.assertNotIn("synthetic-cookie", output)
        self.assertEqual(self.cookie(), before)
        self.assertEqual(self.lines("used-cookies"), ["synthetic-cookie", "synthetic-cookie"])

    def test_success_without_cookie_preserves_existing_jar(self):
        self.success_response()
        before = self.cookie()
        self.shell("touch /fixture/empty-cookie")
        self.hook(expected_status=1)
        self.assertEqual(self.cookie(), before)

    def test_missing_empty_or_malformed_bootstrap_refuses_without_requests(self):
        before = self.cookie()
        for command in ["rm /run/secrets/mam_initial_id", ": >/run/secrets/mam_initial_id",
                        "printf 'bad\\tid' >/run/secrets/mam_initial_id",
                        "printf 'mam_id=wrong-format' >/run/secrets/mam_initial_id"]:
            with self.subTest(command=command):
                self.shell(command)
                self.hook(expected_status=1)
                self.assertEqual(self.lines("requests"), [])
                self.assertEqual(self.cookie(), before)

    def test_parallel_hook_cannot_overwrite_an_active_request(self):
        self.success_response()
        self.shell("touch /fixture/hold-request; sh /scripts/mam_seedbox.sh >/fixture/first-output 2>&1 &")
        self.wait_lines("requests", 1)
        self.assertIn("Another MAM request is active", self.hook())
        self.assertEqual(self.lines("requests"), ["request"])
        self.shell("rm /fixture/hold-request")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if "refreshed-cookie" in self.cookie():
                return
            time.sleep(0.05)
        self.fail("active request did not publish its cookie")

    def test_success_does_not_schedule_retry(self):
        self.shell("printf '{\"Success\":true,\"msg\":\"Completed\"}' >/fixture/response")
        self.assertIn("Request was successful", self.hook())
        self.assertEqual(self.lines("sleeps"), [])
        self.assertIn("refreshed-cookie", self.shell("cat /gluetun/MAM.cookies"))


if __name__ == "__main__":
    unittest.main()
