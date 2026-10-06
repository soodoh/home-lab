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
mkdir -p /gluetun /tmp/gluetun /fixture /usr/local/bin /scripts
printf '192.0.2.1\\n' >/tmp/gluetun/ip
printf 'mam_id synthetic-cookie\\n' >/gluetun/MAM.cookies
printf '{"Success":false,"msg":"Last change too recent"}\\n' >/fixture/response
cat >/usr/local/bin/curl <<'EOF'
#!/bin/sh
printf 'request\\n' >>/fixture/requests
while [ "$#" -gt 0 ]; do
  if [ "$1" = -c ]; then
    shift
    printf 'mam_id refreshed-cookie\\n' >"$1"
  fi
  shift
done
cat /fixture/response
EOF
cat >/usr/local/bin/sleep <<'EOF'
#!/bin/sh
printf '%s\\n' "$1" >>/fixture/sleeps
while [ ! -f /fixture/wake ]; do /bin/sleep 0.05; done
EOF
chmod +x /usr/local/bin/curl /usr/local/bin/sleep
"""


class SeedboxRetry(unittest.TestCase):
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

    def hook(self, max_retries=3):
        result = subprocess.run(
            ["docker", "exec", "-e", f"MAM_MAX_COOLDOWN_RETRIES={max_retries}",
             self.container, "sh", "/scripts/mam_seedbox.sh"],
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

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

    def test_success_does_not_schedule_retry(self):
        self.shell("printf '{\"Success\":true,\"msg\":\"Completed\"}' >/fixture/response")
        self.assertIn("Request was successful", self.hook())
        self.assertEqual(self.lines("sleeps"), [])
        self.assertIn("refreshed-cookie", self.shell("cat /gluetun/MAM.cookies"))


if __name__ == "__main__":
    unittest.main()
