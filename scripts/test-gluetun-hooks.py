#!/usr/bin/env python3
"""Exercise VPN hook ordering and qBittorrent API failures in pinned Alpine."""

from pathlib import Path
import re
import subprocess
import unittest
import uuid

ROOT = Path(__file__).resolve().parent.parent
IMAGE = re.search(r"  gluetun:\n    image: (\S+)", (ROOT / "services/servarr.yml").read_text())[1]

FIXTURE = r"""
mkdir -p /tmp/gluetun /fixture /usr/local/bin /scripts
printf '49251\n' >/tmp/gluetun/forwarded_port
printf '{"listen_port":49251,"upnp":false}\n' >/fixture/preferences
cat >/usr/local/bin/wget <<'EOF'
#!/bin/sh
for arg do
  case "$arg" in
    --body-data=*) printf '%s\n' "${arg#--body-data=}" >>/fixture/posts ;;
    http://*) url=$arg ;;
  esac
done
case "$url" in
  */app/version)
    test ! -f /fixture/unavailable || exit 1
    if [ -f /fixture/startup-failures ]; then
      remaining=$(cat /fixture/startup-failures)
      if [ "$remaining" -gt 0 ]; then
        printf '%s' "$((remaining - 1))" >/fixture/startup-failures
        exit 1
      fi
    fi
    printf 'v5.2.3\n' ;;
  */app/setPreferences)
    printf 'update\n' >>/fixture/events
    test ! -f /fixture/post-error || exit 1 ;;
  */app/preferences)
    printf 'readback\n' >>/fixture/events
    test ! -f /fixture/read-error || exit 1
    cat /fixture/preferences ;;
  *) exit 2 ;;
esac
EOF
cat >/usr/local/bin/sleep <<'EOF'
#!/bin/sh
printf 'wait\n' >>/fixture/waits
EOF
cat >/scripts/mam_seedbox.sh <<'EOF'
#!/bin/sh
printf 'mam\n' >>/fixture/events
exit "$(cat /fixture/mam-exit 2>/dev/null || printf 0)"
EOF
chmod +x /usr/local/bin/wget /usr/local/bin/sleep /scripts/mam_seedbox.sh
"""


class GluetunHooks(unittest.TestCase):
    def setUp(self):
        self.container = "gluetun-hooks-test-" + uuid.uuid4().hex[:12]
        self.addCleanup(self.remove_container)
        self.docker("run", "-d", "--name", self.container, "--network", "none",
                    "--entrypoint", "/bin/sh", IMAGE,
                    "-c", "while :; do /bin/sleep 3600; done")
        self.shell(FIXTURE)
        for name in ("gluetun_up.sh", "qbittorrent_port.sh"):
            self.docker("cp", str(ROOT / "services/data/gluetun" / name),
                        f"{self.container}:/scripts/{name}")

    def docker(self, *args, **kwargs):
        return subprocess.run(["docker", *args], text=True, capture_output=True,
                              check=True, timeout=60, **kwargs).stdout

    def remove_container(self):
        subprocess.run(["docker", "rm", "-f", self.container],
                       capture_output=True, timeout=20)

    def shell(self, script):
        return self.docker("exec", "-i", self.container, "sh", "-s", input=script)

    def hook(self, expected_success=True, script="gluetun_up.sh"):
        result = subprocess.run(["docker", "exec", self.container,
                                 "sh", "/scripts/" + script],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode == 0, expected_success,
                         result.stdout + result.stderr)
        return result.stdout + result.stderr

    def events(self):
        return self.shell("cat /fixture/events 2>/dev/null || true").splitlines()

    def test_mam_runs_only_after_verified_port_update(self):
        self.hook()
        self.assertEqual(self.events(), ["update", "readback", "mam"])
        self.assertIn('"listen_port": 49251', self.shell("cat /fixture/posts"))

    def test_port_change_is_verified_before_each_mam_update(self):
        self.hook()
        self.shell("printf 54091 >/tmp/gluetun/forwarded_port; "
                   "printf '{\"listen_port\":54091}' >/fixture/preferences")
        self.hook()
        self.assertEqual(self.events(), ["update", "readback", "mam"] * 2)
        self.assertIn('"listen_port": 54091', self.shell("tail -1 /fixture/posts"))

    def test_wait_for_client_startup_then_verify_before_mam(self):
        self.shell("printf 2 >/fixture/startup-failures")
        self.hook()
        self.assertEqual(self.events(), ["update", "readback", "mam"])
        self.assertEqual(self.shell("cat /fixture/waits").splitlines(), ["wait", "wait"])

    def test_preferences_are_not_logged_on_failed_verification(self):
        self.shell("printf '{\"listen_port\":6881,\"private\":\"synthetic-secret\"}' "
                   ">/fixture/preferences")
        output = self.hook(expected_success=False)
        self.assertNotIn("synthetic-secret", output)

    def test_api_write_failure_prevents_mam_request(self):
        self.shell("touch /fixture/post-error")
        self.hook(expected_success=False)
        self.assertEqual(self.events(), ["update"])

    def test_api_read_failure_prevents_mam_request(self):
        self.shell("touch /fixture/read-error")
        self.hook(expected_success=False)
        self.assertEqual(self.events(), ["update", "readback"])

    def test_ignored_api_update_prevents_mam_request(self):
        self.shell("printf '{\"listen_port\":6881}' >/fixture/preferences")
        output = self.hook(expected_success=False)
        self.assertNotIn("Successfully", output)
        self.assertNotIn("mam", self.events())

    def test_readback_requires_exact_numeric_port(self):
        for response in ('{"listen_port":492510}', '{"listen_port":"49251"}', '{}'):
            with self.subTest(response=response):
                self.docker("exec", self.container, "sh", "-c",
                            "printf '%s' \"$1\" >/fixture/preferences", "fixture", response)
                self.hook(expected_success=False)
        self.assertNotIn("mam", self.events())

    def test_readback_accepts_json_whitespace(self):
        self.shell("printf '{ \"listen_port\" : 49251 , \"upnp\" : false }' >/fixture/preferences")
        self.hook()
        self.assertEqual(self.events(), ["update", "readback", "mam"])

    def test_missing_or_invalid_forwarded_port_prevents_mam_request(self):
        for port in ("", "0", "65536", "0123", "bad", "123,456", "123;false"):
            with self.subTest(port=port):
                self.docker("exec", self.container, "sh", "-c",
                            "printf '%s' \"$1\" >/tmp/gluetun/forwarded_port", "fixture", port)
                self.hook(expected_success=False)
        self.assertEqual(self.events(), [])
        self.shell("rm /tmp/gluetun/forwarded_port")
        self.hook(expected_success=False)

    def test_startup_wait_is_bounded_and_prevents_mam_request(self):
        self.shell("touch /fixture/unavailable")
        self.hook(expected_success=False)
        self.assertEqual(self.events(), [])
        self.assertEqual(len(self.shell("cat /fixture/waits").splitlines()), 59)

    def test_mam_failure_is_propagated(self):
        self.shell("printf 1 >/fixture/mam-exit")
        self.hook(expected_success=False)
        self.assertEqual(self.events(), ["update", "readback", "mam"])


if __name__ == "__main__":
    unittest.main()
