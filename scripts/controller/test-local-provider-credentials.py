#!/usr/bin/env python3
"""Behavior tests for noninteractive, per-run provider credential handoff."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / "scripts/configure-local-provider-credentials"
CREDENTIALS = {
    "AUTHENTIK_PLAN_TOKEN": "test-authentik-plan",
    "AUTHENTIK_APPLY_TOKEN": "test-authentik-apply",
    "TAILSCALE_PLAN_ID": "test-tailscale-plan-id",
    "TAILSCALE_PLAN_SECRET": "test-tailscale-plan-secret",
    "TAILSCALE_APPLY_ID": "test-tailscale-apply-id",
    "TAILSCALE_APPLY_SECRET": "test-tailscale-apply-secret",
    "OMADA_PLAN_USERNAME": "test-omada-viewer",
    "OMADA_PLAN_PASSWORD": "test-omada-viewer-password",
    "OMADA_APPLY_USERNAME": "test-omada-admin",
    "OMADA_APPLY_PASSWORD": "test-omada-admin-password",
}


class LocalProviderCredentialsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.session = root / "session"
        self.session.mkdir(mode=0o700)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("HOMELAB_") and key not in CREDENTIALS}
        self.env.update(CREDENTIALS)
        self.env["HOME_LAB_PROVIDER_SESSION_DIR"] = str(self.session)

    def run_helper(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(HELPER)], env=self.env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=15)

    def test_uses_distinct_exported_identities_without_tty(self) -> None:
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "local_provider_credentials=session_configured\n")
        self.assertEqual(result.stderr, "")
        plan = self.session / "plan-credentials.json"
        apply = self.session / "apply-credentials.json"
        self.assertEqual(plan.stat().st_mode & 0o777, 0o600)
        self.assertEqual(apply.stat().st_mode & 0o777, 0o600)
        plan_data, apply_data = json.loads(plan.read_text()), json.loads(apply.read_text())
        self.assertEqual(plan_data["AUTHENTIK_TOKEN"], CREDENTIALS["AUTHENTIK_PLAN_TOKEN"])
        self.assertEqual(apply_data["AUTHENTIK_TOKEN"], CREDENTIALS["AUTHENTIK_APPLY_TOKEN"])
        self.assertEqual(plan_data["TAILSCALE_OAUTH_CLIENT_ID"], CREDENTIALS["TAILSCALE_PLAN_ID"])
        self.assertEqual(apply_data["TAILSCALE_OAUTH_CLIENT_SECRET"], CREDENTIALS["TAILSCALE_APPLY_SECRET"])
        self.assertEqual(plan_data["OMADA_USERNAME"], CREDENTIALS["OMADA_PLAN_USERNAME"])
        self.assertEqual(apply_data["OMADA_PASSWORD"], CREDENTIALS["OMADA_APPLY_PASSWORD"])
        self.assertFalse(any(key.startswith("TF_VAR_games_disk") or key.startswith("HOMELAB_")
                             for key in plan_data))
        self.assertNotIn("test-authentik-plan", result.stdout + result.stderr)

    def test_missing_and_identical_credentials_refuse_without_values(self) -> None:
        self.env.pop("AUTHENTIK_PLAN_TOKEN")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AUTHENTIK_PLAN_TOKEN", result.stderr)
        self.assertNotIn("test-authentik-apply", result.stderr)

        self.env["AUTHENTIK_PLAN_TOKEN"] = CREDENTIALS["AUTHENTIK_APPLY_TOKEN"]
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct", result.stderr)
        self.assertNotIn("test-authentik-apply", result.stderr)

    def test_rejects_reused_session(self) -> None:
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertNotEqual(self.run_helper().returncode, 0)

    def test_non_proxmox_credentials_need_no_hardware_observation(self) -> None:
        self.env.pop("HOME_LAB_HARDWARE_FILE", None)
        self.env["HOMELAB_GAMES_DISK_BY_ID"] = "stale-controller-value"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads((self.session / "plan-credentials.json").read_text())
        self.assertNotIn("HOMELAB_GAMES_DISK_BY_ID", plan)


if __name__ == "__main__":
    unittest.main()
