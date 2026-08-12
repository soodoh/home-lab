#!/usr/bin/env python3
"""Structural regression tests for reconciler security boundaries."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]


class ReconcileSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reconciler = (REPOSITORY / "scripts/reconcile-infrastructure").read_text()
        cls.controller = (REPOSITORY / "scripts/local-controller").read_text()
        cls.credential_configurator = (
            REPOSITORY / "scripts/configure-local-provider-credentials"
        ).read_text()
        cls.provider_bundle = (REPOSITORY / "scripts/prepare-provider-ca-bundle").read_text()

    def test_oauth_secret_is_supplied_through_protected_request_file(self) -> None:
        self.assertNotIn('-d "client_secret=$TAILSCALE_OAUTH_CLIENT_SECRET"', self.reconciler)
        self.assertIn('chmod 0600 "$token_request"', self.reconciler)
        self.assertIn('--data-binary @"$token_request"', self.reconciler)
        self.assertIn('rm -f "$token_request"', self.reconciler)

    def test_provider_tls_uses_only_the_strict_ca_bundle(self) -> None:
        start = self.controller.index("prepare_provider_tls() {")
        end = self.controller.index("\n}\n", start) + 3
        setup = self.controller[start:end]
        self.assertIn("scripts/prepare-provider-ca-bundle", setup)
        self.assertIn('export SSL_CERT_FILE="$repo_root/.local/provider-ca/bundle.pem"', setup)
        self.assertNotIn("security ", self.controller)
        self.assertNotIn("keychain", self.controller)
        self.assertNotIn("uname", setup)
        self.assertIn('[[ -n ${NIX_SSL_CERT_FILE:-} && -r $NIX_SSL_CERT_FILE ]]', self.provider_bundle)
        self.assertIn('"$HOME/Library/Keychains/login.keychain-db"', self.provider_bundle)

    def test_local_controller_exposes_only_plan_and_apply(self) -> None:
        self.assertIn('case "$action" in plan|apply)', self.controller)
        self.assertNotIn("  review)", self.controller)
        self.assertNotIn("  approve)", self.controller)
        self.assertNotIn("  validate)", self.controller)

    def test_plan_renders_saved_plans_after_reconciliation(self) -> None:
        dispatch = self.controller.index('case "$action" in', self.controller.index("confirm_apply()"))
        reconcile = self.controller.index("scripts/reconcile-infrastructure plan", dispatch)
        show = self.controller.index("show_saved_plans", reconcile)
        complete = self.controller.index("local_controller=planned", show)
        self.assertLess(reconcile, show)
        self.assertLess(show, complete)

    def test_apply_confirms_before_loading_mutation_credentials(self) -> None:
        dispatch = self.controller.index('case "$action" in', self.controller.index("confirm_apply()"))
        confirm = self.controller.index("confirm_apply", dispatch)
        credentials = self.controller.index("load_credentials apply", confirm)
        reconcile = self.controller.index("scripts/reconcile-infrastructure apply", credentials)
        self.assertLess(confirm, credentials)
        self.assertLess(credentials, reconcile)
        self.assertIn("interactive_confirmation_required", self.controller)
        apply_section = self.controller[confirm:]
        self.assertNotIn("load_credentials plan", apply_section)

    def test_reconciler_always_owns_the_apply_lock(self) -> None:
        self.assertNotIn("RECONCILE_APPLY_LOCK_HELD", self.reconciler)
        self.assertNotIn("RECONCILE_APPLY_LOCK_HELD", self.controller)
        self.assertNotIn("acquire_apply_lock", self.controller)
        self.assertNotIn("RECONCILE_APPROVAL_FILE", self.reconciler)
        self.assertNotIn("RECONCILE_APPROVAL_FILE", self.controller)

    def test_extra_vars_precede_fixed_compose_values(self) -> None:
        for playbook in (
            "playbooks/stage-compose.yml",
            "playbooks/deploy-compose.yml",
            "playbooks/plan-compose-recovery.yml",
            "playbooks/recover-compose.yml",
        ):
            start = self.reconciler.index(playbook)
            next_command = self.reconciler.find("ansible-playbook", start + len(playbook))
            section = self.reconciler[start:next_command if next_command >= 0 else None]
            self.assertLess(
                section.index('${ansible_extra_args[@]}'),
                section.index("compose_artifact_hash="),
                playbook,
            )

    def test_retired_inputs_are_removed(self) -> None:
        self.assertNotIn("PROXMOX_CT_DECOMMISSION_CONFIRMATION", self.reconciler)
        self.assertNotIn('"TF_VAR_adoption_complete": "true"', self.credential_configurator)
        self.assertIn(
            'current.pop("TF_VAR_adoption_complete", None)',
            self.credential_configurator,
        )

    def test_caller_flag_cannot_bypass_existing_apply_lock(self) -> None:
        reconcile_root = REPOSITORY / ".reconcile"
        reconcile_root.mkdir(exist_ok=True)
        lock_dir = reconcile_root / "controller-apply.lock"
        if lock_dir.exists():
            self.skipTest("a real controller apply lock already exists")
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        with tempfile.TemporaryDirectory(dir=reconcile_root) as directory:
            temporary = Path(directory)
            binaries = temporary / "bin"
            binaries.mkdir()
            git = binaries / "git"
            git.write_text(
                f'''#!/usr/bin/env bash
set -euo pipefail
if [[ ${{1:-}} == rev-parse && ${{2:-}} == HEAD ]]; then
  printf '%040d\\n' 0
elif [[ ${{1:-}} == status ]]; then
  exit 0
else
  exec {real_git} "$@"
fi
'''
            )
            git.chmod(git.stat().st_mode | stat.S_IXUSR)
            lock_dir.mkdir(mode=0o700)
            (lock_dir / "owner").write_text("pid=1 commit=other phase=steady\n")
            (lock_dir / "owner").chmod(0o600)
            try:
                result = subprocess.run(
                    [
                        str(REPOSITORY / "scripts/reconcile-infrastructure"),
                        "apply",
                        "--phase",
                        "steady",
                        "--plan-dir",
                        str(temporary / "plans"),
                    ],
                    cwd=REPOSITORY,
                    env={
                        **os.environ,
                        "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
                        "TF_BACKEND_BUCKET": "test-state-bucket",
                        "AWS_REGION": "us-east-1",
                        "TF_VAR_tailscale_enable_management": "false",
                        "TF_VAR_omada_enable_management": "false",
                        "RECONCILE_APPLY_LOCK_HELD": "true",
                    },
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            finally:
                (lock_dir / "owner").unlink(missing_ok=True)
                lock_dir.rmdir()
            self.assertEqual(result.returncode, 75, result.stderr)
            self.assertIn("another controller apply holds", result.stderr)


if __name__ == "__main__":
    unittest.main()
