#!/usr/bin/env python3
"""Structural regression tests for reconciler security boundaries."""

from __future__ import annotations

import fcntl
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
        cls.application_tunnels = (REPOSITORY / "scripts/controller/application-api-tunnels").read_text()

    def test_oauth_secret_is_supplied_through_protected_request_file(self) -> None:
        self.assertNotIn('-d "client_secret=$TAILSCALE_OAUTH_CLIENT_SECRET"', self.reconciler)
        self.assertIn('chmod 0600 "$token_request"', self.reconciler)
        self.assertIn('--data-binary @"$token_request"', self.reconciler)
        self.assertIn('rm -f "$token_request"', self.reconciler)

    def test_provider_tls_uses_only_the_strict_ca_bundle(self) -> None:
        start = self.controller.index("prepare_provider_tls() {")
        end = self.controller.index("\n}\n", start) + 3
        setup = self.controller[start:end]
        prepared_start = self.controller.index("use_prepared_provider_tls() {")
        prepared_end = self.controller.index("\n}\n", prepared_start) + 3
        prepared = self.controller[prepared_start:prepared_end]
        self.assertIn("scripts/prepare-provider-ca-bundle", setup)
        self.assertIn('export SSL_CERT_FILE="$repo_root/.local/provider-ca/bundle.pem"', setup)
        self.assertIn("not path.is_file() or path.is_symlink()", prepared)
        self.assertIn("metadata.st_uid != os.getuid()", prepared)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o600", prepared)
        self.assertIn("metadata.st_size == 0", prepared)
        self.assertIn('export SSL_CERT_FILE="$bundle"', prepared)
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

    def test_manifest_binds_and_reviews_exact_proxmox_nix_plan(self) -> None:
        self.assertIn("proxmox_host_plan=$(plan_proxmox_host true)", self.reconciler)
        self.assertIn("--argjson proxmox_host_plan", self.reconciler)
        self.assertIn(".version == 5", self.reconciler)
        self.assertIn("saved Proxmox Nix host plan is missing or changed", self.reconciler)
        self.assertIn("[proxmox-host-nix]", self.controller)
        self.assertIn("verify_proxmox_host_plan", self.controller)
        self.assertIn("Proxmox Nix plan internal digest differs", self.controller)
        self.assertIn("raw != canonical", self.controller)
        self.assertNotIn("proxmox-nix-shadow", self.controller)

    def test_guarded_nix_order_and_vm_start_prerequisite_are_closed(self) -> None:
        dispatch = self.reconciler.index('case "$action" in', self.reconciler.index("acquire_apply_lock()"))
        recovery = self.reconciler.index("if [[ $phase == recovery ]]", dispatch)
        recovery_tofu = self.reconciler.index("apply_root proxmox", recovery)
        recovery_nix = self.reconciler.index("prepare_apply_proxmox_host", recovery_tofu)
        steady = self.reconciler.index("else", recovery_nix)
        steady_prerequisite = self.reconciler.index('== vm-start-prerequisite', steady)
        steady_prerequisite_tofu = self.reconciler.index("apply_root proxmox", steady_prerequisite)
        steady_exit = self.reconciler.index("requires_new_reviewed_plan=true", steady_prerequisite_tofu)
        steady_nix = self.reconciler.index("prepare_apply_proxmox_host", steady_exit)
        steady_tofu = self.reconciler.index("apply_root proxmox", steady_nix)
        self.assertLess(recovery_tofu, recovery_nix)
        self.assertLess(steady_prerequisite_tofu, steady_exit)
        self.assertLess(steady_exit, steady_nix)
        self.assertLess(steady_nix, steady_tofu)
        self.assertIn("--mode vm-start-prerequisite", self.reconciler)
        self.assertIn('prerequisite == "vm-start"', self.reconciler)
        self.assertIn("roots=(aws-foundation proxmox-legacy proxmox)", self.reconciler)
        self.assertIn("if [[ $manifest_stage == vm-start-prerequisite ]]", self.reconciler)
        self.assertIn("printf '%s\\n' aws-foundation proxmox-legacy proxmox", self.reconciler)
        self.assertIn("verify_fresh_proxmox_host_noop", self.reconciler)
        self.assertIn('if jq -e \'.actions == [] and .status == "ready" and .applyEligible == true\'', self.reconciler)
        self.assertIn("Proxmox Nix host no-op plan has expired", self.reconciler)
        self.assertIn("Skipping Proxmox Nix host apply: exact saved plan is fresh and zero-action.", self.reconciler)
        self.assertIn("Proxmox Nix plan has expired", self.controller)
        self.assertIn("RECONCILE_PROXMOX_NO_CONCURRENT_MUTATION_CONFIRMED", self.reconciler)
        self.assertIn("any(.actions[]; .watchdogRequired == true)", self.reconciler)
        self.assertNotIn("home-lab-proxmox-plan-v4", self.reconciler)
        self.assertGreaterEqual(self.reconciler.count("home-lab-proxmox-plan-v1"), 2)

    def test_confirmation_binds_manifest_recovery_stage_and_rejects_cross_stage_replay(self) -> None:
        self.assertIn('expected_confirmation="apply-reviewed-$operation-$recovery_stage"', self.controller)
        self.assertIn('Ready to apply operation=%s recovery_stage=%s', self.controller)
        self.assertIn('[controller-manifest] operation=%s recovery_stage=%s', self.controller)
        self.assertNotIn('expected_confirmation="apply-reviewed-$operation"', self.controller)
        self.assertIn('confirmation_invalid', self.controller)

    def test_apply_confirms_before_loading_mutation_credentials(self) -> None:
        dispatch = self.controller.index('case "$action" in', self.controller.index("confirm_apply()"))
        authority_gate = self.controller.index("require_ordinary_mutation_authority", dispatch)
        prepared = self.controller.index("use_prepared_provider_tls", authority_gate)
        validation = self.controller.index("run_validation", prepared)
        confirm = self.controller.index("confirm_apply", validation)
        credentials = self.controller.index("load_credentials apply", confirm)
        regenerated = self.controller.index("prepare_provider_tls", credentials)
        reconcile = self.controller.index("scripts/reconcile-infrastructure apply", regenerated)
        self.assertLess(authority_gate, prepared)
        self.assertLess(prepared, validation)
        self.assertLess(validation, confirm)
        self.assertLess(confirm, credentials)
        self.assertLess(credentials, regenerated)
        self.assertLess(regenerated, reconcile)
        self.assertIn("interactive_confirmation_required", self.controller)
        apply_section = self.controller[confirm:]
        self.assertNotIn("load_credentials plan", apply_section)

    def test_migration_authority_refuses_all_ordinary_apply_paths_before_mutation(self) -> None:
        local_dispatch = self.controller.index('case "$action" in', self.controller.index("confirm_apply()"))
        local_gate = self.controller.index("require_ordinary_mutation_authority", local_dispatch)
        local_credentials = self.controller.index("load_credentials apply", local_gate)
        local_apply = self.controller.index("scripts/reconcile-infrastructure apply", local_credentials)
        self.assertLess(local_gate, local_credentials)
        self.assertLess(local_gate, local_apply)

        reconcile_gate = self.reconciler.index(
            "check-vm-100-authority.js --require-ordinary-mutation",
        )
        backend_setup = self.reconciler.index("backend_bucket=${TF_BACKEND_BUCKET:-}", reconcile_gate)
        reconcile_dispatch = self.reconciler.index('case "$action" in', self.reconciler.index("acquire_apply_lock()"))
        reconcile_lock = self.reconciler.index("acquire_apply_lock", reconcile_dispatch)
        first_mutation = self.reconciler.index("apply_root aws-foundation", reconcile_lock)
        self.assertLess(reconcile_gate, backend_setup)
        self.assertLess(reconcile_gate, reconcile_lock)
        self.assertLess(reconcile_gate, first_mutation)
        gate_block = self.reconciler[self.reconciler.rfind("if [[ $action ==", 0, reconcile_gate):backend_setup]
        self.assertIn("$action == apply", gate_block)

    def test_application_tunnels_and_apply_order_are_guarded(self) -> None:
        dispatch = self.controller.index('case "$action" in', self.controller.index("confirm_apply()"))
        plan_credentials = self.controller.index("load_credentials plan", dispatch)
        plan_tunnels = self.controller.index("start_application_tunnels", plan_credentials)
        plan_reconcile = self.controller.index("scripts/reconcile-infrastructure plan", plan_tunnels)
        apply_credentials = self.controller.index("load_credentials apply", plan_reconcile)
        apply_tunnels = self.controller.index("start_application_tunnels", apply_credentials)
        apply_reconcile = self.controller.index("scripts/reconcile-infrastructure apply", apply_tunnels)
        self.assertLess(plan_credentials, plan_tunnels)
        self.assertLess(plan_tunnels, plan_reconcile)
        self.assertLess(apply_credentials, apply_tunnels)
        self.assertLess(apply_tunnels, apply_reconcile)
        self.assertIn("trap stop_application_tunnels EXIT", self.controller)
        self.assertIn("ExitOnForwardFailure=yes", self.application_tunnels)
        self.assertIn("ClearAllForwardings=yes", self.application_tunnels)
        self.assertIn("sudo -n docker inspect gluetun", self.application_tunnels)
        for port in ("18989", "17878", "17879", "19696"):
            self.assertIn(f"127.0.0.1:{port}", self.application_tunnels)
        self.assertNotIn("StrictHostKeyChecking=no", self.application_tunnels)
        self.assertNotIn("UserKnownHostsFile=/dev/null", self.application_tunnels)

        apply_dispatch = self.reconciler.index('case "$action" in', self.reconciler.index("acquire_apply_lock()"))
        compose = self.reconciler.index("compose_apply", apply_dispatch)
        authentik = self.reconciler.index("apply_root authentik", compose)
        media = self.reconciler.index("apply_root media-apps", authentik)
        verify = self.reconciler.index("verify_all", media)
        self.assertLess(compose, authentik)
        self.assertLess(authentik, media)
        self.assertLess(media, verify)
        for secret in ("TF_VAR_authentik_token", "TF_VAR_sonarr_api_key", "TF_VAR_radarr_4k_api_key"):
            self.assertIn(secret, self.reconciler)

    def test_reconciler_owns_and_verifies_one_inherited_apply_lock(self) -> None:
        self.assertIn("controller-apply-lock.py run", self.reconciler)
        self.assertIn("controller-apply-lock.py verify", self.reconciler)
        self.assertIn("RECONCILE_CONTROLLER_LOCK_TOKEN", self.reconciler)
        self.assertIn("RECONCILE_CONTROLLER_LOCK_FD", self.reconciler)
        self.assertNotIn('mkdir "$apply_lock_dir"', self.reconciler)
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
        reconcile_root.mkdir(exist_ok=True, mode=0o700)
        lock_path = reconcile_root / "controller-apply.lock"
        self.assertFalse(lock_path.is_dir(), "legacy directory lock must not exist")
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.fchmod(lock_fd, 0o600)
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.skipTest("a real controller apply lock is already held")
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
                for name in ("tofu", "ansible", "ansible-playbook"):
                    stub = binaries / name
                    stub.write_text("#!/usr/bin/env bash\nexit 0\n")
                    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
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
            self.assertEqual(result.returncode, 75, result.stderr)
            self.assertIn("another controller apply holds", result.stderr)
        finally:
            os.close(lock_fd)
        self.assertTrue(lock_path.is_file())


if __name__ == "__main__":
    unittest.main()
