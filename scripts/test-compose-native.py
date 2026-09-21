#!/usr/bin/env python3
"""Source-only checks for the bounded native Compose workflow.

These checks never contact Docker or a host, decrypt SOPS, install collections, or
run Ansible tasks. They verify the intended safety boundary remains visible in
reviewed source; live qualification is separate.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OBSERVE = ROOT / "ansible/roles/compose_native/tasks/observe.yml"
DEPLOY = ROOT / "ansible/roles/compose_native/tasks/deploy.yml"
GENERATION = ROOT / "ansible/roles/compose_native/tasks/generation.yml"
DEFAULTS = ROOT / "ansible/roles/compose_native/defaults/main.yml"
HOST = ROOT / "ansible/inventory/host_vars/docker-host.yml"
MAINTENANCE = ROOT / "ansible/roles/docker_maintenance/tasks/main.yml"


class NativeComposeSourceTests(unittest.TestCase):
    def text(self, path):
        return path.read_text(encoding="utf-8")

    def test_collection_and_native_entrypoints_are_pinned(self):
        requirements = self.text(ROOT / "ansible/collections/requirements.yml")
        self.assertRegex(requirements, r"(?m)^  - name: community\.docker$")
        self.assertRegex(requirements, r"(?m)^    version: 5\.3\.0$")
        for name, task in (("observe-compose.yml", "observe"), ("deploy-compose.yml", "deploy")):
            source = self.text(ROOT / "ansible/playbooks" / name)
            self.assertIn("hosts: docker-host", source)
            self.assertNotIn("vars_files:", source)
            self.assertNotIn("infrastructure/contract", source)
            self.assertIn("name: compose_native", source)
            self.assertIn(f"tasks_from: {task}", source)
        deploy_play = self.text(ROOT / "ansible/playbooks/deploy-compose.yml")
        self.assertIn("name: apply_lock", deploy_play)
        self.assertIn("apply_lock_operation: compose-native-deploy", deploy_play)

    def test_inventory_fixes_project_paths_and_mounts_without_service_manifest(self):
        source = self.text(HOST)
        required = {
            "compose_native_project_name": "docker-compose",
            "compose_native_current_dir": "/srv/docker-compose/current",
            "compose_native_runtime_env_path": "/etc/docker-compose/production.env",
            "compose_native_expected_service_count": "39",
        }
        for key, value in required.items():
            self.assertRegex(source, rf"(?m)^{re.escape(key)}: {re.escape(value)}$")
        for retired_scope in (
            "compose_native_allowed_services",
            "compose_native_allowed_changed_paths",
            "compose_native_canary_service",
            "compose_native_canary_mounts",
        ):
            self.assertNotIn(retired_scope, source)
        for identity in (
            "31602ce7-0054-498a-9f24-f51ca491e7b3",
            "d4a19647-7879-4079-9fc9-b3e79711b449",
            "192.168.0.123:/storage/docker",
        ):
            self.assertIn(identity, source)

    def test_observation_uses_live_state_not_receipts(self):
        source = self.text(OBSERVE)
        for required in (
            "findmnt", "list-jobs", "systemctl",
            "config', '--quiet", "config', '--services", "config', '--images",
            "image_authority: tracked_digest_references",
            "community.docker.docker_compose_v2", "check_mode: true",
            "compose_native_backup_journal_path", "compose_native_apply_lock_path",
            "compose_native_reconciliation_lock_paths", "restore_readiness_proven: false",
            "compose_native_backup_lock_state", "exec 9<",
        ):
            self.assertIn(required, source)
        for forbidden in (".local", ".reconcile", "receipt", "historical-evidence", "activate-recovered-data"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("state: absent", source)
        self.assertNotIn("ansible.builtin.systemd_service", source)
        for retired in (
            "compose-image-lock.py", "compose_native_image_override_path",
            "compose_native_current_image_lock_path", "compose_native_previous_image_lock_path",
            "compose_native_retained_image_root", "--retained-root",
        ):
            self.assertNotIn(retired, source)
        mutex = source.split("- name: Require the existing backup mutex to be immediately available", 1)[1].split("- name:", 1)[0]
        self.assertIn("/usr/bin/bash", mutex)
        self.assertIn('exec 9< "$1"', mutex)
        self.assertIn("/usr/bin/flock --exclusive --nonblock 9", mutex)
        self.assertNotIn("/usr/bin/flock\n      - --exclusive", mutex)

    def test_deployment_has_deliberate_compose_and_secret_policy(self):
        source = self.text(DEPLOY) + self.text(GENERATION)
        for required in (
            "compose_native_expected_source_commit",
            "compose_native_controller_status.stdout == ''",
            "compose_native_controller_commit.stdout == compose_native_expected_source_commit",
            "--porcelain=v1",
            "--untracked-files=no",
        ):
            self.assertIn(required, source)
        modules = source.count("community.docker.docker_compose_v2:")
        self.assertGreaterEqual(modules, 4)
        for required in (
            "project_name: \"{{ compose_native_project_name }}\"",
            "policy: missing", "pull: never", "build: never", "recreate: auto",
            "compose_native_dependency_isolation",
            "recreate: always", "remove_orphans: false", "renew_anon_volumes: false",
            "wait: true", "wait_timeout:", "compose_native_force_recreate_services",
            "SOPS_AGE_KEY_FILE", "/usr/bin/cmp", "compose_native_runtime_env_path",
            "compose_native_environment_change_confirmed", "compose_native_backup_lock_path",
            "compose_native_authoritative_reconcile", "compose_native_expected_service_additions",
            "compose_native_expected_network_additions",
            "compose_native_expected_protected_service_changes",
            "compose_native_expected_changed_paths", "compose_native_requested_container_names",
            "compose_native_changed_bind_services",
            "compose_native_protected_service_fields", "Refuse unreviewed protected topology changes inside requested services",
            "compose_native_source_candidate_images",
            "services/data/restic/files-from",
            "database_migration_performed: false", "restic_activation_performed: false",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "remove_volumes:", "remove_images:", "assume_yes:", "remove_orphans: true",
            "docker image prune", "docker volume prune", "activate-recovered-data",
            "compose_recovery", "restic-backup preflight",
        ):
            self.assertNotIn(forbidden, source)

        transfer = self.text(DEPLOY).split(
            "- name: Transfer only the deterministic artifact", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("ansible.builtin.copy:", transfer)
        self.assertIn("ansible_pipelining: false", transfer)

        pull = source.split("- name: Pull only operation-approved generation images", 1)[1].split("- name:", 1)[0]
        self.assertIn("community.docker.docker_compose_v2_pull:", pull)
        self.assertIn("services: \"{{ compose_native_requested_services }}\"", pull)
        self.assertIn("include_deps: false", pull)
        self.assertIn("policy: missing", pull)

        preview = source.split("- name: Preview the full published model before container changes", 1)[1].split("- name:", 1)[0]
        self.assertIn("pull: never", preview)
        self.assertNotIn("pull: missing", preview)
        action_guard = source.split("- name: Refuse full-project actions outside requested containers and reviewed networks", 1)[1].split("- name:", 1)[0]
        self.assertIn("item.what == 'container'", action_guard)
        self.assertIn("item.id is match(compose_native_action_container_pattern)", action_guard)
        self.assertIn("item.what == 'network'", action_guard)
        self.assertIn("compose_native_expected_network_action_names", action_guard)
        self.assertNotIn("image-layer", action_guard)

        for retired in (
            "compose-image-lock.py", "image_checkpoint_path", "compose_native_interrupted_image_path",
            "compose_native_current_image_lock_path", "compose_native_previous_image_lock_path",
            "compose_native_retained_image_root", "production-image-override.json",
        ):
            self.assertNotIn(retired, self.text(OBSERVE) + source)

        automatic = source.split("- name: Converge requested services with automatic recreation", 1)[1].split("- name:", 1)[0]
        self.assertIn("recreate: auto", automatic)
        forced = source.split("- name: Converge explicitly selected bind-file restart services", 1)[1].split("- name:", 1)[0]
        self.assertIn("recreate: always", forced)
        bind_guard = source.split("- name: Require explicit forced recreation for changed bind-mounted files", 1)[1].split("- name:", 1)[0]
        self.assertIn("difference(compose_native_force_recreate_services)", bind_guard)

    def test_generation_activation_has_one_small_prepared_input_interface(self):
        deploy = self.text(DEPLOY)
        generation = self.text(GENERATION)
        prepared = deploy.split(
            "- name: Prepare the bounded native generation activation input", 1
        )[1].split("- name:", 1)[0]
        include = deploy.split(
            "- name: Reuse the native Compose generation activation interface", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("ansible.builtin.include_tasks: generation.yml", include)
        self.assertIn(
            'compose_native_generation: "{{ compose_native_prepared_generation }}"', include
        )
        for key in (
            "operation", "artifact_hash", "active_artifact_hash", "artifact_dir",
            "environment_path", "services",
            "force_recreate_services", "dependency_isolation", "action_container_names",
            "expected_network_action_names", "expected_services",
            "expected_service_count", "required_healthy_containers",
        ):
            self.assertRegex(prepared, rf"(?m)^          {key}:")

        for boundary in (
            "Validate the prepared native Compose generation",
            "compose_native_staging_root ~ '/' ~ (compose_native_generation.artifact_hash | default(''))",
            "compose_native_staged_env_root ~ '/' ~ (compose_native_generation.artifact_hash | default('')) ~ '.env'",
            "Recheck the existing backup mutex immediately before publication",
            "Publish a changed source generation with transaction-local before-images",
            "Preview the full published model before container changes",
            "Preview the complete model after requested-service convergence",
            "Refuse post-recreation actions outside exact replacement containers",
            "Settle isolated Compose replacement metadata through dependency-aware auto convergence",
            "Require the complete published model to be idempotent",
            "Recheck required container health after native convergence",
            "Assert complete post-deployment convergence",
            "Publish the exact active artifact identity for backup acceptance",
        ):
            self.assertIn(boundary, generation)
        self.assertGreaterEqual(generation.count("community.docker.docker_compose_v2:"), 6)
        self.assertIn("community.docker.docker_compose_v2_pull:", generation)
        self.assertNotIn("materialize-compose-secret-files.py", generation)
        self.assertNotIn("activate-recovered-data.py", generation)
        self.assertNotIn("nextcloud", generation.lower())
        self.assertNotIn("calibre", generation.lower())
        settle = generation.split(
            "- name: Settle isolated Compose replacement metadata through dependency-aware auto convergence", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("services: \"{{ compose_native_requested_services }}\"", settle)
        self.assertIn("dependencies: true", settle)
        self.assertIn("recreate: auto", settle)
        self.assertIn("when: compose_native_post_preview.changed", settle)
        post_guard = generation.split(
            "- name: Require the exact post-isolated-convergence action count and statuses", 1
        )[1].split("- name:", 1)[0]
        self.assertNotIn("compose_native_force_recreate_services | length > 0", post_guard)

    def test_deployment_refuses_unbounded_model_and_path_changes(self):
        deploy = self.text(DEPLOY)
        for boundary in (
            "Refuse unsafe expected artifact paths",
            "Inventory exact selected artifact differences against the active generation",
            "Bind authoritative reconciliation to every tracked artifact difference",
            "Refuse mutable source candidate images",
            "Require the exact reviewed service-set transition",
            "Refuse unreviewed changes to non-service Compose topology",
            "Require retained network definitions to remain unchanged",
            "Refuse normalized model changes outside requested services",
            "Require unique exact protected-service transition references",
            "Refuse unreviewed protected topology changes inside requested services",
            "Require every reviewed protected-service transition to be exact and used",
            "Reconfirm the exact reviewed service additions before activation",
        ):
            self.assertIn(boundary, deploy)
        self.assertIn(
            "difference(compose_native_declared_services.stdout_lines) | sort ==",
            deploy,
        )
        self.assertIn(
            "difference(compose_native_candidate_services.stdout_lines) | length == 0",
            deploy,
        )

    def test_general_caller_uses_native_models_and_retires_consumed_release(self):
        host = self.text(HOST)
        self.assertIn("compose_native_backup_lock_path: /run/lock/home-lab-backup.lock", host)
        self.assertNotIn("compose_native_canary", host)

        defaults = self.text(DEFAULTS)
        self.assertIn("compose_native_expected_changed_paths: []", defaults)
        self.assertIn("compose_native_expected_service_additions: []", defaults)
        self.assertIn("compose_native_expected_network_additions: []", defaults)
        self.assertIn("compose_native_expected_protected_service_changes: []", defaults)
        self.assertIn("compose_native_observation_expected_service_count:", defaults)
        for protected in ("volumes", "networks", "network_mode", "devices", "ports", "privileged", "secrets"):
            self.assertRegex(defaults, rf"(?m)^  - {protected}$")
        self.assertNotIn("compose_native_allowed_services", defaults)

        deploy = self.text(DEPLOY)
        self.assertNotIn("services/data/litellm/config.yaml", deploy)
        self.assertNotIn("services/nextcloud.yml", deploy)
        self.assertIn("compose_native_expected_changed_paths", deploy)
        self.assertIn("compose_native_requested_container_names", deploy)
        self.assertIn("Candidate source images must all be digest pinned", deploy)
        self.assertNotIn("compose_native_requested_image_id_checks", deploy)
        self.assertNotIn("compose-impact", deploy)
        self.assertIn("compose_native_active_model.services[item]", deploy)
        self.assertIn("compose_native_candidate_model.services[item]", deploy)
        self.assertIn("compose_native_requested_services", deploy)
        candidate_model = deploy.split(
            "- name: Read the candidate model as it will resolve from the published directory", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("compose_native_current_dir", candidate_model)
        self.assertIn("compose_native_candidate_dir ~ '/docker-compose.yml'", candidate_model)
        self.assertNotIn("compose_native_image_override_path", candidate_model)

        self.assertFalse((ROOT / "ansible/playbooks/release-failed-compose-canary.yml").exists())

    def test_interrupted_deployment_documentation_matches_native_boundary(self):
        operations = " ".join(self.text(ROOT / "docs/operations.md").split())
        for marker in (
            "durable production owner",
            "Do not clear them",
            "exact owner",
            "transaction-local",
            "before-images",
            "zero-change final preview",
            "No generic resume",
        ):
            self.assertIn(marker, operations)

    def test_service_specific_recovery_consumers_are_retired(self):
        for relative in (
            "ansible/playbooks/deploy-nextcloud-migration.yml",
            "ansible/playbooks/rollback-nextcloud-migration.yml",
            "ansible/playbooks/stage-compose.yml",
            "ansible/playbooks/review-compose-stage.yml",
            "ansible/playbooks/plan-compose-recovery.yml",
            "ansible/playbooks/recover-compose.yml",
            "ansible/roles/compose_deploy",
            "ansible/roles/compose_rollback",
            "ansible/roles/compose_stage",
            "ansible/roles/compose_recovery",
            "ansible/roles/compose_recovery_preflight",
            "scripts/compose-action-plan.py",
            "scripts/compose-image-lock.py",
            "scripts/compose-recovery-plan.py",
            "scripts/activate-recovered-data.py",
        ):
            self.assertFalse((ROOT / relative).exists(), relative)
        site = self.text(ROOT / "ansible/playbooks/site.yml")
        self.assertIn("hosts: docker-host", site)
        self.assertIn("name: docker_maintenance", site)
        self.assertIn("compose_native_authoritative_reconcile: true", site)
        self.assertIn("tasks_from: retire-legacy", site)
        recovery = " ".join(self.text(ROOT / "recovery/README.md").split())
        self.assertIn("recovery groups", recovery)
        self.assertIn("Git revert", recovery)

    def test_safe_prune_no_longer_depends_on_rollback_image_locks(self):
        source = self.text(MAINTENANCE)
        self.assertIn("docker image prune --all --force --filter until=", source)
        self.assertIn("operation=docker-image-prune", source)
        self.assertIn("Persistent=true", source)
        self.assertIn("RandomizedDelaySec=", source)
        for retired in (
            "compose-image-lock.py", "maintenance_image_lock_bootstrap_confirmed",
            "maintenance_compose_current_image_lock_path", "maintenance_compose_previous_image_lock_path",
            "--check-registry", "home-lab-prune-protection",
        ):
            self.assertNotIn(retired, source)

    def test_generic_rollback_is_git_revert_plus_authoritative_site_convergence(self):
        for relative in ("README.md", "docs/operations.md", "docs/decisions.md"):
            source = " ".join(self.text(ROOT / relative).split())
            self.assertIn("Git revert", source, relative)
            self.assertIn("site", source, relative)


if __name__ == "__main__":
    unittest.main()
