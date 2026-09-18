#!/usr/bin/env python3
"""Source-only checks for the bounded native Compose workflow.

These checks never contact Docker or a host, decrypt SOPS, install collections, or
run Ansible tasks. They verify the intended safety boundary remains visible in
reviewed source; live qualification is separate.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
OBSERVE = ROOT / "ansible/roles/compose_native/tasks/observe.yml"
DEPLOY = ROOT / "ansible/roles/compose_native/tasks/deploy.yml"
DEFAULTS = ROOT / "ansible/roles/compose_native/defaults/main.yml"
HOST = ROOT / "ansible/inventory/host_vars/docker-host.yml"


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
        self.assertIn("apply_lock_operation: compose-native-canary", deploy_play)

    def test_inventory_fixes_project_paths_mounts_and_canary_scope(self):
        source = self.text(HOST)
        required = {
            "compose_native_project_name": "docker-compose",
            "compose_native_current_dir": "/srv/docker-compose/current",
            "compose_native_previous_dir": "/srv/docker-compose/previous",
            "compose_native_runtime_env_path": "/etc/docker-compose/production.env",
            "compose_native_current_image_lock_path": "/var/lib/docker-compose/current-images.json",
            "compose_native_previous_image_lock_path": "/var/lib/docker-compose/previous-images.json",
            "compose_native_retained_image_root": "/var/lib/docker-compose/retained-images",
            "compose_native_expected_service_count": "38",
        }
        for key, value in required.items():
            self.assertRegex(source, rf"(?m)^{re.escape(key)}: {re.escape(value)}$")
        allowed = source.split("compose_native_allowed_services:", 1)[1].split("compose_native_allowed_changed_paths:", 1)[0]
        self.assertEqual(re.findall(r"(?m)^  - (\S+)$", allowed), ["flaresolverr"])
        for identity in (
            "31602ce7-0054-498a-9f24-f51ca491e7b3",
            "d4a19647-7879-4079-9fc9-b3e79711b449",
            "192.168.0.123:/storage/docker",
        ):
            self.assertIn(identity, source)

    def test_observation_uses_live_state_not_receipts(self):
        source = self.text(OBSERVE)
        for required in (
            "findmnt", "list-jobs", "systemctl", "compose-image-lock.py",
            "config', '--quiet", "config', '--services", "config', '--images",
            "community.docker.docker_compose_v2", "check_mode: true",
            "compose_native_backup_journal_path", "compose_native_apply_lock_path",
            "compose_native_reconciliation_lock_paths", "restore_readiness_proven: false",
            "compose_native_backup_lock_state", "exec 9<", "--retained-root",
        ):
            self.assertIn(required, source)
        for forbidden in (".local", ".reconcile", "receipt", "historical-evidence", "activate-recovered-data"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("state: absent", source)
        self.assertNotIn("ansible.builtin.systemd_service", source)
        mutex = source.split("- name: Require the existing backup mutex to be immediately available", 1)[1].split("- name:", 1)[0]
        self.assertIn("/usr/bin/bash", mutex)
        self.assertIn('exec 9< "$1"', mutex)
        self.assertIn("/usr/bin/flock --exclusive --nonblock 9", mutex)
        self.assertNotIn("/usr/bin/flock\n      - --exclusive", mutex)
        image_verify = source.split("- name: Verify current previous and retained rollback images are locally available", 1)[1].split("- name:", 1)[0]
        self.assertIn("ansible.builtin.script:", image_verify)
        self.assertIn("{{ role_path }}/../../../scripts/compose-image-lock.py", image_verify)
        self.assertNotIn("{{ compose_native_current_dir }}/scripts/compose-image-lock.py", image_verify)

    def test_deployment_has_deliberate_compose_and_secret_policy(self):
        source = self.text(DEPLOY)
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
            "policy: missing", "pull: never", "build: never", "recreate: auto", "dependencies: false",
            "recreate: always", "remove_orphans: false", "renew_anon_volumes: false",
            "wait: true", "wait_timeout:", "compose_native_force_recreate_services",
            "SOPS_AGE_KEY_FILE", "/usr/bin/cmp", "compose_native_runtime_env_path",
            "compose_native_previous_dir", "compose_native_previous_env_path",
            "compose_native_current_image_lock_path", "compose_native_previous_image_lock_path",
            "compose_native_interrupted_image_path", "compose_native_retained_image_root", "compose_native_backup_lock_path",
            "compose_native_allowed_changed_paths", "services/authentik.yml", "services/nextcloud.yml",
            "services/data/restic/files-from", "compose_native_canary_mounts",
            "database_migration_performed: false", "restic_activation_performed: false",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "remove_volumes:", "remove_images:", "assume_yes:", "remove_orphans: true",
            "docker image prune", "docker volume prune", "activate-recovered-data",
            "compose_recovery", "restic-backup preflight",
        ):
            self.assertNotIn(forbidden, source)

        pull = source.split("- name: Pull only approved canary images", 1)[1].split("- name:", 1)[0]
        self.assertIn("community.docker.docker_compose_v2_pull:", pull)
        self.assertIn("services: \"{{ compose_native_requested_services }}\"", pull)
        self.assertIn("include_deps: false", pull)
        self.assertIn("policy: missing", pull)

        preview = source.split("- name: Preview the full published model before container changes", 1)[1].split("- name:", 1)[0]
        self.assertIn("pull: never", preview)
        self.assertNotIn("pull: missing", preview)
        action_guard = source.split("- name: Refuse full-project actions outside the canary containers", 1)[1].split("- name:", 1)[0]
        self.assertIn("item.what == 'container'", action_guard)
        self.assertIn("item.id in compose_native_requested_services", action_guard)
        self.assertNotIn("image-layer", action_guard)

        final_verify = source.split("- name: Verify current previous and retained image generations after convergence", 1)[1].split("- name:", 1)[0]
        self.assertIn("--retained-root", final_verify)
        self.assertNotIn("--check-registry", final_verify)

    def test_failure_and_authorization_documentation_matches_boundaries(self):
        operations = " ".join(self.text(ROOT / "docs/operations.md").split())
        self.assertIn("Failures after checkpoint capture retain the production owner and checkpoint", operations)
        self.assertIn("A refusal before checkpoint capture retains the owner but creates no checkpoint", operations)
        self.assertIn("authorized one normal canary attempt", operations)
        self.assertIn("expires after that attempt", operations)
        self.assertIn("does not authorize a retry after failure", operations)
        self.assertIn("does not claim that the normal run occurred", operations)
        self.assertIn("same clean committed checkout", operations)

    def test_general_legacy_deployment_is_retired_but_recovery_consumers_remain(self):
        stage = self.text(ROOT / "ansible/roles/compose_stage/tasks/main.yml")
        deploy = self.text(ROOT / "ansible/roles/compose_deploy/tasks/main.yml")
        review = self.text(ROOT / "ansible/playbooks/review-compose-stage.yml")
        for marker in (
            "compose_stage_retained_operation",
            "nextcloud-five-mount-recovery",
            "calibre-local-rollback",
            "restic-policy-recovery",
            "archive-compose-recovery",
            "General Compose staging is retired",
        ):
            self.assertIn(marker, stage)
        self.assertIn("compose_stage_retained_operation", review)
        self.assertIn("Refuse the retired general Compose deployment lane", deploy)
        for marker in (
            "compose_deploy_nextcloud_migration",
            "compose_deploy_restic_policy_artifact",
            "compose_deploy_calibre_local_rollback",
            "General legacy Compose deployment is retired",
        ):
            self.assertIn(marker, deploy)

        expected = [
            ("ansible/playbooks/deploy-nextcloud-migration.yml", "role: compose_deploy"),
            ("ansible/playbooks/rollback-compose.yml", "role: compose_rollback"),
            ("ansible/playbooks/rollback-nextcloud-migration.yml", "role: compose_rollback"),
            ("ansible/playbooks/recover-compose.yml", "role: compose_recovery"),
            ("ansible/roles/maintenance/tasks/main.yml", "home-lab-safe-image-prune"),
            ("ansible/roles/maintenance/tasks/main.yml", "compose-image-lock.py prune"),
            ("scripts/compose-artifact.py", '"scripts/compose-image-lock.py"'),
        ]
        for relative, marker in expected:
            self.assertIn(marker, self.text(ROOT / relative), relative)
        recovery = " ".join(self.text(ROOT / "recovery/README.md").split())
        self.assertIn("never point that activator at a Restic staging tree", recovery)


if __name__ == "__main__":
    unittest.main()
