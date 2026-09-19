#!/usr/bin/env python3
"""Source-bound safety checks for current recovery-bundle controller staging."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = ROOT / "ansible/playbooks/build-current-restic-recovery-bundles.yml"
EXAMPLE = ROOT / "recovery/current-restic-bundle-build.example.yml"


def main() -> None:
    source = PLAYBOOK.read_text()
    example = EXAMPLE.read_text()
    assert "hosts: docker-host" in source
    assert "gather_facts: false" in source
    assert "any_errors_fatal: true" in source
    assert source.count("build-two-current-encrypted-restic-recovery-bundles") >= 2
    assert "restic_recovery_bundle_host_workspace is not defined" in source
    assert "restic_recovery_bundle_cleanup_unit is not defined" in source
    assert "restic_recovery_bundle_reviewed_commit" in source
    assert "/usr/bin/git" in source, "controller commit check is required"
    assert "status, --porcelain" in source
    assert "restic_recovery_bundle_metadata_sha256" in source
    assert "restic_recovery_bundle_output_root" in source
    assert "not ansible_check_mode" in source

    for protected_input in (
        "prepare-restic-recovery-bundle-metadata",
        "build-current-restic-recovery-bundles",
        "build-restic-recovery-bundle",
        "restore-critical-backup",
        "production.sops.env",
    ):
        assert protected_input in source

    for unit in (
        "home-lab-restic-daily-local.service",
        "home-lab-restic-daily-proton.service",
        "home-lab-restic-maintenance-local.service",
        "home-lab-restic-maintenance-proton.service",
    ):
        assert unit in source
    for guarded_path in (
        "/var/lib/home-lab-restic/interruption.json",
        "/var/lib/iac-ansible-production.lock",
        "/var/lib/home-lab/reconciliation/apply.lock",
        "/var/lib/home-lab/reconciliation/operation.lock",
    ):
        assert guarded_path in source

    assert "ansible.builtin.tempfile:" in source
    assert "/usr/bin/systemd-run" in source
    assert "--on-active=30m" in source
    assert "--one-file-system" in source
    assert "Disarm transient host-workspace cleanup" in source
    assert "--pristine" in source
    assert "exec-env" in source
    assert "SOPS_AGE_KEY_FILE" in source
    assert "no_log: true" in source
    assert "ansible.builtin.shell:" not in source
    assert "--decrypt" not in source
    assert "amazon.aws" not in source and "aws_s3" not in source

    for fetched in (
        "bundle-a.age",
        "bundle-a-result.json",
        "bundle-b.age",
        "bundle-b-result.json",
    ):
        assert fetched in source
    assert source.count("ansible.builtin.fetch:") == 1
    assert "validate_checksum: true" in source
    assert "flat: true" in source
    assert "mode: \"0700\"" in source
    assert "state: absent" in source
    assert "restic_recovery_bundle_host_workspace" in source
    assert "Remove partial controller output root" in source
    assert "always:" in source and "rescue:" in source

    for key in (
        "restic_recovery_bundle_build_confirmed",
        "restic_recovery_bundle_build_confirmation",
        "restic_recovery_bundle_reviewed_commit",
        "restic_recovery_bundle_metadata_path",
        "restic_recovery_bundle_metadata_sha256",
        "restic_recovery_bundle_observation_path",
        "restic_recovery_bundle_observation_sha256",
        "restic_recovery_bundle_output_root",
    ):
        assert example.count(f"{key}:") == 1
    assert "PASSWORD" not in example and "SECRET" not in example and "SOPS_AGE_KEY" not in example

    print("current_restic_recovery_controller=pass")


if __name__ == "__main__":
    main()
