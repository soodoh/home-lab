#!/usr/bin/env python3
"""Safety fixtures for separate Debian access cleanup planning."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    source = (ROOT / "scripts/controller/debian-access-cleanup.py").read_text()
    contract = (ROOT / "infrastructure/contract/home-lab.yml").read_text()
    for required in (
        "home-lab-debian-access-cleanup-manifest-v1",
        "legacy-marker-removal",
        "conventional-key-removal",
        "openssh-tightening",
        "physical-console-attestation-required",
        "independent-post-key-session-canary-required",
        "os.O_EXCL",
        "os.O_NOFOLLOW",
        "StrictHostKeyChecking=yes",
        "DEBIAN_RECOVERY_ATTESTATION_CONFIRMED",
        "DEBIAN_ACCESS_CLEANUP_CONFIRMED",
        "acquire_transfer_lock",
        "--tags",
        "debian_legacy_marker",
        "debian_conventional_keys",
        "rollback_retained",
        "debian_sshd_tightening",
    ):
        assert required in source, required
    assert all(f'add_parser("{name}")' in source for name in ("plan", "attest-recovery", "apply-legacy-marker", "apply-conventional-keys", "apply-openssh"))
    assert "StrictHostKeyChecking=no" not in source and "shell=True" not in source
    remote = source.split("program = r'''", 1)[1].split("'''", 1)[0]
    for forbidden in ("unlink(", "remove(", 'open(path,"w', "usermod"):
        assert forbidden not in remote, forbidden
    role = (ROOT / "ansible/roles/debian_access_cleanup/tasks/main.yml").read_text()
    playbook = (ROOT / "ansible/playbooks/apply-debian-access-cleanup.yml").read_text()
    assert role.count("ansible.builtin.file:") == 1 and "state: absent" in role
    assert "rescue:" in role and "Restore the exact empty legacy marker" in role
    assert "hosts: docker_host" in playbook and "serial: 1" in playbook
    for required in ("fcntl.flock", "access-rollback", "os.O_NOFOLLOW", "conventional key changed after planning", "operation == \"rollback\""):
        assert required in role, required
    for required in ("systemd-run", "--on-active=120s", "watchdog_active", "/usr/sbin/sshd", "status\": \"committed"):
        assert required in role, required
    for required in (
        "access_cleanup:",
        "remove_keys_before_tightening: true",
        "one_change_class_per_transaction: true",
        "target_pubkey_authentication: false",
        "target_permit_root_login: false",
    ):
        assert required in contract, required
    print("debian_access_cleanup=verified")


if __name__ == "__main__":
    main()
