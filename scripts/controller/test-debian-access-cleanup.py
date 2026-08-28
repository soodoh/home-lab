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
    ):
        assert required in source, required
    assert 'add_parser("plan")' in source and 'add_parser("attest-recovery")' in source
    assert "StrictHostKeyChecking=no" not in source and "shell=True" not in source
    remote = source.split("program = r'''", 1)[1].split("'''", 1)[0]
    for forbidden in ("unlink(", "remove(", 'open(path,"w', "usermod", "sshd_config"):
        assert forbidden not in remote, forbidden
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
