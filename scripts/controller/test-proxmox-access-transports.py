#!/usr/bin/env python3
"""Negative command-grammar fixtures for fixed Proxmox Tailscale SSH transports."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-plan-transport"
DEPLOY = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
DEPLOY_ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
FIREWALL = ROOT / "infrastructure/proxmox-firewall/host/proxmox-firewall-transport"
CAPABILITY = ROOT / "scripts/controller/proxmox-plan-capability.py"
DEPLOY_CAPABILITY = ROOT / "scripts/controller/proxmox-deploy-capability.py"
DEPLOY_UPGRADE = ROOT / "scripts/controller/proxmox-deploy-upgrade.py"
PRIVATE_PREPARER_UPGRADE = ROOT / "scripts/physical-console-install-proxmox-private-preparer-upgrade"
PACKAGE_ACTIVATION = ROOT / "scripts/controller/proxmox-package-activation.py"
REBOOT_ACTIVATION = ROOT / "scripts/controller/proxmox-reboot-activation.py"


def invoke(path: Path, *args: str, original: str | None = None) -> int:
    environment = {key: value for key, value in os.environ.items() if key != "SSH_ORIGINAL_COMMAND"}
    if original is not None:
        environment["SSH_ORIGINAL_COMMAND"] = original
    return subprocess.run((path, *args), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, env=environment, check=False).returncode


def main() -> None:
    for path in (PLAN, DEPLOY, DEPLOY_ACTIVATOR, FIREWALL):
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
        assert not path.is_symlink()

    assert invoke(PLAN, "-c", "observe") != 64
    assert invoke(PLAN, "-c", "observe-package") != 64
    for args, original in (
        ((), None), (("-c", "observe;id"), None), (("-c", "/bin/sh"), None),
        (("-c", "observe"), "observe"), (("-c", "observe", "extra"), None),
    ):
        assert invoke(PLAN, *args, original=original) == 64

    for command in ("inspect", "begin", "status", "commit", "rollback"):
        assert invoke(FIREWALL, "-c", command) != 64
        assert invoke(FIREWALL, "-c", "/usr/local/libexec/home-lab/proxmox-firewall-transport", original=command) != 64
    for command in ("authorize", "inspect;id", "begin extra", "/bin/sh", ""):
        assert invoke(FIREWALL, "-c", command) == 64
    assert invoke(FIREWALL, "-c", "inspect", original="inspect") == 64

    digest = "a" * 64
    for command in (f"stage lifecycle-marker {digest}", f"inspect lifecycle-marker {digest}", f"apply lifecycle-marker {digest}"):
        assert invoke(DEPLOY, "-c", command) != 64
    for command in (f"stage package {digest}", f"inspect package {digest}", f"prepare package {digest}", f"apply package {digest}", f"recover package {digest}"):
        assert invoke(DEPLOY, "-c", command) != 64
    for command in (f"stage reboot {digest}", f"inspect reboot {digest}", f"prepare reboot {digest}", f"apply reboot {digest}", f"verify reboot {digest}"):
        assert invoke(DEPLOY, "-c", command) != 64
    for args, original in (
        ((), None), (("-c", "apply lifecycle-marker a;id"), None),
        (("-c", f"apply lifecycle-marker {digest} extra"), None),
        (("-c", "/bin/sh"), None), (("-c", f"inspect lifecycle-marker {digest}"), "inspect"),
    ):
        assert invoke(DEPLOY, *args, original=original) == 64
    deploy_source = DEPLOY.read_text()
    activator_source = DEPLOY_ACTIVATOR.read_text()
    assert "eval" not in deploy_source and "sh -c" not in deploy_source
    assert "sudo -n -- /usr/local/libexec/home-lab/proxmox-ansible-deploy-activator" in deploy_source
    for required in ("os.O_NOFOLLOW", "os.O_EXCL", "origin/main", "apply-lifecycle-marker", "prepare-package", "apply-package", "recover-package", "prepare-reboot", "apply-reboot", "verify-reboot", "--download-only", "--no-download", "automatic_reboot", "acquire_boot_conflict_locks", '"shutdown", "100", "--timeout", "120"', '"onboot: 1"', '"status"] = "vm-stopped"'):
        assert required in activator_source
    assert "shell=True" not in activator_source and "NOPASSWD: ALL" not in activator_source
    assert "apt-get update" not in activator_source and "reboot(" not in activator_source
    package_source = PACKAGE_ACTIVATION.read_text()
    for required in ("PROXMOX_PACKAGE_PREPARE_CONFIRMED", "PROXMOX_PACKAGE_APPLY_CONFIRMED", "PROXMOX_PACKAGE_RECOVERY_CONFIRMED", "os.O_EXCL", "os.O_NOFOLLOW", "automatic_reboot", "access_evidence_sha256", "console_attested"):
        assert required in package_source
    reboot_source = REBOOT_ACTIVATION.read_text()
    for required in ("PROXMOX_REBOOT_PREPARE_CONFIRMED", "PROXMOX_REBOOT_APPLY_CONFIRMED", "backup_attestation_sha256", "access_evidence_sha256", "automatic_reboot", "verify reboot"):
        assert required in reboot_source

    plan_source = PLAN.read_text()
    assert "proxmox-observer observe" in plan_source
    assert "proxmox-package-candidate-observer observe proxmox" in plan_source
    assert "SSH_ORIGINAL_COMMAND" in plan_source
    assert "eval" not in plan_source and "sh -c" not in plan_source
    capability_source = CAPABILITY.read_text()
    for required in ("PROXMOX_PLAN_CAPABILITY_CONFIRMED", "os.O_EXCL", "os.O_NOFOLLOW", "ansible-plan ALL=(root) NOPASSWD"):
        assert required in capability_source
    assert "NOPASSWD: ALL" not in capability_source and "authorized_keys\", \"w" not in capability_source
    deploy_capability_source = DEPLOY_CAPABILITY.read_text()
    for required in ("PROXMOX_DEPLOY_CAPABILITY_CONFIRMED", "os.O_EXCL", "os.O_NOFOLLOW", "saved-action-plans-only"):
        assert required in deploy_capability_source
    assert "authorized_keys\", \"w" not in deploy_capability_source
    upgrade_source = DEPLOY_UPGRADE.read_text()
    for required in ("PROXMOX_DEPLOY_UPGRADE_CONFIRMED", "after_sha256", "saved-actions-and-read-only-compatibility-only", "proxmox-observer", "proxmox-private-preparer", "proxmox-firewall-transaction", "os.O_EXCL", "os.O_NOFOLLOW"):
        assert required in upgrade_source
    preparer_upgrade_source = PRIVATE_PREPARER_UPGRADE.read_text()
    for required in ("physical /dev/ttyN console required", "proxmox-private-preparer", "protectedAccess", "protectedHardware", "private-preparer.before", "os.O_EXCL", "os.O_NOFOLLOW"):
        assert required in preparer_upgrade_source
    assert "proxmox-activator session" not in preparer_upgrade_source
    print("proxmox_access_transports=verified")


if __name__ == "__main__":
    main()
