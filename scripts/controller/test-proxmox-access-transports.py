#!/usr/bin/env python3
"""Source-only assertions for retained Proxmox fixed-command transports."""

from __future__ import annotations

from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
FIREWALL = ROOT / "infrastructure/proxmox-firewall/host/proxmox-firewall-transport"


def check_sources() -> None:
    """Inspect source only; never invoke a valid transport verb."""
    for path in (DEPLOY, FIREWALL):
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
        assert not path.is_symlink()

    deploy_source = DEPLOY.read_text()
    assert "eval" not in deploy_source and "sh -c" not in deploy_source
    assert "SSH_ORIGINAL_COMMAND" in deploy_source
    assert "proxmox-restic-recovery-transport" in deploy_source
    for retired in ("proxmox-ansible-deploy-activator", "stage package", "stage reboot",
                    "stage low-risk", "observe storage-lifecycle"):
        assert retired not in deploy_source

    firewall_source = FIREWALL.read_text()
    assert "eval" not in firewall_source and "sh -c" not in firewall_source
    assert "SSH_ORIGINAL_COMMAND" in firewall_source

    retired_paths = (
        "infrastructure/proxmox-access/host/proxmox-ansible-plan-transport",
        "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator",
        "scripts/controller/proxmox-package-activation.py",
        "scripts/controller/proxmox-reboot-activation.py",
    )
    for raw in retired_paths:
        path = ROOT / raw
        assert not path.exists() and not path.is_symlink(), f"retired source remains: {raw}"


if __name__ == "__main__":
    check_sources()
    print("proxmox_access_transport_sources=verified restic-and-firewall-only")
