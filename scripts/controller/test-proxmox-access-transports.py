#!/usr/bin/env python3
"""Source-only assertions for the retained Proxmox firewall transport."""

from __future__ import annotations

from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[2]
FIREWALL = ROOT / "infrastructure/proxmox-firewall/host/proxmox-firewall-transport"


def check_sources() -> None:
    """Inspect source only; never invoke a valid transport verb."""
    assert stat.S_IMODE(FIREWALL.stat().st_mode) == 0o755
    assert not FIREWALL.is_symlink()

    firewall_source = FIREWALL.read_text()
    assert "eval" not in firewall_source and "sh -c" not in firewall_source
    assert "SSH_ORIGINAL_COMMAND" in firewall_source

    retired_paths = (
        "infrastructure/proxmox-access/host/proxmox-ansible-plan-transport",
        "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator",
        "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport",
        "infrastructure/proxmox-access/host/proxmox-restic-recovery-transport.py",
        "scripts/controller/proxmox-package-activation.py",
        "scripts/controller/proxmox-reboot-activation.py",
    )
    for raw in retired_paths:
        path = ROOT / raw
        assert not path.exists() and not path.is_symlink(), f"retired source remains: {raw}"


if __name__ == "__main__":
    check_sources()
    print("proxmox_access_transport_sources=verified firewall-only")
