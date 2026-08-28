#!/usr/bin/env python3
"""Negative command-grammar fixtures for fixed Proxmox Tailscale SSH transports."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-plan-transport"
FIREWALL = ROOT / "infrastructure/proxmox-firewall/host/proxmox-firewall-transport"
CAPABILITY = ROOT / "scripts/controller/proxmox-plan-capability.py"


def invoke(path: Path, *args: str, original: str | None = None) -> int:
    environment = {key: value for key, value in os.environ.items() if key != "SSH_ORIGINAL_COMMAND"}
    if original is not None:
        environment["SSH_ORIGINAL_COMMAND"] = original
    return subprocess.run((path, *args), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, env=environment, check=False).returncode


def main() -> None:
    for path in (PLAN, FIREWALL):
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
        assert not path.is_symlink()

    assert invoke(PLAN, "-c", "observe") != 64
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

    plan_source = PLAN.read_text()
    assert "proxmox-observer observe" in plan_source
    assert "SSH_ORIGINAL_COMMAND" in plan_source
    assert "eval" not in plan_source and "sh -c" not in plan_source
    capability_source = CAPABILITY.read_text()
    for required in ("PROXMOX_PLAN_CAPABILITY_CONFIRMED", "os.O_EXCL", "os.O_NOFOLLOW", "ansible-plan ALL=(root) NOPASSWD"):
        assert required in capability_source
    assert "NOPASSWD: ALL" not in capability_source and "authorized_keys\", \"w" not in capability_source
    print("proxmox_access_transports=verified")


if __name__ == "__main__":
    main()
