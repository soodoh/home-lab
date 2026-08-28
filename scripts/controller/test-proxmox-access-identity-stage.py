#!/usr/bin/env python3
"""Structural and policy tests for inert Proxmox access identity staging."""

from __future__ import annotations

from datetime import datetime, timezone
import runpy
from pathlib import Path

import json

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/controller/proxmox-access-identity-stage.py"


def absent_observation() -> dict:
    targets = ("ansible-plan", "ansible-deploy")
    return {
        "accounts": [{"name": name, "exists": False} for name in targets],
        "paths": {
            **{f"/home/{name}/{suffix}": False for name in targets for suffix in (".ssh/authorized_keys", ".ssh/authorized_keys2")},
            **{f"/etc/sudoers.d/{name}": False for name in targets},
        },
        "locks": [],
    }


def rejected(validate, value: dict, reason: str) -> None:
    try:
        validate(value)
    except SystemExit as error:
        assert reason in str(error), (reason, error)
    else:
        raise AssertionError(f"unsafe stage observation accepted: {reason}")


def main() -> None:
    module = runpy.run_path(str(SCRIPT), run_name="access_identity_stage_test")
    validate = module["validate_absent"]
    build = module["build_plan"]
    observation = absent_observation()
    validate(observation)
    plan = build(observation, "a" * 40, datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert plan["authorized"] is False
    assert [action["account"] for action in plan["actions"]] == ["ansible-plan", "ansible-deploy"]
    assert all(action["shell"] == "/usr/sbin/nologin" and action["groups"] == [] for action in plan["actions"])
    assert all(action["authorized_keys"] == "absent" and action["sudo"] == "absent" for action in plan["actions"])

    changed = absent_observation(); changed["locks"] = ["/var/lib/home-lab/reconciliation/apply.lock"]; rejected(validate, changed, "active host lock")
    changed = absent_observation(); changed["accounts"][0] = {"name": "ansible-plan", "exists": True}; rejected(validate, changed, "both targets to be absent")
    changed = absent_observation(); changed["paths"]["/etc/sudoers.d/ansible-deploy"] = True; rejected(validate, changed, "key and sudo paths")

    source = SCRIPT.read_text()
    for required in (
        '"/usr/sbin/nologin"', 'StrictHostKeyChecking=yes', 'UpdateHostKeys=no',
        'PROXMOX_ACCESS_IDENTITY_STAGE_CONFIRMED', 'os.O_EXCL', 'os.O_NOFOLLOW',
        '[[ ! -e "/home/$name/.ssh/authorized_keys"', 'sudo": "absent"',
    ):
        assert required in source, required
    for prohibited in ("NOPASSWD: ALL", "shell: /bin/bash"):
        assert prohibited not in source, prohibited

    projection = json.loads((ROOT / "nix/proxmox/projection.json").read_text())
    accounts = {account["name"]: account for account in projection["accounts"]["service"]}
    assert accounts["ansible-plan"]["shell"] == "/usr/local/libexec/home-lab/proxmox-ansible-plan-transport"
    assert accounts["ansible-deploy"]["shell"] == "/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport"
    for name in ("ansible-plan", "ansible-deploy"):
        assert accounts[name]["groups"] == [] and accounts[name]["passwordLock"] is True
    contract_source = (ROOT / "infrastructure/contract/home-lab.yml").read_text()
    assert contract_source.count("state: absent") >= 3
    assert "/etc/sudoers.d/ansible-plan" in contract_source and "/etc/sudoers.d/ansible-deploy" in contract_source
    print("proxmox_access_identity_stage=verified")


if __name__ == "__main__":
    main()
