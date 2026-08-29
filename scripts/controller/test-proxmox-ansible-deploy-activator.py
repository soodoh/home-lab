#!/usr/bin/env python3
"""Adversarial fixtures for the fixed Proxmox saved-plan activator."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"


def load() -> dict:
    source = SOURCE.read_text()
    prefix, separator, _ = source.partition("\ntry:\n    main()")
    assert separator
    namespace = {"__name__": "fixture"}
    exec(compile(prefix, str(SOURCE), "exec"), namespace)
    return namespace


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main() -> None:
    module = load()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    commit = "1" * 40
    plan = {
        "authorized": False,
        "commit": commit,
        "contract_sha256": "2" * 64,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + dt.timedelta(seconds=1800)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "format": "home-lab-lifecycle-marker-plan-v1",
        "host": "proxmox",
        "host_key_fingerprint": module["FINGERPRINT"],
        "inventory_sha256": "3" * 64,
        "marker": {
            "after": {"source_commit": commit, "state": "production", "updated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "version": 1},
            "before": {"exists": False},
            "path": str(module["MARKER"]),
        },
    }
    digest = hashlib.sha256(canonical(plan)).hexdigest()
    assert module["validate_plan"](plan, digest) == plan["marker"]["after"]

    malformed = json.loads(json.dumps(plan))
    malformed["marker"]["path"] = "/tmp/lifecycle-state.json"
    malformed_digest = hashlib.sha256(canonical(malformed)).hexdigest()
    try:
        module["validate_plan"](malformed, malformed_digest)
        raise AssertionError("alternate marker path was accepted")
    except ValueError:
        pass

    proposal = {
        "host": "proxmox",
        "holds": [],
        "change_counts": {"install": 0, "upgrade": 1, "downgrade": 0, "remove": 0},
        "changes": [{"action": "upgrade", "candidate_version": "2", "name": "example-package", "origin": "Example [amd64]", "previous_version": "1", "security": False}],
        "installed_inventory_sha256": "4" * 64,
        "metadata_mtime_epoch": 1,
        "metadata_newest_path": "/var/lib/apt/lists/example",
        "proposal_sha256": "5" * 64,
        "solver": {"command": "apt-get-simulate", "returncode": 0, "stdout_sha256": "6" * 64, "stderr_sha256": "7" * 64},
    }
    package = {
        "access_evidence_sha256": "9" * 64, "authorized": False, "automatic_reboot": False, "commit": commit,
        "console_attested": True,
        "contract_sha256": "2" * 64, "inventory_sha256": "3" * 64,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + dt.timedelta(seconds=1800)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "format": "home-lab-proxmox-package-activation-v1", "host_key_fingerprint": module["FINGERPRINT"],
        "maintenance_plan_sha256": "8" * 64, "proposal": proposal,
    }
    package_digest = hashlib.sha256(canonical(package)).hexdigest()
    assert module["validate_package_plan"](package, package_digest) == proposal
    unsafe_package = json.loads(json.dumps(package)); unsafe_package["proposal"]["change_counts"]["remove"] = 1
    try:
        module["validate_package_plan"](unsafe_package, hashlib.sha256(canonical(unsafe_package)).hexdigest())
        raise AssertionError("package removal was accepted")
    except ValueError:
        pass

    with tempfile.TemporaryDirectory() as temporary:
        parent = Path(temporary)
        parent.chmod(0o700)
        marker = parent / "lifecycle-state.json"
        module["MARKER"] = marker
        native_os = module["os"]

        class RootParentOs:
            def __getattr__(self, name):
                return getattr(native_os, name)

            def lstat(self, path):
                info = native_os.lstat(path)
                candidate = Path(path)
                if candidate == parent or candidate.parent == parent:
                    values = list(info)
                    values[4] = 0
                    values[5] = 0
                    return os.stat_result(values)
                return info

            def chown(self, path, uid, gid):
                if Path(path).parent == parent and uid == 0 and gid == 0:
                    return None
                return native_os.chown(path, uid, gid)

        module["os"] = RootParentOs()
        assert module["install_marker"](plan["marker"]["after"]) == "applied"
        info = marker.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert marker.read_bytes() == canonical(plan["marker"]["after"])
        assert module["install_marker"](plan["marker"]["after"]) == "already-applied"
        marker.write_text("different\n")
        try:
            module["install_marker"](plan["marker"]["after"])
            raise AssertionError("existing marker drift was overwritten")
        except ValueError:
            pass
        marker.unlink()
        marker.symlink_to(parent / "elsewhere")
        try:
            module["install_marker"](plan["marker"]["after"])
            raise AssertionError("marker symlink was followed")
        except ValueError:
            pass

    source = SOURCE.read_text()
    for forbidden in ("shell=True", "os.system(", "eval(", "NOPASSWD: ALL"):
        assert forbidden not in source
    print("proxmox_ansible_deploy_activator=verified")


if __name__ == "__main__":
    main()
