#!/usr/bin/env python3
"""Fixtures for the exact Proxmox reboot activation builder."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/controller/proxmox-reboot-activation.py"


def load():
    spec = importlib.util.spec_from_file_location("reboot_activation_fixture", SOURCE)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def write(path: Path, value: dict) -> None:
    path.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()); path.chmod(0o600)


def main() -> None:
    module = load(); commit = "1" * 40; now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    evidence = {"backup": {}, "boot_id": "b2ab9646-6a22-4252-be34-cc875c92d9f9", "current_kernel": "7.0.14-8-pve",
                "evidence_sha256": "4" * 64, "health": {"vm_100": "status: running", "zpool_storage": True}, "host": "proxmox",
                "installed_kernels": ["7.0.14-8-pve", "7.0.14-14-pve"], "observed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reboot_indicated": True, "reboot_required_file": False, "reboot_required_packages": [],
                "target_kernel": "7.0.14-14-pve", "uptime_seconds": 1, "version": 1}
    maintenance = {"actionable": True, "authorized": False,
                   "bindings": {"contract_sha256": "2" * 64, "git_commit": commit, "host_key_fingerprint": module.FINGERPRINT,
                                "inventory_sha256": "3" * 64, "max_observation_age_seconds": 1800},
                   "blockers": ["saved-reviewed-plan-required", "separate-reboot-authorization-required"],
                   "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "evidence": evidence,
                   "evidence_sha256": module.sha(module.canonical(evidence)),
                   "expires_at": (now + dt.timedelta(seconds=1800)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "format": "home-lab-host-maintenance-plan-v1", "host": "proxmox", "kind": "reboot", "version": 1}
    maintenance["plan_sha256"] = module.sha(module.canonical(maintenance))
    backup = {"accepted_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "accepted_by": "explicit-user-selection", "automatic_reboot": False,
              "authorized": False, "commit": commit,
              "evidence": {"age_seconds": 1, "local_service": {"result": "success"}, "pending_records": 0,
                           "proton_copy_records": 1, "proton_service": {"result": "success"}},
              "format": "home-lab-proxmox-reboot-backup-attestation-v1", "host": "proxmox", "maximum_age_hours": 24,
              "scope": {"host_configuration": "git-managed", "pve_vzdump_present": False, "workload_data": "restic-local-and-proton"}}
    access = {"commit": commit, "format": "home-lab-proxmox-access-evidence-v1",
              "proofs": {"console": {"attested": True}, "deploy_transport": {"positive": True},
                         "human_session": {"positive": True}, "plan_observer": {"positive": True}}}
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary); maintenance_path = root / "maintenance.json"; backup_path = root / "backup.json"; access_path = root / "access.json"
        write(maintenance_path, maintenance); write(backup_path, backup); write(access_path, access)
        module.clean_pushed_commit = lambda: commit
        native_file_sha = module.file_sha
        module.file_sha = lambda path: "2" * 64 if path.name == "home-lab.yml" else "3" * 64
        module.OUTPUT = root / "output"
        target, digest = module.build(maintenance_path, backup_path, access_path)
        value = json.loads(target.read_bytes())
        assert target.name == f"{digest}.json" and value["expected"]["target_kernel"] == "7.0.14-14-pve"
        assert value["automatic_reboot"] is False and value["backup_attestation_sha256"] == module.sha(backup_path.read_bytes())
        module.file_sha = native_file_sha
    source = SOURCE.read_text()
    for required in ("PROXMOX_REBOOT_PREPARE_CONFIRMED", "PROXMOX_REBOOT_APPLY_CONFIRMED", "verify reboot", "automatic_reboot"):
        assert required in source
    print("proxmox_reboot_activation=verified")


if __name__ == "__main__": main()
