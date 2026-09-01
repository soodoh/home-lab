#!/usr/bin/env python3
"""Unit tests for guarded Proxmox helper upgrades."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
import tempfile
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("proxmox_deploy_upgrade", ROOT / "scripts/controller/proxmox-deploy-upgrade.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DeployUpgradeTests(unittest.TestCase):
    def test_source_hashes_are_derived_from_exact_bytes(self) -> None:
        contents = {"/helper/a": b"a", "/helper/b": b"b"}
        with mock.patch.object(MODULE, "source_bytes", return_value=contents):
            self.assertEqual(MODULE.source_hashes(), {path: MODULE.sha(raw) for path, raw in contents.items()})

    def test_apply_requires_separate_exact_confirmation(self) -> None:
        helper = "/usr/local/libexec/home-lab/proxmox-observer"; before_hash = "1" * 64; after_hash = "2" * 64
        before = {"helpers": {helper: {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "symlink": False, "nlink": 1, "sha256": before_hash}}}
        expires = (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat().replace("+00:00", "Z")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); contract = root / "contract"; inventory = root / "inventory"; contract.write_bytes(b"contract"); inventory.write_bytes(b"inventory")
            plan = {"format": "home-lab-proxmox-deploy-upgrade-v1", "commit": "a" * 40,
                    "contract_sha256": MODULE.sha(contract.read_bytes()), "inventory_sha256": MODULE.sha(inventory.read_bytes()),
                    "host_key_fingerprint": MODULE.FINGERPRINT,
                    "expires_at": expires, "before": before, "after_sha256": {helper: after_hash}}
            plan_raw = MODULE.canonical(plan); plan_digest = MODULE.sha(plan_raw); plan_path = root / f"{plan_digest}.json"; plan_path.write_bytes(plan_raw); plan_path.chmod(0o600)
            authorization = {"format": "home-lab-proxmox-deploy-upgrade-authorization-v1", "plan_sha256": plan_digest,
                             "commit": plan["commit"], "authorized_at": datetime.now(timezone.utc).isoformat()}
            auth_raw = MODULE.canonical(authorization); auth_digest = MODULE.sha(auth_raw); auth_path = root / f"authorized-{auth_digest}.json"; auth_path.write_bytes(auth_raw); auth_path.chmod(0o600)
            def hashes(path: Path) -> str:
                return MODULE.sha(contract.read_bytes()) if path.name == "home-lab.yml" else MODULE.sha(inventory.read_bytes())
            with mock.patch.object(MODULE, "clean_pushed_commit", return_value=plan["commit"]), mock.patch.object(MODULE, "file_sha", side_effect=hashes), \
                 mock.patch.object(MODULE, "source_hashes", return_value={helper: after_hash}), mock.patch.object(MODULE, "observe", return_value=before), \
                 mock.patch.object(MODULE, "source_bytes", return_value={helper: b"after"}), mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(SystemExit) as raised:
                    MODULE.apply_upgrade(plan_path, auth_path)
            self.assertIn(f"apply-proxmox-deploy-upgrade-{plan_digest}-{auth_digest}", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
