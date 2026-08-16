#!/usr/bin/env python3
"""Unit tests for the guarded Proxmox VFIO recovery helper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "nix/proxmox/vfio-recover.py"
SPEC = importlib.util.spec_from_file_location("vfio_recover", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load VFIO recovery module")
VFIO = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VFIO
SPEC.loader.exec_module(VFIO)


class FakeBackend:
    def __init__(self) -> None:
        self.members = ("0000:03:00.0",)
        self.identities = {
            "0000:03:00.0": ("1002", "744c"),
        }
        self.drivers = {bdf: "vfio-pci" for bdf in self.members}
        self.node_exists = True
        self.operations: list[tuple[str, str]] = []
        self.fail_binds: dict[str, int] = {}

    def group_members(self, group: int) -> tuple[str, ...]:
        return self.members if group == 14 else ()

    def identity(self, bdf: str) -> tuple[str | None, str | None]:
        return self.identities.get(bdf, (None, None))

    def driver(self, bdf: str) -> str | None:
        return self.drivers.get(bdf)

    def device_node_exists(self, group: int) -> bool:
        return group == 14 and self.node_exists

    def unbind(self, bdf: str) -> None:
        self.operations.append(("unbind", bdf))
        self.drivers[bdf] = None

    def bind(self, bdf: str) -> None:
        self.operations.append(("bind", bdf))
        failures = self.fail_binds.get(bdf, 0)
        if failures:
            self.fail_binds[bdf] = failures - 1
            raise OSError("injected bind failure")
        self.drivers[bdf] = "vfio-pci"


POLICY = VFIO.Policy(
    vmid=100,
    iommu_group=14,
    confirmation="recover-vm-100-vfio-group-14",
    lock_path=Path("/run/lock/home-lab-vfio-recovery.lock"),
    devices=(
        VFIO.DevicePolicy(bdf="0000:03:00.0", vendor="1002", device="744c"),
    ),
)


def stopped(_: int) -> str:
    return "stopped"


def no_users(_: int) -> tuple[str, ...]:
    return ()


class VfioRecoveryTests(unittest.TestCase):
    def test_ready_observation_is_read_only(self) -> None:
        backend = FakeBackend()
        result = VFIO.inspect(POLICY, backend, stopped, no_users)
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["reasons"], [])
        self.assertEqual(backend.operations, [])

    def test_running_vm_blocks_recovery(self) -> None:
        backend = FakeBackend()
        result = VFIO.inspect(POLICY, backend, lambda _: "running", no_users)
        self.assertEqual(result["state"], "blocked")
        self.assertIn("VM 100 must be stopped", result["reasons"][0])
        with self.assertRaisesRegex(VFIO.RecoveryError, "prerequisites are blocked"):
            VFIO.perform_recovery(POLICY, backend, POLICY.confirmation, lambda _: "running", no_users)
        self.assertEqual(backend.operations, [])

    def test_identity_group_and_user_mismatches_block(self) -> None:
        backend = FakeBackend()
        backend.identities["0000:03:00.0"] = ("1002", "ffff")
        backend.members = (*backend.members, "0000:04:00.0")
        result = VFIO.inspect(POLICY, backend, stopped, lambda _: ("4321",))
        self.assertEqual(result["state"], "blocked")
        self.assertTrue(any("group membership" in reason for reason in result["reasons"]))
        self.assertTrue(any("PCI identity mismatch" in reason for reason in result["reasons"]))
        self.assertTrue(any("open by a process" in reason for reason in result["reasons"]))

    def test_exact_confirmation_and_operation_order(self) -> None:
        backend = FakeBackend()
        with self.assertRaisesRegex(VFIO.RecoveryError, "confirmation"):
            VFIO.perform_recovery(POLICY, backend, "wrong", stopped, no_users)
        result = VFIO.perform_recovery(POLICY, backend, POLICY.confirmation, stopped, no_users)
        self.assertTrue(result["recovered"])
        self.assertEqual(backend.operations, [
            ("unbind", "0000:03:00.0"),
            ("bind", "0000:03:00.0"),
        ])

    def test_failure_attempts_full_rebind_rollback(self) -> None:
        backend = FakeBackend()
        backend.fail_binds["0000:03:00.0"] = 1
        with self.assertRaisesRegex(VFIO.RecoveryError, "injected bind failure"):
            VFIO.perform_recovery(POLICY, backend, POLICY.confirmation, stopped, no_users)
        self.assertEqual(backend.drivers, {
            "0000:03:00.0": "vfio-pci",
        })

    def test_policy_loader_rejects_extra_fields(self) -> None:
        document = {
            "confirmation": POLICY.confirmation,
            "devices": [
                {"bdf": device.bdf, "device": device.device, "vendor": device.vendor}
                for device in POLICY.devices
            ],
            "iommuGroup": POLICY.iommu_group,
            "lockPath": str(POLICY.lock_path),
            "vmid": POLICY.vmid,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(VFIO.load_policy(path), POLICY)
            document["unexpected"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(VFIO.RecoveryError, "unexpected fields"):
                VFIO.load_policy(path)


if __name__ == "__main__":
    unittest.main()
