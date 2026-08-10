#!/usr/bin/env python3
"""Focused exact-recovery plan policy tests."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
GENERATOR = REPOSITORY / "scripts/controller/build-recovery-expectations.js"
POLICY = REPOSITORY / "infrastructure/policy/inspect-plan.py"
PROVIDER_SHAPED_FIXTURE = (
    REPOSITORY / "scripts/controller/fixtures/recovery-provider-shaped.json"
)


class RecoveryPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.expectations_path = self.root / "expectations.json"
        environment = {
            **os.environ,
            "TF_VAR_games_disk_by_id": "/dev/disk/by-id/test-games",
            "TF_VAR_serial_usb_paths": '{"zigbee":"2-4.1","zwave":"2-4.2"}',
        }
        subprocess.run(
            ["node", str(GENERATOR), "--output", str(self.expectations_path)],
            cwd=REPOSITORY,
            env=environment,
            check=True,
        )
        self.expectations = json.loads(self.expectations_path.read_text())
        self.assertEqual(self.expectations_path.stat().st_mode & 0o777, 0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def plan(self, actions: dict[str, list[str]] | None = None) -> dict[str, object]:
        selected = actions or {
            address: ["create"] for address in self.expectations["resources"]
        }
        changes = []
        for address, expectation in self.expectations["resources"].items():
            action = selected[address]
            after = copy.deepcopy(expectation["expected"])
            changes.append(
                {
                    "address": address,
                    "type": expectation["type"],
                    "change": {
                        "actions": action,
                        "before": None if action == ["create"] else copy.deepcopy(after),
                        "after": after,
                        "after_unknown": {},
                    },
                }
            )
        return {"format_version": "1.2", "resource_changes": changes}

    def run_policy(self, plan: dict[str, object], *, mode: str = "recovery") -> subprocess.CompletedProcess[str]:
        plan_path = self.root / "plan.json"
        plan_path.write_text(json.dumps(plan))
        command = ["python3", str(POLICY), str(plan_path), "--mode", mode]
        if mode == "recovery":
            command.extend(["--recovery-expectations", str(self.expectations_path)])
        return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_generator_uses_contract_mapping_names_and_null_device_fields(self) -> None:
        resources = self.expectations["resources"]
        self.assertEqual(
            resources['proxmox_hardware_mapping_pci.device["gpu"]']["expected"]["name"],
            "rx-7900-xtx",
        )
        self.assertEqual(
            resources['proxmox_hardware_mapping_usb.device["zigbee"]']["expected"]["name"],
            "zigbee-cp210x",
        )
        self.assertEqual(
            resources['proxmox_hardware_mapping_usb.device["zigbee"]']["expected"]["map"][0]["path"],
            "2-4.1",
        )
        self.assertEqual(
            resources['proxmox_hardware_mapping_usb.device["zwave"]']["expected"]["map"][0]["path"],
            "2-4.2",
        )
        self.assertIsNone(
            resources['proxmox_hardware_mapping_usb.device["bluetooth"]']["expected"]["map"][0]["path"]
        )
        vm = resources["proxmox_virtual_environment_vm.arch"]["expected"]
        self.assertTrue(all(device["id"] is None for device in vm["hostpci"]))
        self.assertTrue(all(device["host"] is None for device in vm["usb"]))

    def test_accepts_independent_provider_shaped_fixture(self) -> None:
        provider_plan = json.loads(PROVIDER_SHAPED_FIXTURE.read_text())
        result = self.run_policy(provider_plan)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_exact_create_retry_and_noop(self) -> None:
        create = self.run_policy(self.plan())
        self.assertEqual(create.returncode, 0, create.stderr)
        addresses = list(self.expectations["resources"])
        retry_actions = {
            address: (["no-op"] if index % 2 else ["create"])
            for index, address in enumerate(addresses)
        }
        retry = self.run_policy(self.plan(retry_actions))
        self.assertEqual(retry.returncode, 0, retry.stderr)
        noop = self.run_policy(
            self.plan({address: ["no-op"] for address in addresses})
        )
        self.assertEqual(noop.returncode, 0, noop.stderr)
        computed = self.plan()
        computed["resource_changes"][0]["change"]["after_unknown"] = {"provider_computed": True}
        computed_result = self.run_policy(computed)
        self.assertEqual(computed_result.returncode, 0, computed_result.stderr)

    def test_rejects_wrong_mapping_extra_missing_update_and_unknown(self) -> None:
        wrong = self.plan()
        wrong["resource_changes"][1]["change"]["after"]["name"] = "wrong"
        self.assertNotEqual(self.run_policy(wrong).returncode, 0)

        extra = self.plan()
        extra["resource_changes"].append(
            {
                "address": "proxmox_virtual_environment_vm.extra",
                "type": "proxmox_virtual_environment_vm",
                "change": {"actions": ["create"], "before": None, "after": {"vm_id": 999}},
            }
        )
        self.assertNotEqual(self.run_policy(extra).returncode, 0)

        missing = self.plan()
        missing["resource_changes"].pop()
        self.assertNotEqual(self.run_policy(missing).returncode, 0)

        update = self.plan()
        update["resource_changes"][0]["change"]["actions"] = ["update"]
        update["resource_changes"][0]["change"]["before"] = {}
        self.assertNotEqual(self.run_policy(update).returncode, 0)

        unknown = self.plan()
        unknown["resource_changes"][-1]["change"]["after_unknown"] = {"disk": True}
        self.assertNotEqual(self.run_policy(unknown).returncode, 0)

    def test_rejects_partial_expectations_projection(self) -> None:
        partial = copy.deepcopy(self.expectations)
        partial["resources"].pop(next(iter(partial["resources"])))
        self.expectations_path.write_text(json.dumps(partial))
        self.expectations_path.chmod(0o600)
        result = self.run_policy(self.plan())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("complete resource set", result.stderr)

    def test_normal_rejects_all_compute_creates_and_managed_to_raw_reverse(self) -> None:
        create = {
            "resource_changes": [
                {
                    "address": "proxmox_virtual_environment_vm.arch",
                    "type": "proxmox_virtual_environment_vm",
                    "change": {"actions": ["create"], "before": None, "after": {"vm_id": 100}},
                }
            ]
        }
        self.assertNotEqual(self.run_policy(create, mode="normal").returncode, 0)
        for address, resource_type in (
            ("proxmox_virtual_environment_vm.extra", "proxmox_virtual_environment_vm"),
            ("proxmox_virtual_environment_container.extra", "proxmox_virtual_environment_container"),
        ):
            extra_compute = {
                "resource_changes": [
                    {
                        "address": address,
                        "type": resource_type,
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {},
                            "after_unknown": {"vm_id": True},
                        },
                    }
                ]
            }
            self.assertNotEqual(
                self.run_policy(extra_compute, mode="normal").returncode,
                0,
                address,
            )

        reverse = {
            "resource_changes": [
                {
                    "address": 'proxmox_hardware_mapping_pci.device["gpu"]',
                    "type": "proxmox_hardware_mapping_pci",
                    "change": {"actions": ["delete"], "before": {"name": "rx-7900-xtx"}, "after": None},
                },
                {
                    "address": "proxmox_virtual_environment_vm.arch",
                    "type": "proxmox_virtual_environment_vm",
                    "change": {
                        "actions": ["update"],
                        "before": {"hostpci": [{"mapping": "rx-7900-xtx", "id": None}]},
                        "after": {"hostpci": [{"mapping": None, "id": "0000:03:00.0"}]},
                    },
                },
            ]
        }
        self.assertNotEqual(self.run_policy(reverse, mode="normal").returncode, 0)


if __name__ == "__main__":
    unittest.main()
