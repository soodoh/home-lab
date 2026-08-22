#!/usr/bin/env python3
"""Adversarial regression tests for exact VM 100 cutover policy modes."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "infrastructure/policy/inspect-plan.py"
FIXTURES = ROOT / "infrastructure/policy/fixtures"
SPEC = importlib.util.spec_from_file_location("inspect_plan", POLICY_PATH)
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class VmCutoverPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.forward = json.loads((FIXTURES / "vm-cutover-forward-safe.json").read_text())
        self.expected_games = "/dev/disk/by-id/PROTECTED-GAMES-DISK"

    def assert_cutover_rejected(self, plan: dict[str, object], message: str | None = None) -> None:
        failure = POLICY.vm_cutover_failure(plan, "vm-cutover-forward", self.expected_games, True)
        self.assertIsNotNone(failure)
        if message is not None:
            self.assertIn(message, failure)

    def mutate_both(self, callback) -> dict[str, object]:
        plan = copy.deepcopy(self.forward)
        change = plan["resource_changes"][0]["change"]
        callback(change["before"])
        callback(change["after"])
        return plan

    def test_safe_forward_and_reverse_with_separate_scsi3_attestation(self) -> None:
        self.assertIsNone(POLICY.vm_cutover_failure(self.forward, "vm-cutover-forward", self.expected_games, True))
        reverse = json.loads((FIXTURES / "vm-cutover-reverse-safe.json").read_text())
        self.assertIsNone(POLICY.vm_cutover_failure(reverse, "vm-cutover-reverse", self.expected_games, True))
        self.assertEqual(POLICY.VM_CUTOVER_BOOT_ORDERS["vm-cutover-forward"], (["scsi0", "net0"], ["scsi3", "scsi0", "net0"]))
        self.assertNotIn("scsi2", POLICY.VM_CUTOVER_BOOT_ORDERS["vm-cutover-forward"][1])

    def test_cutover_is_disabled_without_external_scsi3_attestation(self) -> None:
        failure = POLICY.vm_cutover_failure(self.forward, "vm-cutover-forward", self.expected_games)
        self.assertIn("externally managed scsi3", failure)

    def test_rejects_state_move_empty_read_import_and_noop_drift(self) -> None:
        for label, mutate in (
            ("move", lambda p: p["resource_changes"][1].update(previous_address="terraform_data.previous")),
            ("empty", lambda p: p["resource_changes"][1]["change"].update(actions=[])),
            ("read", lambda p: p["resource_changes"][1]["change"].update(actions=["read"])),
            ("import", lambda p: p["resource_changes"][1]["change"].update(importing={"id":"x"})),
            ("drift", lambda p: p["resource_changes"][1]["change"]["after"].update(input="changed")),
        ):
            with self.subTest(label=label):
                plan = copy.deepcopy(self.forward)
                mutate(plan)
                self.assert_cutover_rejected(plan)

    def test_rejects_alternate_plan_mutation_channels(self) -> None:
        for channel in ("action_invocations", "deferred_changes", "resource_drift"):
            with self.subTest(channel=channel):
                plan = copy.deepcopy(self.forward)
                plan[channel] = [{"unexpected":"mutation"}]
                self.assert_cutover_rejected(plan, channel)

    def test_rejects_incomplete_or_changed_protected_identity(self) -> None:
        mutations = {
            "acpi": lambda v: v.update(acpi=False),
            "bios": lambda v: v.update(bios="ovmf"),
            "machine": lambda v: v.update(machine="i440fx"),
            "migrate": lambda v: v.update(migrate=True),
            "numa": lambda v: v.update(numa=True),
            "template": lambda v: v.update(template=True),
            "root": lambda v: v["disk"][0].update(size=551),
            "games": lambda v: v["disk"][1].update(size=3727),
            "games_path": lambda v: v["disk"][1].update(path_in_datastore="/dev/sdb"),
            "candidate": lambda v: v["disk"][2].update(backup=False),
            "pci": lambda v: v["hostpci"][1].update(rombar=False),
            "usb": lambda v: v["usb"][2].update(usb3=False),
            "lifecycle": lambda v: v.update(on_boot=False),
            "cpu": lambda v: v["cpu"][0].update(cores=23),
            "memory": lambda v: v["memory"][0].update(dedicated=32768),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                self.assert_cutover_rejected(self.mutate_both(mutation))

        alternate_games = self.mutate_both(
            lambda value: value["disk"][1].update(path_in_datastore="/dev/disk/by-id/OTHER-GAMES-DISK")
        )
        self.assert_cutover_rejected(alternate_games, "exact protected games disk")

    def test_rejects_unknown_cutover_value(self) -> None:
        plan = copy.deepcopy(self.forward)
        plan["resource_changes"][0]["change"]["after_unknown"] = {"smbios":[{"uuid":True}]}
        self.assert_cutover_rejected(plan, "known")

    def test_normal_allowlist_cannot_bypass_boot_protection(self) -> None:
        plan = json.loads((FIXTURES / "boot-order-change.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "plan.json"
            allow_path = Path(directory) / "allow.txt"
            plan_path.write_text(json.dumps(plan))
            allow_path.write_text("proxmox_virtual_environment_vm.debian\n")
            result = subprocess.run(
                [str(POLICY_PATH), str(plan_path), "--mode", "normal", "--allow-change-file", str(allow_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("protected field change", result.stderr)

    def test_normal_rejects_unknown_boot_order(self) -> None:
        plan = json.loads((FIXTURES / "boot-order-change.json").read_text())
        plan["resource_changes"][0]["change"]["after_unknown"] = {"boot_order":True}
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "plan.json"
            plan_path.write_text(json.dumps(plan))
            result = subprocess.run(
                [str(POLICY_PATH), str(plan_path), "--mode", "normal"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be known", result.stderr)


if __name__ == "__main__":
    unittest.main()
