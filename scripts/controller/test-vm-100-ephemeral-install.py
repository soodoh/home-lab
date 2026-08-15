#!/usr/bin/env python3
"""Hostile contract tests for the production ephemeral candidate installer."""

import importlib.machinery
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/controller/run-vm-100-ephemeral-install.py"


def load_runner():
    loader = importlib.machinery.SourceFileLoader("vm100_ephemeral_install", str(RUNNER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def authorization(module):
    sha = "a" * 64
    return {
        "candidateToplevel": "/nix/store/" + "a" * 32 + "-nixos-system-archlinux-26.05.test",
        "confirmation": module.CONFIRMATION,
        "device": module.DEVICE,
        "diskoScript": "/nix/store/" + "b" * 32 + "-disko",
        "format": module.FORMAT,
        "hostAttestationSha256": sha,
        "mode": "install",
        "nixosInstall": "/nix/store/" + "c" * 32 + "-nixos-install/bin/nixos-install",
        "productionInspectionEvidenceSha256": sha,
        "qualifiedColdBootEvidenceSha256": sha,
        "qualifiedCommit": "d" * 40,
        "qualifiedInstallEvidenceSha256": sha,
        "serial": module.SERIAL,
        "sizeBytes": module.SIZE,
        "transportCommit": "e" * 40,
        "transportManifestSha256": sha,
        "transportQualificationEvidenceSha256": sha,
        "vmId": 100,
    }


class ProductionInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load_runner()

    def test_authorization_is_exact_and_production_scsi2_only(self):
        value = authorization(self.runner)
        self.assertEqual(self.runner.validate_authorization(value), value)
        for key, replacement in (
            ("vmId", 9900), ("device", "/dev/sda"), ("serial", "drive-scsi2"),
            ("sizeBytes", self.runner.SIZE - 1), ("confirmation", "install"), ("mode", "inspect"),
        ):
            changed = dict(value); changed[key] = replacement
            with self.assertRaises(ValueError):
                self.runner.validate_authorization(changed)
        changed = dict(value); changed["extra"] = True
        with self.assertRaises(ValueError):
            self.runner.validate_authorization(changed)

    def test_host_attestation_requires_running_vmid_100_source_boot(self):
        value = authorization(self.runner)
        host = {
            "bios": "seabios", "bootOrder": "scsi0;net0", "candidateSerial": self.runner.SERIAL,
            "candidateSizeBytes": self.runner.SIZE, "collectedAt": "2026-08-15T00:00:00Z",
            "format": self.runner.HOST_FORMAT, "machine": "q35", "productUuid": "11111111-2222-3333-4444-555555555555",
            "pveConfigSha256": "a" * 64, "result": "passed", "status": "running",
            "transportCommit": value["transportCommit"], "vmId": 100,
        }
        self.runner.validate_host(host, value, host["productUuid"])
        for key, replacement in (("bootOrder", "scsi2;scsi0"), ("status", "stopped"), ("vmId", 9900), ("productUuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")):
            changed = dict(host); changed[key] = replacement
            with self.assertRaises(ValueError):
                self.runner.validate_host(changed, value, host["productUuid"])

    def test_installed_observation_requires_exact_partition_set_and_no_mounts(self):
        devices = [
            {"type": "disk", "size": self.runner.SIZE, "serial": self.runner.SERIAL, "mountpoints": []},
            {"partlabel": "disk-vm100-root-bios", "mountpoints": []},
            {"partlabel": "disk-vm100-root-ESP", "mountpoints": []},
            {"partlabel": "disk-vm100-root-root", "mountpoints": []},
        ]
        with patch.object(self.runner.common, "json_command", return_value={"blockdevices": devices}):
            self.assertEqual(self.runner.installed_observation()["serial"], self.runner.SERIAL)
        mounted = [dict(item) for item in devices]; mounted[-1]["mountpoints"] = ["/mnt/vm-100-candidate"]
        with patch.object(self.runner.common, "json_command", return_value={"blockdevices": mounted}):
            with self.assertRaises(ValueError):
                self.runner.installed_observation()

    def test_schemas_are_strict_and_runner_preserves_boot_and_docker(self):
        for name in ("production-install-authorization", "production-install-host-attestation", "production-install-evidence", "production-install-cleanup"):
            schema = json.loads((ROOT / f"infrastructure/vm-100/{name}.schema.json").read_text())
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
        source = RUNNER.read_text()
        for required in ("install-production-vm-100-scsi2-reviewed", "docker_inventory() != docker_before", "common.boot_id() != before_boot", '"--net"', '"--recursive"', '"require-sigs"', "validate_live_qualification", "bootstrapStorePath']}/bin"):
            self.assertIn(required, source)
        for forbidden in ("qm stop", "qm start", "qm reboot", "docker stop", "systemctl stop docker"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
