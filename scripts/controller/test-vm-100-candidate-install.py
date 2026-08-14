#!/usr/bin/env python3
"""Static and behavioral safety checks for candidate-root installation."""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
INSTALL_GUARD = ROOT / "nix/scripts/vm-100-candidate-install-guard.py"
UPDATE_GUARD = ROOT / "nix/scripts/vm-100-candidate-update-guard.py"


def load_guard(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class CandidateInstallTests(unittest.TestCase):
    def setUp(self):
        self.guard = load_guard(INSTALL_GUARD, "vm100_candidate_install_guard")
        self.update_guard = load_guard(UPDATE_GUARD, "vm100_candidate_update_guard")

    def request(self, root, **updates):
        value = {
            "approvedSerial": self.guard.EXPECTED_SERIAL,
            "device": "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2",
            "format": self.guard.FORMAT,
            "mode": "inspect",
            "observedSizeBytes": self.guard.EXPECTED_SIZE,
        }
        value.update(updates)
        path = Path(root) / "request.json"
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        path.chmod(0o600)
        return path

    def test_request_is_exact_and_rejects_known_non_candidate_paths(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(Path, "lstat", side_effect=lambda: type("Info", (), {"st_mode": stat.S_IFREG | 0o600, "st_uid": 0, "st_gid": 0, "st_nlink": 1, "st_size": 256})()):
                self.assertEqual(self.guard.read_request(self.request(root))["mode"], "inspect")
                for path in (
                    "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi0",
                    "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1",
                    "/dev/sdc",
                ):
                    with self.assertRaises(ValueError):
                        self.guard.read_request(self.request(root, device=path))
                with self.assertRaises(ValueError):
                    self.guard.read_request(self.request(root, observedSizeBytes=1))

    def test_observer_requires_empty_whole_disk_with_exact_capacity(self):
        observed = {"type": "disk", "size": self.guard.EXPECTED_SIZE, "serial": "drive-scsi2", "mountpoints": [None], "fstype": None}
        result = type("Result", (), {"stdout": json.dumps({"blockdevices": [observed]}).encode(), "stderr": b""})()
        with patch.object(Path, "is_symlink", return_value=True), patch.object(self.guard.subprocess, "run", return_value=result):
            self.assertEqual(self.guard.observe("/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2")["size"], self.guard.EXPECTED_SIZE)
        for mutation in ({"size": 1}, {"serial": "drive-scsi0"}, {"children": [{}]}, {"fstype": "ext4"}, {"mountpoints": ["/"]}):
            changed = {**observed, **mutation}
            result = type("Result", (), {"stdout": json.dumps({"blockdevices": [changed]}).encode(), "stderr": b""})()
            with patch.object(Path, "is_symlink", return_value=True), patch.object(self.guard.subprocess, "run", return_value=result), self.assertRaises(ValueError):
                self.guard.observe("/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2")

    def test_update_guard_requires_exact_unmounted_disko_layout(self):
        observed = {
            "type": "disk", "size": self.update_guard.SIZE, "serial": self.update_guard.SERIAL, "mountpoints": [], "fstype": None,
            "children": [
                {"type": "part", "partlabel": "disk-vm100-root-bios", "fstype": None, "mountpoints": []},
                {"type": "part", "partlabel": "disk-vm100-root-ESP", "fstype": "vfat", "mountpoints": []},
                {"type": "part", "partlabel": "disk-vm100-root-root", "fstype": "ext4", "mountpoints": []},
            ],
        }
        result = type("Result", (), {"stdout": json.dumps({"blockdevices": [observed]}).encode(), "stderr": b""})()
        with patch.object(Path, "is_symlink", return_value=True), patch.object(self.update_guard.subprocess, "run", return_value=result):
            self.assertEqual(self.update_guard.observe()["serial"], self.update_guard.SERIAL)
        observed["children"][2]["mountpoints"] = ["/"]
        result = type("Result", (), {"stdout": json.dumps({"blockdevices": [observed]}).encode(), "stderr": b""})()
        with patch.object(Path, "is_symlink", return_value=True), patch.object(self.update_guard.subprocess, "run", return_value=result), self.assertRaises(ValueError):
            self.update_guard.observe()

    def test_installer_source_keeps_destructive_gate_and_exact_closure(self):
        source = (ROOT / "nix/flake.nix").read_text()
        for control in (
            "install-reviewed-qualification-candidate",
            "vm-100-candidate-update",
            "vm-100-candidate-update-guard.py",
            "config.system.build.diskoScript",
            "system.switch.enable = lib.mkForce true",
            "./hosts/vm-100/storage.nix",
            "./hosts/vm-100/secrets.nix",
            'networkConfig.DHCP = "ipv4"',
            "--system ${config.system.build.toplevel}",
            "--no-channel-copy",
            "inspection-passed",
            "/mnt/vm-100-candidate",
        ):
            self.assertIn(control, source)
        self.assertNotIn("nixos-install --flake", source)
        self.assertIn("update-reviewed-qualification-candidate", UPDATE_GUARD.read_text())

    def test_disko_layout_is_closed(self):
        source = (ROOT / "nix/hosts/vm-100/disko.nix").read_text()
        for control in ('type = "gpt"', 'type = "EF02"', 'type = "EF00"', 'format = "vfat"', 'format = "ext4"'):
            self.assertIn(control, source)
        self.assertNotIn("/dev/sd", source)

    def test_compose_artifact_mirror_and_docker_qualification_are_closed(self):
        expected = (ROOT / "nix/compose-artifact.sha256").read_text().strip()
        source_hash = subprocess.run(
            ["python3", "scripts/compose-artifact.py", "hash"], cwd=ROOT,
            check=True, text=True, stdout=subprocess.PIPE,
        ).stdout.strip()
        mirror_hash = subprocess.run(
            ["python3", "scripts/compose-artifact.py", "--root", "nix/compose-artifact", "--no-git", "hash"], cwd=ROOT,
            check=True, text=True, stdout=subprocess.PIPE,
        ).stdout.strip()
        self.assertEqual(source_hash, expected)
        self.assertEqual(mirror_hash, expected)
        module = (ROOT / "nix/hosts/vm-100/compose.nix").read_text()
        self.assertIn("virtualisation.docker", module)
        self.assertIn("autoPrune.enable = false", module)
        flake = (ROOT / "nix/flake.nix").read_text()
        self.assertIn("vm-100-compose-qualification", flake)
        self.assertIn("len(services) != 41", flake)
        self.assertIn('"@sha256:" not in image', flake)


if __name__ == "__main__":
    unittest.main()
