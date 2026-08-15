#!/usr/bin/env python3
"""Static and behavioral safety checks for candidate-root installation."""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
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
        value = {"approvedSerial": self.guard.EXPECTED_SERIAL, "device": "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2", "format": self.guard.FORMAT, "mode": "inspect", "observedSizeBytes": self.guard.EXPECTED_SIZE}
        with patch.object(self.guard, "read_canonical", return_value=value):
            self.assertEqual(self.guard.read_request(Path("/unused"))["mode"], "inspect")
        for device in ("/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi0", "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1", "/dev/sdc"):
            with patch.object(self.guard, "read_canonical", return_value={**value, "device": device}), self.assertRaises(ValueError):
                self.guard.read_request(Path("/unused"))
        with patch.object(self.guard, "read_canonical", return_value={**value, "observedSizeBytes": 1}), self.assertRaises(ValueError):
            self.guard.read_request(Path("/unused"))

    def test_inspection_handoff_rejects_install_even_with_legacy_confirmation(self):
        request = {"mode": "install"}
        handoff = {"mode": "inspect"}
        with patch.dict(os.environ, {"VM100_CANDIDATE_INSTALL_CONFIRMED": "install-reviewed-qualification-candidate"}), self.assertRaises(ValueError):
            self.guard.require_inspection_mode(request, handoff)
        self.guard.require_inspection_mode({"mode": "inspect"}, handoff)
        self.assertNotIn("VM100_CANDIDATE_INSTALL_CONFIRMED", INSTALL_GUARD.read_text())
        with self.assertRaises(ValueError):
            self.guard.require_inspection_mode({"mode": "inspect"}, {"mode": "install"})

    def test_guard_protected_reader_pins_leaf_and_rejects_swap_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = self.request(root)
            real_fstat = self.guard.os.fstat
            def root_metadata(descriptor):
                value = real_fstat(descriptor)
                return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0, st_nlink=value.st_nlink, st_size=value.st_size, st_dev=value.st_dev, st_ino=value.st_ino, st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns)
            with patch.object(self.guard.os, "fstat", side_effect=root_metadata):
                self.assertEqual(self.guard.read_canonical(path, {"approvedSerial", "device", "format", "mode", "observedSizeBytes"}, "request")["mode"], "inspect")
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                self.guard.read_canonical(link, {"approvedSerial", "device", "format", "mode", "observedSizeBytes"}, "request")
            replacement = root / "replacement.json"
            replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600)
            real_read = self.guard.os.read
            swapped = False
            def racing_read(descriptor, size):
                nonlocal swapped
                if not swapped:
                    os.replace(replacement, path)
                    swapped = True
                return real_read(descriptor, size)
            with patch.object(self.guard.os, "fstat", side_effect=root_metadata), patch.object(self.guard.os, "read", side_effect=racing_read), self.assertRaises(ValueError):
                self.guard.read_canonical(path, {"approvedSerial", "device", "format", "mode", "observedSizeBytes"}, "request")

    def test_observer_requires_blank_unmounted_unaliased_unopened_whole_disk(self):
        source = INSTALL_GUARD.read_text()
        for control in (
            '"--bytes", "--json"', '"wipefs"', '"findmnt"', '"fuser"',
            'Path(resolved).name / "holders"', 'resolved == games_resolved',
            'observed.get("children")', 'EXPECTED_SIZE = 137438953472',
            'first != second', 'PROTECTED_FORMAT', 'HANDOFF_FORMAT', 'resolvedDevice',
            'run_json("lsblk", ["--bytes", "--json", "--output", "PATH,TYPE,SIZE,SERIAL,MOUNTPOINTS,FSTYPE", resolved])',
            'run_json("wipefs", ["--json", "--output", "DEVICE,OFFSET,TYPE,UUID,LABEL", resolved])',
        ):
            self.assertIn(control, source)

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
        flat = [{key: value for key, value in observed.items() if key != "children"}, *observed["children"]]
        result = type("Result", (), {"stdout": json.dumps({"blockdevices": flat}).encode(), "stderr": b""})()
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
            "--protected-disk-input",
            "--inspection-handoff",
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

    def test_candidate_bootloader_matches_protected_seabios_firmware(self):
        flake = (ROOT / "nix/flake.nix").read_text()
        exact_disk = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2"
        self.assertIn(f'homeLab.vm100.rootDiskDevice = lib.mkDefault "{exact_disk}"', flake)
        self.assertIn("boot.loader.grub.efiSupport = lib.mkForce false", flake)
        self.assertIn("biosBootModule", flake)
        mirrored_boots = subprocess.run(
            ["nix", "eval", "--json", "path:./nix#nixosConfigurations.vm-100-candidate.config.boot.loader.grub.mirroredBoots"],
            cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE,
        ).stdout
        candidate_efi = subprocess.run(
            ["nix", "eval", "--json", "path:./nix#nixosConfigurations.vm-100-candidate.config.boot.loader.grub.efiSupport"],
            cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE,
        ).stdout
        boots = json.loads(mirrored_boots)
        self.assertEqual(len(boots), 1)
        self.assertEqual(boots[0]["devices"], [exact_disk])
        self.assertFalse(json.loads(candidate_efi))

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
        self.assertIn("len(services) != 41", module)
        self.assertIn('\"@sha256:\" not in image', module)


if __name__ == "__main__":
    unittest.main()
