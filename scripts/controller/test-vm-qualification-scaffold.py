#!/usr/bin/env python3
"""Static safety checks for the inactive VM 100 qualification root."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOFU = ROOT / "infrastructure/tofu/proxmox-vm-qualification"
MAIN = TOFU / "main.tf"
VERSIONS = TOFU / "versions.tf"


class VmQualificationScaffoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.main = MAIN.read_text(encoding="utf-8")
        self.versions = VERSIONS.read_text(encoding="utf-8")

    def test_root_is_inactive_and_state_is_isolated(self) -> None:
        self.assertRegex(self.main, r'variable "enable_qualification"\s*\{[^}]*default\s*=\s*false')
        self.assertIn('count = var.enable_qualification ? 1 : 0', self.main)
        self.assertIn('key          = "home-lab/proxmox-vm-qualification/tofu.tfstate"', self.versions)
        self.assertNotIn('home-lab/proxmox/tofu.tfstate', self.versions)
        self.assertIn('VM100-NixOS-Qualification-Arch-', self.main)
        self.assertIn('content_type       = "iso"', self.main)
        self.assertIn('.qcow2.img"', self.main)
        self.assertIn('file_id      = proxmox_download_file.arch_cloud_image[0].id', self.main)
        self.assertNotIn('import_from  = proxmox_download_file.arch_cloud_image[0].id', self.main)
        self.assertIn('agent    = true', self.main)
        self.assertIn('username = "root"', self.main)
        self.assertIn('name    = local.node', self.main)
        self.assertIn('address = "proxmox"', self.main)
        self.assertNotIn('address = "192.168.0.123"', self.main)
        existing = (ROOT / "infrastructure/tofu/proxmox/qualification.tf").read_text(encoding="utf-8")
        self.assertNotIn('VM100-NixOS-Qualification-Arch-', existing)

    def test_disposable_identity_cannot_overlap_production(self) -> None:
        self.assertRegex(self.main, r'vm_id\s*=\s*9900')
        self.assertRegex(self.main, r'name\s*=\s*"vm-100-nixos-qualification"')
        self.assertNotRegex(self.main, r'vm_id\s*=\s*100(?:\D|$)')
        legacy = (ROOT / "infrastructure/tofu/proxmox/qualification.tf").read_text(encoding="utf-8")
        legacy_variables = (ROOT / "infrastructure/tofu/proxmox/variables.tf").read_text(encoding="utf-8")
        self.assertIn('vm_id      = var.qualification_vm_id', legacy)
        self.assertIn('default = 9899', legacy_variables)
        self.assertNotIn('default = 9900', legacy_variables)
        self.assertIn('on_boot       = false', self.main)
        self.assertIn('started       = false', self.main)
        self.assertIn('protection    = false', self.main)
        self.assertIn('address = "dhcp"', self.main)
        self.assertNotIn('192.168.0.100', self.main)

    def test_qualification_envelope_and_disk_identities_are_exact(self) -> None:
        self.assertIn('machine       = "q35"', self.main)
        self.assertIn('cores = 8', self.main)
        self.assertIn('dedicated = 16384', self.main)
        expected = {
            "scsi0": ("QUAL-SOURCE-32G", "32"),
            "scsi1": ("QUAL-GAMES-32G", "32"),
            "scsi2": ("QUAL-NIXOS-128G", "128"),
        }
        blocks = re.findall(r'disk\s*\{(.*?)\n\s*\}', self.main, re.DOTALL)
        observed = {}
        for block in blocks:
            interface = re.search(r'interface\s*=\s*"([^"]+)"', block)
            serial = re.search(r'serial\s*=\s*"([^"]+)"', block)
            size = re.search(r'size\s*=\s*(\d+)', block)
            if interface and serial and size:
                observed[interface.group(1)] = (serial.group(1), size.group(1))
        self.assertEqual(observed, expected)
        self.assertEqual(len({serial for serial, _ in observed.values()}), 3)
        self.assertIn('boot_order    = ["scsi0"]', self.main)

    def test_no_production_hardware_or_mutation_primitive_is_declared(self) -> None:
        for forbidden in (
            "hostpci", "usb {", "games_disk_by_id", "serial_usb_paths",
            "proxmox_virtual_environment_vm.arch", "prevent_destroy = true",
        ):
            self.assertNotIn(forbidden, self.main)
        self.assertIn('stop_on_destroy                      = true', self.main)
        self.assertIn('purge_on_destroy                     = true', self.main)
        self.assertIn('delete_unreferenced_disks_on_destroy = true', self.main)


if __name__ == "__main__":
    unittest.main()
