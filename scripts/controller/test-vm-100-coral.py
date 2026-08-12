#!/usr/bin/env python3
"""Static and derivation-level checks for the pinned VM 100 Coral module package."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
NIX = ROOT / "nix"
PACKAGE = NIX / "packages/coral-driver/default.nix"
PATCH_NAMES = (
    "0001-linux-6.13-dma-buf-namespace.patch",
    "0002-linux-6.0-remove-no-llseek.patch",
    "0003-linux-7.1-zap-special-vma.patch",
)
PATCH_HASHES = (
    "f630246ed21edd6e8dd0503363657ff90050cfd6e8973f3c307a5cc5aff97c52",
    "140a657b758bbb9ce883c060efca02a44ed87dc3ed85c0712995e0040e7308e8",
    "38e9f1ffa13f339b0e3fc4ce1d55d68cdc3e36602df0591b7c201af2027dee2e",
)
COMMIT = "5815ee3908a46a415aac616ac7b9aedcb98a504c"


def nix_eval(attribute: str) -> object:
    return json.loads(subprocess.run(
        ["nix", "eval", f"path:{NIX}#{attribute}", "--json"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout)


class Vm100CoralTests(unittest.TestCase):
    def test_exact_source_and_patch_identity(self) -> None:
        source = PACKAGE.read_text(encoding="utf-8")
        self.assertIn(f'rev = "{COMMIT}";', source)
        self.assertIn('hash = "sha256-O17+msok1fY5tdX1DvqYVw6plkUDF25i8sqwd6mxYf8=";', source)
        source_root = Path(str(nix_eval("packages.x86_64-linux.vm-100-coral-driver.src")))
        for name, expected_hash in zip(PATCH_NAMES, PATCH_HASHES, strict=True):
            patch = NIX / "packages/coral-driver" / name
            self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), expected_hash)
            self.assertEqual(patch.read_bytes(), (ROOT / "recovery/coral" / name).read_bytes())
            subprocess.run(["patch", "-d", source_root, "-p1", "--dry-run", "--forward"], input=patch.read_bytes(), check=True, capture_output=True)

    def test_derivation_binds_kernel_modules_and_metadata_checks(self) -> None:
        drv_path = str(nix_eval("packages.x86_64-linux.vm-100-coral-driver.drvPath"))
        self.assertRegex(drv_path, r"^/nix/store/[a-z0-9]+-gasket-driver-r236\.5815ee3\.drv$")
        derivation = json.loads(subprocess.run(["nix", "derivation", "show", drv_path], check=True, capture_output=True, text=True).stdout)
        value = next(iter(derivation["derivations"].values()))
        self.assertEqual(value["system"], "x86_64-linux")
        self.assertEqual(value["env"]["pname"], "gasket-driver")
        self.assertEqual(value["env"]["version"], "r236.5815ee3")
        self.assertEqual([Path(path).name.split("-", 1)[1] for path in value["env"]["patches"].split()], list(PATCH_NAMES))
        build = value["env"]["buildPhase"]
        self.assertIn('make -C "', build)
        self.assertIn('"M=$PWD/src" modules', build)
        self.assertNotIn('${makeFlags[@]}', build)
        install = value["env"]["installPhase"]
        for required in ("src/gasket.ko", "src/apex.ko", "modinfo -F vermagic", "modinfo -F srcversion", f"source_commit={COMMIT}"):
            self.assertIn(required, install)

    def test_nixos_configuration_wires_coral_without_activation(self) -> None:
        modules = set(nix_eval("nixosConfigurations.vm-100.config.boot.kernelModules"))
        self.assertTrue({"gasket", "apex"}.issubset(modules))
        self.assertIn("apex", nix_eval("nixosConfigurations.vm-100.config.users.users.docker.extraGroups"))
        rules = str(nix_eval("nixosConfigurations.vm-100.config.services.udev.extraRules"))
        self.assertIn('SUBSYSTEM=="apex", KERNEL=="apex_0", GROUP="apex", MODE="0660"', rules)
        self.assertFalse(nix_eval("nixosConfigurations.vm-100.config.system.switch.enable"))


if __name__ == "__main__":
    unittest.main()
