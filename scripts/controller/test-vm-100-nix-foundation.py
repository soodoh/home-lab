#!/usr/bin/env python3
"""Structural and evaluated checks for the inert VM 100 NixOS scaffold."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
NIX = ROOT / "nix"
PROJECTION = NIX / "vm-100/projection.json"
FORBIDDEN_SOURCE_PATTERNS = (
    re.compile(r"/dev/disk"),
    re.compile(r"sops\.(?:defaultSopsFile|age\.keyFile|age\.generateKey\s*=\s*true|secrets\.[A-Za-z0-9_-]+)"),
    re.compile(r"(?:services\.docker|virtualisation\.docker|docker-compose|compose\.ya?ml)"),
)


class Vm100NixFoundationTests(unittest.TestCase):
    def nix_eval(self, attribute: str) -> str:
        return subprocess.run(
            ["nix", "eval", f"path:{NIX}#{attribute}", "--json"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def test_projection_and_evaluated_configuration_are_inert(self) -> None:
        projection = json.loads(PROJECTION.read_text(encoding="utf-8"))
        self.assertEqual(projection["deploymentAuthority"], "arch")
        self.assertFalse(projection["nixosActivationEnabled"])
        self.assertEqual(json.loads(self.nix_eval("lib.vm-100-scaffold")), projection)
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.networking.hostName")), "archlinux")
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.system.stateVersion")), "26.05")
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.sops.secrets")), {})
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.sops.templates")), {})
        self.assertFalse(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.system.switch.enable")))

    def test_inputs_are_locked_and_follow_the_single_nixpkgs(self) -> None:
        lock = json.loads((NIX / "flake.lock").read_text(encoding="utf-8"))
        for name in ("disko", "sops-nix"):
            node = lock["nodes"][name]
            self.assertEqual(node["inputs"]["nixpkgs"], ["nixpkgs"])
            self.assertRegex(node["locked"]["rev"], r"^[0-9a-f]{40}$")
            self.assertRegex(node["locked"]["narHash"], r"^sha256-")

    def test_scaffold_has_no_destructive_secret_or_runtime_declaration(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((NIX / "hosts/vm-100").glob("*.nix"))
        )
        for pattern in FORBIDDEN_SOURCE_PATTERNS:
            self.assertIsNone(pattern.search(source), pattern.pattern)
        self.assertNotIn("vm-plan", (NIX / "flake.nix").read_text(encoding="utf-8"))
        self.assertNotIn("vm-apply", (NIX / "flake.nix").read_text(encoding="utf-8"))
        self.assertNotIn("vm-install", (NIX / "flake.nix").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
