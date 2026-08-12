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
    re.compile(r"/dev/disk/by-id"),
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
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.groups.docker.gid")), 1000)
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.uid")), 1000)
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.group")), "docker")
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.extraGroups")), ["input", "render", "uucp"])
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.hashedPassword")), "!")
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.openssh.authorizedKeys.keys")), [])
        self.assertTrue(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.services.openssh.enable")))
        self.assertFalse(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.services.openssh.openFirewall")))
        self.assertFalse(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.services.openssh.settings.PasswordAuthentication")))
        self.assertFalse(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.services.openssh.settings.KbdInteractiveAuthentication")))
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.services.openssh.settings.PermitRootLogin")), "no")
        self.assertNotIn("docker", [user for rule in json.loads(self.nix_eval("nixosConfigurations.vm-100.config.security.sudo.extraRules")) for user in rule["users"]])
        self.assertTrue(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.allowNoPasswordLogin")))
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.root.hashedPassword")), "!")
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.root.openssh.authorizedKeys.keys")), [])
        self.assertRegex(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.shell")), r"^/nix/store/[a-z0-9]+-bash-interactive-")
        users = json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users"))
        self.assertNotIn("nix-plan", users)
        self.assertNotIn("nix-copy", users)
        self.assertNotIn("nix-apply", users)
        network = json.loads(self.nix_eval('nixosConfigurations.vm-100.config.systemd.network.networks."20-vm-100".networkConfig'))
        self.assertEqual(network, {"DHCP": False, "DNS": ["1.1.1.1"], "IPv6AcceptRA": False, "LinkLocalAddressing": "no"})
        self.assertEqual(json.loads(self.nix_eval('nixosConfigurations.vm-100.config.systemd.network.networks."20-vm-100".matchConfig')), {"MACAddress": "BC:24:11:89:19:5A", "Name": "ens18"})
        self.assertEqual(json.loads(self.nix_eval('nixosConfigurations.vm-100.config.systemd.network.networks."20-vm-100".address')), ["192.168.0.100/24"])
        self.assertEqual(json.loads(self.nix_eval('nixosConfigurations.vm-100.config.systemd.network.networks."20-vm-100".routes')), [{"Destination": "0.0.0.0/0", "Gateway": "192.168.0.1"}])
        games = json.loads(self.nix_eval('nixosConfigurations.vm-100.config.fileSystems."/mnt/games"'))
        self.assertEqual((games["device"], games["fsType"], games["options"], games["autoFormat"]), ("/dev/disk/by-uuid/31602ce7-0054-498a-9f24-f51ca491e7b3", "ext4", ["noatime"], False))
        shared = json.loads(self.nix_eval('nixosConfigurations.vm-100.config.fileSystems."/mnt/storage"'))
        self.assertEqual((shared["device"], shared["fsType"], shared["options"], shared["autoFormat"]), ("192.168.0.123:/storage/docker", "nfs4", ["defaults"], False))

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
