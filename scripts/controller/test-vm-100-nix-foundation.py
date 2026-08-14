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
    re.compile(r"sops\.age\.generateKey\s*=\s*true"),
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
        secrets = json.loads(self.nix_eval("nixosConfigurations.vm-100.config.sops.secrets"))
        self.assertEqual(list(secrets), ["compose-production-env-canonical"])
        self.assertEqual((secrets["compose-production-env-canonical"]["path"], secrets["compose-production-env-canonical"]["owner"], secrets["compose-production-env-canonical"]["group"], secrets["compose-production-env-canonical"]["mode"]), ("/run/home-lab/compose/production.env.canonical", "root", "root", "0400"))
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.sops.templates")), {})
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.sops.age.keyFile")), "/var/lib/sops-nix/age/keys.txt")
        self.assertFalse(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.sops.age.generateKey")))
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.sops.defaultSopsFormat")), "dotenv")
        self.assertFalse(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.system.switch.enable")))
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.groups.docker.gid")), 1000)
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.uid")), 1000)
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.group")), "docker")
        self.assertEqual(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.extraGroups")), ["input", "render", "uucp", "apex"])
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
        modules = json.loads(self.nix_eval("nixosConfigurations.vm-100.config.boot.kernelModules"))
        self.assertTrue({"uhid", "uinput", "tun", "gasket", "apex"}.issubset(modules))
        initrd_modules = set(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.boot.initrd.availableKernelModules")))
        self.assertTrue({"virtio_pci", "virtio_scsi", "sd_mod"}.issubset(initrd_modules))
        self.assertIn("options amdgpu runpm=0", json.loads(self.nix_eval("nixosConfigurations.vm-100.config.boot.extraModprobeConfig")))
        sysctls = json.loads(self.nix_eval("nixosConfigurations.vm-100.config.boot.kernel.sysctl"))
        self.assertEqual({key: sysctls[key] for key in ("fs.inotify.max_user_instances", "fs.inotify.max_user_watches", "user.max_user_namespaces")}, {"fs.inotify.max_user_instances": 1024, "fs.inotify.max_user_watches": 1048576, "user.max_user_namespaces": 28633})
        self.assertTrue(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.services.qemuGuest.enable")))
        self.assertTrue(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.hardware.graphics.enable")))
        self.assertTrue(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.hardware.bluetooth.enable")))
        rules = json.loads(self.nix_eval("nixosConfigurations.vm-100.config.services.udev.extraRules"))
        for expected in ('KERNEL=="uinput", GROUP="input", MODE="0660"', 'KERNEL=="uhid", GROUP="input", MODE="0660"', 'ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", GROUP="uucp", MODE="0660"'):
            self.assertIn(expected, rules)
        self.assertNotIn("zigbee", rules)
        self.assertNotIn("zwave", rules)
        self.assertIn('SUBSYSTEM=="apex", KERNEL=="apex_0", GROUP="apex", MODE="0660"', rules)
        self.assertIn("apex", json.loads(self.nix_eval("nixosConfigurations.vm-100.config.users.users.docker.extraGroups")))
        coral_drv = json.loads(self.nix_eval("packages.x86_64-linux.vm-100-coral-driver.drvPath"))
        self.assertRegex(coral_drv, r"^/nix/store/[a-z0-9]+-gasket-driver-r236\.5815ee3\.drv$")

    def test_inputs_are_locked_and_follow_the_single_nixpkgs(self) -> None:
        lock = json.loads((NIX / "flake.lock").read_text(encoding="utf-8"))
        for name in ("disko", "sops-nix"):
            node = lock["nodes"][name]
            self.assertEqual(node["inputs"]["nixpkgs"], ["nixpkgs"])
            self.assertRegex(node["locked"]["rev"], r"^[0-9a-f]{40}$")
            self.assertRegex(node["locked"]["narHash"], r"^sha256-")

    def test_scaffold_keeps_disk_and_compose_activation_inert(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((NIX / "hosts/vm-100").glob("*.nix"))
            if path.name != "compose.nix"
        )
        for pattern in FORBIDDEN_SOURCE_PATTERNS:
            self.assertIsNone(pattern.search(source), pattern.pattern)
        compose = (NIX / "hosts/vm-100/compose.nix").read_text(encoding="utf-8")
        self.assertIn("virtualisation.docker", compose)
        self.assertNotIn("docker compose up", compose)
        self.assertNotIn("wantedBy", compose)
        self.assertFalse(json.loads(self.nix_eval("nixosConfigurations.vm-100.config.system.switch.enable")))
        self.assertNotIn("vm-plan", (NIX / "flake.nix").read_text(encoding="utf-8"))
        self.assertNotIn("vm-apply", (NIX / "flake.nix").read_text(encoding="utf-8"))
        self.assertNotIn("vm-install", (NIX / "flake.nix").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
