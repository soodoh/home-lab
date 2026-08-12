#!/usr/bin/env python3
"""Validate VM 100 SOPS recipient separation and runtime materialization metadata."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NIX = ROOT / "nix"
SOPS_CONFIG = ROOT / ".sops.yaml"
ROOT_CIPHERTEXT = ROOT / "secrets/production.sops.env"
NIX_CIPHERTEXT = NIX / "secrets/production.sops.env"
EXPECTED_ROLES = ("arch rollback", "NixOS runtime", "independent recovery")
ARCH_RECIPIENT = "age1vvzm5pczjum52v5alall8euucjen9q4v9xa5g0xmswhna5vare9qwv9rq6"
NIXOS_RUNTIME_RECIPIENT = "age12jcxxrv3hej0rjgyu0rvstaxuxm32uuc46l6pfucaw9sprvetgesjz67nf"
INDEPENDENT_RECOVERY_RECIPIENT = "age1ddk0qtwjclc2za5afrz5pl4j5kley02rqv2vh0s07c27a8t5u58sph58qm"
EXPECTED_RECIPIENTS = (ARCH_RECIPIENT, NIXOS_RUNTIME_RECIPIENT, INDEPENDENT_RECOVERY_RECIPIENT)


def recipients(path: Path) -> list[str]:
    found = re.findall(r"age1[0-9a-z]+", path.read_text(encoding="utf-8"))
    return list(dict.fromkeys(found))


class Vm100SopsTests(unittest.TestCase):
    def nix_eval(self, attribute: str) -> str:
        return subprocess.run(
            ["nix", "eval", f"path:{NIX}#{attribute}", "--raw"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def nix_eval_json(self, attribute: str):
        return __import__("json").loads(subprocess.run(
            ["nix", "eval", f"path:{NIX}#{attribute}", "--json"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout)

    def test_three_distinct_recipient_roles_are_bound(self) -> None:
        configured = recipients(SOPS_CONFIG)
        encrypted = recipients(ROOT_CIPHERTEXT)
        self.assertEqual(EXPECTED_ROLES, ("arch rollback", "NixOS runtime", "independent recovery"))
        self.assertEqual(tuple(configured), EXPECTED_RECIPIENTS)
        self.assertEqual(len(set(EXPECTED_RECIPIENTS)), len(EXPECTED_ROLES))
        self.assertEqual(set(encrypted), set(EXPECTED_RECIPIENTS))

    def test_ciphertext_structure_manifest_layout_and_recipients(self) -> None:
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/check-sops-env.py"),
                str(ROOT_CIPHERTEXT),
                str(ROOT / "secrets/production.env.keys"),
                str(ROOT / "secrets/production.env.layout.json"),
                *EXPECTED_RECIPIENTS,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "sops_ciphertext_structure=pass variables=90 recipients=3 blank_lines=20")

    def test_nix_ciphertext_is_exact_and_secret_free_metadata_is_packaged(self) -> None:
        self.assertEqual(NIX_CIPHERTEXT.read_bytes(), ROOT_CIPHERTEXT.read_bytes())
        self.assertEqual(
            (NIX / "secrets/production.env.keys").read_bytes(),
            (ROOT / "secrets/production.env.keys").read_bytes(),
        )
        self.assertEqual(
            (NIX / "secrets/production.env.layout.json").read_bytes(),
            (ROOT / "secrets/production.env.layout.json").read_bytes(),
        )

    def test_runtime_secret_is_ephemeral_root_only_and_uses_external_identity(self) -> None:
        prefix = "nixosConfigurations.vm-100.config.sops"
        self.assertEqual(self.nix_eval(f"{prefix}.age.keyFile"), "/var/lib/sops-nix/age/keys.txt")
        self.assertTrue(self.nix_eval_json(f"{prefix}.useSystemdActivation"))
        secret = f'{prefix}.secrets."compose-production-env-canonical"'
        self.assertEqual(self.nix_eval(f"{secret}.path"), "/run/home-lab/compose/production.env.canonical")
        self.assertEqual(self.nix_eval(f"{secret}.owner"), "root")
        self.assertEqual(self.nix_eval(f"{secret}.group"), "root")
        self.assertEqual(self.nix_eval(f"{secret}.mode"), "0400")
        self.assertEqual(self.nix_eval_json(f"{secret}.restartUnits"), ["restore-compose-production-env.service"])
        service = "nixosConfigurations.vm-100.config.systemd.services.restore-compose-production-env"
        self.assertEqual(self.nix_eval(f"{service}.serviceConfig.Type"), "oneshot")
        self.assertEqual(self.nix_eval_json(f"{service}.requiredBy"), ["docker.service"])
        self.assertEqual(self.nix_eval_json(f"{service}.requires"), ["sops-install-secrets.service"])
        self.assertIn("sops-install-secrets.service", self.nix_eval(f"{service}.script"))
        self.assertIn("restore-dotenv-layout.py", self.nix_eval(f"{service}.script"))


if __name__ == "__main__":
    unittest.main()
