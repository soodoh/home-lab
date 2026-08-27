#!/usr/bin/env python3
from __future__ import annotations

import os
import json
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY / "scripts" / "prepare-omada-provider-fork"
PINNED_COMMIT = "6d81edfd9f160c02eb53f5dc056dde857d8e5f8d"


class OmadaProviderForkTests(unittest.TestCase):
    def test_ignored_vendor_source_is_rejected_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            binaries = root / "bin"
            source.mkdir()
            (source / ".git").mkdir()
            binaries.mkdir()
            marker = root / "go-was-called"

            git = binaries / "git"
            git.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                f"  *'rev-parse HEAD') echo {PINNED_COMMIT} ;;\n"
                "  *'diff --quiet') exit 0 ;;\n"
                "  *'diff --cached --quiet') exit 0 ;;\n"
                "  *'status --porcelain=v1 --untracked-files=all --ignored=matching') echo '!! vendor/' ;;\n"
                "  *) echo \"unexpected git invocation: $*\" >&2; exit 2 ;;\n"
                "esac\n"
            )
            git.chmod(0o755)

            go = binaries / "go"
            go.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
            go.chmod(0o755)

            env = {
                **os.environ,
                "OMADA_PROVIDER_FORK_SOURCE": str(source),
                "PATH": f"{binaries}:/usr/bin:/bin",
            }
            result = subprocess.run(
                [str(SCRIPT)],
                cwd=REPOSITORY,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 65, result.stderr)
            self.assertIn("exact clean checkout", result.stderr)
            self.assertFalse(marker.exists(), "go build ran despite ignored vendor source")

    def test_client_configuration_encrypts_all_sensitive_scalars(self) -> None:
        encrypted = REPOSITORY / "infrastructure/tofu/omada/client-config.sops.json"
        data = json.loads(encrypted.read_text())

        self.assertEqual(len(data["client_aliases"]), 68)
        self.assertEqual(len(data["requested_reservations"]), 1)
        for item in data["client_aliases"]:
            self.assertEqual(set(item), {"mac", "alias"})
            self.assertTrue(all(value.startswith("ENC[AES256_GCM,") for value in item.values()))
        for item in data["requested_reservations"]:
            self.assertEqual(set(item), {"mac", "ip", "name", "enable"})
            self.assertTrue(all(value.startswith("ENC[AES256_GCM,") for value in item.values()))
        authorized = set(re.findall(r"age1[0-9a-z]+", (REPOSITORY / ".sops.yaml").read_text()))
        recipients = {entry["recipient"] for entry in data["sops"]["age"]}
        self.assertEqual(recipients, authorized)

    def test_plaintext_client_associations_are_absent_from_hcl(self) -> None:
        main = (REPOSITORY / "infrastructure/tofu/omada/main.tf").read_text()
        reconcile = (REPOSITORY / "scripts/reconcile-infrastructure").read_text()
        prepare = (REPOSITORY / "scripts/prepare-omada-plan-input").read_text()

        self.assertIsNone(re.search(r'"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}"\s*=\s*"', main))
        self.assertIn("jsondecode(file(var.omada_client_config_path))", main)
        self.assertIn("omada_client_config_path=$repo_root/.local/omada/client-config.json", reconcile)
        self.assertIn("sops --decrypt --output-type json", prepare)
        self.assertIn("mv -f \"$client_config\" .local/omada/client-config.json", prepare)


if __name__ == "__main__":
    unittest.main()
