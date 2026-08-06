#!/usr/bin/env python3
"""Exercise the real legacy root's retired tombstone and hard confirmation gate."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

REPOSITORY = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPOSITORY / "infrastructure/tofu/proxmox-legacy"
CONTRACT = REPOSITORY / "infrastructure/contract/home-lab.yml"
TEST_CONFIRMATION = "test-only-confirmation"


def replace_once(text: str, pattern: str, replacement: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"expected exactly one test substitution for {pattern}")
    return updated


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        root = temporary / "infrastructure/tofu/proxmox-legacy"
        contract = temporary / "infrastructure/contract/home-lab.yml"
        root.mkdir(parents=True)
        contract.parent.mkdir(parents=True)

        for source in SOURCE_ROOT.glob("*.tf"):
            shutil.copy2(source, root / source.name)
        shutil.copy2(SOURCE_ROOT / ".terraform.lock.hcl", root / ".terraform.lock.hcl")
        (root / ".terraform").symlink_to(SOURCE_ROOT / ".terraform", target_is_directory=True)

        contract_text = replace_once(
            CONTRACT.read_text(),
            r"^(\s*retirement_stage:)\s+\S+\s*$",
            r"\1 retired",
        )
        contract.write_text(contract_text)

        main_tf = root / "main.tf"
        source_main_tf = main_tf.read_text()
        confirmation_block = re.search(
            r'variable "decommission_confirmation" \{(?P<body>.*?)\n\}',
            source_main_tf,
            re.DOTALL,
        )
        if confirmation_block is None or "ephemeral = true" not in confirmation_block.group("body"):
            raise RuntimeError("decommission confirmation must remain an ephemeral input")
        test_digest = hashlib.sha256(TEST_CONFIRMATION.encode()).hexdigest()
        main_tf.write_text(
            replace_once(
                source_main_tf,
                r'(sha256\(var\.decommission_confirmation\) == ")[0-9a-f]{64}("\s*)',
                rf"\g<1>{test_digest}\g<2>",
            )
        )

        tests = root / "tests"
        tests.mkdir()
        (tests / "retired.tftest.hcl").write_text(
            f'''mock_provider "proxmox" {{}}

run "retired_missing_confirmation" {{
  command = plan

  variables {{
    proxmox_endpoint = "https://example.invalid:8006"
  }}

  expect_failures = [var.decommission_confirmation]
}}

run "retired_invalid_confirmation" {{
  command = plan

  variables {{
    proxmox_endpoint         = "https://example.invalid:8006"
    decommission_confirmation = "invalid-test-value"
  }}

  expect_failures = [var.decommission_confirmation]
}}

run "retired_tombstone" {{
  command = plan

  variables {{
    proxmox_endpoint          = "https://example.invalid:8006"
    decommission_confirmation = "{TEST_CONFIRMATION}"
  }}

  assert {{
    condition     = length(proxmox_virtual_environment_container.tailscale_gateway) == 0
    error_message = "retired stage must disable CT 101"
  }}
}}
'''
        )
        subprocess.run(
            ["tofu", f"-chdir={root}", "test", "-filter=tests/retired.tftest.hcl"],
            check=True,
        )

        # OpenTofu's mock provider currently crashes on configuration-driven import.
        # Remove only that test-copy block to exercise the protected/no-secret branch.
        contract.write_text(
            replace_once(
                CONTRACT.read_text(),
                r"^(\s*retirement_stage:)\s+\S+\s*$",
                r"\1 protected",
            )
        )
        main_tf.write_text(
            replace_once(main_tf.read_text(), r"\nimport \{[\s\S]*?\n\}\n$", "\n")
        )
        (tests / "protected.tftest.hcl").write_text(
            '''mock_provider "proxmox" {}

run "protected_none_without_confirmation" {
  command = plan

  variables {
    proxmox_endpoint = "https://example.invalid:8006"
  }

  assert {
    condition     = length(proxmox_virtual_environment_container.tailscale_gateway) == 1
    error_message = "protected steady state must retain CT 101 without confirmation"
  }
}
'''
        )
        subprocess.run(
            ["tofu", f"-chdir={root}", "test", "-filter=tests/protected.tftest.hcl"],
            check=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
