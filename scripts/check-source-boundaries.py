#!/usr/bin/env python3
"""Refuse committed controller state and retired compatibility dependencies."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_PREFIXES = (
    ".local/",
    ".reconcile/",
    "infrastructure/evidence/",
    "infrastructure/retirement/",
)
FORBIDDEN_SUFFIXES = (".tfstate", ".tfstate.backup", ".tfplan")
FORBIDDEN_REFERENCES = (
    "infrastructure/evidence/",
    "infrastructure/contract/home-lab.yml",
    "ansible/group_vars/docker_host.yml",
    ".local/nextcloud-recovery-qualification.tfstate",
    ".local/authentik/",
    ".local/live-inventory/",
    ".local/omada/",
    ".local/provider-ca/",
    ".reconcile/proxmox-firewall/",
)
TEXT_SUFFIXES = {
    "", ".cfg", ".env", ".hcl", ".json", ".md", ".py", ".sh", ".tf",
    ".ts", ".txt", ".yaml", ".yml",
}


def tracked_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [Path(value.decode()) for value in result.stdout.split(b"\0") if value]


def main() -> None:
    failures: list[str] = []
    this_file = Path(__file__).resolve().relative_to(ROOT)
    for relative in tracked_paths():
        rendered = relative.as_posix()
        path = ROOT / relative
        if not path.exists():
            continue
        if rendered.startswith(FORBIDDEN_PREFIXES) or rendered.endswith(FORBIDDEN_SUFFIXES):
            failures.append(f"committed runner artifact: {rendered}")
            continue
        if relative == this_file or path.suffix not in TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for reference in FORBIDDEN_REFERENCES:
            if reference in source:
                failures.append(f"retired source dependency: {rendered}: {reference}")
    if failures:
        raise SystemExit("\n".join(failures))
    print("source_boundaries=verified disposable-controller")


if __name__ == "__main__":
    main()
