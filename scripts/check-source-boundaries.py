#!/usr/bin/env python3
"""Refuse committed controller state, plans and private scratch artifacts."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_PREFIXES = (
    ".local/", ".reconcile/", "infrastructure/evidence/", "infrastructure/retirement/",
)
FORBIDDEN_SUFFIXES = (".tfstate", ".tfstate.backup", ".tfplan")


def main() -> None:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    failures: list[str] = []
    for value in result.stdout.split(b"\0"):
        if not value:
            continue
        rendered = Path(value.decode()).as_posix()
        if rendered.startswith(FORBIDDEN_PREFIXES) or rendered.endswith(FORBIDDEN_SUFFIXES):
            failures.append(f"controller artifact: {rendered}")
    if failures:
        raise SystemExit("\n".join(failures))
    print("source_boundaries=verified disposable-controller")


if __name__ == "__main__":
    main()
