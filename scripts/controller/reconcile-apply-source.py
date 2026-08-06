#!/usr/bin/env python3
"""Require special infrastructure applies to use a valid committed revision."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence


class ApplySourceError(ValueError):
    """Raised when the current checkout cannot identify an exact revision."""


Git = Callable[[Sequence[str]], str]


def run_git(arguments: Sequence[str]) -> str:
    result = subprocess.run(
        ["git", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def validate_apply_source(environment: Mapping[str, str], git: Git = run_git) -> None:
    del environment
    current_commit = git(("rev-parse", "HEAD"))
    if re.fullmatch(r"[0-9a-f]{40}", current_commit) is None:
        raise ApplySourceError("current commit identity is invalid")


def main() -> int:
    try:
        validate_apply_source(os.environ)
        return 0
    except (ApplySourceError, subprocess.CalledProcessError) as error:
        print(f"Lifecycle apply source validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
