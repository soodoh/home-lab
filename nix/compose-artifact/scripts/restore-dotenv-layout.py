#!/usr/bin/env python3
"""Restore non-secret blank-line layout after SOPS dotenv decryption."""

from argparse import ArgumentParser
import json
from pathlib import Path


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("canonical", type=Path)
    parser.add_argument("layout", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    layout = json.loads(args.layout.read_text(encoding="utf-8"))
    if set(layout) != {"version", "source_lines", "final_newline", "blank_lines"}:
        raise SystemExit("dotenv layout keys are missing or unexpected")
    if layout["version"] != 1:
        raise SystemExit("dotenv layout version is unsupported")
    if not isinstance(layout["source_lines"], int) or layout["source_lines"] < 0:
        raise SystemExit("dotenv source line count is invalid")
    if not isinstance(layout["final_newline"], bool):
        raise SystemExit("dotenv final-newline flag is invalid")
    blank_lines = layout["blank_lines"]
    if not isinstance(blank_lines, list) or any(
        not isinstance(line, int) for line in blank_lines
    ):
        raise SystemExit("dotenv blank-line positions are invalid")
    if blank_lines != sorted(set(blank_lines)) or any(
        line < 1 or line > layout["source_lines"] for line in blank_lines
    ):
        raise SystemExit("dotenv blank-line positions are invalid")

    canonical_text = args.canonical.read_text(encoding="utf-8")
    canonical_lines = canonical_text.splitlines()
    expected_canonical_lines = layout["source_lines"] - len(blank_lines)
    if len(canonical_lines) != expected_canonical_lines:
        raise SystemExit("canonical dotenv line count differs from the layout")

    blank_line_set = set(blank_lines)
    canonical_iterator = iter(canonical_lines)
    restored_lines = [
        "" if line_number in blank_line_set else next(canonical_iterator)
        for line_number in range(1, layout["source_lines"] + 1)
    ]
    restored_text = "\n".join(restored_lines)
    if layout["final_newline"]:
        restored_text += "\n"

    if args.output.exists():
        raise SystemExit("refusing to overwrite an existing restored dotenv file")
    args.output.write_text(restored_text, encoding="utf-8")
    print(
        f"dotenv_layout_restore=pass source_lines={layout['source_lines']} "
        f"blank_lines={len(blank_lines)}"
    )


if __name__ == "__main__":
    main()
