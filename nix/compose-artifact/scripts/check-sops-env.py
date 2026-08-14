#!/usr/bin/env python3
"""Validate SOPS dotenv ciphertext structure without a decryption identity."""

from argparse import ArgumentParser
import json
from pathlib import Path
import re

KEY_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ENCRYPTED_VALUE_PATTERN = re.compile(
    r"ENC\[AES256_GCM,data:[^,]*,iv:[^,]+,tag:[^,]+,type:[^\]]+\]"
)


def read_manifest(path: Path) -> set[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if any(KEY_PATTERN.fullmatch(line) is None for line in lines):
        raise SystemExit("key manifest contains an invalid variable name")
    if len(lines) != len(set(lines)):
        raise SystemExit("key manifest contains duplicate variable names")
    if lines != sorted(lines):
        raise SystemExit("key manifest is not sorted")
    return set(lines)


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("ciphertext", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("layout", type=Path)
    parser.add_argument("expected_recipients", nargs="+")
    args = parser.parse_args()

    expected_keys = read_manifest(args.manifest)
    observed_keys: set[str] = set()
    metadata: dict[str, str] = {}
    content_line_count = 0

    for line_number, raw_line in enumerate(
        args.ciphertext.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            encrypted_comment = line.removeprefix("#")
            if ENCRYPTED_VALUE_PATTERN.fullmatch(encrypted_comment) is None:
                raise SystemExit(f"unencrypted ciphertext comment at line {line_number}")
            content_line_count += 1
            continue

        key, separator, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not separator or KEY_PATTERN.fullmatch(key) is None:
            raise SystemExit(f"invalid ciphertext assignment at line {line_number}")
        if key.startswith("sops_"):
            if key in metadata:
                raise SystemExit(f"duplicate SOPS metadata key at line {line_number}")
            metadata[key] = value
            continue
        if key in observed_keys:
            raise SystemExit(f"duplicate ciphertext key at line {line_number}")
        if ENCRYPTED_VALUE_PATTERN.fullmatch(value) is None:
            raise SystemExit(f"unencrypted ciphertext value at line {line_number}")
        observed_keys.add(key)
        content_line_count += 1

    if observed_keys != expected_keys:
        raise SystemExit("ciphertext variable-name set differs from the manifest")

    expected_recipients = args.expected_recipients
    if len(expected_recipients) != len(set(expected_recipients)):
        raise SystemExit("expected SOPS recipients contain duplicates")
    required_metadata = {
        "sops_lastmodified",
        "sops_mac",
        "sops_unencrypted_suffix",
        "sops_version",
    }
    for index in range(len(expected_recipients)):
        required_metadata.add(f"sops_age__list_{index}__map_enc")
        required_metadata.add(f"sops_age__list_{index}__map_recipient")
    if set(metadata) != required_metadata:
        raise SystemExit("SOPS metadata keys are missing or unexpected")
    observed_recipients = []
    for index in range(len(expected_recipients)):
        observed_recipients.append(metadata[f"sops_age__list_{index}__map_recipient"])
        encrypted_key = metadata[f"sops_age__list_{index}__map_enc"]
        if not encrypted_key.startswith(
            "-----BEGIN AGE ENCRYPTED FILE-----\\n"
        ) or not encrypted_key.endswith("-----END AGE ENCRYPTED FILE-----\\n"):
            raise SystemExit("SOPS encrypted age data-key metadata is invalid")
    if set(observed_recipients) != set(expected_recipients):
        raise SystemExit("SOPS age recipients differ from the expected recipients")
    if ENCRYPTED_VALUE_PATTERN.fullmatch(metadata["sops_mac"]) is None:
        raise SystemExit("SOPS MAC metadata is missing or invalid")
    if metadata["sops_unencrypted_suffix"] != "_unencrypted":
        raise SystemExit("SOPS unencrypted suffix metadata is unexpected")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", metadata["sops_version"]) is None:
        raise SystemExit("SOPS version metadata is invalid")

    layout = json.loads(args.layout.read_text(encoding="utf-8"))
    if set(layout) != {"version", "source_lines", "final_newline", "blank_lines"}:
        raise SystemExit("dotenv layout keys are missing or unexpected")
    blank_lines = layout["blank_lines"]
    if (
        layout["version"] != 1
        or not isinstance(layout["source_lines"], int)
        or not isinstance(layout["final_newline"], bool)
        or not isinstance(blank_lines, list)
        or any(not isinstance(line, int) for line in blank_lines)
        or blank_lines != sorted(set(blank_lines))
        or any(line < 1 or line > layout["source_lines"] for line in blank_lines)
        or layout["source_lines"] - len(blank_lines) != content_line_count
    ):
        raise SystemExit("dotenv layout metadata is invalid")

    print(
        f"sops_ciphertext_structure=pass variables={len(observed_keys)} "
        f"recipients={len(expected_recipients)} blank_lines={len(blank_lines)}"
    )


if __name__ == "__main__":
    main()
