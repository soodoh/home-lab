#!/usr/bin/env python3
"""Compare a protected desired WebUI login to qBittorrent's pinned PBKDF2 config.

Input is one JSON document on stdin (never argv); output is only in_sync or
out_of_sync. The hash format and parameters are unchanged between qBittorrent 5.2.3 and
5.3.0's src/base/utils/password.cpp. Version 5.3 moves Preferences/WebUI/*
to WebUI/* (src/app/upgrade.cpp). Unknown or ambiguous layouts fail closed.
"""

import base64
import binascii
import configparser
import hashlib
import hmac
import json
import sys


def matches(conf: str, username: str, password: str) -> bool:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(conf)
    layouts = [
        ("Preferences", r"WebUI\Username", r"WebUI\Password_PBKDF2"),
        ("WebUI", "Username", "Password_PBKDF2"),
    ]
    present = [
        layout for layout in layouts
        if any(parser.has_option(layout[0], key) for key in layout[1:])
    ]
    if len(present) != 1:
        raise ValueError("missing or ambiguous qBittorrent WebUI configuration")
    section, user_key, password_key = present[0]
    try:
        existing_user = parser.get(section, user_key)
        stored = parser.get(section, password_key)
    except configparser.Error as exc:
        raise ValueError("missing qBittorrent WebUI configuration") from exc
    if stored.startswith('"') and stored.endswith('"'):
        stored = stored[1:-1]
    if not (stored.startswith("@ByteArray(") and stored.endswith(")")):
        raise ValueError("unrecognized qBittorrent password encoding")
    parts = stored[len("@ByteArray(") : -1].split(":")
    if len(parts) != 2:
        raise ValueError("unrecognized qBittorrent password hash")
    try:
        salt, digest = (base64.b64decode(part, validate=True) for part in parts)
    except binascii.Error as exc:
        raise ValueError("invalid qBittorrent password hash") from exc
    if len(salt) != 16 or len(digest) != 64:
        raise ValueError("unrecognized qBittorrent password hash lengths")
    actual = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 100000, dklen=64)
    return hmac.compare_digest(existing_user, username) and hmac.compare_digest(actual, digest)


def main() -> int:
    try:
        data = json.load(sys.stdin)
        if not all(isinstance(data.get(k), str) and data[k] for k in ("config", "username", "password")):
            raise ValueError("missing desired login or configuration")
        print("in_sync" if matches(data["config"], data["username"], data["password"]) else "out_of_sync")
        return 0
    except (ValueError, configparser.Error, KeyError):
        print("invalid_config", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
