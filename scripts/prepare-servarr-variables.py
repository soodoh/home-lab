#!/usr/bin/env python3
"""Create one protected, per-run OpenTofu input from the three SOPS sources.

The Arr APIs offer one full-privilege key each. The owner explicitly accepted
its use for both reviewed plans and approved applies; this helper never prints
plaintext and never writes it under the repository.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time


KEYS = ("SONARR", "RADARR", "RADARR_4K", "PROWLARR", "READARR")


def require_private_session(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("provider session must be an absolute, non-symlink path")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("provider session must be an owned mode-0700 directory")
    if not 0 <= time.time() - info.st_mtime <= 3600:
        raise ValueError("provider session is not current")


def load_sops(path: Path) -> dict:
    result = subprocess.run(
        ["sops", "--decrypt", "--output-type", "json", str(path)],
        check=True, capture_output=True,
    )
    return json.loads(result.stdout)


def build_inputs(production: dict, clients: dict, servarr: dict) -> dict:
    values = {f"{name.lower()}_api_key": production[f"{name}_API_KEY"] for name in KEYS}
    values.update({
        "radarr_internal_url": production["RADARR_URL"],
        "qbittorrent_username": clients["qbittorrent_username"],
        "qbittorrent_password": clients["qbittorrent_password"],
        "sabnzbd_api_key": clients["sabnzbd_api_key"],
        "root_folders": servarr["root_folders"],
        "indexer_secrets": servarr["indexers"],
    })
    if not all(values.values()):
        raise ValueError("required provider input is empty")
    return values


def main() -> int:
    try:
        repo = Path(__file__).resolve().parent.parent
        session = Path(os.environ["HOME_LAB_PROVIDER_SESSION_DIR"])
        if not os.environ.get("SOPS_AGE_KEY_FILE"):
            raise ValueError("SOPS_AGE_KEY_FILE is required")
        require_private_session(session)
        if session.resolve().is_relative_to(repo):
            raise ValueError("provider session must remain outside Git")
        target = session / "servarr.auto.tfvars.json"
        if target.exists() or target.is_symlink():
            raise ValueError("provider session input already exists")
        values = build_inputs(
            load_sops(repo / "secrets/production.sops.yaml"),
            load_sops(repo / "secrets/download-clients.sops.yaml"),
            load_sops(repo / "secrets/servarr.sops.yaml"),
        )
        # Exclusive create; never reuse an old session input or write into Git.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(values, out, sort_keys=True)
            out.write("\n")
        print("servarr_provider_input=prepared")
        return 0
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError):
        print("servarr_provider_input=refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
