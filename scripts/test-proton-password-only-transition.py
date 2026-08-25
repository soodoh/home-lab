#!/usr/bin/env python3
"""Behavioral fixtures for the local-only Proton password-only transition."""

from configparser import ConfigParser
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
TRANSACTION = "a" * 64
AUTH_SHA256 = "b" * 64
ROTATION_SHA256 = "c" * 64
USERNAME_SHA256 = hashlib.sha256(b"fixture-account").hexdigest()


def config_text(legacy_totp: bool, cached: bool) -> str:
    fields = {
        "type": "protondrive",
        "username": "fixture-account",
        "password": "obscured-password",
        "replace_existing_draft": "true",
        "enable_caching": "true",
        "original_file_size": "true",
    }
    if legacy_totp:
        fields["otp_secret_key"] = "obscured-seed"
    if cached:
        fields.update(
            {
                "client_uid": "obscured-uid",
                "client_access_token": "obscured-access",
                "client_refresh_token": "obscured-refresh",
                "client_salted_key_pass": "obscured-key",
            }
        )
    return "[proton-backup]\n" + "".join(f"{key} = {value}\n" for key, value in fields.items())


def started_marker() -> dict[str, object]:
    return {
        "account_username_sha256": USERNAME_SHA256,
        "auth_diagnostic_evidence_sha256": AUTH_SHA256,
        "credential_rotation_evidence_sha256": ROTATION_SHA256,
        "started_at": "2026-08-25T00:00:00Z",
        "state": "started",
        "transaction_sha256": TRANSACTION,
        "version": 1,
    }


def run_fixture(legacy_totp: bool, cached: bool = False, marker: dict[str, object] | None = None) -> tuple[str, str | None, bool]:
    module = runpy.run_path(str(ROOT / "scripts/diagnose-proton-auth"), run_name="password_only_transition_test")
    transition = module["run_password_only_transition_under_lock"]
    globals_ = transition.__globals__
    script_sha256 = hashlib.sha256((ROOT / "scripts/diagnose-proton-auth").read_bytes()).hexdigest()

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = root / "rclone.conf"
        config.write_text(config_text(legacy_totp, cached), encoding="utf-8")
        config.chmod(0o600)
        transition_path = root / f"proton-password-only-transition-{TRANSACTION}.json"
        if marker is not None:
            transition_path.write_text(json.dumps(marker) + "\n", encoding="utf-8")
            transition_path.chmod(0o600)

        globals_["CONFIG"] = config
        globals_["EVIDENCE_PARENT"] = root
        globals_["RESULT"] = root / "qualification-result.json"
        globals_["HOST_EVIDENCE"] = root / "qualification-evidence.json"
        globals_["MUTEX"] = root / "backup.lock"
        globals_["require_regular"] = lambda *_args, **_kwargs: None
        globals_["require_directory"] = lambda *_args, **_kwargs: None
        globals_["digest_file"] = lambda _path: script_sha256
        globals_["validate_lock"] = lambda _expected: b"retained-owner"
        globals_["require_no_backup_processes"] = lambda: None
        globals_["load_policy"] = lambda _gid: {
            "credentials": {"bootstrap_enabled": True, "state": "provisioned"},
            "migration_state": "inert",
            "qualification": {
                "remote_directory": globals_["REMOTE_DIRECTORY"],
                "state": "ready",
                "username_sha256": USERNAME_SHA256,
            },
            "repositories": {"games": {"id": None}, "nfs": {"id": None}, "proton": {"id": None}},
        }
        globals_["load_auth_diagnostic_evidence"] = lambda _transaction, _sha256: {
            "account_username_sha256": USERNAME_SHA256
        }
        globals_["load_credential_rotation_evidence"] = lambda _transaction, _auth, _rotation: {
            "account_username_sha256": USERNAME_SHA256
        }

        def atomic_json(path: Path, value: dict[str, object], replace: bool) -> str:
            if not replace and path.exists():
                raise AssertionError("exclusive evidence claim was not respected")
            content = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            path.write_bytes(content)
            path.chmod(0o600)
            return hashlib.sha256(content).hexdigest()

        def atomic_config(parser: ConfigParser, _uid: int, _gid: int) -> None:
            with config.open("w", encoding="utf-8") as stream:
                parser.write(stream)
            config.chmod(0o600)

        globals_["atomic_json"] = atomic_json
        globals_["atomic_config"] = atomic_config
        identity = SimpleNamespace(pw_uid=60000, pw_gid=60000)
        group = SimpleNamespace(gr_gid=60000)
        output = io.StringIO()
        error: str | None = None
        with (
            patch.object(os, "getuid", return_value=0),
            patch.object(os, "getgid", return_value=0),
            patch.object(globals_["pwd"], "getpwnam", return_value=identity),
            patch.object(globals_["grp"], "getgrnam", return_value=group),
            contextlib.redirect_stdout(output),
        ):
            try:
                transition(TRANSACTION, script_sha256, AUTH_SHA256, ROTATION_SHA256)
            except module["DiagnosticError"] as exception:
                error = str(exception)

        rendered = config.read_text(encoding="utf-8")
        evidence_exists = transition_path.exists()
        if error is None:
            evidence = json.loads(transition_path.read_text(encoding="utf-8"))
            assert evidence["state"] == "password-only"
            assert evidence["provider_requests"] == 0
            assert evidence["removed_field"] == "otp_secret_key"
            assert output.getvalue().startswith("proton_password_only_transition=passed evidence_sha256=")
        return rendered, error, evidence_exists


def main() -> None:
    rendered, error, evidence_exists = run_fixture(legacy_totp=False)
    assert error == "password_only_legacy_field_absent"
    assert not evidence_exists, "a missing first-use legacy field must fail before evidence claim"
    assert "otp_secret_key" not in rendered

    rendered, error, _evidence_exists = run_fixture(legacy_totp=True)
    assert error is None
    assert "otp_secret_key" not in rendered

    rendered, error, _evidence_exists = run_fixture(legacy_totp=True, marker=started_marker())
    assert error is None
    assert "otp_secret_key" not in rendered

    rendered, error, _evidence_exists = run_fixture(legacy_totp=False, marker=started_marker())
    assert error is None
    assert "otp_secret_key" not in rendered

    _rendered, error, evidence_exists = run_fixture(legacy_totp=True, cached=True)
    assert error == "password_only_auth_cache_present"
    assert not evidence_exists, "a cached first-use config must fail before evidence claim"

    malformed = started_marker()
    malformed["state"] = "password-only"
    _rendered, error, _evidence_exists = run_fixture(legacy_totp=True, marker=malformed)
    assert error == "password_only_transition_evidence_invalid"

    print("proton password-only transition fixtures passed")


if __name__ == "__main__":
    main()
