#!/usr/bin/env python3
"""Regression fixtures for the local-only Proton TOTP config transition."""

import contextlib
import hashlib
import io
import json
import os
import runpy
import tempfile
from configparser import ConfigParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = runpy.run_path(str(ROOT / "scripts/transition-proton-totp-config"), run_name="proton_totp_transition_test")
SECRET = "JBSWY3DPEHPK3PXP"
TRANSACTION = "a" * 64


def config(*, totp: bool = False, cache: str = "none") -> bytes:
    fields = {
        "type": "protondrive",
        "username": "backup@example.test",
        "password": "obscured-password",
        "replace_existing_draft": "true",
        "enable_caching": "true",
        "original_file_size": "true",
    }
    if totp:
        fields["otp_secret_key"] = f"obscured:{SECRET}"
    cache_values = {
        "client_uid": "uid",
        "client_access_token": "access",
        "client_refresh_token": "refresh",
        "client_salted_key_pass": "salted",
    }
    if cache == "full":
        fields.update(cache_values)
    elif cache == "partial":
        fields["client_uid"] = "uid"
    parser = ConfigParser(interpolation=None)
    parser["proton-backup"] = fields
    stream = io.StringIO()
    parser.write(stream, space_around_delimiters=True)
    return stream.getvalue().encode()


def run_transition(config_content: bytes, *, secret: str = SECRET, marker: dict[str, object] | None = None):
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    config_path = root / "rclone.conf"
    evidence_path = root / "evidence.json"
    config_path.write_bytes(config_content)
    config_path.chmod(0o600)
    if marker is not None:
        evidence_path.write_bytes(MODULE["canonical"](marker))
        evidence_path.chmod(0o600)
    original_atomic = MODULE["atomic_write"]
    original_require = MODULE["require_regular"]

    def fixture_atomic(path: Path, content: bytes, _uid: int, _gid: int, mode: int) -> None:
        original_atomic(path, content, os.getuid(), os.getgid(), mode)

    def fixture_require(path: Path, _uid: int, _gid: int, mode: int):
        return original_require(path, os.getuid(), os.getgid(), mode)

    globals_value = MODULE["transition_config"].__globals__
    globals_value["atomic_write"] = fixture_atomic
    globals_value["require_regular"] = fixture_require
    try:
        result = MODULE["transition_config"](
            config_path,
            evidence_path,
            secret,
            TRANSACTION,
            os.getuid(),
            os.getgid(),
            lambda value: f"obscured:{value}",
        )
        return temporary, config_path, evidence_path, result
    except BaseException:
        temporary.cleanup()
        raise
    finally:
        globals_value["atomic_write"] = original_atomic
        globals_value["require_regular"] = original_require


def expect_failure(content: bytes, reason: str, **kwargs: object) -> None:
    error = io.StringIO()
    try:
        with contextlib.redirect_stderr(error):
            run_transition(content, **kwargs)
    except SystemExit:
        assert reason in error.getvalue()
        assert SECRET not in error.getvalue()
    else:
        raise AssertionError(f"transition unexpectedly passed: {reason}")


def main() -> None:
    assert MODULE["parse_secret"](f"PROTON_BACKUP_TOTP_SECRET={SECRET}\n") == SECRET
    for invalid in ("", "lowercaseinvalid", "JBSWY3DP=", "A"):
        error = io.StringIO()
        try:
            with contextlib.redirect_stderr(error):
                MODULE["parse_secret"](f"PROTON_BACKUP_TOTP_SECRET={invalid}\n")
        except SystemExit:
            assert "totp_secret_format" in error.getvalue()
            assert not invalid or invalid not in error.getvalue()
        else:
            raise AssertionError("invalid secret passed")

    temporary, config_path, evidence_path, result = run_transition(config(cache="full"))
    try:
        transitioned = MODULE["parser_from_bytes"](config_path.read_bytes())["proton-backup"]
        assert transitioned["otp_secret_key"] == f"obscured:{SECRET}"
        assert not (set(transitioned) & MODULE["CACHE_FIELDS"])
        assert result["provider_requests"] == 0
        evidence = evidence_path.read_text()
        assert SECRET not in evidence
        assert "obscured:" not in evidence
        completed_marker = json.loads(evidence)
        assert completed_marker["state"] == "completed"
        completed_config = config_path.read_bytes()
    finally:
        temporary.cleanup()

    temporary, config_path, evidence_path, result = run_transition(completed_config, marker=completed_marker)
    try:
        assert result == completed_marker
        assert config_path.read_bytes() == completed_config
        assert json.loads(evidence_path.read_text())["provider_requests"] == 0
    finally:
        temporary.cleanup()

    prior = config()
    username_sha = hashlib.sha256(b"backup@example.test").hexdigest()
    marker = {
        "prior_config_sha256": hashlib.sha256(prior).hexdigest(),
        "state": "started",
        "transaction_sha256": TRANSACTION,
        "totp_secret_binding_sha256": MODULE["secret_binding"](SECRET, TRANSACTION),
        "username_sha256": username_sha,
        "version": 1,
    }
    temporary, config_path, evidence_path, result = run_transition(config(totp=True), marker=marker)
    try:
        assert result["state"] == "completed"
        assert result["prior_config_sha256"] == marker["prior_config_sha256"]
        assert json.loads(evidence_path.read_text())["provider_requests"] == 0
    finally:
        temporary.cleanup()

    expect_failure(config(cache="partial"), "partial_client_cache")
    expect_failure(config(totp=True), "totp_secret_mismatch", secret="MFRGGZDFMZTWQ2LK")
    print("proton_totp_transition_tests=passed")


if __name__ == "__main__":
    main()
