#!/usr/bin/env python3
"""Focused failure-path tests for guarded Proton qualification tooling."""

import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def policy(username_sha256: str) -> dict[str, object]:
    return {
        "credentials": {"bootstrap_enabled": True, "state": "provisioned"},
        "migration_state": "inert",
        "proton": {
            "authentication_mode": "password-only",
            "exclusive_client": True,
            "minimum_free_bytes": 100_000_000_000,
            "trash_cleanup": "manual-only",
        },
        "qualification": {
            "result_path": "/var/lib/restic-proton/proton-qualification-result.json",
            "state": "ready",
            "username_sha256": username_sha256,
        },
        "repositories": {
            "games": {"id": None},
            "nfs": {"id": None},
            "proton": {"minimum_allocated_bytes": 1_000_000_000_000, "id": None},
        },
    }


def main() -> None:
    module = runpy.run_path(str(ROOT / "scripts/qualify-proton-backup"), run_name="proton_qualification_test")
    assert module["ALLOWED_COMMANDS"] == {"about", "cat", "copyto", "deletefile", "lsjson", "moveto", "rmdir"}
    assert (ROOT / "scripts/qualify-proton-backup").read_text().count('rclone(["copyto"') == 1
    assert not ({"cleanup", "delete", "mount", "nfsmount", "purge", "sync", "bisync"} & module["ALLOWED_COMMANDS"])
    username = "dedicated-backup@example.invalid"
    username_sha256 = hashlib.sha256(username.encode()).hexdigest()
    test_policy = policy(username_sha256)
    globals_ = module["validate_config"].__globals__

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = root / "rclone.conf"
        cache = root / "cache"
        result = root / "result.json"
        cache.mkdir(mode=0o700)
        config.write_text(
            "[proton-backup]\n"
            "type = protondrive\n"
            f"username = {username}\n"
            "password = obscured-password\n"
            "replace_existing_draft = true\n"
            "enable_caching = true\n"
            "original_file_size = true\n"
            "client_uid = obscured-uid\n"
            "client_access_token = obscured-access\n"
            "client_refresh_token = obscured-refresh\n"
            "client_salted_key_pass = obscured-key\n",
            encoding="utf-8",
        )
        config.chmod(0o600)
        globals_["CONFIG"] = config
        globals_["CACHE"] = cache
        globals_["RESULT"] = result
        module["validate_config"](test_policy, require_cache=True)
        module["invalidate_auth_cache"](test_policy)
        module["validate_config"](test_policy, require_cache=False)
        rendered = config.read_text(encoding="utf-8")
        assert "client_access_token" not in rendered
        assert "obscured-password" in rendered and username in rendered

        evidence = {"state": "qualified", "version": 1}
        evidence_sha256 = module["write_result"](evidence)
        assert result.stat().st_mode & 0o777 == 0o600
        assert evidence_sha256 == hashlib.sha256(result.read_bytes()).hexdigest()

        result.unlink()
        test_policy["qualification"]["remote_directory"] = "Backups/.home-lab-rclone-qualification"
        original_inventory = globals_["qualification_inventory"]
        original_rclone_call = globals_["rclone"]
        globals_["qualification_inventory"] = lambda _path: (True, ["unexpected.bin"])
        try:
            module["recover_remote_qualification"](test_policy, test_policy["qualification"], "d" * 64)
        except module["QualificationError"] as error:
            assert str(error) == "qualification_recovery_scope"
        else:
            raise AssertionError("unknown qualification recovery entry was accepted")

        inventory_results = iter([(True, ["fixture-renamed.bin", "fixture.bin"]), (False, [])])
        recovered_commands: list[list[str]] = []
        globals_["qualification_inventory"] = lambda _path: next(inventory_results)
        globals_["rclone"] = lambda arguments, _label: (
            recovered_commands.append(arguments) or subprocess.CompletedProcess(arguments, 0, b"", b"")
        )
        module["recover_remote_qualification"](test_policy, test_policy["qualification"], "d" * 64)
        assert recovered_commands == [
            ["deletefile", "proton-backup:Backups/.home-lab-rclone-qualification/fixture-renamed.bin"],
            ["deletefile", "proton-backup:Backups/.home-lab-rclone-qualification/fixture.bin"],
            ["rmdir", "proton-backup:Backups/.home-lab-rclone-qualification"],
        ]
        recovery_evidence = json.loads(result.read_text(encoding="utf-8"))
        assert recovery_evidence["recovered_files"] == ["fixture-renamed.bin", "fixture.bin"]
        assert recovery_evidence["transaction_sha256"] == "d" * 64
        globals_["qualification_inventory"] = original_inventory
        globals_["rclone"] = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, b"null\n", b"")
        assert module["qualification_inventory"]("proton-backup:Backups/.home-lab-rclone-qualification") == (False, [])
        globals_["rclone"] = original_rclone_call

    secret_error = b"provider response contains a protected account identifier"
    expected_error_hash = hashlib.sha256(secret_error).hexdigest()
    original_run = globals_["subprocess"].run
    captured_run: dict[str, object] = {}

    def failed_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured_run.update(kwargs)
        return subprocess.CompletedProcess([], 5, b"", secret_error)

    globals_["subprocess"].run = failed_run
    try:
        module["rclone"](["about", "proton-backup:", "--json"], "about")
    except module["QualificationError"] as error:
        assert secret_error.decode() not in str(error)
        assert str(error) == f"about_rc_5_stderr_sha256_{expected_error_hash}"
        assert captured_run["env"] == module["controlled_environment"]()
        assert not any(name.startswith("RCLONE_") for name in captured_run["env"])
    else:
        raise AssertionError("rclone provider failure was accepted")
    finally:
        globals_["subprocess"].run = original_run

    try:
        module["rclone"](["purge", "proton-backup:"], "forbidden")
    except module["QualificationError"] as error:
        assert str(error) == "rclone_command_forbidden"
    else:
        raise AssertionError("prohibited rclone command was accepted")

    original_rclone = globals_["rclone"]
    globals_["rclone"] = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [],
        0,
        json.dumps({"total": 1_073_741_824_000, "used": 0, "free": 1_073_741_824_000}).encode(),
        b"",
    )
    assert module["quota"](test_policy)["total"] == 1_073_741_824_000
    globals_["rclone"] = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [],
        0,
        json.dumps({"total": 999_999_999_999, "used": 0, "free": 999_999_999_999}).encode(),
        b"",
    )
    try:
        module["quota"](test_policy)
    except module["QualificationError"] as error:
        assert str(error) == "quota_gate"
    else:
        raise AssertionError("Proton allocation below the minimum was accepted")
    globals_["rclone"] = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [],
        0,
        json.dumps({"total": 1_073_741_824_000, "used": 973_741_824_001, "free": 99_999_999_999}).encode(),
        b"",
    )
    try:
        module["quota"](test_policy)
    except module["QualificationError"] as error:
        assert str(error) == "quota_gate"
    else:
        raise AssertionError("Proton free-space reserve boundary was accepted")
    finally:
        globals_["rclone"] = original_rclone

    assert module["require_policy"](test_policy)["state"] == "ready"
    pending = policy(username_sha256)
    pending["qualification"]["state"] = "pending"
    try:
        module["require_policy"](pending)
    except module["QualificationError"] as error:
        assert str(error) == "qualification_policy"
    else:
        raise AssertionError("pending qualification policy was accepted")

    print("proton qualification safety fixtures passed")


if __name__ == "__main__":
    main()
