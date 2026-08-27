#!/usr/bin/env python3
"""Static and focused failure-path tests for the inert Restic implementation."""

import json
import contextlib
from configparser import ConfigParser
import io
from datetime import datetime
import hashlib
import os
from pathlib import Path
import runpy
import re
import subprocess
import tempfile
import sys
import time


ROOT = Path(__file__).resolve().parent.parent


def contract() -> dict:
    script = "const{load}=require('js-yaml');const fs=require('fs');process.stdout.write(JSON.stringify(load(fs.readFileSync('infrastructure/contract/home-lab.yml','utf8'))))"
    result = subprocess.run(["node", "-e", script], cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
    return json.loads(result.stdout)


def main() -> None:
    value = contract()
    policy = value["backups"]["restic"]
    offen = value["backups"]["legacy_offen"]
    retirement = offen["retirement"]
    assert retirement["state"] in {"retirement-planned", "retirement-finalizing", "retired"}
    assert offen["scheduler_state"] == ("quiesced" if retirement["state"] == "retirement-planned" else "retired")
    assert offen["scheduler_services"] == ["daily-local-backup", "weekly-remote-backup"]
    manifest_path = ROOT / retirement["manifest_file"]
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    assert retirement["manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()
    assert retirement["acceptance"] == manifest["acceptance"]
    assert retirement["materialized_service_count_before"] == 42
    assert retirement["planned_source_service_count"] == 40
    if retirement["state"] == "retirement-planned":
        assert retirement["evidence_file"] is retirement["evidence_sha256"] is None
    elif retirement["state"] == "retired":
        assert retirement["evidence_file"] == "infrastructure/evidence/offen-retirement.json"
        assert isinstance(retirement["evidence_sha256"], str) and len(retirement["evidence_sha256"]) == 64
    else:
        assert (retirement["evidence_file"] is retirement["evidence_sha256"] is None) or (
            retirement["evidence_file"] == "infrastructure/evidence/offen-retirement-finalizing.json"
            and isinstance(retirement["evidence_sha256"], str) and len(retirement["evidence_sha256"]) == 64)
    assert len(manifest["local"]["archives"]) == 12
    assert len(manifest["local"]["metadata_files"]) == 8
    assert manifest["aws"]["version_id_sha256"] == "3e42bf4017bedaaac231ce234cc8be64536a87da0ba8e401b90967864c73a8c0"
    assert "restic-recovery-bundle-b" in manifest["preserve"]
    assert "proton-trash" in manifest["preserve"]
    assert offen["migration_retention_hold"] == {
        "state": "applied" if retirement["state"] == "retirement-planned" else "retired",
        "current_object_retention_days": 365,
        "lifecycle_rule_id": "critical-backup-retention",
        "delete_marker_rule_id": "expired-delete-marker-cleanup",
        "expected_principal_arn_sha256": "cbfd4986207c28758c6d4561f6636cbaf31bbeca8972891d347ed25180be2ac7",
        "recovery_object_key": "weekly-backup-2026-08-23T06-00-00.tar.gz.gpg",
        "recovery_object_bytes": 2_399_491_160,
        "recovery_object_last_modified": "2026-08-23T13:03:53Z",
        "recovery_object_storage_class": "STANDARD",
        "plan_sha256": "6239f3c0a67c66d2a3b23ca7dfa84853391fca98bf8b5b9d116004925d6684ae",
        "recovery_object_version_id_sha256": "3e42bf4017bedaaac231ce234cc8be64536a87da0ba8e401b90967864c73a8c0",
        "verified_at": "2026-08-24T16:48:02Z",
        "review_deadline": "2026-09-23T16:48:02Z",
    }
    preservation = offen["migration_archive_preservation"]
    assert preservation["state"] == ({"retirement-planned": "applied", "retirement-finalizing": "retirement-finalizing", "retired": "retired"}[retirement["state"]])
    assert preservation["protected_subdirectory"] == ".migration-preserved-offen"
    assert preservation["replica_roots"] == ["/mnt/games/backups", "/mnt/storage/backups"]
    assert preservation["archives"] == [
        {
            "basename": "daily-local-backup-2026-08-21T22-32-08.tar.gz.gpg",
            "bytes": 2_319_938_554,
            "sha256": "0b46561cf52c15bfababef0f75fe3bbe2cf1f7e1305eb1f7cfe4c1ca0db5c431",
        },
        {
            "basename": "daily-local-backup-2026-08-23T05-00-00.tar.gz.gpg",
            "bytes": 2_411_062_883,
            "sha256": "8034bcf7a03d19c446a23c30a56c1b9a8c4ffdd2d829557a5a16e39c0aab1f08",
        },
    ]
    final_archive = offen["final_archive"]
    evidence_path = ROOT / "infrastructure/evidence/offen-final-archive-2026-08-23-restore-proof.json"
    evidence_bytes = evidence_path.read_bytes()
    evidence = json.loads(evidence_bytes)
    assert hashlib.sha256(evidence_bytes).hexdigest() == "89712ec78f8724730d2e3eeb07c3929db0b7c2fad7cb30410d517cc115f7eff1"
    assert evidence["archive_integrity"] == "pass" and evidence["safe_paths"] == "pass"
    assert len(evidence["required_state_classes"]) == 39
    assert all(item["status"] == "present" for item in evidence["required_state_classes"].values())
    assert len(evidence["excluded_state_classes"]) == 17
    assert all(item["status"] == "absent" for item in evidence["excluded_state_classes"].values())
    assert len(evidence["sqlite_databases"]) == 6
    assert all(item["sqlite_integrity"] == "pass" for item in evidence["sqlite_databases"].values())
    if preservation["state"] == "planned":
        assert preservation["verified_at"] is None
        assert final_archive["basename"] == preservation["archives"][0]["basename"]
        assert "restore_proof" not in final_archive
    else:
        restore_proof = final_archive["restore_proof"]
        assert preservation["verified_at"] is not None
        assert final_archive["basename"] == preservation["archives"][1]["basename"]
        assert hashlib.sha256(evidence_bytes).hexdigest() == restore_proof["evidence_sha256"]
        assert final_archive["replica_paths"] == ["/mnt/games/backups/.migration-preserved-offen", "/mnt/storage/backups/.migration-preserved-offen"]
        assert restore_proof["verifier_sha256"] == "e78f1f009d89af872fe2d48b2f091597c66a309f657842f1e522c221f643ac5c"
        assert restore_proof["restore_pipeline"] == restore_proof["decrypted_cleanup"] == "pass"
        assert restore_proof["archive_integrity"] == evidence["archive_integrity"] == "pass"
        assert restore_proof["safe_paths"] == evidence["safe_paths"] == "pass"
        started_at = datetime.fromisoformat(restore_proof["started_at"].replace("Z", "+00:00"))
        finished_at = datetime.fromisoformat(restore_proof["finished_at"].replace("Z", "+00:00"))
        assert int((finished_at - started_at).total_seconds()) == restore_proof["elapsed_seconds"]
        for key in ("member_count", "regular_file_count", "total_uncompressed_bytes", "member_path_stream_sha256"):
            assert evidence[key] == restore_proof[key]
    assert policy["migration_state"] == "active"
    assert [policy["retention"][key] for key in ("keep_daily", "keep_weekly", "keep_monthly")] == [7, 5, 12]
    assert policy["schedule"]["proton_independent_timer"] is False
    assert policy["proton"]["trash_cleanup"] == "manual-only"
    assert policy["repositories"]["games"]["id"] == "b15627185df9b10a95b5dffe7d194dbccdba6ba4eb8a038ee03e750fedbde08f"
    assert policy["repositories"]["nfs"]["id"] == "61d50fa782d194374deb24f354a07b0f11634721afa1b268963e4d017b93bb95"
    assert policy["repositories"]["proton"]["id"] == "d1faa9cd772dd13275b8d4db376c2bbba0b82a9415a28b0d03a8b17e37b7fb7e"
    assert policy["repositories"]["nfs"]["copy_chunker_params_from"] == "games"
    assert policy["repositories"]["proton"]["copy_chunker_params_from"] == "games"
    assert policy["repositories"]["proton"]["minimum_allocated_bytes"] == 1_000_000_000_000
    assert policy["proton"]["warning_minimum_used_bytes"] == 100_000_000_000
    assert policy["proton"]["minimum_free_bytes"] == 100_000_000_000
    assert policy["retention"]["group_by"] == "host,paths"
    assert policy["restore"]["modes"] == ["staging"]
    assert policy["restore"]["activation_status"] == "unavailable-pending-isolated-proofs"
    assert policy["credentials"] == {"bootstrap_enabled": True, "state": "provisioned"}
    assert policy["qualification"]["state"] == "qualified"
    assert policy["qualification"]["username_sha256"] == "809cd2b0e14ad028438ad5a0a7af801dce013a86a3f1d62926a605177198389b"
    assert policy["qualification"]["evidence_sha256"] == "81f93aca27a87fe38d90137f33da60d823ed5e391296c95cb7ab1be867dfc679"
    assert policy["qualification"]["verified_at"] == "2026-08-26T00:42:08Z"
    assert policy["initialization"]["state"] == "initialized"
    assert policy["initialization"]["source_policy_sha256"] == "7ec54b69a21e118f5b6ef6c9d3a73cdbb8c16cbe0629491fcad0c782227e2501"
    assert policy["initialization"]["evidence_sha256"] == "b8ac8cd34a3d8259ef6aa2273a97b6b4ace601d9116a0bd1886beb1e666b9e7e"
    assert policy["initialization"]["verified_at"] == "2026-08-26T01:36:31Z"
    assert len({repository["id"] for repository in policy["repositories"].values()}) == 3
    assert policy["qualification"]["remote_directory"] == "Backups/.home-lab-rclone-qualification"
    assert policy["runner"]["sha256"] == hashlib.sha256((ROOT / "scripts/restic-backup").read_bytes()).hexdigest()
    assert policy["first_run"]["state"] == "completed"
    assert policy["first_run"]["snapshots"] == {
        "games": "edd4f507cec382e6fae48e2690ffa53ae7ef7a61e24581983975631cbe5a32e2",
        "nfs": "d64f24f17b7cfb2b5aaefe0f2ff625837b9ab198061470269f15f2026651b88d",
        "proton": "95be7e9b0a03cedd06340fdcf63055c67205c3a6c28687ffd2dc99e733bfa71e",
    }
    assert policy["first_run"]["evidence_sha256"] == "fea8502382d2b1dc8f3330a03d28f3bff52395942ca219332f722bca32559c6e"
    assert policy["first_run"]["aws_evidence_sha256"] == "203651f97fd599a095ec973aabb799ef8c4f62d93e8ef82ff60111ca4796983f"

    files_from = (ROOT / "services/data/restic/files-from").read_text().splitlines()
    excludes = (ROOT / "services/data/restic/excludes").read_text().splitlines()
    assert files_from == [entry["path"] for entry in policy["sources"]]
    assert excludes == policy["excludes"]
    assert not any("restic/home-lab" in source for source in files_from)

    runner_text = (ROOT / "scripts/restic-backup").read_text()
    assert 'SUBCOMMANDS = {"preflight", "daily-local", "daily-proton", "maintenance", "status"}' in runner_text
    for command in ("cleanup", "mount", "nfsmount", "purge", "sync", "bisync"):
        assert f'"{command}"' in runner_text
    assert "restic_partial_source" in runner_text
    assert '"--read-data-subset"' in runner_text
    assert 'warning_repository_multiplier' in runner_text and 'minimum_free_bytes' in runner_text
    assert "an NFS outage cannot suppress the primary local recovery point" in runner_text
    assert "concurrent_deploy" in runner_text
    apply_lock = (ROOT / "ansible/roles/apply_lock/tasks/main.yml").read_text()
    assert "apply_lock_backup_guard_path" in apply_lock and "/usr/bin/flock" in apply_lock
    assert "stderr" not in runner_text.split("def require_success", 1)[1].split("def atomic_json", 1)[0]

    module = runpy.run_path(str(ROOT / "scripts/restic-backup"), run_name="restic_test_module")
    partial = subprocess.CompletedProcess(["restic"], 3, "", "provider secret response")
    try:
        module["require_success"](partial, "backup")
    except module["WorkflowError"] as error:
        assert str(error) == "restic_partial_source"
    else:
        raise AssertionError("Restic exit 3 was accepted")
    try:
        module["run"](["/usr/local/bin/rclone", "cleanup", "proton-backup:"])
    except module["WorkflowError"] as error:
        assert str(error) == "prohibited_rclone_command"
    else:
        raise AssertionError("prohibited rclone cleanup was accepted")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        stopped = root / "journal.json"
        stopped.write_text("{}")
        test_policy = {
            "stop_groups": {"start_order": ["database", "application"]},
            "runner": {"journal_path": "/journal.json"},
        }
        started = []
        runner_globals = module["restart_recorded"].__globals__
        runner_globals["testing"] = lambda: True
        runner_globals["rooted"] = lambda path: root / path.lstrip("/")
        runner_globals["compose"] = lambda _policy, arguments: (started.append(arguments[-1]) or subprocess.CompletedProcess(arguments, 0, "", ""))
        runner_globals["service_healthy"] = lambda _policy, _service: True
        module["restart_recorded"](test_policy, {"running_services": ["application", "database"]})
        assert started == ["database", "application"]
        assert not stopped.exists()

    runner_globals["service_container"] = lambda _policy, _service: "a" * 64
    runner_globals["run"] = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "secret provider failure")
    try:
        module["service_running"](policy, "database")
    except module["WorkflowError"] as error:
        assert str(error) == "service_inventory"
    else:
        raise AssertionError("Docker inspection failure was treated as stopped")

    runner_globals["proton_identity"] = lambda: (12345, 12346)
    owners = module["shared_state_owners"]()
    assert {0, 12345} <= owners

    try:
        module["pending_entry"](policy, {"source_snapshot": "malformed"})
    except module["WorkflowError"] as error:
        assert str(error) == "pending_entry_schema"
    else:
        raise AssertionError("malformed pending replication evidence was accepted")
    maintenance_text = runner_text.split("def maintenance", 1)[1].split("def status", 1)[0]
    assert "pending_entry(policy, item)" in maintenance_text

    captured = []
    runner_globals["restic_result"] = lambda _policy, name, arguments, **_kwargs: (
        captured.append((name, arguments)) or subprocess.CompletedProcess(arguments, 0, "[]", "")
    )
    module["retention"](policy, "games", set())
    dry_arguments = captured[0][1]
    assert ["--group-by", "host,paths"] == dry_arguments[dry_arguments.index("--group-by"):dry_arguments.index("--group-by") + 2]
    assert "cadence=daily" in dry_arguments

    runner_globals["command_paths"] = lambda _policy: ("/usr/local/bin/restic", "/usr/local/bin/rclone")
    runner_globals["rooted"] = lambda path: Path(path)
    runner_globals["run"] = lambda arguments, **_kwargs: subprocess.CompletedProcess(
        arguments,
        0,
        json.dumps({"used": 973_741_824_000, "free": 100_000_000_000, "total": 1_073_741_824_000}) if "about" in arguments else json.dumps({"bytes": 1}),
        "",
    )
    try:
        module["quota"](policy, 1)
    except module["WorkflowError"] as error:
        assert str(error) == "proton_quota_gate"
    else:
        raise AssertionError("Proton copy headroom could cross the free-space reserve")

    role = (ROOT / "ansible/roles/restic_backup/tasks/main.yml").read_text()
    bootstrap = (ROOT / "scripts/bootstrap-restic-credentials").read_text()
    assert "required_sops_keys_absent" in bootstrap
    assert "state={'changed' if changed else 'noop'}" in bootstrap
    assert '["/usr/local/bin/rclone", "obscure", "-"]' in bootstrap
    assert "path.read_text(encoding=\"utf-8\") == content" in bootstrap
    assert "except (ConfigError, OSError)" in bootstrap
    assert 'remote.get("original_file_size") != "true"' in bootstrap
    assert '"otp_secret_key"' not in bootstrap
    assert 'sys.argv[3] != "--check"' in bootstrap
    assert 'fail("credential_drift")' in bootstrap
    assert 'operation = "validated" if check_only else "materialized"' in bootstrap
    bootstrap_module = runpy.run_path(str(ROOT / "scripts/bootstrap-restic-credentials"), run_name="restic_bootstrap_test_module")
    parse_dotenv = bootstrap_module["parse_dotenv"]
    valid_credentials = {
        "RESTIC_LOCAL_PASSWORD": "a" * 32,
        "RESTIC_PROTON_PASSWORD": "b" * 32,
        "PROTON_BACKUP_USERNAME": "fixture-account",
        "PROTON_BACKUP_PASSWORD": "A1" * 20,
    }

    def parse_credentials(values: dict[str, str]) -> dict[str, str]:
        return parse_dotenv("".join(f"{key}={value}\n" for key, value in values.items()))

    assert parse_credentials(valid_credentials) == valid_credentials
    invalid_credentials = (
        ({**valid_credentials, "RESTIC_LOCAL_PASSWORD": "short"}, "restic_password_minimum_length"),
        ({**valid_credentials, "RESTIC_PROTON_PASSWORD": "a" * 32}, "restic_passwords_not_distinct"),
        ({**valid_credentials, "PROTON_BACKUP_PASSWORD": "short"}, "proton_login_password_policy"),
        ({**valid_credentials, "PROTON_BACKUP_PASSWORD": "A!" * 20}, "proton_login_password_policy"),
        ({**valid_credentials, "RESTIC_LOCAL_PASSWORD": "A1" * 20}, "proton_login_password_not_distinct"),
        ({**valid_credentials, "PROTON_BACKUP_TOTP_SEED": "A" * 32}, "proton_totp_seed_forbidden"),
    )
    for invalid, expected_reason in invalid_credentials:
        error = io.StringIO()
        try:
            with contextlib.redirect_stderr(error):
                parse_credentials(invalid)
        except SystemExit:
            assert expected_reason in error.getvalue()
        else:
            raise AssertionError(f"invalid credential fixture passed: {expected_reason}")

    require_credential_contents = bootstrap_module["require_credential_contents"]
    with tempfile.TemporaryDirectory() as credential_directory:
        credential_path = Path(credential_directory) / "password"
        credential_path.write_text("expected\n", encoding="utf-8")
        credential_path.chmod(0o440)
        require_credential_contents(
            {credential_path: "expected\n"},
            os.getuid(),
            os.getgid(),
            0o440,
        )
        before = credential_path.read_bytes()
        error = io.StringIO()
        try:
            with contextlib.redirect_stderr(error):
                require_credential_contents(
                    {credential_path: "different\n"},
                    os.getuid(),
                    os.getgid(),
                    0o440,
                )
        except SystemExit:
            assert "credential_drift" in error.getvalue()
        else:
            raise AssertionError("credential drift was accepted by non-mutating validation")
        assert credential_path.read_bytes() == before
    qualification = (ROOT / "scripts/qualify-proton-backup").read_text()
    assert 'ALLOWED_COMMANDS = {"about", "cat", "copyto", "deletefile", "lsjson", "moveto", "rmdir"}' in qualification
    assert "stderr_sha256" in qualification and "digest_bytes(result.stderr)" in qualification
    assert "print(result.stderr" not in qualification
    assert qualification.count("invalidate_auth_cache(policy)") >= 3
    assert "if value is None:" in qualification
    qualification_module = runpy.run_path(
        str(ROOT / "scripts/qualify-proton-backup"),
        run_name="qualify_proton_backup_test_module",
    )
    qualification_inventory = qualification_module["qualification_inventory"]
    assert qualification_module["json_type"]({"protected": "value"}) == "object"
    assert qualification_module["json_type"]("protected") == "string"
    qualification_globals = qualification_inventory.__globals__
    saved_qualification_rclone = qualification_globals["rclone"]
    try:
        qualification_globals["rclone"] = lambda *_args: subprocess.CompletedProcess([], 3, b"null\n", b"directory not found")
        assert qualification_inventory("proton-backup:Backups/.home-lab-rclone-qualification") == (False, [])
        qualification_globals["rclone"] = lambda *_args: subprocess.CompletedProcess([], 0, b" \nnull \n", b"")
        assert qualification_inventory("proton-backup:Backups/.home-lab-rclone-qualification") == (False, [])
        qualification_globals["rclone"] = lambda *_args: subprocess.CompletedProcess([], 3, b"null", b"directory not found")
        assert qualification_inventory("proton-backup:Backups/.home-lab-rclone-qualification") == (False, [])
        qualification_globals["rclone"] = lambda *_args: subprocess.CompletedProcess([], 3, b" \n\t", b"directory not found")
        assert qualification_inventory("proton-backup:Backups/.home-lab-rclone-qualification") == (False, [])
        qualification_globals["rclone"] = lambda *_args: subprocess.CompletedProcess([], 3, b"[\n", b"directory not found")
        assert qualification_inventory("proton-backup:Backups/.home-lab-rclone-qualification") == (False, [])
        qualification_globals["rclone"] = lambda *_args: subprocess.CompletedProcess([], 3, b"{}\n", b"directory not found")
        try:
            qualification_inventory("proton-backup:Backups/.home-lab-rclone-qualification")
        except qualification_module["QualificationError"] as error:
            assert str(error) == "qualification_directory_rc_3_object"
        else:
            raise AssertionError("unexpected missing-directory output passed")
        invalid_inventory = b"protected provider output"
        qualification_globals["rclone"] = lambda *_args: subprocess.CompletedProcess([], 3, invalid_inventory, b"directory not found")
        try:
            qualification_inventory("proton-backup:Backups/.home-lab-rclone-qualification")
        except qualification_module["QualificationError"] as error:
            controlled = str(error)
            assert invalid_inventory.decode() not in controlled
            assert controlled == (
                f"qualification_directory_rc_3_invalid_json_bytes_{len(invalid_inventory)}_sha256_"
                f"{hashlib.sha256(invalid_inventory).hexdigest()}"
            )
        else:
            raise AssertionError("invalid Proton inventory output passed")
    finally:
        qualification_globals["rclone"] = saved_qualification_rclone
    invalidate_auth_cache = qualification_module["invalidate_auth_cache"]
    invalidate_globals = invalidate_auth_cache.__globals__
    saved_qualification_config = invalidate_globals["CONFIG"]
    with tempfile.TemporaryDirectory() as partial_cache_directory:
        partial_cache_config = Path(partial_cache_directory) / "rclone.conf"
        partial_cache_config.write_text(
            "[proton-backup]\n"
            "type = protondrive\n"
            "username = backup@example.test\n"
            "password = obscured-password\n"
            "replace_existing_draft = true\n"
            "enable_caching = true\n"
            "original_file_size = true\n"
            "client_uid = partial-cache\n\n"
        )
        partial_cache_config.chmod(0o600)
        invalidate_globals["CONFIG"] = partial_cache_config
        try:
            invalidate_auth_cache(
                {"qualification": {"username_sha256": hashlib.sha256(b"backup@example.test").hexdigest()}}
            )
            partial_parser = ConfigParser(interpolation=None)
            partial_parser.read(partial_cache_config)
            assert set(partial_parser["proton-backup"]) == qualification_module["STATIC_KEYS"] - {"mailbox_password"}
        finally:
            invalidate_globals["CONFIG"] = saved_qualification_config
    recovery_function = qualification.split("def recover_remote_qualification", 1)[1].split("def main", 1)[0]
    qualification_function = qualification.split('if action == "recover":', 1)[1].split("except QualificationError", 1)[0]
    assert recovery_function.index("finally:") < recovery_function.index("write_result(evidence)")
    assert qualification_function.index("finally:") < qualification_function.index("write_result(evidence)")
    inspect_function = qualification.split("def inspect_remote_qualification", 1)[1].split("def recover_remote_qualification", 1)[0]
    assert "finally:" in inspect_function and "invalidate_auth_cache(policy)" in inspect_function
    assert 'remote_directory != "Backups/.home-lab-rclone-qualification"' in qualification
    assert "secrets.token_bytes" in qualification
    assert "password_reauthentication" in qualification
    group_vars = (ROOT / "ansible/group_vars/docker_host.yml").read_text()
    assert 'restic_archive_sha256: "{{ backups.restic.tools.restic.archive_sha256 }}"' in group_vars
    assert 'rclone_archive_sha256: "{{ backups.restic.tools.rclone.archive_sha256 }}"' in group_vars
    assert 'restic_credentials_bootstrap_enabled: "{{ backups.restic.credentials.bootstrap_enabled }}"' in group_vars
    assert 'rclone_binary_sha256: "{{ backups.restic.tools.rclone.installed_sha256 }}"' in group_vars
    assert 'restic_binary_sha256: "{{ backups.restic.tools.restic.installed_sha256 }}"' in group_vars
    assert policy["tools"]["restic"]["installed_sha256"] == "20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639"
    assert policy["tools"]["rclone"]["installed_sha256"] == "f3f9aff817f9766029e50adf9a7963c169e475b8f10c7927823568a0d9443db7"
    assert policy["qualification"]["helper_sha256"] == hashlib.sha256((ROOT / "scripts/qualify-proton-backup").read_bytes()).hexdigest()
    assert policy["initialization"]["helper_sha256"] == hashlib.sha256((ROOT / "scripts/initialize-restic-repositories").read_bytes()).hexdigest()
    assert policy["tools"]["restic"]["archive_sha256"] == "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c"
    assert policy["tools"]["rclone"]["archive_sha256"] == "aa2804e08f48250e71009c727124b6341cd0288465804a9a09d14663cabafbaa"
    assert "ansible_facts.architecture == 'x86_64'" in role
    assert "Refusing to replace a non-regular, symlinked, or hard-linked Restic tool destination" in role
    assert "Refusing a pre-existing games Restic repository until its exact ID is recorded" in role
    assert "The games Restic repository ID differs from the contract" in role
    assert "Refusing Restic deployment without the exact contract repository mount" in role
    assert "import bz2" in role and "zipfile.ZipFile" in role
    assert "/usr/bin/bzip2" not in role and "/usr/bin/unzip" not in role and "ansible.builtin.unarchive" not in role
    assert "Refuse ordinary convergence before guarded password-only transition" in role
    assert role.index("Refuse ordinary convergence before guarded password-only transition") < role.index("Install rendered Restic policy JSON")
    assert role.index("Refuse ordinary convergence before guarded password-only transition") < role.index("Install canonical SOPS ciphertext")
    sops_install = role.split("Install canonical SOPS ciphertext", 1)[1].split("Gather confined Restic identity records", 1)[0]
    assert "no_log: true" in sops_install
    reconcile = (ROOT / "scripts/reconcile-infrastructure").read_text()
    steady_tags = reconcile.split("apply_debian_steady()", 1)[1].split("compose_apply()", 1)[0]
    assert "restic_backup" in steady_tags
    assert "restic-proton" in role and "groups: []" in role and "shell: /usr/sbin/nologin" in role
    assert "enabled: false" in role and "state: stopped" in role
    assert "Inspect inert Restic unit state before enforcement" in role
    assert "item.stdout_lines != ['inactive', item.item.value]" in role
    assert "qualify-proton-backup" in role
    assert 'group: "{{ item.group | default(\'root\') }}"' in role
    assert "dest: /usr/local/libexec/home-lab/qualify-proton-backup\n      group: restic-proton\n      mode: \"0750\"" in role
    assert "Require contract-backed credential materialization state" in role
    qualification_playbook = (ROOT / "ansible/playbooks/qualify-proton-backup.yml").read_text()
    rclone_version_preflight = qualification_playbook.split("Inspect the pinned rclone version before lock acquisition", 1)[1].split("Require the exact pinned rclone version before lock acquisition", 1)[0]
    assert "check_mode: false" in rclone_version_preflight
    assert "apply_lock_operation: proton-qualification" in qualification_playbook
    assert "qualify-proton-bounded-operations" not in qualification_playbook
    assert "backups.restic.qualification.confirmation" in qualification_playbook
    assert "Require a complete quiesced source-state audit before Proton qualification" in qualification_playbook
    assert "Remove only the transient user-owned qualification result" in qualification_playbook
    assert "Require exact reviewed qualification artifact metadata and hashes" in qualification_playbook
    assert "installed policy to equal the reviewed contract" in qualification_playbook
    recovery_playbook = (ROOT / "ansible/playbooks/recover-proton-qualification.yml").read_text()
    assert "recover-only-proton-qualification-fixtures" in recovery_playbook
    assert "Refuse cleanup after qualification result or evidence publication" in recovery_playbook
    assert "release only the proton-qualification lock" in recovery_playbook
    assert "proton-qualification-recovery-{{ proton_recovery_transaction_sha256 }}.json" in recovery_playbook
    assert "evidence.transaction_sha256 == proton_recovery_transaction_sha256" in recovery_playbook
    assert "proton_qualification_recovery_expected_transaction_sha256" in recovery_playbook
    assert "proton_qualification_recovery_expected_transition_evidence_sha256" in recovery_playbook
    assert "proton_qualification_recovery_expected_deployment_evidence_sha256" in recovery_playbook
    assert "proton_qualification_recovery_expected_account_reset_evidence_sha256" in recovery_playbook
    assert "Require exact account-reset reconciliation evidence for recovery" in recovery_playbook
    assert "reconciliation.installed_config_sha256" in recovery_playbook
    assert "Require reconciled rclone config bytes before any recovery mutation" in recovery_playbook
    assert "Require Proton cache to remain empty before any recovery mutation" in recovery_playbook
    assert "Inspect account-reset referenced evidence before recovery" in recovery_playbook
    assert "Require exact password-only transition evidence for recovery" in recovery_playbook
    assert "Require exact password-only deployment evidence for recovery" in recovery_playbook
    assert "evidence.provider_requests == 0" in recovery_playbook
    empty_recovery_path = ROOT / "scripts/finalize-proton-empty-recovery"
    empty_recovery = empty_recovery_path.read_text()
    empty_recovery_sha256 = hashlib.sha256(empty_recovery_path.read_bytes()).hexdigest()
    assert f"proton_empty_recovery_script_sha256: {empty_recovery_sha256}" in recovery_playbook
    assert "7164a86b3c7d4c61c64ec780c192e333e2ee26407a9f39dfa38f6a5fdff6405b" in recovery_playbook
    assert "post-reset-diagnostic-v4" in empty_recovery
    assert 'observation.get("category") != "reachable"' in empty_recovery
    assert 'observation.get("rclone_rc") != 3' in empty_recovery
    assert '"recovered_files": []' in empty_recovery
    assert "tempfile.mkstemp" in empty_recovery and "os.link" in empty_recovery
    assert "/usr/local/bin/rclone" not in empty_recovery
    assert "Require exact backup mutex before empty-directory recovery" in recovery_playbook
    assert "proton_empty_recovery_mutex.stat.nlink == 1" in recovery_playbook
    assert "apply_lock_expected_owner_sha256" in recovery_playbook
    empty_recovery_module = runpy.run_path(
        str(empty_recovery_path),
        run_name="finalize_proton_empty_recovery_test_module",
    )
    write_empty_recovery = empty_recovery_module["write_result"]
    write_empty_globals = write_empty_recovery.__globals__
    saved_empty_result = write_empty_globals["RESULT"]
    saved_service_uid = write_empty_globals["SERVICE_UID"]
    saved_service_gid = write_empty_globals["SERVICE_GID"]
    with tempfile.TemporaryDirectory() as empty_result_directory:
        empty_result = Path(empty_result_directory) / "result.json"
        write_empty_globals["RESULT"] = empty_result
        write_empty_globals["SERVICE_UID"] = os.getuid()
        write_empty_globals["SERVICE_GID"] = os.getgid()
        try:
            empty_value = {"state": "recovered", "version": 1}
            empty_hash = write_empty_recovery(empty_value)
            expected_empty_content = (json.dumps(empty_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            assert empty_result.read_bytes() == expected_empty_content
            assert empty_hash == hashlib.sha256(expected_empty_content).hexdigest()
            assert not list(Path(empty_result_directory).glob(".proton-qualification-result.*"))
            try:
                write_empty_recovery(empty_value)
            except empty_recovery_module["FinalizationError"] as error:
                assert str(error) == "prior_result_present"
            else:
                raise AssertionError("empty recovery result replay passed")
            assert empty_result.read_bytes() == expected_empty_content
            assert not list(Path(empty_result_directory).glob(".proton-qualification-result.*"))
        finally:
            write_empty_globals["RESULT"] = saved_empty_result
            write_empty_globals["SERVICE_UID"] = saved_service_uid
            write_empty_globals["SERVICE_GID"] = saved_service_gid
    resume_playbook = (ROOT / "ansible/playbooks/resume-proton-qualification.yml").read_text()
    helper_metadata = "\n".join(
        (
            "          path: /usr/local/libexec/home-lab/qualify-proton-backup",
            "          owner: root",
            "          group: restic-proton",
            '          mode: "0750"',
        )
    )
    for helper_consumer_playbook in (qualification_playbook, recovery_playbook, resume_playbook):
        assert helper_metadata in helper_consumer_playbook
    assert "Require an exact qualification helper before execute-access repair" in recovery_playbook
    assert "proton_recovery_helper_before_access_repair.stat.gr_name in ['root', 'restic-proton']" in recovery_playbook
    assert "proton_recovery_helper_before_access_repair.stat.checksum == backups.restic.qualification.helper_sha256" in recovery_playbook
    assert "Grant only restic-proton execute access to the exact qualification helper" in recovery_playbook
    assert "ansible_check_mode\n              and item.item.name == 'helper'\n              and item.stat.gr_name == 'root'" in recovery_playbook
    auth_diagnostic_playbook = (ROOT / "ansible/playbooks/diagnose-proton-auth.yml").read_text()
    assert "diagnose-only-proton-authentication" in auth_diagnostic_playbook
    assert "proton_auth_diagnostic_expected_transaction_sha256" in auth_diagnostic_playbook
    assert "operation=proton-qualification" in auth_diagnostic_playbook
    assert "proton-auth-diagnostic-{{ proton_auth_diagnostic_lock_owner.content | b64decode | hash('sha256') }}.json" in auth_diagnostic_playbook
    auth_diagnostic_path = ROOT / "scripts/diagnose-proton-auth"
    auth_diagnostic = auth_diagnostic_path.read_text()
    auth_diagnostic_sha256 = hashlib.sha256(auth_diagnostic_path.read_bytes()).hexdigest()
    assert f"proton_auth_diagnostic_script_sha256: {auth_diagnostic_sha256}" in auth_diagnostic_playbook
    assert "ansible.builtin.script:" in auth_diagnostic_playbook
    assert "failed_when: false" in auth_diagnostic_playbook
    assert "Capture only a controlled Proton authentication diagnostic failure" in auth_diagnostic_playbook
    assert "proton_auth_diagnostic_run.stderr | length == 0" not in auth_diagnostic_playbook
    assert "backup_mutex" in auth_diagnostic_playbook and "evidence_parent" in auth_diagnostic_playbook
    assert "atomic Proton authentication diagnostic evidence" in auth_diagnostic_playbook
    assert "apply_lock_action: release" not in auth_diagnostic_playbook
    assert "proton_auth_diagnostic_evidence_path" in auth_diagnostic_playbook
    assert 'FLOCK = Path("/usr/bin/flock")' in auth_diagnostic
    assert 'RUNUSER = Path("/usr/sbin/runuser")' in auth_diagnostic
    assert 'REMOTE_DIRECTORY = "Backups/.home-lab-rclone-qualification"' in auth_diagnostic
    assert "os.O_EXCL" in auth_diagnostic and '"state": "started"' in auth_diagnostic
    assert "--conflict-exit-code" in auth_diagnostic and 'fail("backup_mutex_busy")' in auth_diagnostic
    assert "validate_lock(expected_transaction)" in auth_diagnostic
    assert auth_diagnostic.count("validate_lock(expected_transaction)") >= 3
    assert "static_after != static_before" in auth_diagnostic
    assert '"mailbox_password"' in auth_diagnostic
    assert "launch_marker" in auth_diagnostic and 'fail("rclone_exec")' in auth_diagnostic
    assert "print(result.stderr" not in auth_diagnostic and "print(result.stdout" not in auth_diagnostic
    assert 'str(FLOCK),\n        "--exclusive",\n        "--nonblock"' in auth_diagnostic
    assert 'str(RUNUSER),\n        "--user",\n        "restic-proton",\n        "--",\n        str(ENV)' in auth_diagnostic
    assert 'str(INSTALL),\n        "--mode",\n        "0600",\n        "/dev/null"' in auth_diagnostic
    diagnostic_module = runpy.run_path(str(auth_diagnostic_path), run_name="proton_auth_diagnostic_test_module")
    try:
        raise TypeError("sensitive detail must not be emitted")
    except TypeError as error:
        exception_reason = diagnostic_module["local_exception_reason"](error)
    assert exception_reason.startswith("local_exception_typeerror_main_")
    assert "sensitive" not in exception_reason
    classify_proton_failure = diagnostic_module["classify"]
    classify_post_reset_v2 = diagnostic_module["classify_post_reset_v2"]
    assert classify_proton_failure(1, b"unrelated object has wrong type") == "rclone_unclassified"
    assert classify_proton_failure(1, b"user ID signature with wrong type") == "account_key_incompatible"
    assert classify_proton_failure(1, b"the main share assumption has failed") == "rclone_unclassified"
    assert classify_post_reset_v2(1, b"the main share assumption has failed") == "drive_share_incompatible"
    assert classify_post_reset_v2(1, b"no active volume was found") == "drive_volume_incompatible"
    assert classify_post_reset_v2(1, b"gopenpgp: failed to unlock user keys") == "account_key_incompatible"
    assert classify_post_reset_v2(1, b"422 GET https://drive-api.proton.me/example") == "proton_api_failure"
    sanitize_verbose_log = diagnostic_module["sanitize_verbose_log"]
    sanitized_lines, redaction_count = sanitize_verbose_log(
        (
            b"DEBUG : Creating backend with remote proton-backup:Backups/.home-lab-rclone-qualification\n"
            b"DEBUG : login backup@example.test password=obscured-target Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
            b"DEBUG : root link ID '01234567-89ab-cdef-0123-456789abcdef' https://drive-api.proton.me/share?token=secret\n"
            b"ERROR : Failed to create file system: user key ID=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n"
        ),
        ("backup@example.test", "obscured-target"),
    )
    sanitized_text = "\n".join(sanitized_lines)
    assert "Creating backend" in sanitized_text and "Proton initialization failed" in sanitized_text
    assert redaction_count == 3
    assert "backup@example.test" not in sanitized_text
    assert "obscured-target" not in sanitized_text
    assert "abcdefghijklmnopqrstuvwxyz" not in sanitized_text
    assert "01234567-89ab-cdef-0123-456789abcdef" not in sanitized_text
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in sanitized_text
    adversarial_verbose = (
        "root link ID 'abcdefghijklmnopqrstuv': account Paul DiLoreto\n"
        "Set-Cookie: session=short-token\n"
        '{"Name":"Paúl Diloréto","Address":"private street","UID":"shortid"}\n'
        "https://drive-api.proton.me/share/short-id/private%40example.test?x=short\n"
        "entirely unknown provider text with personal material\n"
    ).encode()
    adversarial_lines, adversarial_redactions = sanitize_verbose_log(adversarial_verbose, ())
    assert adversarial_redactions == 5
    assert all(re.fullmatch(r"REDACTED : unrecognized_verbose_line_sha256=[0-9a-f]{64}", line) for line in adversarial_lines)
    adversarial_text = "\n".join(adversarial_lines)
    for forbidden in ("abcdefghijklmnopqrstuv", "short-token", "Paúl", "private street", "shortid", "private%40example.test", "personal material"):
        assert forbidden not in adversarial_text
    parse_account_reset_payload = diagnostic_module["parse_account_reset_payload"]
    account_reset_boundary = diagnostic_module["ACCOUNT_RESET_BOUNDARY"]
    diagnostic_error = diagnostic_module["DiagnosticError"]
    old_reset_values = {
        "RESTIC_LOCAL_PASSWORD": "L" * 32,
        "RESTIC_PROTON_PASSWORD": "R" * 32,
        "PROTON_BACKUP_USERNAME": "backup@example.test",
        "PROTON_BACKUP_PASSWORD": "A1" * 20,
        "UNCHANGED_VALUE": "preserved",
    }
    new_reset_values = {**old_reset_values, "PROTON_BACKUP_PASSWORD": "B2" * 20}

    def reset_dotenv(values: dict[str, str]) -> bytes:
        return "".join(f"{key}={value}\n" for key, value in values.items()).encode()

    old_parsed, new_parsed = parse_account_reset_payload(
        reset_dotenv(old_reset_values) + account_reset_boundary + reset_dotenv(new_reset_values)
    )
    assert old_parsed == old_reset_values
    assert new_parsed == new_reset_values
    invalid_reset_payloads = (
        reset_dotenv(old_reset_values) + reset_dotenv(new_reset_values),
        reset_dotenv(old_reset_values) + account_reset_boundary + reset_dotenv({**new_reset_values, "UNCHANGED_VALUE": "drift"}),
        reset_dotenv(old_reset_values)
        + account_reset_boundary
        + reset_dotenv({**new_reset_values, "PROTON_BACKUP_TOTP_SEED": "A" * 32}),
        reset_dotenv(old_reset_values)
        + account_reset_boundary
        + reset_dotenv({**new_reset_values, "PROTON_BACKUP_MAILBOX_PASSWORD": "mailbox"}),
    )
    for invalid_payload in invalid_reset_payloads:
        try:
            parse_account_reset_payload(invalid_payload)
        except diagnostic_error:
            pass
        else:
            raise AssertionError("invalid account-reset secret payload passed")

    run_account_reset = diagnostic_module["run_account_reset_under_lock"]
    original_digest = diagnostic_module["digest_file"]
    reset_globals = run_account_reset.__globals__
    reset_global_names = (
        "os",
        "pwd",
        "grp",
        "CONFIG",
        "CACHE",
        "MUTEX",
        "EVIDENCE_PARENT",
        "RCLONE",
        "INSTALLED_CIPHERTEXT",
        "require_regular",
        "require_directory",
        "require_no_backup_processes",
        "require_empty_cache",
        "load_policy",
        "validate_lock",
        "load_auth_diagnostic_evidence",
        "load_credential_rotation_evidence",
        "load_password_only_evidence",
        "load_beta_evidence",
        "obscure",
        "atomic_config",
        "atomic_json",
    )
    saved_reset_globals = {name: reset_globals[name] for name in reset_global_names}

    class RootIdentity:
        @staticmethod
        def getuid() -> int:
            return 0

        @staticmethod
        def getgid() -> int:
            return 0

    class ServiceIdentity:
        pw_uid = 60000
        pw_gid = 60000
        gr_gid = 60000

    with tempfile.TemporaryDirectory() as account_reset_directory:
        reset_root = Path(account_reset_directory)
        config_path = reset_root / "rclone.conf"
        cache_path = reset_root / "cache"
        cache_path.mkdir()
        evidence_path = reset_root / "evidence"
        evidence_path.mkdir()
        rclone_path = reset_root / "rclone"
        rclone_path.write_bytes(b"stable-rclone")
        prior_ciphertext_path = reset_root / "installed.sops.env"
        prior_ciphertext_path.write_bytes(b"prior-ciphertext")
        target_ciphertext_path = reset_root / "target.sops.env"
        target_ciphertext_path.write_bytes(b"target-ciphertext")
        prior_config = (
            "[proton-backup]\n"
            "type = protondrive\n"
            "username = backup@example.test\n"
            "password = obscured-old\n"
            "replace_existing_draft = true\n"
            "enable_caching = true\n"
            "original_file_size = true\n\n"
        ).encode()
        config_path.write_bytes(prior_config)
        transaction = "a" * 64
        auth_hash = "b" * 64
        rotation_hash = "c" * 64
        transition_hash = "d" * 64
        deployment_hash = "e" * 64
        beta_hash = "f" * 64
        beta_binary_hash = "1" * 64
        target_ciphertext_hash = original_digest(target_ciphertext_path)
        prior_ciphertext_hash = original_digest(prior_ciphertext_path)
        prior_config_hash = hashlib.sha256(prior_config).hexdigest()
        username_hash = hashlib.sha256(b"backup@example.test").hexdigest()
        payload = reset_dotenv(old_reset_values) + account_reset_boundary + reset_dotenv(new_reset_values)
        obscure_calls: list[str] = []

        def fake_atomic_config(parser: object, _uid: int, _gid: int) -> None:
            config_path.write_bytes(diagnostic_module["config_content"](parser))

        def fake_atomic_json(path: Path, value: dict[str, object], replace: bool) -> str:
            if not replace and path.exists():
                raise diagnostic_error("prior_diagnostic_evidence")
            content = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            path.write_bytes(content)
            return hashlib.sha256(content).hexdigest()

        try:
            reset_globals.update(
                {
                    "os": RootIdentity,
                    "pwd": type("Pwd", (), {"getpwnam": staticmethod(lambda _name: ServiceIdentity())}),
                    "grp": type("Grp", (), {"getgrnam": staticmethod(lambda _name: ServiceIdentity())}),
                    "CONFIG": config_path,
                    "CACHE": cache_path,
                    "MUTEX": reset_root / "mutex",
                    "EVIDENCE_PARENT": evidence_path,
                    "RCLONE": rclone_path,
                    "INSTALLED_CIPHERTEXT": prior_ciphertext_path,
                    "require_regular": lambda *_args: None,
                    "require_directory": lambda *_args: None,
                    "require_no_backup_processes": lambda: None,
                    "require_empty_cache": lambda *_args: None,
                    "load_policy": lambda _gid: {
                        "qualification": {"username_sha256": username_hash},
                        "proton": {"authentication_mode": "password-only"},
                        "tools": {"rclone": {"installed_sha256": original_digest(rclone_path)}},
                    },
                    "validate_lock": lambda _transaction: b"retained-owner-bytes",
                    "load_auth_diagnostic_evidence": lambda *_args: {"account_username_sha256": username_hash},
                    "load_credential_rotation_evidence": lambda *_args: {"account_username_sha256": username_hash},
                    "load_password_only_evidence": lambda *_args: (
                        {
                            "auth_diagnostic_evidence_sha256": auth_hash,
                            "credential_rotation_evidence_sha256": rotation_hash,
                        },
                        {
                            "transition_evidence_sha256": transition_hash,
                            "ciphertext_sha256": prior_ciphertext_hash,
                        },
                    ),
                    "load_beta_evidence": lambda *_args: {},
                    "obscure": lambda value: obscure_calls.append(value) or "obscured-target",
                    "atomic_config": fake_atomic_config,
                    "atomic_json": fake_atomic_json,
                }
            )
            arguments = (
                transaction,
                auth_diagnostic_sha256,
                target_ciphertext_path,
                target_ciphertext_hash,
                prior_config_hash,
                auth_hash,
                rotation_hash,
                transition_hash,
                deployment_hash,
                beta_hash,
                beta_binary_hash,
                "1.76.0-beta.test",
                payload,
            )
            with contextlib.redirect_stdout(io.StringIO()) as first_output:
                run_account_reset(*arguments)
            assert first_output.getvalue().startswith("proton_account_reset_reconciliation=passed evidence_sha256=")
            final_evidence_path = evidence_path / f"proton-account-reset-reconciliation-{transaction}.json"
            final_evidence = json.loads(final_evidence_path.read_text())
            assert final_evidence["provider_requests"] == 0
            assert final_evidence["state"] == "reconciled"
            assert hashlib.sha256(config_path.read_bytes()).hexdigest() == final_evidence["installed_config_sha256"]
            assert set(diagnostic_module["parser_from_config"]()["proton-backup"]) == diagnostic_module["PASSWORD_ONLY_KEYS"]
            assert obscure_calls == [new_reset_values["PROTON_BACKUP_PASSWORD"]]
            completed_config = config_path.read_bytes()
            completed_evidence = final_evidence_path.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                run_account_reset(*arguments)
            assert config_path.read_bytes() == completed_config
            assert final_evidence_path.read_bytes() == completed_evidence

            final_evidence_path.unlink()
            config_path.write_bytes(prior_config)
            real_atomic_json = reset_globals["atomic_json"]
            claim_interrupted = False

            def interrupt_after_claim(path: Path, value: dict[str, object], replace: bool) -> str:
                nonlocal claim_interrupted
                digest = fake_atomic_json(path, value, replace)
                if not replace and not claim_interrupted:
                    claim_interrupted = True
                    raise diagnostic_error("fixture_interrupted_after_claim")
                return digest

            reset_globals["atomic_json"] = interrupt_after_claim
            try:
                run_account_reset(*arguments)
            except diagnostic_error:
                pass
            else:
                raise AssertionError("account-reset claim interruption did not fail")
            assert config_path.read_bytes() == prior_config
            assert json.loads(final_evidence_path.read_text())["state"] == "started"
            reset_globals["atomic_json"] = real_atomic_json
            with contextlib.redirect_stdout(io.StringIO()):
                run_account_reset(*arguments)
            assert json.loads(final_evidence_path.read_text())["state"] == "reconciled"

            final_evidence_path.unlink()
            config_path.write_bytes(prior_config)
            real_atomic_config = reset_globals["atomic_config"]

            def interrupt_after_config(parser: object, uid: int, gid: int) -> None:
                real_atomic_config(parser, uid, gid)
                raise diagnostic_error("fixture_interrupted_after_config")

            reset_globals["atomic_config"] = interrupt_after_config
            try:
                run_account_reset(*arguments)
            except diagnostic_error:
                pass
            else:
                raise AssertionError("account-reset config interruption did not fail")
            assert json.loads(final_evidence_path.read_text())["state"] == "started"
            reset_globals["atomic_config"] = real_atomic_config
            with contextlib.redirect_stdout(io.StringIO()):
                run_account_reset(*arguments)
            assert json.loads(final_evidence_path.read_text())["state"] == "reconciled"

            final_evidence_path.unlink()
            config_path.write_bytes(prior_config)
            reset_globals["atomic_json"] = interrupt_after_claim
            claim_interrupted = False
            try:
                run_account_reset(*arguments)
            except diagnostic_error:
                pass
            marker = json.loads(final_evidence_path.read_text())
            marker["beta_evidence_sha256"] = "0" * 64
            final_evidence_path.write_text(json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n")
            reset_globals["atomic_json"] = real_atomic_json
            try:
                run_account_reset(*arguments)
            except diagnostic_error:
                pass
            else:
                raise AssertionError("mismatched account-reset evidence resumed")

            cache_marker = cache_path / "unexpected-cache"
            cache_marker.write_bytes(b"cache")
            try:
                saved_reset_globals["require_empty_cache"](60000, 60000)
            except diagnostic_error as error:
                assert str(error) == "account_reset_cache_state"
            else:
                raise AssertionError("account-reset cache drift passed")
            cache_marker.unlink()
        finally:
            reset_globals.update(saved_reset_globals)

    load_post_reset = diagnostic_module["load_account_reset_reconciliation"]
    post_reset_globals = load_post_reset.__globals__
    saved_post_reset_parent = post_reset_globals["EVIDENCE_PARENT"]
    saved_post_reset_regular = post_reset_globals["require_regular"]
    with tempfile.TemporaryDirectory() as post_reset_directory:
        post_reset_root = Path(post_reset_directory)
        transaction = "a" * 64
        username_hash = hashlib.sha256(b"backup@example.test").hexdigest()
        config_hash = hashlib.sha256(b"reconciled-config").hexdigest()
        referenced_paths = {
            "auth_diagnostic_evidence_sha256": post_reset_root / f"proton-auth-diagnostic-{transaction}.json",
            "beta_evidence_sha256": post_reset_root / f"proton-beta-diagnostic-{transaction}.json",
            "credential_rotation_evidence_sha256": post_reset_root / f"proton-credential-rotation-{transaction}.json",
            "deployment_evidence_sha256": post_reset_root / f"proton-password-only-deployment-{transaction}.json",
            "transition_evidence_sha256": post_reset_root / f"proton-password-only-transition-{transaction}.json",
        }
        referenced_hashes = {}
        for index, (key, path) in enumerate(referenced_paths.items()):
            path.write_bytes(f"evidence-{index}\n".encode())
            referenced_hashes[key] = hashlib.sha256(path.read_bytes()).hexdigest()
        reconciliation = {
            **referenced_hashes,
            "account_username_sha256": username_hash,
            "account_reset_attestation": "disposable-account-reset-without-data-recovery",
            "cache_state": "absent",
            "config_reconciliation": "pass",
            "installed_config_sha256": config_hash,
            "prior_ciphertext_sha256": "1" * 64,
            "prior_config_sha256": "2" * 64,
            "provider_requests": 0,
            "reconciled_at": "2026-08-25T00:00:01Z",
            "started_at": "2026-08-25T00:00:00Z",
            "state": "reconciled",
            "target_ciphertext_sha256": "3" * 64,
            "target_config_sha256": config_hash,
            "transaction_sha256": transaction,
            "version": 1,
        }
        reconciliation_path = post_reset_root / f"proton-account-reset-reconciliation-{transaction}.json"
        reconciliation_content = (json.dumps(reconciliation, sort_keys=True, separators=(",", ":")) + "\n").encode()
        reconciliation_path.write_bytes(reconciliation_content)
        reconciliation_hash = hashlib.sha256(reconciliation_content).hexdigest()
        try:
            post_reset_globals["EVIDENCE_PARENT"] = post_reset_root
            post_reset_globals["require_regular"] = lambda *_args: None
            loaded_reconciliation = load_post_reset(
                transaction,
                reconciliation_hash,
                config_hash,
                username_hash,
            )
            assert loaded_reconciliation == reconciliation
            referenced_paths["beta_evidence_sha256"].write_bytes(b"drift\n")
            try:
                load_post_reset(transaction, reconciliation_hash, config_hash, username_hash)
            except diagnostic_error as error:
                assert str(error) == "post_reset_referenced_evidence"
            else:
                raise AssertionError("post-reset referenced evidence drift passed")
        finally:
            post_reset_globals["EVIDENCE_PARENT"] = saved_post_reset_parent
            post_reset_globals["require_regular"] = saved_post_reset_regular

    run_post_reset = diagnostic_module["run_post_reset_diagnostic_under_lock"]
    run_post_reset_globals = run_post_reset.__globals__
    post_reset_names = (
        "os",
        "pwd",
        "grp",
        "CONFIG",
        "CACHE",
        "MUTEX",
        "EVIDENCE_PARENT",
        "RCLONE",
        "RUNUSER",
        "INSTALL",
        "require_regular",
        "require_directory",
        "load_policy",
        "validate_lock",
        "require_no_backup_processes",
        "load_account_reset_reconciliation",
        "bounded_subprocess",
        "atomic_json",
        "POST_RESET_V2_EVIDENCE_SHA256",
        "POST_RESET_V3_EVIDENCE_SHA256",
    )
    saved_post_reset_globals = {name: run_post_reset_globals[name] for name in post_reset_names}
    with tempfile.TemporaryDirectory() as post_reset_run_directory:
        post_reset_root = Path(post_reset_run_directory)
        post_reset_config = post_reset_root / "rclone.conf"
        post_reset_cache = post_reset_root / "cache"
        post_reset_cache.mkdir()
        post_reset_evidence = post_reset_root / "evidence"
        post_reset_evidence.mkdir()
        post_reset_rclone = post_reset_root / "rclone"
        post_reset_rclone.write_bytes(b"stable-rclone")
        post_reset_config_bytes = (
            "[proton-backup]\n"
            "type = protondrive\n"
            "username = backup@example.test\n"
            "password = obscured-target\n"
            "replace_existing_draft = true\n"
            "enable_caching = true\n"
            "original_file_size = true\n\n"
        ).encode()
        post_reset_config.write_bytes(post_reset_config_bytes)
        transaction = "a" * 64
        account_reset_hash = "b" * 64
        config_hash = hashlib.sha256(post_reset_config_bytes).hexdigest()
        username_hash = hashlib.sha256(b"backup@example.test").hexdigest()
        bounded_calls: list[tuple[list[str], dict[str, str]]] = []

        def fake_post_reset_atomic(path: Path, value: dict[str, object], replace: bool) -> str:
            if not replace and path.exists():
                raise diagnostic_error("prior_post_reset_diagnostic")
            content = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            path.write_bytes(content)
            return hashlib.sha256(content).hexdigest()

        def successful_post_reset_bounded(
            command: list[str],
            _timeout: int,
            environment: dict[str, str],
            _input_data: bytes | None = None,
            _inherit_stdin: bool = False,
        ) -> subprocess.CompletedProcess[bytes]:
            bounded_calls.append((command, environment))
            if len(bounded_calls) < 3:
                return subprocess.CompletedProcess(command, 1, b"", b"opaque provider failure")
            if len(bounded_calls) == 3:
                verbose = (
                    b"DEBUG : rclone: Version v1.75.0 starting with parameters\n"
                    b"DEBUG : Creating backend with remote proton-backup:Backups/.home-lab-rclone-qualification\n"
                    b"DEBUG : Using config file from /dev/null\n"
                    b"ERROR : Failed to create file system for proton-backup: local environment remote mismatch\n"
                )
                return subprocess.CompletedProcess(command, 1, b"", verbose)
            verbose = (
                b"DEBUG : rclone: Version v1.75.0 starting with parameters\n"
                b"DEBUG : Creating backend with remote proton_backup:Backups/.home-lab-rclone-qualification\n"
                b"DEBUG : Using config file from /dev/null\n"
                b"DEBUG : proton drive root link ID 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456': Using username and password to log in\n"
                b"DEBUG : proton drive root link ID 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456': Used username and password to initialize the ProtonDrive API\n"
                b"ERROR : directory not found\n"
            )
            return subprocess.CompletedProcess(command, 3, b"", verbose)

        try:
            run_post_reset_globals.update(
                {
                    "os": RootIdentity,
                    "pwd": type("Pwd", (), {"getpwnam": staticmethod(lambda _name: ServiceIdentity())}),
                    "grp": type("Grp", (), {"getgrnam": staticmethod(lambda _name: ServiceIdentity())}),
                    "CONFIG": post_reset_config,
                    "CACHE": post_reset_cache,
                    "MUTEX": post_reset_root / "mutex",
                    "EVIDENCE_PARENT": post_reset_evidence,
                    "RCLONE": post_reset_rclone,
                    "RUNUSER": Path("/usr/sbin/runuser"),
                    "INSTALL": Path("/usr/bin/install"),
                    "require_regular": lambda *_args: None,
                    "require_directory": lambda *_args: None,
                    "load_policy": lambda _gid: {
                        "qualification": {"username_sha256": username_hash},
                        "proton": {"authentication_mode": "password-only"},
                        "tools": {"rclone": {"installed_sha256": original_digest(post_reset_rclone)}},
                    },
                    "validate_lock": lambda _transaction: b"retained-owner-bytes",
                    "require_no_backup_processes": lambda: None,
                    "load_account_reset_reconciliation": lambda *_args: {},
                    "bounded_subprocess": successful_post_reset_bounded,
                    "atomic_json": fake_post_reset_atomic,
                }
            )
            with contextlib.redirect_stdout(io.StringIO()) as post_reset_output:
                run_post_reset(transaction, auth_diagnostic_sha256, account_reset_hash, config_hash)
            assert post_reset_output.getvalue().startswith(
                "proton_post_reset_diagnostic=observed category=rclone_unclassified evidence_sha256="
            )
            assert len(bounded_calls) == 1
            command, environment = bounded_calls[0]
            assert command.count("lsjson") == 1
            assert command[command.index("--config") + 1] == "/dev/null"
            diagnostic_config_environment = {
                key: value
                for key, value in environment.items()
                if key.startswith("RCLONE_CONFIG_PROTON_BACKUP_")
            }
            assert diagnostic_config_environment == {
                "RCLONE_CONFIG_PROTON_BACKUP_TYPE": "protondrive",
                "RCLONE_CONFIG_PROTON_BACKUP_USERNAME": "backup@example.test",
                "RCLONE_CONFIG_PROTON_BACKUP_PASSWORD": "obscured-target",
                "RCLONE_CONFIG_PROTON_BACKUP_REPLACE_EXISTING_DRAFT": "true",
                "RCLONE_CONFIG_PROTON_BACKUP_ENABLE_CACHING": "false",
                "RCLONE_CONFIG_PROTON_BACKUP_ORIGINAL_FILE_SIZE": "true",
            }
            assert post_reset_config.read_bytes() == post_reset_config_bytes
            assert not any(post_reset_cache.iterdir())
            result_path = post_reset_evidence / f"proton-post-reset-diagnostic-{transaction}.json"
            result = json.loads(result_path.read_text())
            assert result["provider_requests"] == 1
            assert result["state"] == "observed"
            prior_diagnostic_hash = hashlib.sha256(result_path.read_bytes()).hexdigest()
            with contextlib.redirect_stdout(io.StringIO()):
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    prior_diagnostic_hash,
                    2,
                )
            assert len(bounded_calls) == 2
            v2_path = post_reset_evidence / f"proton-post-reset-diagnostic-v2-{transaction}.json"
            v2_result = json.loads(v2_path.read_text())
            assert v2_result["category"] == "rclone_unclassified"
            assert v2_result["prior_diagnostic_evidence_sha256"] == prior_diagnostic_hash
            assert v2_result["provider_requests"] == 1
            assert v2_result["version"] == 2
            v2_hash = hashlib.sha256(v2_path.read_bytes()).hexdigest()
            run_post_reset_globals["POST_RESET_V2_EVIDENCE_SHA256"] = v2_hash
            try:
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    "0" * 64,
                    3,
                )
            except diagnostic_error as error:
                assert str(error) == "post_reset_prior_diagnostic"
            else:
                raise AssertionError("post-reset v3 accepted an unpinned v2 evidence hash")
            assert len(bounded_calls) == 2
            with contextlib.redirect_stdout(io.StringIO()):
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    v2_hash,
                    3,
                )
            assert len(bounded_calls) == 3
            v3_command, _v3_environment = bounded_calls[2]
            assert "-vv" in v3_command
            assert "--log-level" not in v3_command
            v3_path = post_reset_evidence / f"proton-post-reset-diagnostic-v3-{transaction}.json"
            v3_result = json.loads(v3_path.read_text())
            assert v3_result["browser_drive_initialized"] is True
            assert v3_result["category"] == "rclone_unclassified"
            assert v3_result["log_level"] == "DEBUG"
            assert v3_result["prior_diagnostic_evidence_sha256"] == v2_hash
            assert v3_result["provider_requests"] == 1
            assert v3_result["verbose_log_redactions"] >= 1
            assert v3_result["version"] == 3
            v3_log = "\n".join(v3_result["verbose_log"])
            assert "backup@example.test" not in v3_log
            assert "obscured-target" not in v3_log
            assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in v3_log
            v3_hash = hashlib.sha256(v3_path.read_bytes()).hexdigest()
            run_post_reset_globals["POST_RESET_V3_EVIDENCE_SHA256"] = v3_hash
            try:
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    "0" * 64,
                    4,
                )
            except diagnostic_error as error:
                assert str(error) == "post_reset_prior_diagnostic"
            else:
                raise AssertionError("post-reset v4 accepted an unpinned v3 evidence hash")
            assert len(bounded_calls) == 3
            with contextlib.redirect_stdout(io.StringIO()):
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    v3_hash,
                    4,
                )
            assert len(bounded_calls) == 4
            v4_command, _v4_environment = bounded_calls[3]
            assert f"proton_backup:{diagnostic_module['REMOTE_DIRECTORY']}" in v4_command
            v4_path = post_reset_evidence / f"proton-post-reset-diagnostic-v4-{transaction}.json"
            v4_result = json.loads(v4_path.read_text())
            assert v4_result["category"] == "reachable"
            assert v4_result["diagnostic_remote_name"] == "proton_backup"
            assert v4_result["prior_diagnostic_evidence_sha256"] == v3_hash
            assert v4_result["prior_provider_requests_reclassified"] == 0
            assert v4_result["provider_request_boundary"] == "backend-recognized-environment-remote"
            assert v4_result["provider_requests"] == 1
            assert v4_result["version"] == 4
            try:
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    v3_hash,
                    4,
                )
            except diagnostic_error as error:
                assert str(error) == "prior_post_reset_diagnostic"
            else:
                raise AssertionError("post-reset v4 provider diagnostic replay passed")
            try:
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    v2_hash,
                    3,
                )
            except diagnostic_error as error:
                assert str(error) == "prior_post_reset_diagnostic"
            else:
                raise AssertionError("post-reset v3 provider diagnostic replay passed")
            try:
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    prior_diagnostic_hash,
                    2,
                )
            except diagnostic_error as error:
                assert str(error) == "prior_post_reset_diagnostic"
            else:
                raise AssertionError("post-reset v2 provider diagnostic replay passed")
            try:
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    "0" * 64,
                    2,
                )
            except diagnostic_error as error:
                assert str(error) == "post_reset_prior_diagnostic"
            else:
                raise AssertionError("post-reset v2 accepted a mismatched prior hash")
            prior_bytes = result_path.read_bytes()
            wrong_prior = json.loads(prior_bytes)
            wrong_prior["category"] = "reachable"
            wrong_prior_bytes = (json.dumps(wrong_prior, sort_keys=True, separators=(",", ":")) + "\n").encode()
            result_path.write_bytes(wrong_prior_bytes)
            try:
                run_post_reset(
                    transaction,
                    auth_diagnostic_sha256,
                    account_reset_hash,
                    config_hash,
                    hashlib.sha256(wrong_prior_bytes).hexdigest(),
                    2,
                )
            except diagnostic_error as error:
                assert str(error) == "post_reset_prior_diagnostic"
            else:
                raise AssertionError("post-reset v2 accepted a classified prior result")
            result_path.write_bytes(prior_bytes)
            try:
                run_post_reset(transaction, auth_diagnostic_sha256, account_reset_hash, config_hash)
            except diagnostic_error as error:
                assert str(error) == "prior_post_reset_diagnostic"
            else:
                raise AssertionError("post-reset provider diagnostic replay passed")
            assert len(bounded_calls) == 4

            for failure_name in ("timeout", "exec"):
                result_path.unlink()
                bounded_calls.clear()
                if failure_name == "timeout":
                    def failing_bounded(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
                        raise subprocess.TimeoutExpired("rclone", 600)
                else:
                    def failing_bounded(command: list[str], *_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
                        bounded_calls.append((command, {}))
                        return subprocess.CompletedProcess(command, 126, b"", b"local exec failure")
                run_post_reset_globals["bounded_subprocess"] = failing_bounded
                try:
                    run_post_reset(transaction, auth_diagnostic_sha256, account_reset_hash, config_hash)
                except (diagnostic_error, subprocess.TimeoutExpired):
                    pass
                else:
                    raise AssertionError(f"post-reset {failure_name} fixture passed")
                assert json.loads(result_path.read_text())["state"] == "started"
                assert post_reset_config.read_bytes() == post_reset_config_bytes
                assert not any(post_reset_cache.iterdir())
        finally:
            run_post_reset_globals.update(saved_post_reset_globals)

    account_reset_playbook = (ROOT / "ansible/playbooks/reconcile-proton-account-reset.yml").read_text()
    assert f"proton_account_reset_script_sha256: {auth_diagnostic_sha256}" in account_reset_playbook
    assert "reconcile-only-password-after-disposable-proton-account-reset" in account_reset_playbook
    assert "account-reset-supervise" in account_reset_playbook
    assert "proton_account_reset_expected_beta_evidence_sha256" in account_reset_playbook
    assert "proton_account_reset_expected_prior_config_sha256" in account_reset_playbook
    assert "PROTON_BACKUP_PASSWORD changed" in account_reset_playbook
    assert "Require exact resumable account-reset reconciliation claim" in account_reset_playbook
    assert "observed_config_sha256 in [marker.prior_config_sha256, marker.target_config_sha256]" in account_reset_playbook
    assert "reason=[a-z0-9_.-]+\\r?$" in account_reset_playbook
    assert "reason=[a-z0-9_.-]+\\\\r?$" not in account_reset_playbook
    assert "account_reset_failure_match" in account_reset_playbook
    assert "proton_account_reset_run.stderr" in account_reset_playbook
    assert "account_reset_failure_output\n              | regex_search" not in account_reset_playbook
    assert "provider_requests == 0" in account_reset_playbook
    assert "apply_lock_action: release" not in account_reset_playbook
    assert "/etc/home-lab/restic/production.sops.env" in account_reset_playbook
    assert "/usr/bin/printf 'HOME_LAB_PROTON_ACCOUNT_RESET_BOUNDARY_7b9e0c4f2ad68135\\n'" in account_reset_playbook
    assert "export SOPS_AGE_KEY_FILE=/etc/sops/age/keys.txt &&" in account_reset_playbook
    assert "/usr/local/bin/sops --decrypt --output-type dotenv /etc/home-lab/restic/production.sops.env &&" in account_reset_playbook
    assert "--output-type dotenv\n                /etc/home-lab/restic/production.sops.env" not in account_reset_playbook

    quota_diagnostic_path = ROOT / "scripts/diagnose-proton-quota"
    quota_diagnostic = quota_diagnostic_path.read_text()
    assert '"about", "proton_backup:", "--json"' in quota_diagnostic
    assert quota_diagnostic.count('"about", "proton_backup:", "--json"') == 1
    assert '"--config", "/dev/null"' in quota_diagnostic
    assert '"RCLONE_CONFIG_PROTON_BACKUP_ENABLE_CACHING": "false"' in quota_diagnostic
    assert "os.O_EXCL" in quota_diagnostic
    assert '"provider_requests": 1' in quota_diagnostic
    assert '"stable_rclone_sha256": expected_rclone' in quota_diagnostic
    assert 'for name in ("total", "used", "free")' in quota_diagnostic
    assert "print(result.stdout" not in quota_diagnostic and "print(result.stderr" not in quota_diagnostic
    assert quota_diagnostic.count("require_no_processes()") >= 2
    assert "require_regular(MUTEX, 0, service_group.gr_gid, 0o660)" in quota_diagnostic
    assert "rclone_process_group_survived" in quota_diagnostic
    assert "write_all(descriptor, content)" in quota_diagnostic
    assert "validate_post_state(" in quota_diagnostic
    quota_module = runpy.run_path(
        str(quota_diagnostic_path),
        run_name="diagnose_proton_quota_test_module",
    )
    try:
        quota_module["bounded"](
            ["/bin/sh", "-c", "exec /bin/sleep 30"],
            {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
            0.05,
        )
    except subprocess.TimeoutExpired:
        pass
    else:
        raise AssertionError("quota diagnostic timeout did not abort")
    staged_recovery_path = ROOT / "scripts/supervise-staged-proton-recovery"
    staged_recovery = staged_recovery_path.read_text()
    assert 'Path(f"/run/qualify-proton-backup-recovery-{transaction}")' in staged_recovery
    assert 'digest(owner) != transaction' in staged_recovery
    assert 'require_regular(staged, 0, 0, 0o755)' in staged_recovery
    assert 'str(FLOCK), "--exclusive", "--nonblock", "--conflict-exit-code", "75"' in staged_recovery
    assert 'str(RUNUSER), "--user", "restic-proton"' in staged_recovery
    assert 'PYTHON = Path("/usr/bin/python3.13")' in staged_recovery
    assert 'str(PYTHON), str(staged)' in staged_recovery
    assert "validate_post_state(" in staged_recovery
    assert 'QUALIFICATION_EVIDENCE.exists()' in staged_recovery
    assert "remove_validated_staged(" in staged_recovery
    assert "print(result.stdout" not in staged_recovery and "print(result.stderr" not in staged_recovery
    staged_recovery_module = runpy.run_path(
        str(staged_recovery_path),
        run_name="supervise_staged_proton_recovery_test_module",
    )
    controlled_child_error = b"proton_qualification=failed reason=qualification_directory_output\n"
    assert staged_recovery_module["child_failure_reason"](controlled_child_error) == "qualification_directory_output"
    protected_child_error = b"provider response contains protected account data"
    assert staged_recovery_module["child_failure_reason"](protected_child_error) == (
        "stderr_sha256_" + hashlib.sha256(protected_child_error).hexdigest()
    )
    try:
        staged_recovery_module["bounded"](
            ["/bin/sh", "-c", "exec /bin/sleep 30"],
            0.05,
        )
    except subprocess.TimeoutExpired:
        pass
    else:
        raise AssertionError("staged Proton recovery timeout did not abort")
    with tempfile.TemporaryDirectory() as staged_artifact_directory:
        artifact_root = Path(staged_artifact_directory)
        artifact = artifact_root / "helper"
        artifact.write_bytes(b"reviewed helper")
        artifact.chmod(0o600)
        assert staged_recovery_module["require_regular"](artifact, os.getuid(), os.getgid(), 0o600) == b"reviewed helper"
        artifact.chmod(0o644)
        try:
            staged_recovery_module["require_regular"](artifact, os.getuid(), os.getgid(), 0o600)
        except staged_recovery_module["RecoveryError"] as error:
            assert str(error) == "helper_metadata"
        else:
            raise AssertionError("unsafe staged recovery metadata was accepted")
        artifact.unlink()
        artifact.symlink_to(staged_recovery_path)
        try:
            staged_recovery_module["require_regular"](artifact, os.getuid(), os.getgid(), 0o777)
        except staged_recovery_module["RecoveryError"] as error:
            assert str(error) == "helper_type"
        else:
            raise AssertionError("staged recovery symlink was accepted")
        artifact.unlink()
        artifact.write_bytes(b"reviewed helper")
        artifact.chmod(0o755)
        reviewed_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
        staged_recovery_module["remove_validated_staged"](
            artifact, reviewed_hash, False, os.getuid(), os.getgid()
        )
        assert artifact.exists()
        staged_recovery_module["remove_validated_staged"](
            artifact, "0" * 64, True, os.getuid(), os.getgid()
        )
        assert artifact.exists()
        artifact.chmod(0o644)
        staged_recovery_module["remove_validated_staged"](
            artifact, reviewed_hash, True, os.getuid(), os.getgid()
        )
        assert artifact.exists()
        artifact.chmod(0o755)
        staged_recovery_module["remove_validated_staged"](
            artifact, reviewed_hash, True, os.getuid(), os.getgid()
        )
        assert not artifact.exists()
    staged_finalizer_path = ROOT / "scripts/finalize-staged-proton-recovery"
    staged_finalizer = staged_finalizer_path.read_text()
    assert "os.O_EXCL" in staged_finalizer
    assert "signal.pthread_sigmask" in staged_finalizer
    assert "fcntl.LOCK_EX | fcntl.LOCK_NB" in staged_finalizer
    assert staged_finalizer.index("mutex_descriptor = acquire_mutex()") < staged_finalizer.index("publish(destination, result_raw)")
    assert "if not result_present and not evidence_present:" in staged_finalizer
    assert staged_finalizer.index("publish(destination, result_raw)") < staged_finalizer.index("RESULT.unlink()")
    assert staged_finalizer.index("RESULT.unlink()") < staged_finalizer.index('(APPLY_LOCK / "owner").unlink()')
    assert staged_finalizer.index('(APPLY_LOCK / "owner").unlink()') < staged_finalizer.index("APPLY_LOCK.rmdir()")
    staged_finalizer_module = runpy.run_path(
        str(staged_finalizer_path),
        run_name="finalize_staged_proton_recovery_test_module",
    )
    finalizer_globals = staged_finalizer_module["acquire_mutex"].__globals__
    saved_finalizer_mutex = finalizer_globals["MUTEX"]
    with tempfile.TemporaryDirectory() as finalizer_state_directory:
        finalizer_root = Path(finalizer_state_directory)
        test_mutex = finalizer_root / "backup.lock"
        test_mutex.touch(mode=0o660)
        test_mutex.chmod(0o660)
        finalizer_globals["MUTEX"] = test_mutex
        mutex_descriptor = staged_finalizer_module["acquire_mutex"](os.getuid(), os.getgid())
        try:
            try:
                staged_finalizer_module["acquire_mutex"](os.getuid(), os.getgid())
            except staged_finalizer_module["FinalizationError"] as error:
                assert str(error) == "mutex_busy"
            else:
                raise AssertionError("concurrent staged finalization acquired the mutex")
        finally:
            os.close(mutex_descriptor)
            finalizer_globals["MUTEX"] = saved_finalizer_mutex
        resumed_evidence = finalizer_root / "recovery.json"
        recovery_bytes = b'{"state":"recovered"}\n'
        staged_finalizer_module["publish"](
            resumed_evidence, recovery_bytes, os.getuid(), os.getgid()
        )
        staged_finalizer_module["publish"](
            resumed_evidence, recovery_bytes, os.getuid(), os.getgid()
        )
        try:
            staged_finalizer_module["publish"](
                resumed_evidence, b"different\n", os.getuid(), os.getgid()
            )
        except staged_finalizer_module["FinalizationError"] as error:
            assert str(error) == "prior_recovery_evidence"
        else:
            raise AssertionError("differing resumed recovery evidence passed")
    transaction = "d" * 64
    username_hash = "e" * 64
    valid_recovery = {
        "account_username_sha256": username_hash,
        "recovered_at": "2026-08-26T00:00:00Z",
        "recovered_files": [],
        "remote_cleanup": "pass",
        "state": "recovered",
        "transaction_sha256": transaction,
        "version": 1,
    }
    staged_finalizer_module["validate_evidence"](
        (json.dumps(valid_recovery) + "\n").encode(), transaction, username_hash
    )
    invalid_recovery = {**valid_recovery, "recovered_files": ["unexpected.bin"]}
    try:
        staged_finalizer_module["validate_evidence"](
            (json.dumps(invalid_recovery) + "\n").encode(), transaction, username_hash
        )
    except staged_finalizer_module["FinalizationError"] as error:
        assert str(error) == "result_shape"
    else:
        raise AssertionError("out-of-scope staged recovery result passed")
    post_reset_playbook = (ROOT / "ansible/playbooks/diagnose-proton-post-reset.yml").read_text()
    assert f"proton_post_reset_script_sha256: {auth_diagnostic_sha256}" in post_reset_playbook
    assert "diagnose-one-post-reset-proton-lsjson-v4-corrected-environment-remote" in post_reset_playbook
    assert "post-reset-v4-supervise" in post_reset_playbook
    assert "verbose_log_sha256" in post_reset_playbook
    assert "browser_drive_initialized" in post_reset_playbook
    assert "proton_backup" in post_reset_playbook
    assert "fb511d7a9960217256108a7a5914a89bca8da04e2db7b97fae1c8b39665450bb" in post_reset_playbook
    assert "proton_post_reset_expected_account_reset_evidence_sha256" in post_reset_playbook
    assert "proton_post_reset_expected_config_sha256" in post_reset_playbook
    assert "proton_post_reset_expected_prior_diagnostic_sha256" in post_reset_playbook
    assert "environment-only" in post_reset_playbook
    assert "provider_requests == 1" in post_reset_playbook
    assert "apply_lock_action: release" not in post_reset_playbook
    assert "print(result.stderr" not in auth_diagnostic
    assert '"--config",\n        "/dev/null"' in auth_diagnostic
    assert '"--protondrive-enable-caching=false"' in auth_diagnostic
    assert "proton-post-reset-diagnostic-" in auth_diagnostic
    assert ".proton-post-reset-diagnostic-launch-" not in auth_diagnostic
    assert 'atomic_json(evidence_path, marker, replace=False)' in auth_diagnostic
    bounded_subprocess = diagnostic_module["bounded_subprocess"]
    stdin_reader = [sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"]
    stdin_result = bounded_subprocess(
        stdin_reader,
        10,
        dict(os.environ),
        b"protected-payload",
    )
    assert stdin_result.stdout == b"protected-payload"
    saved_stdin = os.dup(0)
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"inherited-protected-payload")
        os.close(write_fd)
        write_fd = -1
        os.dup2(read_fd, 0)
        inherited_result = bounded_subprocess(
            stdin_reader,
            10,
            dict(os.environ),
            inherit_stdin=True,
        )
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)
        os.dup2(saved_stdin, 0)
        os.close(saved_stdin)
    assert inherited_result.stdout == b"inherited-protected-payload"
    assert "bounded_subprocess(command, 180, controlled_environment(), inherit_stdin=True)" in auth_diagnostic
    assert "raw_payload = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)\n                run_account_reset_under_lock" in auth_diagnostic
    with tempfile.TemporaryDirectory() as process_directory:
        child_pid_path = Path(process_directory) / "child.pid"
        launcher = (
            "import pathlib,subprocess,sys,time;"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
            f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid));"
            "time.sleep(60)"
        )
        try:
            bounded_subprocess([sys.executable, "-c", launcher], 1, dict(os.environ))
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError("bounded subprocess did not enforce timeout")
        child_pid = json.loads(child_pid_path.read_text())
        child_gone = False
        for _attempt in range(50):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                child_gone = True
                break
            time.sleep(0.1)
        assert child_gone, "bounded subprocess left a descendant running"
    assert "start_new_session=True" in auth_diagnostic
    assert "terminate_process_group(process)" in auth_diagnostic
    classify = diagnostic_module["classify"]
    assert classify(0, b"remote listing") == "reachable"
    assert classify(3, b"not found") == "reachable"
    assert classify(1, b"Code=9001") == "api_captcha"
    assert classify(1, b"Code=8002") == "invalid_credentials"
    assert classify(1, b"TOTP rejected") == "two_factor_rejected"
    assert classify(1, b"missing signature") == "account_key_incompatible"
    assert classify(1, b"Status=429") == "rate_limited"
    assert classify(1, b"TLS handshake timeout") == "network_failure"
    assert classify(1, b"opaque provider failure") == "rclone_unclassified"
    for forbidden in ("copyto", "deletefile", "moveto", "rmdir", "purge", "sync", "bisync", "mount"):
        assert f'"{forbidden}"' not in auth_diagnostic
    credential_rotation_playbook = (ROOT / "ansible/playbooks/rotate-proton-login-credential.yml").read_text()
    assert "rotate-only-proton-login-password" in credential_rotation_playbook
    assert f"proton_credential_rotation_script_sha256: {auth_diagnostic_sha256}" in credential_rotation_playbook
    assert "proton_credential_rotation_expected_transaction_sha256" in credential_rotation_playbook
    assert "proton_credential_rotation_expected_auth_evidence_sha256" in credential_rotation_playbook
    assert "SOPS_AGE_KEY_FILE=/etc/sops/age/keys.txt" in credential_rotation_playbook
    assert 'checksum: "{{ sops_sha256 }}"' in credential_rotation_playbook
    assert "PATH=/usr/local/bin:/usr/bin:/bin" in credential_rotation_playbook
    assert "/usr/bin/python3\n              {{ proton_credential_rotation_script_temp | quote }}" in credential_rotation_playbook
    assert "rotate-supervise" in credential_rotation_playbook
    assert "no_log: true" in credential_rotation_playbook
    assert "apply_lock_action: release" not in credential_rotation_playbook
    assert "proton-credential-rotation-{{ proton_credential_rotation_lock_owner.content | b64decode | hash('sha256') }}.json" in credential_rotation_playbook
    assert "Remove only ephemeral Proton credential rotation inputs" in credential_rotation_playbook
    assert 'action not in {"rotate-supervise", "rotate-under-lock"}' in auth_diagnostic
    assert 'remote["password"] = new_obscured_password' in auth_diagnostic
    assert "for key in CACHE_KEYS:" in auth_diagnostic
    assert "rotation_static_config_drift" in auth_diagnostic
    password_only_playbook = (ROOT / "ansible/playbooks/transition-proton-password-only.yml").read_text()
    assert "remove-only-obsolete-proton-totp-field" in password_only_playbook
    assert f"proton_password_only_script_sha256: {auth_diagnostic_sha256}" in password_only_playbook
    assert "password-only-supervise" in password_only_playbook
    assert "provider_requests == 0" in password_only_playbook
    assert "apply_lock_action: release" not in password_only_playbook
    assert 'LEGACY_TOTP_KEY = "otp_secret_key"' in auth_diagnostic
    assert "run_password_only_transition_under_lock" in auth_diagnostic
    assert '"provider_requests": 0' in auth_diagnostic
    assert "proton_totp_seed_forbidden" in auth_diagnostic
    assert "Require exact resumable password-only transition claim" in password_only_playbook
    beta_playbook = (ROOT / "ansible/playbooks/diagnose-proton-beta.yml").read_text()
    assert "diagnose-only-proton-with-official-beta" in beta_playbook
    assert f"proton_beta_script_sha256: {auth_diagnostic_sha256}" in beta_playbook
    assert "proton_beta_archive_sha256: f37f14b7922280dd5b9352e2d1c3101f94739f57d3786132e517fc106cb4c245" in beta_playbook
    assert "proton_beta_binary_sha256: b64e72891b07b0f55462121090e9e200e8e75c7d0b95530ba9c1f06517daeac5" in beta_playbook
    assert "Run exactly one non-mutating Proton lsjson with the beta" in beta_playbook
    assert "Require exact controller-side Proton beta supervisor hash" in beta_playbook
    assert "Remove all ephemeral Proton beta files" in beta_playbook
    assert "apply_lock_action: release" not in beta_playbook
    assert '"--config",\n        "/dev/null"' in auth_diagnostic
    assert '"RCLONE_CONFIG_PROTON_BACKUP_ENABLE_CACHING": "false"' in auth_diagnostic
    assert '"provider_requests": 1' in auth_diagnostic
    assert "beta_installed_artifact_drift" in auth_diagnostic
    assert "tmp_dest: /var/tmp" in beta_playbook
    assert "Ephemeral beta filesystem policy differs" in beta_playbook
    assert "Terminate and verify any residual ephemeral beta process group" in beta_playbook
    assert "Require no residual ephemeral beta process" in beta_playbook
    assert "bounded_subprocess(command, 600, beta_environment)" in auth_diagnostic
    assert "bounded_subprocess(command, 660, controlled_environment())" in auth_diagnostic
    beta_order = [
        beta_playbook.index(name)
        for name in (
            "Require exact controller-side Proton beta supervisor hash",
            "Download checksum-pinned official rclone beta archive",
            "Extract only the hash-pinned beta binary",
            "Stage hash-pinned Proton beta supervisor",
            "Run exactly one non-mutating Proton lsjson with the beta",
            "Terminate and verify any residual ephemeral beta process group",
            "Remove all ephemeral Proton beta files",
            "Read transaction-bound ephemeral Proton beta evidence",
            "Confirm beta observation retained exact qualification lock",
        )
    ]
    assert beta_order == sorted(beta_order)

    load_password_only_evidence = diagnostic_module["load_password_only_evidence"]
    evidence_globals = load_password_only_evidence.__globals__
    with tempfile.TemporaryDirectory() as evidence_directory:
        evidence_root = Path(evidence_directory)
        transaction = "a" * 64
        username_sha256 = "d" * 64
        transition = {
            "account_username_sha256": username_sha256,
            "auth_diagnostic_evidence_sha256": "b" * 64,
            "cache_state": "absent",
            "credential_rotation_evidence_sha256": "c" * 64,
            "provider_requests": 0,
            "removed_field": "otp_secret_key",
            "state": "password-only",
            "transaction_sha256": transaction,
            "transitioned_at": "2026-08-25T00:00:00Z",
            "version": 1,
        }
        deployment = {
            "account_username_sha256": username_sha256,
            "bootstrap_helper_sha256": "e" * 64,
            "ciphertext_sha256": "f" * 64,
            "credential_materialization": "noop",
            "deployed_at": "2026-08-25T00:01:00Z",
            "policy_sha256": "1" * 64,
            "provider_requests": 0,
            "qualification_helper_sha256": "2" * 64,
            "state": "deployed",
            "transaction_sha256": transaction,
            "transition_evidence_sha256": "",
            "version": 1,
        }

        def write_evidence(name: str, value: dict[str, object]) -> str:
            content = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            (evidence_root / name).write_bytes(content)
            return hashlib.sha256(content).hexdigest()

        transition_sha256 = write_evidence(f"proton-password-only-transition-{transaction}.json", transition)
        deployment["transition_evidence_sha256"] = transition_sha256
        deployment_name = f"proton-password-only-deployment-{transaction}.json"
        deployment_sha256 = write_evidence(deployment_name, deployment)
        original_root = evidence_globals["EVIDENCE_PARENT"]
        original_require_regular = evidence_globals["require_regular"]
        evidence_globals["EVIDENCE_PARENT"] = evidence_root
        evidence_globals["require_regular"] = lambda *_args: None
        try:
            load_password_only_evidence(transaction, transition_sha256, deployment_sha256, username_sha256)
            deployment["provider_requests"] = 1
            invalid_deployment_sha256 = write_evidence(deployment_name, deployment)
            try:
                load_password_only_evidence(transaction, transition_sha256, invalid_deployment_sha256, username_sha256)
            except diagnostic_module["DiagnosticError"] as error:
                assert str(error) == "password_only_deployment_evidence_invalid"
            else:
                raise AssertionError("remote-bearing deployment evidence was accepted")
        finally:
            evidence_globals["EVIDENCE_PARENT"] = original_root
            evidence_globals["require_regular"] = original_require_regular
    password_only_deployment = (ROOT / "ansible/playbooks/deploy-proton-password-only-artifacts.yml").read_text()
    assert "deploy-only-password-only-proton-artifacts" in password_only_deployment
    bootstrap_sha256 = hashlib.sha256((ROOT / "scripts/bootstrap-restic-credentials").read_bytes()).hexdigest()
    assert f"proton_password_only_new_bootstrap_sha256: {bootstrap_sha256}" in password_only_deployment
    assert "proton_password_only_deployment_expected_transition_evidence_sha256" in password_only_deployment
    assert 'checksum: "{{ sops_sha256 }}"' in password_only_deployment
    assert "/usr/bin/python3\n          /usr/local/libexec/home-lab/bootstrap-restic-credentials" in password_only_deployment
    assert "provider_requests': 0" in password_only_deployment
    assert "/usr/local/bin/rclone" not in password_only_deployment
    assert "apply_lock_action: release" not in password_only_deployment
    assert "proton_password_only_legacy_policy_sha256" in password_only_deployment
    assert "Require exact controller-side password-only source hashes" in password_only_deployment
    assert "Require single-writer artifact deployment claim" in password_only_deployment
    assert "60000 60000 --check" in password_only_deployment
    assert "restic_credentials=validated state=noop" in password_only_deployment
    deployment_order = [
        password_only_deployment.index(name)
        for name in (
            "Require exact controller-side password-only source hashes",
            "Claim password-only artifact deployment transaction",
            "Require single-writer artifact deployment claim",
            "Install reviewed password-only policy",
            "Install reviewed password-only helpers",
            "Install reviewed password-only SOPS ciphertext",
            "Validate protected password-only credential materialization as a no-op",
            "Finalize password-only artifact deployment evidence",
        )
    ]
    assert deployment_order == sorted(deployment_order)
    parse_rotation_dotenv = diagnostic_module["parse_rotation_dotenv"]
    rotation_values = parse_rotation_dotenv(
        (
            "RESTIC_LOCAL_PASSWORD=" + "L" * 40 + "\n"
            "RESTIC_PROTON_PASSWORD=" + "R" * 40 + "\n"
            "PROTON_BACKUP_USERNAME=backup@example.test\n"
            "PROTON_BACKUP_PASSWORD=" + "A1" * 20 + "\n"
        ).encode()
    )
    assert rotation_values["PROTON_BACKUP_PASSWORD"] == "A1" * 20

    def exact_service_user_command(*action_lines: str) -> str:
        return "\n".join(
            (
                "        argv:",
                "          - /usr/bin/flock",
                "          - --exclusive",
                "          - --nonblock",
                "          - --",
                '          - "{{ backups.restic.runner.lock_path }}"',
                "          - /usr/sbin/runuser",
                "          - --user",
                "          - restic-proton",
                "          - --",
                "          - /usr/local/libexec/home-lab/qualify-proton-backup",
                *(f"          - {line}" for line in action_lines),
                "      become: true",
            )
        )

    exact_service_user_commands = (
        (qualification_playbook, exact_service_user_command("qualify")),
        (resume_playbook, exact_service_user_command("inspect")),
    )
    for service_user_playbook, exact_command in exact_service_user_commands:
        assert exact_command in service_user_playbook
        assert "become_user: restic-proton" not in service_user_playbook
    assert "/run/proton-empty-recovery-{{ proton_recovery_transaction_sha256 }}" in recovery_playbook
    assert "          - /usr/bin/python3" in recovery_playbook
    assert "become_user: restic-proton" not in recovery_playbook
    controlled_failure_pattern = "regex_search('(?m)^proton_qualification=failed reason=[a-z0-9_.-]+\\r?$')"
    for controlled_playbook in (qualification_playbook, recovery_playbook, resume_playbook):
        assert controlled_playbook.count(controlled_failure_pattern) == 2
        assert "failed_when: false" in controlled_playbook
        assert "proton_qualification=failed reason=unclassified_stderr_sha256_" in controlled_playbook
        assert "hash('sha256')" in controlled_playbook
    for forbidden in ("cleanup", "delete", "mount", "nfsmount", "purge", "sync", "bisync"):
        assert f"/usr/local/bin/rclone {forbidden}" not in qualification_playbook

    daily_target = (ROOT / "ansible/roles/restic_backup/templates/home-lab-restic-daily.target.j2").read_text()
    local_service = (ROOT / "ansible/roles/restic_backup/templates/home-lab-restic-daily-local.service.j2").read_text()
    local_mount_requirement = next(line for line in local_service.splitlines() if line.startswith("RequiresMountsFor="))
    assert "repositories.games.mountpoint" in local_mount_requirement
    assert "repositories.nfs.mountpoint" not in local_mount_requirement
    proton_service = (ROOT / "ansible/roles/restic_backup/templates/home-lab-restic-daily-proton.service.j2").read_text()
    post_nfs_recovery = (ROOT / "ansible/playbooks/recover-post-nfs-first-run.yml").read_text()
    first_run_finalize = (ROOT / "ansible/playbooks/finalize-first-restic-backup.yml").read_text()
    timers = list((ROOT / "ansible/roles/restic_backup/templates").glob("*.timer.j2"))
    restic_role_tasks = (ROOT / "ansible/roles/restic_backup/tasks/main.yml").read_text()
    assert "daily-local.service home-lab-restic-daily-proton.service" in daily_target
    assert "Requires=home-lab-restic-daily-local.service" in proton_service
    assert "User=restic-proton" in proton_service
    inaccessible_paths = next(line for line in proton_service.splitlines() if line.startswith("InaccessiblePaths="))
    assert "/mnt/games" not in inaccessible_paths.removeprefix("InaccessiblePaths=").split()
    assert "TemporaryFileSystem=/mnt/games:ro" in proton_service
    assert "BindReadOnlyPaths={{ backups.restic.repositories.games.path }}" in proton_service
    assert "ReadWritePaths=/var/lib/home-lab-restic/replication /var/lib/restic-proton {{ backups.restic.runner.lock_path }}" in proton_service
    assert "Converge the confined Proton mount namespace repair" in post_nfs_recovery
    assert "Reload systemd unconditionally after the confined namespace repair" in post_nfs_recovery
    assert "daemon_reload: true" in post_nfs_recovery
    assert "post_nfs_proton_unit.changed" not in post_nfs_recovery
    assert "Read committed controller evidence inputs" in first_run_finalize
    assert "Read retained host transaction inputs" in first_run_finalize
    assert "'localhost' if item.local else inventory_hostname" not in first_run_finalize
    assert len(timers) == 2
    assert all("proton" not in path.name for path in timers)
    assert all("Persistent=false" in path.read_text() for path in timers)
    assert "pgrep -x restic" not in restic_role_tasks
    assert "Require no interrupted backup before scheduling convergence" not in restic_role_tasks

    compose_deploy = (ROOT / "ansible/roles/compose_deploy/tasks/main.yml").read_text()
    compose_rollback = (ROOT / "ansible/roles/compose_rollback/tasks/main.yml").read_text()
    assert "current-artifact.sha256" in compose_deploy
    retired_offen_tooling = [
        ROOT / "scripts/retire-offen-local",
        ROOT / "scripts/retire-offen-aws-object",
        ROOT / "scripts/recover-offen-retirement-preflight",
        ROOT / "scripts/test-offen-retirement.py",
        ROOT / "scripts/controller/normalize-offen-retirement-aws-plan.py",
        ROOT / "scripts/controller/offen-retirement-aws-state.py",
        ROOT / "infrastructure/policy/inspect-offen-retirement-aws-plan.py",
        ROOT / "ansible/playbooks/retire-offen-local.yml",
        ROOT / "ansible/playbooks/recover-offen-retirement-preflight.yml",
        ROOT / "ansible/playbooks/finalize-offen-retirement.yml",
    ]
    assert all(not path.exists() for path in retired_offen_tooling)
    assert "s3:DeleteObjectVersion" not in (ROOT / "infrastructure/tofu/aws-foundation/iam.tf").read_text()
    assert "/usr/local/libexec/home-lab/retire-offen-local" in restic_role_tasks
    assert "/etc/home-lab/offen-retirement-manifest.json" in restic_role_tasks
    assert "state: absent" in restic_role_tasks
    health = (ROOT / "ansible/roles/health/tasks/main.yml").read_text()
    audit = (ROOT / "ansible/roles/audit/tasks/main.yml").read_text()
    assert "audit_expected_stopped_compose_services" in health
    assert "audit_expected_stopped_compose_services" in audit
    assert "['ps', '--quiet', '--all']" in audit
    migration = (ROOT / "ansible/playbooks/migrate-preserved-backup-data.yml").read_text()
    assert "gather_facts: true" in migration
    assert migration.count("apply_lock_operation: preserved-data-migration") == 2
    assert "/usr/bin/findmnt" in migration and "mount_source" in migration
    assert "--checksum" in migration and "--itemize-changes" in migration and "--no-times" in migration
    assert "Remove only current-run paths after revalidating the destination mount" in migration
    assert "Require restarted migration owners to become healthy or running" in migration
    assert "preserved_migration_token" in migration and ".home-lab-migration-owner" in migration
    assert all(name in migration for name in ("preserved_migration_findmnt", "preserved_migration_active_findmnt", "preserved_migration_activation_findmnt"))
    assert "--operation up" in compose_deploy
    assert "action_services | difference(compose_deploy_plan.recreate_services)" in compose_deploy
    assert "start_services | difference(compose_deploy_plan.recreate_services)" in compose_deploy
    assert "stop_services | difference(compose_deploy_plan.recreate_services)" in compose_deploy
    assert "compose_deploy_post_plan.action_count == 0" in compose_deploy
    assert "deploy-reviewed-restic-policy:" in compose_deploy
    assert "services/data/restic/excludes" in compose_deploy
    assert "services/data/restic/files-from" in compose_deploy
    assert "rollback-calibre-to-local:" in compose_deploy
    assert "Verify the live Calibre rollback boundary" in compose_deploy
    assert "Reconcile the authoritative NFS Calibre library into retained local storage" in compose_deploy
    assert "Verify the reconciled local Calibre SQLite database" in compose_deploy
    assert "/mnt/storage/media/calibre/books/" in compose_deploy
    assert "/srv/home-lab-state/calibre-data/books/" in compose_deploy
    assert "compose_deploy_calibre_local_rollback_resume" in compose_deploy
    assert "compose_deploy_plan.changed_paths == []" in compose_deploy
    assert "compose_deploy_artifact_hashes.results[1].stdout == compose_artifact_hash" in compose_deploy
    assert "not compose_deploy_calibre_local_rollback_resume" in compose_deploy
    assert "expected_running = {{ (not compose_deploy_calibre_local_rollback_resume)" in compose_deploy
    assert "--output TARGET,SOURCE,FSTYPE,UUID" in compose_deploy
    assert "proxmox.vm.state_disk.filesystem_uuid" in compose_deploy
    assert "Stop Restic timers during Calibre authority reconciliation" in compose_deploy
    assert "Install reconciled Restic source policy files" in compose_deploy
    assert "Verify installed reconciled Restic policy semantics" in compose_deploy
    assert "compose_deploy_dependency_args" not in compose_deploy
    assert "current-artifact.sha256" in compose_rollback

    restore = (ROOT / "scripts/restore-critical-backup").read_text()
    assert '"$restic_path" restore "$restic_snapshot_id" --target "$RECOVERY_TARGET" --verify' in restore
    assert "restore --delete" not in restore
    assert "RECOVERY_EXPECTED_RESTIC_REPOSITORY_ID" in restore
    assert "RECOVERY_EXPECTED_POLICY_SHA256" in restore
    assert "RECOVERY_EXPECTED_COMPOSE_ARTIFACT_SHA256" in restore
    assert "RCLONE_CONFIG_PROTON_BACKUP_CLIENT_UID" not in restore
    assert "for variable in ${!RCLONE_@}" in restore
    assert "RECOVERY_EXPECTED_ORIGINAL_SNAPSHOT_ID" in restore
    assert "realpath --canonicalize-existing" in restore
    assert '$(stat -c %u "$RECOVERY_TARGET") == 0' in restore
    assert '$(stat -c %a "$RECOVERY_TARGET") == 700' in restore
    assert policy["restore"]["activation"]["replace-tree"] == "unavailable"
    assert policy["restore"]["activation"]["replace-entries"] == "unavailable"
    assert "remote_backup_id" not in restore
    assert "RECOVERY_GPG_KEY_FILE" not in restore
    assert "home-lab-restore-critical-archive" not in restore

    apps = (ROOT / "services/apps.yml").read_text()
    servarr = (ROOT / "services/servarr.yml").read_text()
    nextcloud = (ROOT / "services/nextcloud.yml").read_text()
    assert apps.count("/srv/home-lab-state/calibre-data/books") == 2
    assert "NETWORK_SHARE_MODE: false" in apps
    assert "${MEDIA_PATH}/caro-tachidesk" in servarr
    assert "/srv/home-lab-state/calibre-data/books" in servarr
    assert "${MEDIA_PATH}/calibre/books" not in apps + servarr
    assert "${MEDIA_PATH}/nextcloud/data" in nextcloud
    calibre_source = next(entry for entry in policy["sources"] if entry["path"] == "/srv/home-lab-state/calibre-data/books")
    assert calibre_source["class"] == "replace-entries"
    assert calibre_source["mutable_database"] is True
    assert calibre_source["writers"] == ["calibre", "calibre-web-automated", "bookshelf"]
    assert "/srv/home-lab-state/calibre-data/books/**" not in policy["excludes"]
    assert not any(pattern.startswith("/srv/home-lab-state/**") for pattern in policy["excludes"])
    assert "/srv/home-lab-state/calibre-data/books/metadata.db" in policy["critical_fixtures"]

    restic_role = (ROOT / "ansible/roles/restic_backup/tasks/main.yml").read_text()
    assert "Inspect fixed Restic deployment ancestors" in restic_role
    assert "- { path: /usr/local/libexec, required: true }" in restic_role
    assert "- { path: /usr/local/libexec/home-lab, required: false }" in restic_role
    assert "- { path: /usr/local/libexec/home-lab, owner: root, group: root, mode: '0755' }" in restic_role
    assert "Refusing to manage a non-directory or symlinked protected Restic destination." in restic_role
    assert "gid: \"{{ restic_proton_gid }}\"" in restic_role
    assert "uid: \"{{ restic_proton_uid }}\"" in restic_role
    assert "Reject fixed restic-proton ownership in protected source trees" in restic_role
    restic_group_vars = (ROOT / "ansible/group_vars/docker_host.yml").read_text()
    assert "restic_proton_uid: 60000" in restic_group_vars
    assert "restic_proton_gid: 60000" in restic_group_vars
    restic_audit = (ROOT / "ansible/roles/audit/tasks/restic.yml").read_text()
    assert "Require exact non-aliased inert Restic service identity" in restic_audit
    assert "Reject inert Restic identity ownership in protected source trees" in restic_audit
    for source in (restic_role, restic_audit):
        assert "matches=$(/usr/bin/find /srv/home-lab-state /mnt/games" in source
        assert 'test -z "$matches"' in source
        assert 'test -z "$(/usr/bin/find /srv/home-lab-state /mnt/games' not in source
    with tempfile.TemporaryDirectory() as directory:
        failing_find = Path(directory) / "find"
        failing_find.write_text("#!/bin/sh\nexit 7\n")
        failing_find.chmod(0o700)
        traversal = subprocess.run(
            ["/bin/bash", "-c", 'set -euo pipefail; matches=$("$1"); test -z "$matches"', "ownership-scan", str(failing_find)],
            check=False,
        )
        assert traversal.returncode == 7

    visudo_sources = [
        ROOT / "ansible/group_vars/docker_host.yml",
        ROOT / "ansible/roles/deploy_user/tasks/main.yml",
        ROOT / "ansible/playbooks/plan-controller-audit.yml",
    ]
    for source in visudo_sources:
        content = source.read_text()
        assert "/usr/bin/visudo" not in content
        assert "/usr/sbin/visudo" in content
    human_access = (ROOT / "ansible/roles/human_access/tasks/main.yml").read_text()
    assert "Inspect the required sudoers validator before convergence" in human_access
    assert "human_access_visudo.stat.mode == '0755'" in human_access
    assert "human_access_groups_inspection.results[account_index].stdout.split() | sort" in human_access
    assert "human_access_groups_result.results[account_index].stdout.split() | sort" in human_access

    apply_lock = (ROOT / "ansible/roles/apply_lock/tasks/main.yml").read_text()
    owner_publish = apply_lock.index("/usr/bin/printf 'controller=%s\\noperation=%s\\nstarted=%s\\n'")
    acquire = apply_lock.index('/usr/bin/mv --no-target-directory -- "$staging" "$lock"', owner_publish)
    assert owner_publish < acquire
    detach = apply_lock.index('/usr/bin/mv --no-target-directory -- "$lock" "$tombstone"')
    remove_owner = apply_lock.index('/usr/bin/rm -- "$tombstone/owner"', detach)
    remove_tombstone = apply_lock.index('/usr/bin/rmdir -- "$tombstone"', remove_owner)
    assert detach < remove_owner < remove_tombstone
    assert "Record the production apply-lock owner" not in apply_lock
    assert "apply_lock_guard_path if apply_lock_guard_path | length > 0 else apply_lock_backup_guard_path" in apply_lock

    clear_failed_lock = (ROOT / "ansible/playbooks/clear-failed-apply-lock.yml").read_text()
    clear_detach = clear_failed_lock.index('/usr/bin/mv --no-target-directory -- "$lock" "$tombstone"')
    clear_owner = clear_failed_lock.index('/usr/bin/rm -- "$tombstone/owner"', clear_detach)
    clear_tombstone = clear_failed_lock.index('/usr/bin/rmdir -- "$tombstone"', clear_owner)
    assert clear_detach < clear_owner < clear_tombstone
    assert "Remove only the inspected owner record" not in clear_failed_lock
    assert '"{{ backups.restic.runner.lock_path }}"' in clear_failed_lock
    assert all(operation in clear_failed_lock for operation in ('proton-qualification', 'restic-repository-initialization', 'restic-first-run', 'offen-retirement-local'))
    initialization_playbook = (ROOT / "ansible/playbooks/initialize-restic-repositories.yml").read_text()
    initialization_resume = (ROOT / "ansible/playbooks/resume-restic-repository-initialization.yml").read_text()
    initialization_finalize = (ROOT / "ansible/playbooks/finalize-restic-repository-initialization.yml").read_text()
    assert "apply_lock_operation: restic-repository-initialization" in initialization_playbook
    assert "the production lock intentionally remains held" in initialization_playbook
    assert "resume-owner-bound-restic-repository-initialization" in initialization_resume
    assert "restic_repository_exclusive_client_confirmation" in initialization_resume
    assert "current_object_retention_days >= 365" in initialization_resume
    assert "migration_retention_hold.review_deadline > now" in initialization_resume
    initialization_helper = (ROOT / "scripts/initialize-restic-repositories").read_text()
    assert "PROTON_ID = 60000" in initialization_helper
    assert 'os.getgrouplist("restic-proton", service.pw_gid)' in initialization_helper
    assert "sorted(set(groups)) != [PROTON_ID]" in initialization_helper
    assert "finalize-owner-bound-restic-repository-initialization" in initialization_finalize
    assert "apply_lock_expected_owner_sha256" in initialization_finalize

    restic_documentation = (ROOT / "docs/restic-backups.md").read_text()
    assert "iac_failed_lock_expected_operation=restic_backup" in restic_documentation
    assert "operation-specific owner lock must remain until exact R2 evidence authorizes finalize" in restic_documentation
    assert "Proton Trash cleanup are forbidden recovery actions" in restic_documentation

    foundation = (ROOT / "infrastructure/tofu/aws-foundation/main.tf").read_text()
    assert "resource \"aws_s3_bucket\" \"state\"" in foundation
    assert "prevent_destroy = true" in foundation
    assert "critical-backup-retention" not in foundation
    assert "current_object_retention_days" not in foundation
    assert "noncurrent_version_expiration" not in foundation
    assert 'id     = "incomplete-multipart-cleanup"' in foundation
    assert 'id     = "expired-delete-marker-cleanup"' in foundation
    assert "force_destroy" not in foundation

    print("restic static safety fixtures passed")


if __name__ == "__main__":
    main()
