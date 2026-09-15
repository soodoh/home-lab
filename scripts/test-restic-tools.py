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
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def contract() -> dict:
    script = "const{load}=require('js-yaml');const fs=require('fs');process.stdout.write(JSON.stringify(load(fs.readFileSync('infrastructure/contract/home-lab.yml','utf8'))))"
    result = subprocess.run(["node", "-e", script], cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
    return json.loads(result.stdout)


def restic_role_source() -> str:
    """Expand fixed shared task imports for source checks; never execute them."""
    tasks = ROOT / "ansible/roles/restic_backup/tasks"
    source = (tasks / "main.yml").read_text()
    for name, filename in (
        ("Converge pinned Restic tools", "tools.yml"),
        ("Install and verify shared pinned Restic tools", "tools-install.yml"),
        ("Configure shared confined Restic identity", "identity.yml"),
        ("Install shared generated Restic inputs", "inputs.yml"),
        ("Install shared Restic runner", "runner.yml"),
        ("Render shared Restic unit definitions", "units.yml"),
    ):
        seam = f"- name: {name}\n  ansible.builtin.import_tasks: {filename}\n"
        assert source.count(seam) == 1
        source = source.replace(seam, (tasks / filename).read_text().removeprefix("---\n"))
    return source


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
    assert policy["schedule"]["state"] == "active"
    assert policy["proton"]["trash_cleanup"] == "manual-only"
    assert policy["repositories"]["games"]["id"] == "b15627185df9b10a95b5dffe7d194dbccdba6ba4eb8a038ee03e750fedbde08f"
    assert policy["repositories"]["nfs"]["id"] == "61d50fa782d194374deb24f354a07b0f11634721afa1b268963e4d017b93bb95"
    assert policy["repositories"]["proton"]["id"] == "dce8dbc3cde106047631317a09257c23ee5eab4d9ece5f88d52108ae384a8503"
    assert policy["repositories"]["proton"]["path"] == "rclone:proton-backup:Backups/home-lab-restic"
    assert "damaged_predecessor" not in policy["repositories"]["proton"]
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
    assert 'SUBCOMMANDS = {"preflight", "daily-local", "daily-proton", "diagnose-proton", "maintenance", "repair-proton-index", "status"}' in runner_text
    full_index = "e59972a3621be54dbad90b47f8fb91f96bd725ab69495a0dcefcc4a544411d70"
    assert "HOME_LAB_RESTIC_REPAIR_CONFIRMATION" in runner_text and f"repair-proton-index-{full_index}" in runner_text
    assert "restic_backup=diagnose_proton repository_check=passed mutation=false" in runner_text
    runner_module = runpy.run_path(ROOT / "scripts/restic-backup")
    repair_signature = runner_module["repair_signature"]
    exact_stdout = json.dumps({"message_type": "summary", "num_errors": 1, "broken_packs": None, "suggest_repair_index": True, "suggest_prune": False}, separators=(",", ":")) + "\n"
    errors = [
        {"message_type": "error", "message": f"error: error loading index {full_index}: LoadRaw(<index/e59972a362>): invalid data returned\n"},
        {"message_type": "error", "message": "\nThe repository index is damaged and must be repaired. You must run `restic repair index' to correct this.\n\n"},
        {"message_type": "exit_error", "code": 1, "message": "Fatal: repository contains errors"},
    ]
    exact_stderr = "\n".join(json.dumps(item, separators=(",", ":")) for item in errors) + "\n"
    assert repair_signature(exact_stdout, exact_stderr)
    assert not repair_signature("", exact_stderr)
    changed = exact_stderr.replace(full_index, "f" * 64)
    assert not repair_signature(exact_stdout, changed)
    assert not repair_signature(exact_stdout, exact_stderr + json.dumps({"message_type": "error", "message": "additional"}) + "\n")
    extra_field_errors = [errors[0], {**errors[1], "extra": True}, errors[2]]
    assert not repair_signature(exact_stdout, "\n".join(json.dumps(item, separators=(",", ":")) for item in extra_field_errors) + "\n")
    repair_precondition = runner_module["repair_precondition"]
    assert repair_precondition(1, exact_stdout, exact_stderr)
    assert not repair_precondition(2, exact_stdout, exact_stderr)
    # Retirement decisions/evidence are documented in docs/proton-source-retirement.md.
    # These source checks do not attest live transaction closure. Keep their evidence.
    for retired in (
        "scripts/migrate-proton-restic-v2",
        "scripts/transition-proton-totp-config",
        "scripts/test-proton-totp-transition.py",
        "ansible/playbooks/prepare-proton-totp-transition.yml",
        "ansible/playbooks/transition-proton-totp.yml",
        "ansible/playbooks/finalize-proton-totp-transition.yml",
        "scripts/diagnose-proton-auth",
        "scripts/diagnose-proton-quota",
        "scripts/supervise-staged-proton-recovery",
        "scripts/finalize-staged-proton-recovery",
        "scripts/test-proton-password-only-transition.py",
        "ansible/playbooks/diagnose-proton-auth.yml",
        "ansible/playbooks/diagnose-proton-beta.yml",
        "ansible/playbooks/diagnose-proton-post-reset.yml",
        "ansible/playbooks/rotate-proton-login-credential.yml",
        "ansible/playbooks/transition-proton-password-only.yml",
        "ansible/playbooks/reconcile-proton-account-reset.yml",
        "ansible/playbooks/deploy-proton-password-only-artifacts.yml",
    ):
        assert not (ROOT / retired).exists()
    evidence_root = ROOT / "infrastructure/evidence"
    totp_cutover = json.loads((evidence_root / "proton-totp-cutover.json").read_bytes())
    totp_qualification_raw = (evidence_root / "proton-totp-qualification.json").read_bytes()
    totp_qualification = json.loads(totp_qualification_raw)
    assert totp_cutover["production_lock_absent"] is True
    assert totp_cutover["qualification_evidence_sha256"] == hashlib.sha256(totp_qualification_raw).hexdigest()
    assert totp_cutover["transition_evidence_sha256"] == totp_qualification["local_transition_evidence_sha256"]
    assert totp_cutover["recovery_bundle_evidence_sha256"] == hashlib.sha256(
        (evidence_root / "proton-totp-recovery-bundles.json").read_bytes()
    ).hexdigest()
    incident = json.loads((evidence_root / "proton-incident-resolution.json").read_bytes())
    assert incident["status"] == "committed"
    assert incident["after"]["damaged_v2"]["present"] is False
    # Incident closure explicitly preserves these nonterminal historical labels.
    assert incident["historical_journals"]["canonical_creation"]["status"] == "copied"
    assert incident["historical_journals"]["trash"]["status"] == "cleanup-started"
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

    role = restic_role_source()
    audit_restic = (ROOT / "ansible/roles/audit/tasks/restic.yml").read_text()
    bootstrap = (ROOT / "scripts/bootstrap-restic-credentials").read_text()
    assert "required_sops_keys_absent" in bootstrap
    assert "state={'changed' if changed else 'noop'}" in bootstrap
    assert '["/usr/local/bin/rclone", "obscure", "-"]' in bootstrap
    assert "path.read_text(encoding=\"utf-8\") == content" in bootstrap
    assert "except (ConfigError, OSError)" in bootstrap
    assert 'remote.get("original_file_size") != "true"' in bootstrap
    assert '"otp_secret_key"' in bootstrap
    assert 'sys.argv[4] != "--check"' in bootstrap
    assert 'PROTON_BACKUP_TOTP_SECRET' in bootstrap
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
        ({**valid_credentials, "PROTON_BACKUP_TOTP_SECRET": "A" * 32}, "proton_totp_secret_forbidden"),
    )
    valid_totp = {**valid_credentials, "PROTON_BACKUP_TOTP_SECRET": "JBSWY3DPEHPK3PXP"}
    assert parse_dotenv(
        "".join(f"{key}={value}\n" for key, value in valid_totp.items()),
        "totp",
    ) == valid_totp
    for invalid_totp in (
        valid_credentials,
        {**valid_credentials, "PROTON_BACKUP_TOTP_SECRET": "lowercaseinvalid"},
        {**valid_credentials, "PROTON_BACKUP_TOTP_SECRET": "JBSWY3DP="},
    ):
        error = io.StringIO()
        try:
            with contextlib.redirect_stderr(error):
                parse_dotenv("".join(f"{key}={value}\n" for key, value in invalid_totp.items()), "totp")
        except SystemExit:
            assert "proton_totp_secret_format" in error.getvalue()
        else:
            raise AssertionError("invalid TOTP credential fixture passed")
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
    assert policy["tools"]["rclone"]["installed_sha256"] == "acd2c7aca2996c884a8cd0012b27d74213bc7d02c514d9711166b5023e51ca49"
    assert policy["qualification"]["helper_sha256"] == hashlib.sha256((ROOT / "scripts/qualify-proton-backup").read_bytes()).hexdigest()
    assert policy["initialization"]["helper_sha256"] == hashlib.sha256((ROOT / "scripts/initialize-restic-repositories").read_bytes()).hexdigest()
    assert policy["tools"]["restic"]["archive_sha256"] == "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c"
    assert policy["tools"]["rclone"]["archive_sha256"] == "8d836165cfc92b273f8735dc91e4158c55267dfa69f9e35ed838805802a89dec"
    assert "ansible_facts.architecture == 'x86_64'" in role
    assert "Refusing to replace a non-regular, symlinked, or hard-linked Restic tool destination" in role
    assert "Keep incident-suspended Restic timers disabled and stopped" in role
    assert "Clear retained incident failure markers before active scheduling" in role
    assert "Remove terminal incident-only Restic capabilities" in role
    for helper in ("cleanup-damaged-proton-restic-v1", "empty-proton-trash", "create-canonical-proton-restic", "promote-qualified-proton-restic", "retire-proton-incident-artifacts"):
        assert f'src: "{{{{ playbook_dir }}}}/../../scripts/{helper}"' not in role
        assert f"/usr/local/libexec/home-lab/{helper}" in role
    assert "backups.restic.schedule.state == 'active'" in role
    assert "backups.restic.schedule.state == 'active'" in audit_restic
    assert "backups.restic.schedule.state == 'incident-suspended'" in audit_restic
    assert "'disabled' if item.item.key.endswith('.timer')" in audit_restic
    assert "Refusing a pre-existing games Restic repository until its exact ID is recorded" in role
    assert "The games Restic repository ID differs from the contract" in role
    assert "Refusing Restic deployment without the exact contract repository mount" in role
    assert "import bz2" in role and "zipfile.ZipFile" in role
    assert "/usr/bin/bzip2" not in role and "/usr/bin/unzip" not in role and "ansible.builtin.unarchive" not in role
    assert "Refuse ordinary convergence before guarded authentication transition" in role
    assert "backups.restic.proton.authentication_mode in ['password-only', 'totp']" in role
    assert "present == expected" in role
    assert role.index("Refuse ordinary convergence before guarded authentication transition") < role.index("Install rendered Restic policy JSON")
    assert role.index("Refuse ordinary convergence before guarded authentication transition") < role.index("Install canonical SOPS ciphertext")
    sops_install = role.split("Install canonical SOPS ciphertext", 1)[1].split("Gather confined Restic identity records", 1)[0]
    assert "no_log: true" in sops_install
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
    assert "restic_systemd.games_mountpoint" in local_mount_requirement
    assert "restic_systemd.nfs_mountpoint" not in local_mount_requirement
    proton_service = (ROOT / "ansible/roles/restic_backup/templates/home-lab-restic-daily-proton.service.j2").read_text()
    post_nfs_recovery = (ROOT / "ansible/playbooks/recover-post-nfs-first-run.yml").read_text()
    first_run_finalize = (ROOT / "ansible/playbooks/finalize-first-restic-backup.yml").read_text()
    timers = list((ROOT / "ansible/roles/restic_backup/templates").glob("*.timer.j2"))
    restic_role_tasks = restic_role_source()
    assert "daily-local.service home-lab-restic-daily-proton.service" in daily_target
    assert "Requires=home-lab-restic-daily-local.service" in proton_service
    assert "User=restic-proton" in proton_service
    inaccessible_paths = next(line for line in proton_service.splitlines() if line.startswith("InaccessiblePaths="))
    assert "/mnt/games" not in inaccessible_paths.removeprefix("InaccessiblePaths=").split()
    assert "TemporaryFileSystem=/mnt/games:ro" in proton_service
    assert "BindReadOnlyPaths={{ restic_systemd.games_repository_path }}" in proton_service
    assert "ReadWritePaths=/var/lib/home-lab-restic/replication /var/lib/restic-proton {{ restic_systemd.lock_path }}" in proton_service
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
    assert "Restrict Compose deployment resume to the exact interrupted Calibre transaction" in compose_deploy
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

    restic_role = restic_role_source()
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

    foundation = (ROOT / "infrastructure/tofu/aws-foundation/main.tf").read_text()
    state_manifest = json.loads((ROOT / "infrastructure/tofu/aws-foundation/state-objects.json").read_text())
    assert "resource \"aws_s3_bucket\" \"state\"" in foundation
    assert "prevent_destroy = true" in foundation
    assert "critical-backup-retention" not in foundation
    assert "current_object_retention_days" not in foundation
    assert 'resource "aws_s3_bucket_lifecycle_configuration" "state"' in foundation
    assert "noncurrent_version_expiration" in foundation
    assert state_manifest["noncurrent_lock_retention_days"] == 1
    assert state_manifest["retired_object_expiration_days"] == 1
    recovery_lifecycle = foundation[foundation.index('resource "aws_s3_bucket_lifecycle_configuration" "recovery"'):]
    assert "noncurrent_version_expiration" not in recovery_lifecycle
    assert 'id     = "incomplete-multipart-cleanup"' in recovery_lifecycle
    assert 'id     = "expired-delete-marker-cleanup"' in recovery_lifecycle
    assert "force_destroy" not in foundation

    print("restic static safety fixtures passed")


if __name__ == "__main__":
    main()
