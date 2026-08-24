#!/usr/bin/env python3
"""Static and focused failure-path tests for the inert Restic implementation."""

import json
from datetime import datetime
import hashlib
from pathlib import Path
import runpy
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def contract() -> dict:
    script = "const{load}=require('js-yaml');const fs=require('fs');process.stdout.write(JSON.stringify(load(fs.readFileSync('infrastructure/contract/home-lab.yml','utf8'))))"
    result = subprocess.run(["node", "-e", script], cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
    return json.loads(result.stdout)


def main() -> None:
    value = contract()
    policy = value["backups"]["restic"]
    offen = value["backups"]["legacy_offen"]
    assert offen["scheduler_state"] == "active"
    assert offen["scheduler_services"] == ["daily-local-backup", "weekly-remote-backup"]
    assert offen["migration_retention_hold"] == {
        "state": "planned",
        "current_object_retention_days": 365,
        "plan_sha256": None,
        "recovery_object_version_id_sha256": None,
        "verified_at": None,
        "review_deadline": None,
    }
    preservation = offen["migration_archive_preservation"]
    assert preservation["state"] in {"planned", "applied"}
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
    assert hashlib.sha256((ROOT / "scripts/verify-backup-archive.py").read_bytes()).hexdigest() == "e78f1f009d89af872fe2d48b2f091597c66a309f657842f1e522c221f643ac5c"
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
        assert restore_proof["verifier_sha256"] == hashlib.sha256((ROOT / "scripts/verify-backup-archive.py").read_bytes()).hexdigest()
        assert restore_proof["restore_pipeline"] == restore_proof["decrypted_cleanup"] == "pass"
        assert restore_proof["archive_integrity"] == evidence["archive_integrity"] == "pass"
        assert restore_proof["safe_paths"] == evidence["safe_paths"] == "pass"
        started_at = datetime.fromisoformat(restore_proof["started_at"].replace("Z", "+00:00"))
        finished_at = datetime.fromisoformat(restore_proof["finished_at"].replace("Z", "+00:00"))
        assert int((finished_at - started_at).total_seconds()) == restore_proof["elapsed_seconds"]
        for key in ("member_count", "regular_file_count", "total_uncompressed_bytes", "member_path_stream_sha256"):
            assert evidence[key] == restore_proof[key]
    assert policy["migration_state"] == "inert"
    assert [policy["retention"][key] for key in ("keep_daily", "keep_weekly", "keep_monthly")] == [7, 5, 12]
    assert policy["schedule"]["proton_independent_timer"] is False
    assert policy["proton"]["trash_cleanup"] == "manual-only"
    assert policy["repositories"]["games"]["id"] is None
    assert policy["repositories"]["nfs"]["copy_chunker_params_from"] == "games"
    assert policy["repositories"]["proton"]["copy_chunker_params_from"] == "games"
    assert policy["repositories"]["proton"]["allocated_bytes"] == 1_000_000_000_000
    assert policy["proton"]["warning_minimum_used_bytes"] == 100_000_000_000
    assert policy["proton"]["hard_failure_used_bytes"] == 900_000_000_000
    assert policy["retention"]["group_by"] == "host,paths"
    assert policy["restore"]["modes"] == ["staging"]
    assert policy["restore"]["activation_status"] == "unavailable-pending-isolated-proofs"

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
    assert 'warning_repository_multiplier' in runner_text and 'hard_failure_used_bytes' in runner_text
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
        runner_globals["service_healthy"] = lambda _service: True
        module["restart_recorded"](test_policy, {"running_services": ["application", "database"]})
        assert started == ["database", "application"]
        assert not stopped.exists()

    runner_globals["run"] = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "secret provider failure")
    try:
        module["service_running"]("database")
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
        json.dumps({"used": 899_999_999_999, "free": 100_000_000_001, "total": 1_000_000_000_000}) if "about" in arguments else json.dumps({"bytes": 1}),
        "",
    )
    try:
        module["quota"](policy, 1)
    except module["WorkflowError"] as error:
        assert str(error) == "proton_quota_gate"
    else:
        raise AssertionError("Proton copy headroom could cross the hard quota")

    role = (ROOT / "ansible/roles/restic_backup/tasks/main.yml").read_text()
    bootstrap = (ROOT / "scripts/bootstrap-restic-credentials").read_text()
    assert "required_sops_keys_absent" in bootstrap
    assert "state={'changed' if changed else 'noop'}" in bootstrap
    assert '["/usr/local/bin/rclone", "obscure", "-"]' in bootstrap
    assert "path.read_text(encoding=\"utf-8\") == content" in bootstrap
    assert "except (ConfigError, OSError)" in bootstrap
    assert 'remote.get("original_file_size") != "true"' in bootstrap
    assert 'remote.get("otp_secret_key")' in bootstrap
    group_vars = (ROOT / "ansible/group_vars/docker_host.yml").read_text()
    assert 'restic_archive_sha256: "{{ backups.restic.tools.restic.archive_sha256 }}"' in group_vars
    assert 'rclone_archive_sha256: "{{ backups.restic.tools.rclone.archive_sha256 }}"' in group_vars
    assert policy["tools"]["restic"]["archive_sha256"] == "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c"
    assert policy["tools"]["rclone"]["archive_sha256"] == "aa2804e08f48250e71009c727124b6341cd0288465804a9a09d14663cabafbaa"
    assert "ansible_facts.architecture == 'x86_64'" in role
    assert "Refusing to replace a non-regular, symlinked, or hard-linked Restic tool destination" in role
    assert "Refusing a pre-existing games Restic repository until its exact ID is recorded" in role
    assert "The games Restic repository ID differs from the contract" in role
    assert "Refusing Restic deployment without the exact contract repository mount" in role
    assert "import bz2" in role and "zipfile.ZipFile" in role
    assert "/usr/bin/bzip2" not in role and "/usr/bin/unzip" not in role and "ansible.builtin.unarchive" not in role
    sops_install = role.split("Install canonical SOPS ciphertext", 1)[1].split("Gather confined Restic identity records", 1)[0]
    assert "no_log: true" in sops_install
    reconcile = (ROOT / "scripts/reconcile-infrastructure").read_text()
    steady_tags = reconcile.split("apply_debian_steady()", 1)[1].split("compose_apply()", 1)[0]
    assert "restic_backup" in steady_tags
    assert "restic-proton" in role and "groups: []" in role and "shell: /usr/sbin/nologin" in role
    assert "enabled: false" in role and "state: stopped" in role

    daily_target = (ROOT / "ansible/roles/restic_backup/templates/home-lab-restic-daily.target.j2").read_text()
    local_service = (ROOT / "ansible/roles/restic_backup/templates/home-lab-restic-daily-local.service.j2").read_text()
    local_mount_requirement = next(line for line in local_service.splitlines() if line.startswith("RequiresMountsFor="))
    assert "repositories.games.mountpoint" in local_mount_requirement
    assert "repositories.nfs.mountpoint" not in local_mount_requirement
    proton_service = (ROOT / "ansible/roles/restic_backup/templates/home-lab-restic-daily-proton.service.j2").read_text()
    timers = list((ROOT / "ansible/roles/restic_backup/templates").glob("*.timer.j2"))
    assert "daily-local.service home-lab-restic-daily-proton.service" in daily_target
    assert "Requires=home-lab-restic-daily-local.service" in proton_service
    assert "User=restic-proton" in proton_service
    assert "InaccessiblePaths=/srv/home-lab-state" in proton_service
    assert "BindReadOnlyPaths={{ backups.restic.repositories.games.path }}" in proton_service
    assert "ReadWritePaths=/var/lib/home-lab-restic/replication /var/lib/restic-proton {{ backups.restic.runner.lock_path }}" in proton_service
    assert len(timers) == 2
    assert all("proton" not in path.name for path in timers)
    assert all("Persistent=false" in path.read_text() for path in timers)

    compose_deploy = (ROOT / "ansible/roles/compose_deploy/tasks/main.yml").read_text()
    compose_rollback = (ROOT / "ansible/roles/compose_rollback/tasks/main.yml").read_text()
    assert "current-artifact.sha256" in compose_deploy
    offen_transition = (ROOT / "ansible/playbooks/quiesce-offen-backups.yml").read_text()
    assert "stop-offen-keep-definitions-and-archives" in offen_transition
    assert "resume-offen-existing-definitions" in offen_transition
    assert "Refuse to stop an Offen scheduler with an active child process" in offen_transition
    assert "sha256sum" in offen_transition and "state: absent" not in offen_transition
    assert "dockervolumebackup.lock" in offen_transition
    assert "Require exact declared, materialized, and non-Offen running service sets" in offen_transition
    assert "backup-root-wide non-deletion" in offen_transition
    assert "offen_scheduler_expected_aws_hold_plan_sha256" in offen_transition
    assert ".total_seconds() <= 2592000" in offen_transition
    assert "Require a complete source-state audit before an initial Offen quiescence" in offen_transition
    assert "migration_archive_preservation.state == 'applied'" in offen_transition
    assert "every protected Offen archive replica" in offen_transition
    offen_preservation = (ROOT / "ansible/playbooks/preserve-offen-archives.yml").read_text()
    assert "copy-both-offen-generations-to-protected-replicas" in offen_preservation
    assert "apply_lock_operation: offen-archive-preservation" in offen_preservation
    assert "/usr/bin/cp --reflink=never" in offen_preservation
    assert "offen_archive_preservation=verified" in offen_preservation
    assert "exec /bin/sleep 1800" in offen_preservation
    assert "async: 1200" in offen_preservation
    assert offen_preservation.index("Inspect free bytes on each protected replica filesystem") < offen_preservation.index("Acquire each Offen scheduler internal lock")
    assert offen_preservation.index("Recheck preservation locks immediately before the bounded copy") < offen_preservation.index("Create and verify independent protected archive copies")
    assert "force_handlers: true" in offen_preservation
    assert "ansible.builtin.meta: flush_handlers" in offen_preservation
    assert "listen: Release Offen internal preservation locks" in offen_preservation
    assert offen_preservation.index('test "$matches" -eq 1;') < offen_preservation.index('kill "$candidate";')
    assert offen_preservation.count(".offen-archive-preservation-lock.{{ item }}.pid") == 2
    assert ".offen-archive-preservation-lock.pid" not in offen_preservation
    assert "/usr/bin/rm -f -- \"$temporary\"" in offen_preservation
    assert "rm -rf" not in offen_preservation
    health = (ROOT / "ansible/roles/health/tasks/main.yml").read_text()
    audit = (ROOT / "ansible/roles/audit/tasks/main.yml").read_text()
    assert "audit_expected_stopped_compose_services" in health
    assert "audit_expected_stopped_compose_services" in audit
    assert "['ps', '--quiet', '--all']" in audit
    migration = (ROOT / "ansible/playbooks/migrate-preserved-backup-data.yml").read_text()
    assert "/usr/bin/findmnt" in migration and "mount_source" in migration
    assert "--checksum" in migration and "--itemize-changes" in migration
    assert "Remove only current-run paths after revalidating the destination mount" in migration
    assert "Require restarted migration owners to become healthy or running" in migration
    assert "preserved_migration_token" in migration and ".home-lab-migration-owner" in migration
    assert all(name in migration for name in ("preserved_migration_findmnt", "preserved_migration_active_findmnt", "preserved_migration_activation_findmnt"))
    assert "current-artifact.sha256" in compose_rollback

    offen_proof = (ROOT / "scripts/run-backup-restore-proof.fish").read_text()
    assert "'a/archive=' 's/sha256=' 'b/bytes='" in offen_proof
    assert "archive_identity=invalid" in offen_proof
    assert "archive_sha256=invalid" in offen_proof
    assert "archive_bytes=invalid" in offen_proof
    assert "test (count $argv) -ne 0" in offen_proof
    assert "0b46561cf52c15bfababef0f75fe3bbe2cf1f7e1305eb1f7cfe4c1ca0db5c431" not in offen_proof
    verifier_sha256 = hashlib.sha256((ROOT / "scripts/verify-backup-archive.py").read_bytes()).hexdigest()
    assert f'test "$ACTUAL_SHA256" = {verifier_sha256}' in offen_proof

    restore = (ROOT / "scripts/restore-critical-backup").read_text()
    assert 'restic restore "$restic_snapshot_id" --target "$RECOVERY_TARGET" --verify' in restore
    assert "restore --delete" not in restore
    assert "RECOVERY_EXPECTED_RESTIC_REPOSITORY_ID" in restore
    assert "RECOVERY_EXPECTED_POLICY_SHA256" in restore
    assert "RECOVERY_EXPECTED_COMPOSE_ARTIFACT_SHA256" in restore
    assert "realpath --canonicalize-existing" in restore
    assert '$(stat -c %u "$RECOVERY_TARGET") == 0' in restore
    assert '$(stat -c %a "$RECOVERY_TARGET") == 700' in restore
    assert policy["restore"]["activation"]["replace-tree"] == "unavailable"
    assert policy["restore"]["activation"]["replace-entries"] == "unavailable"
    assert "/srv/home-lab-state" not in restore.split("if [[ -n $restic_snapshot_id ]]", 1)[1].split("fi", 1)[0]

    apps = (ROOT / "services/apps.yml").read_text()
    servarr = (ROOT / "services/servarr.yml").read_text()
    nextcloud = (ROOT / "services/nextcloud.yml").read_text()
    assert apps.count("${MEDIA_PATH}/calibre/books") == 2
    assert "${MEDIA_PATH}/caro-tachidesk" in servarr
    assert "${MEDIA_PATH}/calibre/books" in servarr
    assert "${MEDIA_PATH}/nextcloud/data" in nextcloud

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

    restic_documentation = (ROOT / "docs/restic-backups.md").read_text()
    assert "iac_failed_lock_expected_operation=restic_backup" in restic_documentation
    assert "atomically publishes it under the shared backup mutex" in restic_documentation
    assert "Recovery from a partial inert deployment is forward convergence" in restic_documentation

    foundation = (ROOT / "infrastructure/tofu/aws-foundation/main.tf").read_text()
    assert "resource \"aws_s3_bucket\" \"state\"" in foundation
    assert "prevent_destroy = true" in foundation
    assert "migration_retention_hold.current_object_retention_days" in foundation
    assert "force_destroy" not in foundation

    print("restic static safety fixtures passed")


if __name__ == "__main__":
    main()
