#!/usr/bin/env python3
"""Executable transaction-boundary fixtures for the guarded first Restic chain."""
from __future__ import annotations

import hashlib
import io
import json
import os
import runpy
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/restic-backup"
SUPERVISOR = ROOT / "scripts/run-first-restic-backup"
AWS_PROOF = ROOT / "scripts/prove-aws-recovery-hold"
VERSION_ID = "fixture-version-1"
VERSION_HASH = hashlib.sha256(VERSION_ID.encode()).hexdigest()
KEY = "weekly-backup-2026-08-23T06-00-00.tar.gz.gpg"


def write(path: Path, raw: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def contract() -> dict[str, object]:
    return {
        "backups": {"legacy_offen": {
            "migration_retention_hold": {
                "current_object_retention_days": 365,
                "lifecycle_rule_id": "critical-backup-retention",
                "delete_marker_rule_id": "expired-delete-marker-cleanup",
                "expected_principal_arn_sha256": hashlib.sha256(b"arn:aws:iam::123456789012:user/fixture-offen-backup").hexdigest(),
                "recovery_object_key": KEY,
                "recovery_object_bytes": 2399491160,
                "recovery_object_last_modified": "2026-08-23T13:03:53Z",
                "recovery_object_storage_class": "STANDARD",
                "recovery_object_version_id_sha256": VERSION_HASH,
            },
            "final_archive": {"sha256": "8034bcf7a03d19c446a23c30a56c1b9a8c4ffdd2d829557a5a16e39c0aab1f08"},
        }}
    }


def provider_fixture() -> dict[str, object]:
    return {
        "identity": {"UserId": "AIDAFIXTURE", "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/fixture-offen-backup"},
        "versioning": {"Status": "Enabled"},
        "lifecycle": {"Rules": [
            {"ID": "critical-backup-retention", "Status": "Enabled", "Filter": {}, "Expiration": {"Days": 365},
             "NoncurrentVersionExpiration": {"NoncurrentDays": 1}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}},
            {"ID": "expired-delete-marker-cleanup", "Status": "Enabled", "Filter": {},
             "Expiration": {"ExpiredObjectDeleteMarker": True}},
        ]},
        "versions": {"Versions": [{"Key": KEY, "VersionId": VERSION_ID, "IsLatest": True, "LastModified": "2026-08-23T13:03:53+00:00", "Size": 2399491160, "StorageClass": "STANDARD"}], "DeleteMarkers": []},
    }


def run_aws_fixture(root: Path, fixture: dict[str, object]) -> subprocess.CompletedProcess[str]:
    root.mkdir(parents=True, exist_ok=True)
    contract_path = root / "contract.json"
    contract_path.write_text(json.dumps(contract()))
    sops = root / "sops"
    write(sops, b"#!/bin/sh\nprintf '%s\\n' 'AWS_ACCESS_KEY_ID=fixture' 'AWS_SECRET_ACCESS_KEY=fixture-secret' 'AWS_S3_BUCKET_NAME=fixture-bucket'\n", 0o755)
    fixture_path = root / "provider.json"
    fixture_path.write_text(json.dumps(fixture))
    aws = root / "aws"
    aws_source = f'''#!/usr/bin/env python3
import json,sys
fixture=json.load(open({str(fixture_path)!r}))
args=sys.argv[1:]
if args[:2]==["sts","get-caller-identity"]: value=fixture["identity"]
elif args[:2]==["s3api","get-bucket-versioning"]: value=fixture["versioning"]
elif args[:2]==["s3api","get-bucket-lifecycle-configuration"]: value=fixture["lifecycle"]
elif args[:2]==["s3api","list-object-versions"]: value=fixture["versions"]
else: raise SystemExit(64)
print(json.dumps(value,separators=(",",":")))
'''
    write(aws, aws_source.encode(), 0o755)
    return subprocess.run(
        [str(AWS_PROOF), str(contract_path)], text=True, capture_output=True, check=False,
        env={**os.environ, "HOME_LAB_SOPS_BINARY": str(sops), "HOME_LAB_AWS_BINARY": str(aws),
             "HOME_LAB_SOPS_FILE": str(root / "secret"), "SOPS_AGE_KEY_FILE": str(root / "age")},
    )


def aws_proof_fixtures(root: Path) -> None:
    fixture = provider_fixture()
    passed = run_aws_fixture(root, fixture)
    assert passed.returncode == 0, passed.stderr
    proof = json.loads(passed.stdout)
    assert proof["principal_arn_sha256"] == hashlib.sha256(b"arn:aws:iam::123456789012:user/fixture-offen-backup").hexdigest()
    assert proof["current_days"] == 365 and proof["noncurrent_days"] == 1 and proof["multipart_days"] == 1
    assert proof["object_key"] == KEY and proof["object_last_modified"] == "2026-08-23T13:03:53Z"
    assert proof["object_storage_class"] == "STANDARD" and proof["version_id_sha256"] == VERSION_HASH

    negatives: list[tuple[str, str, object]] = [
        ("principal_identity", "identity.Arn", "arn:aws:iam::123456789012:user/other"),
        ("retention_state", "lifecycle.Rules.0.Expiration.Days", 366),
        ("recovery_object_identity", "versions.Versions.0.LastModified", "2026-08-23T13:03:54+00:00"),
        ("recovery_object_identity", "versions.Versions.0.StorageClass", "GLACIER"),
        ("recovery_object_latest", "versions.Versions.0.IsLatest", False),
        ("recovery_object_version", "versions.Versions.0.VersionId", "replaced-version"),
    ]
    for expected, dotted, replacement in negatives:
        changed = json.loads(json.dumps(provider_fixture()))
        target: Any = changed
        parts = dotted.split(".")
        for part in parts[:-1]:
            target = target[int(part)] if isinstance(target, list) else target[part]
        if isinstance(target, list):
            target[int(parts[-1])] = replacement
        else:
            target[parts[-1]] = replacement
        result = run_aws_fixture(root, changed)
        assert result.returncode == 1 and f"reason={expected}" in result.stderr, (dotted, result.stderr)

    unrelated_prefix = provider_fixture()
    unrelated_lifecycle: Any = unrelated_prefix["lifecycle"]
    unrelated_lifecycle["Rules"].append({
        "ID": "unrelated-prefix", "Status": "Enabled", "Filter": {"Prefix": "unrelated/"},
        "Expiration": {"Days": 1},
    })
    result = run_aws_fixture(root, unrelated_prefix)
    assert result.returncode == 0, result.stderr

    for filter_value in (
        {"Prefix": "weekly-backup-"},
        {"Tag": {"Key": "retention", "Value": "short"}},
        {"And": {"Prefix": "weekly-backup-", "Tags": [{"Key": "retention", "Value": "short"}]}},
    ):
        competing = provider_fixture()
        competing_lifecycle: Any = competing["lifecycle"]
        competing_lifecycle["Rules"].append({
            "ID": "competing", "Status": "Enabled", "Filter": filter_value, "Expiration": {"Days": 365},
        })
        result = run_aws_fixture(root, competing)
        expected = "lifecycle_applicability" if "Prefix" in filter_value else "lifecycle_filter"
        assert result.returncode == 1 and f"reason={expected}" in result.stderr, (filter_value, result.stderr)

    deleted = provider_fixture()
    deleted_versions: Any = deleted["versions"]
    deleted_versions["DeleteMarkers"] = [{"Key": KEY, "VersionId": "marker", "IsLatest": True}]
    result = run_aws_fixture(root, deleted)
    assert result.returncode == 1 and "reason=recovery_object_latest" in result.stderr


def runner_fixtures(root: Path) -> None:
    namespace = runpy.run_path(str(RUNNER))
    rendered = subprocess.run([
        "node", "-e", "const fs=require('fs'),y=require('js-yaml');process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1],'utf8')).backups.restic))",
        str(ROOT / "infrastructure/contract/home-lab.yml"),
    ], capture_output=True, text=True, check=True)
    policy = json.loads(rendered.stdout)
    policy_hash = "a" * 64
    artifact = "b" * 64
    os.environ["HOME_LAB_RESTIC_TESTING"] = "1"
    os.environ["HOME_LAB_RESTIC_TEST_ROOT"] = str(root)
    installed = root / policy["runner"]["path"].lstrip("/")
    write(installed, RUNNER.read_bytes(), 0o755)
    write(root / policy["runner"]["artifact_hash_path"].lstrip("/"), (artifact + "\n").encode(), 0o640)
    assert namespace["first_run_context"](policy, policy_hash, "daily-local") is None
    owner = b"controller=ansible-deploy\noperation=restic-first-run\nstarted=2026-08-26T02:00:00Z\n"
    lock = root / policy["runner"]["deploy_lock_path"].lstrip("/")
    write(lock / "owner", owner, 0o600)
    owner_hash = hashlib.sha256(owner).hexdigest()
    journal = {
        "version": 1, "operation": "restic-first-run", "stage": "nfs_completed", "lock_owner_sha256": owner_hash,
        "source_policy_sha256": policy_hash, "artifact_sha256": artifact, "runner_sha256": policy["runner"]["sha256"],
    }
    authorization = {
        "version": 1, "operation": "restic-first-run", "lock_owner_sha256": owner_hash,
        "source_policy_sha256": policy_hash, "artifact_sha256": artifact, "runner_sha256": policy["runner"]["sha256"],
    }
    authorization_raw = (json.dumps(authorization, sort_keys=True, separators=(",", ":")) + "\n").encode()
    write(root / policy["first_run"]["authorization_path"].lstrip("/"), authorization_raw, 0o440)
    write(root / policy["first_run"]["journal_path"].lstrip("/"), (json.dumps(journal) + "\n").encode(), 0o660)

    token = root / policy["first_run"]["proton_token_path"].lstrip("/")
    consumed = root / policy["first_run"]["proton_consumed_token_path"].lstrip("/")
    token_globals = namespace["consume_first_run_proton_token"].__globals__
    original_validate = token_globals["validate_first_run_proton_token"]
    original_unlink = token_globals["durable_unlink"]

    namespace["publish_first_run_proton_token"](policy, policy_hash, journal)
    assert token.stat().st_mode & 0o777 == 0o440
    token_globals["validate_first_run_proton_token"] = lambda *_: (_ for _ in ()).throw(RuntimeError("after-rename"))
    try:
        namespace["consume_first_run_proton_token"](policy, policy_hash, journal)
        raise AssertionError("after-rename interruption did not fire")
    except RuntimeError as error:
        assert str(error) == "after-rename"
    finally:
        token_globals["validate_first_run_proton_token"] = original_validate
    assert consumed.exists() and not token.exists()
    namespace["publish_first_run_proton_token"](policy, policy_hash, journal)
    assert token.exists() and not consumed.exists()
    namespace["consume_first_run_proton_token"](policy, policy_hash, journal)

    namespace["publish_first_run_proton_token"](policy, policy_hash, journal)
    token_globals["durable_unlink"] = lambda *_: (_ for _ in ()).throw(RuntimeError("after-validation"))
    try:
        namespace["consume_first_run_proton_token"](policy, policy_hash, journal)
        raise AssertionError("after-validation interruption did not fire")
    except RuntimeError as error:
        assert str(error) == "after-validation"
    finally:
        token_globals["durable_unlink"] = original_unlink
    assert consumed.exists() and not token.exists()
    namespace["publish_first_run_proton_token"](policy, policy_hash, journal)
    assert token.exists() and not consumed.exists()
    namespace["consume_first_run_proton_token"](policy, policy_hash, journal)

    namespace["publish_first_run_proton_token"](policy, policy_hash, journal)
    shutil.rmtree(lock)
    write(lock / "owner", owner, 0o600)
    try:
        namespace["consume_first_run_proton_token"](policy, policy_hash, journal)
        raise AssertionError("replaced production lock accepted by Proton token")
    except namespace["WorkflowError"] as error:
        assert str(error) == "first_run_token_binding"
    assert consumed.exists()
    try:
        namespace["publish_first_run_proton_token"](policy, policy_hash, journal)
        raise AssertionError("replaced-lock failure minted a second Proton token")
    except namespace["WorkflowError"] as error:
        assert str(error) == "first_run_token_binding"
    assert consumed.exists() and not token.exists()

    calls: list[str] = []
    globals_value = namespace["adopt_or_copy_snapshot"].__globals__
    original_mappings = globals_value["snapshot_mappings"]
    original_copy = globals_value["copy_snapshot"]
    try:
        globals_value["snapshot_mappings"] = lambda *_: ["c" * 64]
        globals_value["copy_snapshot"] = lambda *_: calls.append("copy")
        assert namespace["adopt_or_copy_snapshot"]({}, "games", "nfs", "d" * 64, "ambiguous") == "c" * 64
        assert calls == []
        globals_value["snapshot_mappings"] = lambda *_: ["c" * 64, "e" * 64]
        try:
            namespace["adopt_or_copy_snapshot"]({}, "games", "nfs", "d" * 64, "ambiguous")
            raise AssertionError("duplicate NFS mappings accepted")
        except namespace["WorkflowError"] as error:
            assert str(error) == "ambiguous"
    finally:
        globals_value["snapshot_mappings"] = original_mappings
        globals_value["copy_snapshot"] = original_copy


def supervisor_fixture(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    namespace = runpy.run_path(str(SUPERVISOR))
    artifact_path = root / "artifact"
    artifact_path.write_text("b" * 64 + "\n")
    state = root / "state"
    policy = {
        "runner": {
            "sha256": "c" * 64, "artifact_hash_path": str(artifact_path),
            "accepted_path": str(state / "accepted.json"), "journal_path": str(state / "interruption.json"),
        },
        "first_run": {
            "baseline": {"games": [], "nfs": [], "proton": []},
            "result_path": str(state / "result.json"), "host_evidence_path": str(state / "evidence.json"),
            "authorization_path": str(state / "authorization.json"), "proton_token_path": str(state / "token.json"),
            "proton_consumed_token_path": str(state / "consumed.json"),
        },
    }
    baseline_globals = namespace["pre_journal_baseline"].__globals__
    original_snapshots = baseline_globals["snapshots"]
    try:
        baseline_globals["snapshots"] = lambda *_: []
        assert namespace["pre_journal_baseline"](policy) == {"games": [], "nfs": [], "proton": []}
        baseline_globals["snapshots"] = lambda _policy, name: [{"id": "1" * 64}] if name == "proton" else []
        try:
            namespace["pre_journal_baseline"](policy)
            raise AssertionError("nonempty pre-journal repository was adopted")
        except namespace["FirstRunError"] as error:
            assert str(error) == "pre_journal_repository_state"
        write(state / "accepted.json", b"{}\n", 0o600)
        baseline_globals["snapshots"] = lambda *_: []
        try:
            namespace["pre_journal_baseline"](policy)
            raise AssertionError("pre-journal accepted state was adopted")
        except namespace["FirstRunError"] as error:
            assert str(error) == "pre_journal_state"
    finally:
        baseline_globals["snapshots"] = original_snapshots

    pending_raw = json.dumps(policy, separators=(",", ":")).encode()
    previous_stdin = os.sys.stdin
    previous_hash = os.environ.get("HOME_LAB_RESTIC_PENDING_POLICY_SHA256")
    try:
        os.environ["HOME_LAB_RESTIC_PENDING_POLICY_SHA256"] = hashlib.sha256(pending_raw).hexdigest()
        os.sys.stdin = io.TextIOWrapper(io.BytesIO(pending_raw))
        pending_policy, observed_raw = namespace["pending_verify_policy"]()
        assert pending_policy == policy and observed_raw == pending_raw
    finally:
        os.sys.stdin = previous_stdin
        if previous_hash is None:
            os.environ.pop("HOME_LAB_RESTIC_PENDING_POLICY_SHA256", None)
        else:
            os.environ["HOME_LAB_RESTIC_PENDING_POLICY_SHA256"] = previous_hash

    journal = {
        "version": 1, "operation": "restic-first-run", "stage": "complete", "lock_owner_sha256": "d" * 64,
        "source_policy_sha256": "a" * 64, "artifact_sha256": "b" * 64, "runner_sha256": "c" * 64,
        "aws_evidence_sha256": "e" * 64, "started_at": "2026-08-26T01:00:00Z", "completed_at": None,
        "baseline": {"games": [], "nfs": [], "proton": []},
        "initially_running_writers": [], "stopped_writers": [], "restarted_writers": [],
        "snapshots": {"games": None, "nfs": None, "proton": None},
        "checks": {"games": False, "nfs": False, "proton": False},
        "retention": {"games": False, "nfs": False, "proton": False}, "quota": {},
    }
    try:
        namespace["validate_journal"](journal, policy, "a" * 64, "d" * 64)
        raise AssertionError("complete journal accepted null completed_at")
    except namespace["FirstRunError"] as error:
        assert str(error) == "journal_completed_at"


def main() -> None:
    source = RUNNER.read_text()
    supervisor = SUPERVISOR.read_text()
    aws_source = AWS_PROOF.read_text()
    assert all(value in aws_source for value in ("get-caller-identity", "get-bucket-versioning", "get-bucket-lifecycle-configuration", "list-object-versions"))
    assert not any(command in aws_source for command in ("delete-object", "put-bucket", "abort-multipart-upload"))
    assert 'SUBCOMMANDS = {"preflight", "daily-local", "daily-proton", "maintenance", "status"}' in source
    assert '["/usr/bin/systemctl","start","--wait",target]' in supervisor
    assert not any(term in supervisor for term in ('"sync"', '"bisync"', '"purge"', '"cleanup"', '"mount"'))
    retained_update = (ROOT / "ansible/playbooks/update-retained-first-run-tools.yml").read_text()
    for protected_path in ("authorization_path", "proton_token_path", "proton_consumed_token_path"):
        assert f"first_run.{protected_path}" in retained_update
    post_nfs_recovery = (ROOT / "ansible/playbooks/recover-post-nfs-first-run.yml").read_text()
    for safety_check in ("os.O_NOFOLLOW", "os.fstat(parent_descriptor)", "parent_metadata.st_gid in {0,60000}", "stat.S_IMODE(parent_metadata.st_mode)==0o750", "stat.gr_name == 'restic-proton'"):
        assert safety_check in post_nfs_recovery
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        aws_proof_fixtures(root / "aws")
        runner_fixtures(root / "runner")
        supervisor_fixture(root / "supervisor")
    print("restic first-run executable fixtures passed")


if __name__ == "__main__":
    main()
