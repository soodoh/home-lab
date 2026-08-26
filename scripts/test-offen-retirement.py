#!/usr/bin/env python3
"""Static and pure-function safety tests for planned Offen retirement."""
from __future__ import annotations

import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "infrastructure/retirement/offen-retirement-manifest.json"
EXPECTED = "c67d0351b26fddaa7fdb4057a85511b8a3359b40851a9df542c532f8abc00d2c"

raw = MANIFEST.read_bytes()
assert hashlib.sha256(raw).hexdigest() == EXPECTED
value = json.loads(raw)
assert value["restic_repositories"] == {
    "games": "b15627185df9b10a95b5dffe7d194dbccdba6ba4eb8a038ee03e750fedbde08f",
    "nfs": "61d50fa782d194374deb24f354a07b0f11634721afa1b268963e4d017b93bb95",
    "proton": "d1faa9cd772dd13275b8d4db376c2bbba0b82a9415a28b0d03a8b17e37b7fb7e",
}
archives = value["local"]["archives"]
assert len(archives) == 12
assert len({item["path"] for item in archives}) == 12
metadata = value["local"]["metadata_files"]
assert len(metadata) == 8 and len({item["path"] for item in metadata}) == 8
assert all(item["bytes"] == 116 for item in metadata)
assert all(item["archive_path"] + ".sha256" == item["path"] for item in metadata)
assert value["local"]["protected_directories"] == [
    {"path": "/mnt/games/backups/.migration-preserved-offen", "uid": 0, "gid": 0, "mode": "0700"},
    {"path": "/mnt/storage/backups/.migration-preserved-offen", "uid": 0, "gid": 0, "mode": "0700"},
]
assert {item["bytes"] for item in archives} == {2319938554, 2331814541, 2411062883, 2422649137}
assert all(item["path"].startswith(("/mnt/games/backups/", "/mnt/storage/backups/")) for item in archives)
assert value["compose"]["services"] == ["daily-local-backup", "weekly-remote-backup"]
assert value["compose"]["project"] == "docker-compose"
assert value["compose"]["working_directory"] == "/srv/docker-compose/current"
assert value["compose"]["base_commit"] == "d1e37374c38cc0b85f64a92d5ca0345b82e53960"
assert value["compose"]["retirement_commit"] == "606248628d75d57e81535d8bf4fd0dec0c4194dd"
assert value["compose"]["base_artifact_sha256"] == "722252e11e15cf315a5ade5cc1f5708eaacf636ecea4706a00ff5670d86ebd74"
assert value["compose"]["retirement_artifact_sha256"] == "1e994b12d49f814f9dcef946802a6daf1e1027c95c9c9bf9a918aab53490cef9"
assert value["aws"]["version_id_sha256"] == "3e42bf4017bedaaac231ce234cc8be64536a87da0ba8e401b90967864c73a8c0"
assert "version_id" not in value["aws"]
assert {"restic-recovery-bundle-a", "restic-recovery-bundle-b", "proton-trash"} <= set(value["preserve"])
shared_key = ROOT / "services/data/backup-gpg-public.asc"
access_recovery = ROOT / "scripts/create-sops-age-identity.sh"
assert shared_key.is_file() and "BEGIN PGP PUBLIC KEY BLOCK" in shared_key.read_text()
access_source = access_recovery.read_text()
assert "backup-gpg-public.asc" in access_source and "sops-age-recovery.txt.gpg" in access_source
for key, path in (
    ("local_helper_sha256", ROOT / "scripts/retire-offen-local"),
    ("aws_helper_sha256", ROOT / "scripts/retire-offen-aws-object"),
    ("aws_state_helper_sha256", ROOT / "scripts/controller/offen-retirement-aws-state.py"),
    ("aws_plan_inspector_sha256", ROOT / "infrastructure/policy/inspect-offen-retirement-aws-plan.py"),
    ("evidence_validator_sha256", ROOT / "scripts/controller/validate-offen-retirement-evidence.js"),
):
    assert hashlib.sha256(path.read_bytes()).hexdigest() == value["tools"][key]

helper_path = ROOT / "scripts/retire-offen-local"
spec = importlib.util.spec_from_loader("retire_offen_local", SourceFileLoader("retire_offen_local", str(helper_path)))
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
REAL_CONVERGE_IMAGE_OVERRIDE = module.converge_image_override
REAL_COMPOSE_ARTIFACT_IDENTITY = module.compose_artifact_identity
REAL_ROLLBACK_COMPOSE_SOURCE = module.rollback_compose_source
REAL_RUN = module.run
REAL_FSYNC_COMPOSE_PARENT = module.fsync_compose_parent
REAL_FCHOWN = module.os.fchown
module.container_state = lambda service, _manifest_hash: (service, "sha256:image", "container-" + service)
plan = module.action_plan(value, EXPECTED)
assert len(plan["file_renames"]) == 20 and len(plan["container_renames"]) == 2
assert all(EXPECTED[:16] in item["to"] for item in plan["file_renames"] + plan["container_renames"])
assert module.canonical(plan) == module.canonical(json.loads(module.canonical(plan)))

subprocess.run(["bash", "-n", str(ROOT / "scripts/retire-offen-aws-object")], check=True)
subprocess.run(["bash", "-n", str(ROOT / "scripts/restore-critical-backup")], check=True)
aws_source = (ROOT / "scripts/retire-offen-aws-object").read_text()
assert "s3api delete-object" in aws_source
assert "s3api list-object-versions" in aws_source
assert "DeleteObjects" not in aws_source and "--recursive" not in aws_source
assert all(forbidden not in aws_source for forbidden in ("rclone purge", "rclone cleanup", "aws s3 rm"))
local_source = (ROOT / "scripts/retire-offen-local").read_text()
assert 'stat.S_IMODE(info.st_mode) != 0o644' in local_source
assert 'observed_ids != expected_ids' in local_source
assert 'expected_ids = manifest.get("restic_repositories", {})' in local_source
assert local_source.index("file_rename_started") < local_source.index("irreversible_unlink_started")
assert "rollback_forbidden" in local_source
assert "fcntl.LOCK_EX" in local_source
assert "temporary.unlink()" in local_source
assert "rollback_compose_source(manifest, manifest_hash)" in local_source
assert '["/usr/bin/mv", "--exchange"' in local_source
retirement_playbook = (ROOT / "ansible/playbooks/retire-offen-local.yml").read_text()
assert "compose_base_artifact_sha256" in (ROOT / "ansible/roles/compose_deploy/tasks/main.yml").read_text()
assert "when: offen_retirement_action == 'rollback'" in retirement_playbook and "apply_lock_action: release" in retirement_playbook

iam = (ROOT / "infrastructure/tofu/aws-foundation/iam.tf").read_text()
lifecycle = (ROOT / "infrastructure/tofu/aws-foundation/main.tf").read_text()
assert 'actions = ["s3:DeleteObjectVersion"]' in iam
assert 'retirement.state == "retirement-planned"' in iam
assert 'migration_retention_hold.state == "retired" ? [] : [1]' in lifecycle
assert 'id     = "incomplete-multipart-cleanup"' in lifecycle
inspector = ROOT / "infrastructure/policy/inspect-offen-retirement-aws-plan.py"
for operation in ("grant", "finalize"):
    fixture = ROOT / f"infrastructure/policy/fixtures/offen-retirement-aws-{operation}.json"
    subprocess.run([
        "python3", str(inspector), "--operation", operation,
        "--manifest", str(MANIFEST), "--plan", str(fixture),
    ], check=True, stdout=subprocess.PIPE, text=True)
    baseline = json.loads(fixture.read_text())
    hostile = []
    missing_access = json.loads(json.dumps(baseline))
    policy_change = next(item for item in missing_access["resource_changes"] if item["address"] == "aws_iam_user_policy.recovery")
    policy = json.loads(policy_change["change"]["after"]["policy"])
    policy["Statement"] = [item for item in policy["Statement"] if "s3:GetObject" not in ([item["Action"]] if isinstance(item["Action"], str) else item["Action"])]
    policy_change["change"]["after"]["policy"] = json.dumps(policy)
    hostile.append(missing_access)
    disabled_lifecycle = json.loads(json.dumps(baseline))
    lifecycle_change = next(item for item in disabled_lifecycle["resource_changes"] if item["address"] == "aws_s3_bucket_lifecycle_configuration.recovery")
    lifecycle_change["change"]["after"]["rule"][0]["status"] = "Disabled"
    hostile.append(disabled_lifecycle)
    filtered_lifecycle = json.loads(json.dumps(baseline))
    lifecycle_change = next(item for item in filtered_lifecycle["resource_changes"] if item["address"] == "aws_s3_bucket_lifecycle_configuration.recovery")
    lifecycle_change["change"]["after"]["rule"][0]["filter"] = [{"prefix": "offen/"}]
    hostile.append(filtered_lifecycle)
    transitioned_lifecycle = json.loads(json.dumps(baseline))
    lifecycle_change = next(item for item in transitioned_lifecycle["resource_changes"] if item["address"] == "aws_s3_bucket_lifecycle_configuration.recovery")
    lifecycle_change["change"]["after"]["rule"][0]["transition"] = [{"days": 1, "storage_class": "GLACIER"}]
    hostile.append(transitioned_lifecycle)
    alternate_expiration = json.loads(json.dumps(baseline))
    lifecycle_change = next(item for item in alternate_expiration["resource_changes"] if item["address"] == "aws_s3_bucket_lifecycle_configuration.recovery")
    lifecycle_change["change"]["after"]["rule"][0].setdefault("expiration", []).append({"days": 2})
    hostile.append(alternate_expiration)
    wrong_binding = json.loads(json.dumps(baseline))
    policy_change = next(item for item in wrong_binding["resource_changes"] if item["address"] == "aws_iam_user_policy.recovery")
    policy = json.loads(policy_change["change"]["after"]["policy"])
    policy["Statement"][0]["Resource"] = ["arn:aws:s3:::wrong", "arn:aws:s3:::protected-state"]
    policy_change["change"]["after"]["policy"] = json.dumps(policy)
    hostile.append(wrong_binding)
    for item in hostile:
        with tempfile.NamedTemporaryFile("w", suffix=".json") as target:
            json.dump(item, target); target.flush()
            result = subprocess.run(["python3", str(inspector), "--operation", operation, "--manifest", str(MANIFEST), "--plan", target.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert result.returncode != 0

# Exercise auto-paginated aggregate classification, truncation rejection, and
# response-loss adoption of an already absent exact version.
state_helper = ROOT / "scripts/controller/offen-retirement-aws-state.py"
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); listed = root / "listed.json"; selected = root / "selected"
    version_id = "exact-version"
    entries = [{"Key": f"unrelated-{index}", "VersionId": str(index), "Size": index, "IsLatest": True} for index in range(150)]
    entries.append({"Key": value["aws"]["object_key"], "VersionId": version_id, "Size": value["aws"]["object_bytes"], "IsLatest": True})
    listed.write_text(json.dumps({"IsTruncated": False, "Versions": entries, "DeleteMarkers": []}))
    subprocess.run(["python3", str(state_helper), "select", "--input", str(listed), "--key", value["aws"]["object_key"], "--bytes", str(value["aws"]["object_bytes"]), "--version-id-sha256", hashlib.sha256(version_id.encode()).hexdigest(), "--output", str(selected)], check=True, stdout=subprocess.PIPE)
    assert selected.read_text() == version_id
    listed.write_text(json.dumps({"IsTruncated": False, "Versions": [], "DeleteMarkers": []}))
    subprocess.run(["python3", str(state_helper), "prove-absent", "--input", str(listed), "--key", value["aws"]["object_key"]], check=True, stdout=subprocess.PIPE)
    listed.write_text(json.dumps({"IsTruncated": True, "NextKeyMarker": "hidden", "Versions": []}))
    assert subprocess.run(["python3", str(state_helper), "prove-absent", "--input", str(listed), "--key", value["aws"]["object_key"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0

# Exercise irreversible response-loss recovery: the first invocation crashes after
# one successful unlink, and the exact retained transaction resumes to completion.
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    module.OWNER = root / "owner.json"
    module.ACTION_PLAN = root / "action-plan.json"
    module.JOURNAL = root / "journal.jsonl"
    module.TRANSACTION = root
    module.STAGED_EVIDENCE = root / "staged.json"
    module.FINAL_RESULT = root / "final.json"
    module._regular_private = lambda path: path.read_bytes()
    manifest_hash = "a" * 64
    archive = root / "archive.gpg"; archive.write_bytes(b"archive")
    metadata_file = root / "archive.gpg.sha256"
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    metadata_file.write_text(f"{archive_hash}  archive.gpg\n")
    protected_one = root / "protected-one"; protected_one.mkdir()
    protected_two = root / "protected-two"; protected_two.mkdir()
    fixture_manifest = {"local": {"archives": [{"path": str(archive), "bytes": archive.stat().st_size, "sha256": archive_hash}], "metadata_files": [{"path": str(metadata_file), "archive_path": str(archive), "bytes": metadata_file.stat().st_size, "sha256": hashlib.sha256(metadata_file.read_bytes()).hexdigest(), "expected_archive_sha256": archive_hash}], "protected_directories": [{"path": str(protected_one)}, {"path": str(protected_two)}]}, "compose": {"services": [], "image": "example.invalid/offen@sha256:" + "b" * 64, "image_override": {"path": str(root / "override.json"), "before_sha256": "1" * 64, "after_sha256": "2" * 64, "removed_services": {}}}}
    plan = module.action_plan(fixture_manifest, manifest_hash)
    plan_raw = module.canonical(plan)
    module.ACTION_PLAN.write_bytes(plan_raw)
    plan_hash = hashlib.sha256(plan_raw).hexdigest()
    owner_raw = module.canonical({"operation": "offen-retirement-local", "manifest_sha256": manifest_hash, "action_plan_sha256": plan_hash})
    module.OWNER.write_bytes(owner_raw)
    module.JOURNAL.write_bytes(
        module.canonical({"event": "apply_complete", "action_plan_sha256": plan_hash})
        + module.canonical({"event": "image_remove_started", "image_sha256": "b" * 64})
    )
    staged = {"version": 1, "phase": "retirement-finalizing", "manifest_sha256": manifest_hash, "aws_object_absent": True, "bundle_b_preserved": True, "delete_authorization_removed": True, "lifecycle_converged": True, "local_action_plan_sha256": plan_hash, "local_transaction_owner_sha256": hashlib.sha256(owner_raw).hexdigest()}
    module.STAGED_EVIDENCE.write_bytes(module.canonical(staged))
    evidence_hash = hashlib.sha256(module.STAGED_EVIDENCE.read_bytes()).hexdigest()
    for item in module.retirement_files(fixture_manifest):
        Path(item["path"]).rename(module.tombstone(Path(item["path"]), manifest_hash))
    module.verify_status = lambda: None
    module.verify_status_under_lock = lambda _manifest: None
    module.verify_mounts = lambda _manifest: None
    module.verify_archives = lambda *_args, **_kwargs: None
    module.verify_containers = lambda *_args, **_kwargs: None
    module.require_image_override = lambda *_args, **_kwargs: None
    module.require_compose_source = lambda *_args, **_kwargs: None
    module.run = lambda _args: ""
    module.subprocess.run = lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="")
    authoritative_journal = module.JOURNAL.read_bytes()
    module.JOURNAL.write_bytes(module.canonical({"event": "image_remove_started", "image_sha256": "b" * 64}))
    try:
        module.finalize(fixture_manifest, manifest_hash, evidence_hash)
        raise AssertionError("finalize accepted a missing authoritative apply_complete")
    except SystemExit:
        pass
    module.JOURNAL.write_bytes(authoritative_journal)
    original_append = module.append
    crashed = {"value": False}
    def crash_after_first_unlink(event):
        original_append(event)
        if event.get("event") == "file_unlinked" and not crashed["value"]:
            crashed["value"] = True
            raise RuntimeError("simulated response loss")
    module.append = crash_after_first_unlink
    try:
        module.finalize(fixture_manifest, manifest_hash, evidence_hash)
        raise AssertionError("crash injection did not fire")
    except RuntimeError:
        pass
    module.append = original_append
    module.finalize(fixture_manifest, manifest_hash, evidence_hash)
    assert module.FINAL_RESULT.is_file()
    assert not archive.exists() and not metadata_file.exists()
    assert not protected_one.exists() and not protected_two.exists()
    module.finalize(fixture_manifest, manifest_hash, evidence_hash)

# A saved action-plan or transaction-owner byte change blocks rollback before
# any canonical tombstone rename can occur.
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    module.TRANSACTION = root
    module.OWNER = root / "owner.json"
    module.ACTION_PLAN = root / "action-plan.json"
    module.JOURNAL = root / "journal.jsonl"
    module._regular_private = lambda path: path.read_bytes()
    manifest_hash = "c" * 64
    source = root / "archive.gpg"; source.write_bytes(b"rollback")
    item = {"path": str(source), "bytes": source.stat().st_size, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    rollback_manifest = {"local": {"archives": [item], "metadata_files": [], "protected_directories": []}, "compose": {"services": [], "image": "example.invalid/offen@sha256:" + "d" * 64, "image_override": {"path": str(root / "override.json"), "before_sha256": "3" * 64, "after_sha256": "4" * 64, "removed_services": {}}}}
    module.converge_image_override = lambda *_args, **_kwargs: None
    module.require_image_override = lambda *_args, **_kwargs: None
    module.rollback_compose_source = lambda *_args, **_kwargs: None
    plan = module.action_plan(rollback_manifest, manifest_hash)
    plan_raw = module.canonical(plan); plan_hash = hashlib.sha256(plan_raw).hexdigest()
    owner_raw = module.canonical({"operation": "offen-retirement-local", "manifest_sha256": manifest_hash, "action_plan_sha256": plan_hash})
    module.ACTION_PLAN.write_bytes(plan_raw); module.OWNER.write_bytes(owner_raw)
    module.JOURNAL.write_bytes(module.canonical({"event": "apply_complete", "action_plan_sha256": plan_hash}))
    source.rename(module.tombstone(source, manifest_hash))
    tampered = json.loads(plan_raw); tampered["file_renames"][0]["to"] += ".other"
    module.ACTION_PLAN.write_bytes(module.canonical(tampered))
    try:
        module.rollback(rollback_manifest, manifest_hash)
        raise AssertionError("tampered rollback action plan passed")
    except SystemExit:
        pass
    module.ACTION_PLAN.write_bytes(plan_raw); module.OWNER.write_text("{}\n")
    try:
        module.rollback(rollback_manifest, manifest_hash)
        raise AssertionError("synthetic rollback owner passed")
    except SystemExit:
        pass
    module.OWNER.write_bytes(owner_raw)
    module.rollback(rollback_manifest, manifest_hash)
    assert source.read_bytes() == b"rollback"
module.converge_image_override = REAL_CONVERGE_IMAGE_OVERRIDE
module.rollback_compose_source = REAL_ROLLBACK_COMPOSE_SOURCE

# The production image override transition is exact, idempotent, and reversible.
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    override = root / "override.json"
    before_value = {"services": {"daily-local-backup": {"image": "sha256:" + "a" * 64}, "weekly-remote-backup": {"image": "sha256:" + "a" * 64}, "keep": {"image": "sha256:" + "b" * 64}}}
    before_raw = module.canonical(before_value); override.write_bytes(before_raw)
    after_value = json.loads(json.dumps(before_value))
    del after_value["services"]["daily-local-backup"]; del after_value["services"]["weekly-remote-backup"]
    after_raw = module.canonical(after_value)
    override_manifest = {"compose": {"image_override": {"path": str(override), "before_sha256": hashlib.sha256(before_raw).hexdigest(), "after_sha256": hashlib.sha256(after_raw).hexdigest(), "removed_services": {"daily-local-backup": {"image": "sha256:" + "a" * 64}, "weekly-remote-backup": {"image": "sha256:" + "a" * 64}}}}}
    module.TRANSACTION = root; module.JOURNAL = root / "journal.jsonl"
    module._regular_private = lambda path: path.read_bytes()
    module.image_override_state = lambda _manifest: (override, json.loads(override.read_text()), hashlib.sha256(override.read_bytes()).hexdigest())
    module.os.fchown = lambda *_args: None
    module.converge_image_override(override_manifest, "e" * 64, True)
    assert override.read_bytes() == after_raw
    module.converge_image_override(override_manifest, "e" * 64, True)
    module.converge_image_override(override_manifest, "e" * 64, False)
    assert override.read_bytes() == before_raw
    module.converge_image_override(override_manifest, "e" * 64, False)
module.os.fchown = REAL_FCHOWN

# Compose source rollback adopts an exchange after response loss and recovers
# the crash-only state where current is absent but exact base previous remains.
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); current = root / "current"; previous = root / "previous"
    current.mkdir(); previous.mkdir(); (current / "identity").write_text("retired"); (previous / "identity").write_text("base")
    compose_manifest = {"compose": {"working_directory": str(current), "previous_directory": str(previous), "base_artifact_sha256": "base", "retirement_artifact_sha256": "retired"}}
    module.TRANSACTION = root; module.JOURNAL = root / "journal.jsonl"; module._regular_private = lambda path: path.read_bytes()
    module.compose_artifact_identity = lambda path: (path / "identity").read_text()
    def exchange_then_lose(_command):
        swap = root / "swap"; current.rename(swap); previous.rename(current); swap.rename(previous)
        raise RuntimeError("simulated exchange response loss")
    module.run = exchange_then_lose
    try:
        module.rollback_compose_source(compose_manifest, "f" * 64)
        raise AssertionError("exchange response-loss injection did not fire")
    except RuntimeError:
        pass
    module.run = lambda _command: ""
    module.rollback_compose_source(compose_manifest, "f" * 64)
    assert (current / "identity").read_text() == "base" and (previous / "identity").read_text() == "retired"
    missing = root / "missing"; missing.mkdir(); missing_current = missing / "current"; missing_previous = missing / "previous"
    missing_previous.mkdir(); (missing_previous / "identity").write_text("base")
    missing_manifest = {"compose": {"working_directory": str(missing_current), "previous_directory": str(missing_previous), "base_artifact_sha256": "base", "retirement_artifact_sha256": "retired"}}
    module.fsync_compose_parent = lambda _path: (_ for _ in ()).throw(RuntimeError("simulated missing-current response loss"))
    try:
        module.recover_missing_current(missing_manifest)
        raise AssertionError("missing-current response-loss injection did not fire")
    except RuntimeError:
        pass
    module.fsync_compose_parent = REAL_FSYNC_COMPOSE_PARENT
    module.recover_missing_current(missing_manifest)
    assert (missing_current / "identity").read_text() == "base" and not missing_previous.exists()
    assert len([item for item in module.journal_events() if item.get("event") == "compose_missing_current_recovered"]) == 1
module.compose_artifact_identity = REAL_COMPOSE_ARTIFACT_IDENTITY
module.fsync_compose_parent = REAL_FSYNC_COMPOSE_PARENT
module.run = REAL_RUN

# The terminal evidence validator accepts a schema-complete canonical shape and
# rejects altered manifest/bundle semantics before any release path can clean up.
def schema_sample(node):
    if "const" in node:
        return node["const"]
    if node.get("type") == "object":
        return {key: schema_sample(node["properties"][key]) for key in node.get("required", [])}
    if node.get("type") == "string":
        pattern = node.get("pattern", "")
        return "2026-08-26T00:00:00Z" if pattern.startswith("^[0-9]{4}-") else "0" * 64
    raise AssertionError(f"unsupported schema sample: {node}")

validator = ROOT / "scripts/controller/validate-offen-retirement-evidence.js"
with tempfile.TemporaryDirectory() as temporary:
    evidence_path = Path(temporary) / "evidence.json"
    evidence = schema_sample(json.loads((ROOT / "infrastructure/evidence/offen-retirement.schema.json").read_text()))
    evidence["manifest_sha256"] = EXPECTED
    evidence["aws"]["version_id_sha256"] = value["aws"]["version_id_sha256"]
    evidence["aws"]["bundle_b_after_head_sha256"] = evidence["aws"]["bundle_b_before_head_sha256"]
    evidence["restic"]["restore_proof_sha256"] = value["restic_evidence"]["restore_proof_sha256"]
    evidence["preserved"] = value["preserve"]
    evidence_path.write_text(json.dumps(evidence, separators=(",", ":")) + "\n")
    command = ["node", str(validator), str(ROOT / "infrastructure/evidence/offen-retirement.schema.json"), str(evidence_path), str(MANIFEST)]
    subprocess.run(command, check=True, stdout=subprocess.PIPE)
    evidence["aws"]["bundle_b_after_head_sha256"] = "f" * 64
    evidence_path.write_text(json.dumps(evidence, separators=(",", ":")) + "\n")
    assert subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0

assert "--page-size 100" in aws_source and "delete_response_lost" in aws_source
assert "OFFEN_RETIREMENT_LOCAL_OWNER_FILE" in aws_source and "OFFEN_RETIREMENT_LOCAL_OWNER_SHA256" not in aws_source
assert "[[ $OFFEN_RETIREMENT_LOCAL_OWNER_FILE == /var/lib/iac-ansible-production.lock/owner ]]" in aws_source
assert aws_source.index("local_owner_path_differs") < aws_source.index("command -v sops")
assert '"local_owner_sha256":"%s"' in aws_source and "verify_owner; verify_terminal_journal" in aws_source
assert "offen-retirement-local" in (ROOT / "ansible/playbooks/clear-failed-apply-lock.yml").read_text()
assert "apply_lock_action: \"{{ 'acquire' if offen_retirement_action == 'apply' else 'adopt' }}\"" in (ROOT / "ansible/playbooks/retire-offen-local.yml").read_text()
controller = (ROOT / "scripts/reconcile-infrastructure").read_text()
assert "inspect-offen-retirement-aws-plan.py" in controller
assert "offen_retirement_operation" in controller and "OFFEN_RETIREMENT_OPERATION" not in controller
assert "retirement-finalizing) printf 'finalize" in controller
assert "OFFEN_RETIREMENT_OPERATION" not in controller
assert controller.count("inspect-offen-retirement-aws-plan.py") >= 2
finalizer = (ROOT / "ansible/playbooks/finalize-offen-retirement.yml").read_text()
assert "apply_lock_action: adopt" in finalizer and "apply_lock_action: release" in finalizer
assert "final_result_sha256" in finalizer and "action_plan_sha256" in finalizer
final_schema = json.loads((ROOT / "infrastructure/evidence/offen-retirement.schema.json").read_text())
staged_schema = json.loads((ROOT / "infrastructure/evidence/offen-retirement-staged.schema.json").read_text())
assert staged_schema["properties"]["phase"]["const"] == "retirement-finalizing"
assert "archive_files_removed" not in staged_schema["properties"]
assert {"journal_sha256", "transaction_owner_sha256"} <= set(final_schema["properties"]["aws"]["required"])
assert {"final_result_sha256", "journal_sha256", "action_plan_sha256"} <= set(final_schema["properties"]["local"]["required"])
assert "release)" in aws_source and "OFFEN_RETIREMENT_FINAL_EVIDENCE_FILE" in aws_source
assert "if ! grep -q '\"event\":\"delete_started\"'" in aws_source
assert "if ! grep -q '\"event\":\"delete_complete\"'" in aws_source
assert "offen_retirement_aws=released-retained" in aws_source
assert "rm -f -- \"$journal\" \"$owner\"" not in aws_source
assert "rm -rf" not in aws_source
assert "find \"$workspace\" -mindepth 1 -maxdepth 1 -print0" in aws_source
assert "rmdir -- \"$workspace\"" in aws_source
assert "state: absent" not in finalizer
assert finalizer.index("apply_lock_action: release") > finalizer.index("Local or AWS terminal retirement evidence differs")
print("offen_retirement_tests=passed")
