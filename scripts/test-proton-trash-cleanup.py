#!/usr/bin/env python3
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
os.environ["HOME_LAB_PROTON_TRASH_TESTING"] = "1"
os.environ["HOME_LAB_PROTON_V1_CLEANUP_BASE"] = str(ROOT / "scripts/cleanup-damaged-proton-restic-v1")
HOST = SourceFileLoader("proton_trash_cleanup_host", str(ROOT / "scripts/empty-proton-trash")).load_module()
CONTROLLER = SourceFileLoader("proton_trash_cleanup_controller", str(ROOT / "scripts/controller/proton-trash-cleanup.py")).load_module()


def host_observation() -> dict:
    contract, _ = CONTROLLER.C.contract_policy()
    return {
        "format": "home-lab-proton-trash-cleanup-observation-v1",
        "helper_sha256": CONTROLLER.C.sha((ROOT / "scripts/empty-proton-trash").read_bytes()),
        "base_helper_sha256": CONTROLLER.C.sha((ROOT / "scripts/cleanup-damaged-proton-restic-v1").read_bytes()),
        "runner_sha256": contract["backups"]["restic"]["runner"]["sha256"],
        "policy_sha256": "a" * 64,
        "active_directories": ["home-lab-restic-v2/"],
        "replacement": {"repository_id": CONTROLLER.C.NEW_ID, "snapshot_id": CONTROLLER.C.NEW_SNAPSHOT, "original_snapshot_id": CONTROLLER.C.ORIGINAL_SNAPSHOT},
        "migration": {"sha256": "3213ceff96d067da22c5b243a213f39a00e7f9cce74905fc53c5d5229ac1f4a5", "full_read_data_check": True},
        "v1_cleanup": {"plan_sha256": HOST.V1_PLAN, "receipt_sha256": HOST.V1_RECEIPT_SHA256},
        "usage": {"total": 1000, "used": 600, "free": 400},
        "trash_scope": "entire-account-trash-unenumerable",
    }


def test_controller_binds_explicit_unenumerable_entire_trash_scope():
    contract, _ = CONTROLLER.C.contract_policy()
    CONTROLLER.validate_observation(host_observation(), contract)
    assert CONTROLLER.action() == {"kind": "empty-entire-proton-trash", "scope": "entire-account-trash-at-authorized-execution", "enumerable": False, "permanent_delete": True}


def test_exact_cleanup_wrapper_cannot_change_remote_or_command():
    result = subprocess.CompletedProcess([], 0, "", "")
    with patch.object(HOST.subprocess, "run", return_value=result) as invoked:
        HOST.exact_empty_trash("/usr/local/bin/rclone", Path("/var/lib/restic-proton/rclone.conf"), {"HOME": "/var/lib/restic-proton"})
    arguments = invoked.call_args.args[0]
    assert arguments == ["/usr/local/bin/rclone", "cleanup", "--config", "/var/lib/restic-proton/rclone.conf", "proton-backup:"]


def test_receipt_validation_binds_full_read_and_usage():
    started = {
        "format": HOST.RECEIPT_FORMAT,
        "status": "cleanup-started",
        "plan_sha256": "b" * 64,
        "authorization_sha256": "c" * 64,
        "authorization_history": ["c" * 64],
        "started_at": "2026-09-02T12:00:00Z",
        "before_usage": {"total": 1000, "used": 600, "free": 400},
        "execution_usage": {"total": 1000, "used": 600, "free": 400},
    }
    receipt = {
        **started,
        "status": "committed",
        "committed_at": "2026-09-02T12:10:00Z",
        "scope": "entire-account-trash",
        "permanent_delete": True,
        "v1_cleanup_receipt_sha256": HOST.V1_RECEIPT_SHA256,
        "after_usage": {"total": 1000, "used": 300, "free": 700},
        "active_directories": [HOST.B.NEW_REMOTE_DIRECTORY],
        "replacement_check": "full-read-data-zero-errors",
        "recovery_evidence_sha256": HOST.B.RECOVERY_SHA256,
        "recovery_journal_sha256": HOST.B.RECOVERY_JOURNAL_SHA256,
    }
    HOST.validate_receipt(receipt, started, "b" * 64, "c" * 64)
    changed = {**receipt, "active_directories": []}
    try:
        HOST.validate_receipt(changed, started, "b" * 64, "c" * 64)
    except SystemExit as error:
        assert "receipt-state" in str(error)
    else:
        raise AssertionError("replacement directory drift was accepted")



def exercise_apply(*, started: bool = False, expired: bool = False, drift: bool = False, receipt_ahead: bool = False) -> tuple[dict, list[bool]]:
    class FakeModule:
        def command_paths(self, _policy):
            return "/usr/local/bin/restic", "/usr/local/bin/rclone"

        def credential_environment(self, _policy, _destination, _source):
            return {"HOME": "/var/lib/restic-proton"}

        def rooted(self, path):
            return Path(path)

    digest = "b" * 64
    old_auth = "c" * 64
    auth_digest = "d" * 64 if started and not receipt_ahead else old_auth
    plan_observation = host_observation()
    plan = {"host_observation": plan_observation}
    now = datetime.now(timezone.utc)
    auth_created = now - timedelta(minutes=1)
    auth_expires = now - timedelta(seconds=1) if expired else now + timedelta(minutes=10)
    purges: list[bool] = []
    current = {**plan_observation, "usage": {"total": 1000, "used": 600, "free": 400}}
    if drift:
        current = {**current, "replacement": {**current["replacement"], "repository_id": "f" * 64}}
    after = {**plan_observation, "usage": {"total": 1000, "used": 300, "free": 700}}
    summary = json.dumps({"message_type": "summary", "num_errors": 0, "broken_packs": None, "suggest_repair_index": False, "suggest_prune": False}) + "\n"
    with tempfile.TemporaryDirectory() as directory:
        journal_root = Path(directory) / "journals"
        journal_root.mkdir(mode=0o700)
        lock = Path(directory) / "lock"
        lock.write_bytes(b"")
        if started:
            journal = journal_root / digest
            journal.mkdir(mode=0o700)
            state = {
                "format": HOST.RECEIPT_FORMAT,
                "status": "cleanup-started",
                "plan_sha256": digest,
                "authorization_sha256": old_auth,
                "authorization_history": [old_auth],
                "started_at": (now - timedelta(minutes=2)).isoformat(),
                "before_usage": plan_observation["usage"],
            }
            if receipt_ahead:
                state = {**state, "execution_usage": current["usage"]}
            with patch.object(HOST, "JOURNAL_ROOT", journal_root):
                HOST.B.write_private(journal / "state.json", state, exclusive=True)
                if receipt_ahead:
                    receipt = {
                        **state,
                        "status": "committed",
                        "committed_at": now.isoformat(),
                        "scope": "entire-account-trash",
                        "permanent_delete": True,
                        "v1_cleanup_receipt_sha256": HOST.V1_RECEIPT_SHA256,
                        "after_usage": after["usage"],
                        "active_directories": [HOST.B.NEW_REMOTE_DIRECTORY],
                        "replacement_check": "full-read-data-zero-errors",
                        "recovery_evidence_sha256": HOST.B.RECOVERY_SHA256,
                        "recovery_journal_sha256": HOST.B.RECOVERY_JOURNAL_SHA256,
                    }
                    HOST.B.write_private(journal / "receipt.json", receipt, exclusive=True)
        observations = iter([current] if receipt_ahead else [plan_observation, current, after] if not started else [current, after])

        def checked_run(_module, argv, _environment, _label, _timeout=600):
            assert argv[-1] == "--read-data"
            return summary

        with ExitStack() as stack:
            stack.enter_context(patch.object(HOST, "JOURNAL_ROOT", journal_root))
            stack.enter_context(patch.object(HOST.B, "require_identity", lambda: None))
            stack.enter_context(patch.object(HOST, "validate_plan", lambda _path: (plan, digest, now + timedelta(hours=1))))
            stack.enter_context(patch.object(HOST, "validate_authorization", lambda *_args: (auth_digest, auth_created, auth_expires)))
            stack.enter_context(patch.object(HOST.B, "validate_recovery", lambda *_args: None))
            stack.enter_context(patch.object(HOST.B, "module_and_policy", lambda: (FakeModule(), {}, "a" * 64)))
            stack.enter_context(patch.object(HOST.B, "acquire_lock", lambda *_args: os.open(lock, os.O_RDONLY)))
            stack.enter_context(patch.object(HOST, "observe_locked", lambda *_args: next(observations)))
            stack.enter_context(patch.object(HOST.B, "reject_processes", lambda *_args: None))
            stack.enter_context(patch.object(HOST, "exact_empty_trash", lambda *_args: purges.append(True)))
            stack.enter_context(patch.object(HOST.B, "run", checked_run))
            stack.enter_context(patch.dict(os.environ, {"PROTON_TRASH_CLEANUP_CONFIRMED": f"empty-entire-proton-trash-{digest}-{auth_digest}"}))
            with redirect_stdout(io.StringIO()):
                try:
                    HOST.apply(Path("plan"), Path("auth"), Path("recovery"), Path("journal"))
                except SystemExit as error:
                    result = {"error": str(error)}
                else:
                    result, _ = HOST.B.load_private(journal_root / digest / "state.json")
        return result, purges


def test_fresh_authorization_supersedes_started_transaction():
    state, purges = exercise_apply(started=True)
    assert purges == [True]
    assert state["status"] == "committed"
    assert state["authorization_history"] == ["c" * 64, "d" * 64]
    assert state["authorization_sha256"] == "d" * 64


def test_expired_started_retry_cannot_empty_trash():
    result, purges = exercise_apply(started=True, expired=True)
    assert purges == []
    assert "fresh-authorization-required" in result["error"]


def test_current_v2_drift_blocks_cleanup_before_mutation():
    result, purges = exercise_apply(started=True, drift=True)
    assert purges == []
    assert "current-precondition-replacement" in result["error"]


def test_receipt_ahead_is_adopted_without_cleanup():
    state, purges = exercise_apply(started=True, expired=True, receipt_ahead=True)
    assert purges == []
    assert state["status"] == "committed"


def test_started_replay_requires_fresh_authorization():
    source = (ROOT / "scripts/empty-proton-trash").read_text()
    receipt_branch = source.index("if os.path.lexists(receipt_path):")
    freshness = source.index('fail("fresh-authorization-required")', receipt_branch)
    cleanup = source.index("exact_empty_trash(rclone, config_path, environment)", freshness)
    assert receipt_branch < freshness < cleanup
    assert '[restic, "-r", B.NEW_REPOSITORY, "check", "--json", "--read-data"]' in source


def test_playbook_uses_only_exact_helper_and_protected_artifacts():
    source = (ROOT / "ansible/playbooks/proton-trash-cleanup.yml").read_text()
    assert "empty-entire-proton-trash-" in source
    assert "PROTON_TRASH_CLEANUP_CONFIRMED" in source
    assert "Protect fetched Proton Trash receipt" in source
    assert "ansible.builtin.shell" not in source


def main() -> None:
    test_controller_binds_explicit_unenumerable_entire_trash_scope()
    test_exact_cleanup_wrapper_cannot_change_remote_or_command()
    test_receipt_validation_binds_full_read_and_usage()
    test_started_replay_requires_fresh_authorization()
    test_playbook_uses_only_exact_helper_and_protected_artifacts()
    test_fresh_authorization_supersedes_started_transaction()
    test_expired_started_retry_cannot_empty_trash()
    test_current_v2_drift_blocks_cleanup_before_mutation()
    test_receipt_ahead_is_adopted_without_cleanup()
    print("Proton Trash cleanup safety fixtures passed")


if __name__ == "__main__":
    main()
