#!/usr/bin/env python3
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
from importlib.machinery import SourceFileLoader
import io
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HOST = SourceFileLoader("proton_v1_cleanup_host", str(ROOT / "scripts/cleanup-damaged-proton-restic-v1")).load_module()
CONTROLLER = SourceFileLoader("proton_v1_cleanup_controller", str(ROOT / "scripts/controller/proton-v1-cleanup.py")).load_module()


def observation(present: bool) -> dict:
    damaged = (
        {
            "present": True,
            "repository_id": HOST.OLD_ID,
            "bytes": 12892898017,
            "objects": 768,
            "sizeless": 0,
            "inventory_sha256": "a" * 64,
        }
        if present
        else {"present": False}
    )
    return {
        "format": "home-lab-proton-v1-cleanup-observation-v1",
        "helper_sha256": hashlib.sha256((ROOT / "scripts/cleanup-damaged-proton-restic-v1").read_bytes()).hexdigest(),
        "runner_sha256": CONTROLLER.contract_policy()[0]["backups"]["restic"]["runner"]["sha256"],
        "policy_sha256": "b" * 64,
        "parent_directories": ["home-lab-restic-v2/", "home-lab-restic/"] if present else ["home-lab-restic-v2/"],
        "damaged": damaged,
        "replacement": {
            "repository_id": HOST.NEW_ID,
            "snapshot_id": HOST.NEW_SNAPSHOT,
            "original_snapshot_id": HOST.ORIGINAL_SNAPSHOT,
        },
        "migration": {"sha256": HOST.MIGRATION_SHA256, "full_read_data_check": True},
    }


def test_controller_accepts_only_exact_present_and_absent_boundaries():
    contract, _ = CONTROLLER.contract_policy()
    assert CONTROLLER.validate_observation(observation(True), contract) is True
    assert CONTROLLER.validate_observation(observation(False), contract) is False
    changed = observation(True)
    changed["damaged"]["repository_id"] = "f" * 64
    try:
        CONTROLLER.validate_observation(changed, contract)
    except SystemExit as error:
        assert str(error) == "damaged Proton repository inventory differs"
    else:
        raise AssertionError("repository identity drift was accepted")


def test_recovery_evidence_is_exact_and_qualified():
    CONTROLLER.recovery_proof()
    assert hashlib.sha256(CONTROLLER.RECOVERY.read_bytes()).hexdigest() == HOST.RECOVERY_SHA256
    assert hashlib.sha256(CONTROLLER.RECOVERY_JOURNAL.read_bytes()).hexdigest() == HOST.RECOVERY_JOURNAL_SHA256


def test_replacement_check_summary_is_exact():
    exact = json.dumps({"message_type": "summary", "num_errors": 0, "broken_packs": None, "suggest_repair_index": False, "suggest_prune": False}) + "\n"
    HOST.validate_check_summary(exact)
    try:
        HOST.validate_check_summary(exact.replace('"num_errors": 0', '"num_errors": 1'))
    except SystemExit as error:
        assert "replacement-check-summary" in str(error)
    else:
        raise AssertionError("failed replacement check was accepted")


def test_cleanup_surface_is_exact_and_crash_resumable():
    source = (ROOT / "scripts/cleanup-damaged-proton-restic-v1").read_text()
    assert 'arguments = [rclone, "purge", "--config", str(config_path), OLD_REMOTE]' in source
    assert 'module.run(arguments' not in source
    assert '"status": "deletion-started"' in source
    assert 'state.get("status") == "committed"' in source
    assert '"replacement_check": "full-read-data-zero-errors"' in source
    assert '[restic, "-r", NEW_REPOSITORY, "check", "--json", "--read-data"]' in source
    assert '"sync"' not in source
    assert '"bisync"' not in source
    assert '"deletefile"' not in source
    assert '"rmdirs"' not in source
    assert '[rclone, "cleanup"' not in source
    assert '"space_reclamation": "blocked-global-trash-scope"' in source


def test_playbook_stages_only_exact_artifacts_and_removes_successful_stage():
    source = (ROOT / "ansible/playbooks/proton-v1-cleanup.yml").read_text()
    assert "PROTON_V1_CLEANUP_CONFIRMED" in source
    assert "delete-damaged-proton-v1-" in source
    assert source.count("proton_v1_cleanup_operation == 'apply'") >= 6
    assert "state: absent" in source
    assert "Protect fetched cleanup receipt" in source
    assert source.count('mode: "0600"') >= 2
    assert "ansible.builtin.shell" not in source


def test_private_writer_and_loader_preserve_canonical_mode():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "artifact.json"
        raw = CONTROLLER.canonical({"value": 1})
        CONTROLLER.write_private(path, raw)
        value, loaded = CONTROLLER.load_private(path)
        assert value == {"value": 1}
        assert loaded == raw
        assert path.stat().st_mode & 0o777 == 0o600



def exercise_apply(*, resumed: bool, expired: bool, check_errors: int = 0, committed: bool = False, receipt_ahead: bool = False) -> tuple[dict, list[bool]]:
    class FakeModule:
        def command_paths(self, _policy):
            return "/usr/local/bin/restic", "/usr/local/bin/rclone"

        def credential_environment(self, _policy, _destination, _source):
            return {"HOME": "/var/lib/restic-proton"}

        def rooted(self, path):
            return Path(path)

    digest = "c" * 64
    auth_digest = "d" * 64
    plan = {"host_observation": observation(True)}
    now = datetime.now(timezone.utc)
    created = now - timedelta(hours=2) if expired else now - timedelta(minutes=1)
    expires = now - timedelta(hours=1) if expired else now + timedelta(minutes=10)
    summary = json.dumps({"message_type": "summary", "num_errors": check_errors, "broken_packs": None, "suggest_repair_index": False, "suggest_prune": False}) + "\n"
    purges: list[bool] = []
    with tempfile.TemporaryDirectory() as directory:
        journal_root = Path(directory) / "journals"
        journal_root.mkdir(mode=0o700)
        lock = Path(directory) / "lock"
        lock.write_bytes(b"")
        if resumed:
            started_state = {
                "format": HOST.RECEIPT_FORMAT,
                "status": "deletion-started",
                "plan_sha256": digest,
                "authorization_sha256": auth_digest,
                "started_at": created.isoformat(),
                "before": plan["host_observation"]["damaged"],
            }
            receipt = {
                **started_state,
                "status": "committed",
                "committed_at": (created + timedelta(minutes=1)).isoformat(),
                "after": {"present": False, "parent_directories": [HOST.NEW_REMOTE_DIRECTORY]},
                "provider_effect": "moved-exact-directory-to-proton-trash",
                "permanent_delete": False,
                "space_reclamation": "blocked-global-trash-scope",
                "replacement_check": "full-read-data-zero-errors",
                "recovery_evidence_sha256": HOST.RECOVERY_SHA256,
                "recovery_journal_sha256": HOST.RECOVERY_JOURNAL_SHA256,
            }
            state = receipt if committed else started_state
            (journal_root / digest).mkdir(mode=0o700)
            with patch.object(HOST, "JOURNAL_ROOT", journal_root):
                HOST.write_private(journal_root / digest / "state.json", state, exclusive=True)
                if committed or receipt_ahead:
                    HOST.write_private(journal_root / digest / "receipt.json", receipt, exclusive=True)
        resume_values = iter([observation(False)] if committed or receipt_ahead else [observation(True), observation(False)] if resumed else [observation(False)])

        def checked_run(_module, argv, _environment, _label, _timeout=600):
            assert argv[-1] == "--read-data"
            return summary

        with ExitStack() as stack:
            stack.enter_context(patch.object(HOST, "JOURNAL_ROOT", journal_root))
            stack.enter_context(patch.object(HOST, "require_identity", lambda: None))
            stack.enter_context(patch.object(HOST, "validate_plan", lambda _path: (plan, b"", digest, expires)))
            stack.enter_context(patch.object(HOST, "validate_authorization", lambda _path, _digest, _plan: (auth_digest, created, expires)))
            stack.enter_context(patch.object(HOST, "validate_recovery", lambda *_args: None))
            stack.enter_context(patch.object(HOST, "module_and_policy", lambda: (FakeModule(), {}, "b" * 64)))
            stack.enter_context(patch.object(HOST, "acquire_lock", lambda *_args: os.open(lock, os.O_RDONLY)))
            stack.enter_context(patch.object(HOST, "observe_locked", lambda *_args: observation(True)))
            stack.enter_context(patch.object(HOST, "resume_observation_locked", lambda *_args: next(resume_values)))
            stack.enter_context(patch.object(HOST, "reject_processes", lambda *_args: None))
            stack.enter_context(patch.object(HOST, "exact_purge", lambda *_args: purges.append(True)))
            stack.enter_context(patch.object(HOST, "run", checked_run))
            stack.enter_context(patch.dict(os.environ, {"PROTON_V1_CLEANUP_CONFIRMED": f"delete-damaged-proton-v1-{digest}-{auth_digest}"}))
            with redirect_stdout(io.StringIO()):
                if check_errors:
                    try:
                        HOST.apply(Path("plan"), Path("authorization"), Path("recovery"), Path("journal"))
                    except SystemExit as error:
                        assert "replacement-check-summary" in str(error)
                    else:
                        raise AssertionError("failed full read-data check was accepted")
                else:
                    HOST.apply(Path("plan"), Path("authorization"), Path("recovery"), Path("journal"))
        state, _ = HOST.load_private(journal_root / digest / "state.json")
        return state, purges


def test_apply_commits_after_exact_purge_and_full_read_check():
    state, purges = exercise_apply(resumed=False, expired=False)
    assert purges == [True]
    assert state["status"] == "committed"
    assert state["provider_effect"] == "moved-exact-directory-to-proton-trash"
    assert state["permanent_delete"] is False
    assert state["replacement_check"] == "full-read-data-zero-errors"


def test_expired_started_transaction_resumes_partial_purge():
    state, purges = exercise_apply(resumed=True, expired=True)
    assert purges == [True]
    assert state["status"] == "committed"


def test_post_check_failure_retains_resumable_started_state():
    state, purges = exercise_apply(resumed=False, expired=False, check_errors=1)
    assert purges == [True]
    assert state["status"] == "deletion-started"



def test_expired_committed_transaction_recovers_receipt():
    state, purges = exercise_apply(resumed=True, expired=True, committed=True)
    assert purges == []
    assert state["status"] == "committed"



def test_receipt_ahead_of_started_state_is_adopted():
    state, purges = exercise_apply(resumed=True, expired=True, receipt_ahead=True)
    assert purges == []
    assert state["status"] == "committed"
    assert state["replacement_check"] == "full-read-data-zero-errors"



def main() -> None:
    test_controller_accepts_only_exact_present_and_absent_boundaries()
    test_recovery_evidence_is_exact_and_qualified()
    test_replacement_check_summary_is_exact()
    test_cleanup_surface_is_exact_and_crash_resumable()
    test_playbook_stages_only_exact_artifacts_and_removes_successful_stage()
    test_private_writer_and_loader_preserve_canonical_mode()
    test_apply_commits_after_exact_purge_and_full_read_check()
    test_expired_started_transaction_resumes_partial_purge()
    test_post_check_failure_retains_resumable_started_state()
    test_expired_committed_transaction_recovers_receipt()
    test_receipt_ahead_of_started_state_is_adopted()
    print("Proton v1 cleanup safety fixtures passed")


if __name__ == "__main__":
    main()
