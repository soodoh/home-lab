#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
from importlib.machinery import SourceFileLoader

ROOT = Path(__file__).resolve().parents[1]
os.environ["HOME_LAB_CANONICAL_PROTON_TESTING"] = "1"
os.environ["HOME_LAB_CANONICAL_PROTON_BASE"] = str(ROOT / "scripts/cleanup-damaged-proton-restic-v1")
HOST = SourceFileLoader("canonical_proton_host_test", str(ROOT / "scripts/create-canonical-proton-restic")).load_module()
CONTROLLER = SourceFileLoader("canonical_proton_controller_test", str(ROOT / "scripts/controller/canonical-proton-creation.py")).load_module()


def observation() -> dict:
    contract, _ = CONTROLLER.C.contract_policy()
    return {
        "format": "home-lab-canonical-proton-creation-observation-v1",
        "helper_sha256": CONTROLLER.C.sha((ROOT / "scripts/create-canonical-proton-restic").read_bytes()),
        "base_helper_sha256": CONTROLLER.C.sha((ROOT / "scripts/cleanup-damaged-proton-restic-v1").read_bytes()),
        "runner_sha256": contract["backups"]["restic"]["runner"]["sha256"],
        "policy_sha256": "a" * 64,
        "active_directories": [HOST.DAMAGED_DIRECTORY],
        "active_directories_sha256": "b" * 64,
        "target": {"present": False},
        "source": {"repository_id": HOST.SOURCE_ID, "snapshot_id": HOST.SOURCE_SNAPSHOT, "chunker_polynomial": "poly", "full_read_data_check": "zero-errors"},
        "damaged": {"repository": HOST.DAMAGED_REPOSITORY, "repository_id": HOST.DAMAGED_ID, "broken_pack": HOST.BROKEN_PACK, "check_summary": {"message_type": "summary", "num_errors": 1, "broken_packs": [HOST.BROKEN_PACK], "suggest_repair_index": False, "suggest_prune": False}},
        "trash_transaction": {"plan_sha256": HOST.TRASH_PLAN, "state_sha256": "c" * 64, "status": "cleanup-started"},
        "stopped_timers": ["home-lab-restic-daily.timer", "home-lab-restic-maintenance.timer"],
    }


def test_controller_binds_exact_incident_and_target():
    contract, _ = CONTROLLER.C.contract_policy()
    CONTROLLER.validate_observation(observation(), contract)
    assert CONTROLLER.action() == {"kind": "create-canonical-proton-repository", "target": HOST.TARGET_REPOSITORY, "source_repository_id": HOST.SOURCE_ID, "source_snapshot_id": HOST.SOURCE_SNAPSHOT, "preserve_damaged_repository": HOST.DAMAGED_REPOSITORY}


def test_receipt_binds_healthy_target_and_preserved_damage():
    state = {"status": "copied"}
    receipt = {
        "format": HOST.RECEIPT_FORMAT, "status": "committed", "plan_sha256": "d" * 64, "authorization_sha256": "e" * 64, "authorization_history": ["e" * 64],
        "started_at": "2026-09-02T12:00:00Z", "initialized_at": "2026-09-02T12:01:00Z", "copied_at": "2026-09-02T12:02:00Z", "committed_at": "2026-09-02T12:03:00Z",
        "target": {"repository_id": "f" * 64, "snapshot_id": "1" * 64, "original_snapshot_id": HOST.SOURCE_SNAPSHOT, "chunker_polynomial": "poly"},
        "source": {"repository_id": HOST.SOURCE_ID, "snapshot_id": HOST.SOURCE_SNAPSHOT},
        "damaged_repository_preserved": {"repository": HOST.DAMAGED_REPOSITORY, "repository_id": HOST.DAMAGED_ID, "broken_pack": HOST.BROKEN_PACK},
        "structural_check": "zero-errors", "full_read_data_check": "zero-errors",
    }
    HOST.validate_receipt(receipt, state, "d" * 64, "e" * 64)
    changed = {**receipt, "damaged_repository_preserved": {**receipt["damaged_repository_preserved"], "broken_pack": "2" * 64}}
    try: HOST.validate_receipt(changed, state, "d" * 64, "e" * 64)
    except SystemExit as error: assert "receipt-binding" in str(error)
    else: raise AssertionError("damaged repository drift was accepted")


def test_host_command_scope_is_creation_only():
    source = (ROOT / "scripts/create-canonical-proton-restic").read_text()
    assert '[restic, "-r", TARGET_REPOSITORY, "init", "--from-repo", module.repository(policy, "games"), "--copy-chunker-params"]' in source
    assert '[restic, "-r", TARGET_REPOSITORY, "copy", "--from-repo", module.repository(policy, "games"), SOURCE_SNAPSHOT]' in source
    assert '[restic, "-r", TARGET_REPOSITORY, "check", "--json", "--read-data"]' in source
    for forbidden in ('"purge"', '"cleanup"', '"forget"', '"prune"', '"repair"', '"moveto"', '"move"', '"delete"', '"remove"'):
        assert forbidden not in source


def test_receipt_ahead_precedes_fresh_authorization_and_mutation():
    source = (ROOT / "scripts/create-canonical-proton-restic").read_text()
    receipt = source.index("if os.path.lexists(receipt_path):")
    freshness = source.index('fail("fresh-authorization-required")', receipt)
    initialize = source.index('"target-init"', freshness)
    assert receipt < freshness < initialize


def test_source_uses_local_password_and_full_read_check():
    source = (ROOT / "scripts/create-canonical-proton-restic").read_text()
    assert 'source_environment = module.credential_environment(policy, "games")' in source
    assert 'source_proof(module, policy, source_environment, restic)' in source
    assert '[restic, "-r", repository, "check", "--json", "--read-data"]' in source
    assert '"full_read_data_check": "zero-errors"' in source


def test_receipt_replay_revalidates_live_postconditions():
    source = (ROOT / "scripts/create-canonical-proton-restic").read_text()
    receipt_branch = source.index("if os.path.lexists(receipt_path):")
    promotion = source.index('B.write_private(journal / "state.json", receipt)', receipt_branch)
    assert source.index('"receipt-full-check"', receipt_branch) < promotion
    assert source.index('"receipt-postcondition-directories"', receipt_branch) < promotion
    assert source.index('"receipt-postcondition-damaged"', receipt_branch) < promotion


def test_playbook_protects_artifacts_and_avoids_shell():
    source = (ROOT / "ansible/playbooks/canonical-proton-creation.yml").read_text()
    assert "Read committed canonical Proton receipt" in source
    assert "Persist protected canonical Proton receipt durably" in source
    assert "os.fsync(handle.fileno())" in source and "os.fsync(directory)" in source
    assert "os.O_NOFOLLOW" in source and "mode: \"0600\"" in source
    assert "ansible.builtin.fetch" not in source
    assert "ansible.builtin.shell" not in source


def main():
    test_controller_binds_exact_incident_and_target()
    test_receipt_binds_healthy_target_and_preserved_damage()
    test_host_command_scope_is_creation_only()
    test_receipt_ahead_precedes_fresh_authorization_and_mutation()
    test_source_uses_local_password_and_full_read_check()
    test_receipt_replay_revalidates_live_postconditions()
    test_playbook_protects_artifacts_and_avoids_shell()
    print("Canonical Proton creation safety fixtures passed")


if __name__ == "__main__": main()
