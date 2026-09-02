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
os.environ.setdefault("HOME_LAB_PROTON_RETIREMENT_TESTING", "1")
os.environ.setdefault("HOME_LAB_PROTON_RETIREMENT_BASE", str(ROOT / "scripts/cleanup-damaged-proton-restic-v1"))
H = SourceFileLoader("proton_incident_retirement_test_host", str(ROOT / "scripts/retire-proton-incident-artifacts")).load_module()
C = SourceFileLoader("proton_incident_retirement_test_controller", str(ROOT / "scripts/controller/proton-incident-retirement.py")).load_module()


def inventory(objects: int = 8, size: int = 167772160) -> dict:
    return {"objects": objects, "bytes": size, "zero_byte_objects": 0, "inventory_sha256": "a" * 64, "directories_sha256": "b" * 64, "nested_directories": []}


def observation(stage: str = "initial") -> dict:
    contract, _ = C.contract_policy()
    damaged = {"present": True, "repository_id": H.DAMAGED_ID, "broken_pack": H.DAMAGED_PACK, "check_summary": {"message_type": "summary", "num_errors": 1, "broken_packs": [H.DAMAGED_PACK], "suggest_repair_index": False, "suggest_prune": False}, **inventory(600, 10000000000)} if stage == "initial" else {"present": False}
    if stage in {"initial", "v2-retired"}:
        fixtures = {"present": True, "parent_present": True, "children": H.DIAGNOSTIC_CHILDREN, "stable": inventory(), "beta": inventory()}
    elif stage == "stable-retired":
        fixtures = {"present": True, "parent_present": True, "children": [H.BETA_NAME], "beta": inventory()}
    else:
        fixtures = {"present": False, "parent_present": True, "children": []}
    backups = ["home-lab-restic-v2/", "home-lab-restic/"] if stage == "initial" else ["home-lab-restic/"]
    return {
        "format": "home-lab-proton-incident-retirement-observation-v1",
        "helper_sha256": hashlib.sha256((ROOT / "scripts/retire-proton-incident-artifacts").read_bytes()).hexdigest(),
        "base_helper_sha256": hashlib.sha256((ROOT / "scripts/cleanup-damaged-proton-restic-v1").read_bytes()).hexdigest(),
        "runner_sha256": contract["backups"]["restic"]["runner"]["sha256"],
        "policy_sha256": C.deployed_policy_sha256(contract),
        "rclone_sha256": H.RCLONE_SHA256,
        "canonical": {"repository_id": H.CANONICAL_ID, "snapshot_id": H.CANONICAL_SNAPSHOT, "original_snapshot_id": H.ORIGINAL_SNAPSHOT, "chunker_polynomial": "255a608adc8769", "structural_check": "zero-errors", "full_read_data_check": "zero-errors"},
        "damaged_v2": damaged,
        "diagnostic_fixtures": fixtures,
        "namespace_listings": {"backups": backups, "backups_sha256": "c" * 64, "diagnostics": [H.DIAGNOSTICS_NAME], "diagnostics_sha256": "d" * 64},
        "retained_states": {"trash": {"sha256": "e" * 64, "status": "cleanup-started"}, "canonical_creation": {"sha256": "f" * 64, "status": "copied"}},
        "timers": [{"unit": "home-lab-restic-daily.timer", "active": "active", "unit_file": "enabled"}, {"unit": "home-lab-restic-maintenance.timer", "active": "active", "unit_file": "enabled"}],
        "services": [{"unit": "home-lab-restic-daily-proton.service", "active": "inactive", "result": "success"}, {"unit": "home-lab-restic-maintenance-proton.service", "active": "inactive", "result": "success"}],
    }


def test_service_state_parses_named_properties_without_order_dependency() -> None:
    class FakeModule:
        def run(self, *_args, **_kwargs):
            class Result:
                returncode = 0
                stdout = "Result=success\nActiveState=inactive\n"
            return Result()

    assert H.service_states(FakeModule()) == [{"unit": "home-lab-restic-daily-proton.service", "active": "inactive", "result": "success"}, {"unit": "home-lab-restic-maintenance-proton.service", "active": "inactive", "result": "success"}]

def test_controller_requires_exact_live_boundary() -> None:
    contract, _ = C.contract_policy()
    C.validate_observation(observation(), contract)
    changed = observation()
    changed["diagnostic_fixtures"]["stable"]["objects"] = 7
    try:
        C.validate_observation(changed, contract)
    except SystemExit:
        pass
    else:
        raise AssertionError("diagnostic inventory drift accepted")


def test_mutation_surface_and_playbook_locking() -> None:
    helper = (ROOT / "scripts/retire-proton-incident-artifacts").read_text()
    playbook = (ROOT / "ansible/playbooks/proton-incident-retirement.yml").read_text()
    assert "allowed = {DAMAGED_REMOTE, STABLE_REMOTE, BETA_REMOTE}" in helper
    assert 'argv = [rclone, "purge", "--config", str(config), remote]' in helper
    assert "allowed = {DAMAGED_REMOTE, DIAGNOSTICS_PARENT}" not in helper
    assert '"cleanup"' not in helper
    assert "EmptyTrash" not in helper
    for status in ("started", "damaged-v2-retirement-started", "damaged-v2-retired", "stable-fixture-retirement-started", "stable-fixture-retired", "beta-fixture-retirement-started", "beta-fixture-retired", "committed"):
        assert f'"{status}"' in helper
    assert "always:" in playbook
    assert "Release shared production lock" in playbook
    assert "Fail closed by suspending Restic timers after retirement failure" in playbook


def test_apply_commits_only_after_three_exact_purges_and_full_check() -> None:
    class FakeModule:
        def command_paths(self, _policy):
            return "/usr/local/bin/restic", "/usr/local/bin/rclone"

        def credential_environment(self, _policy, _destination, _source):
            return {"HOME": "/var/lib/restic-proton"}

        def rooted(self, path):
            return Path(path)

    planned = observation()
    plan = {"host_observation": planned, "contract_sha256": "1" * 64, "deployed_policy_sha256": "3" * 64}
    purges: list[str] = []
    sequence = [planned, observation("v2-retired"), observation("stable-retired"), observation("complete")]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        root.chmod(0o700)
        plan_path = root / "plan.json"
        H.B.write_private(plan_path, plan, exclusive=True)
        digest = H.B.sha(H.B.canonical(plan))
        lock = root / "lock"
        lock.write_bytes(b"")
        with ExitStack() as stack:
            stack.enter_context(patch.object(H, "JOURNAL_ROOT", root / "journals"))
            stack.enter_context(patch.object(H.B, "require_identity", lambda: None))
            stack.enter_context(patch.object(H, "validate_plan", lambda *_args, **_kwargs: (plan, digest, None)))
            stack.enter_context(patch.object(H, "validate_authorization", lambda *_args, **_kwargs: ("2" * 64, None)))
            stack.enter_context(patch.object(H, "staged_proofs", lambda *_args: None))
            stack.enter_context(patch.object(H, "load_policy", lambda: (FakeModule(), {}, "3" * 64)))
            stack.enter_context(patch.object(H.B, "acquire_lock", lambda *_args: os.open(lock, os.O_RDONLY)))
            stack.enter_context(patch.object(H, "observe_locked", lambda *_args, **_kwargs: sequence.pop(0) if sequence else observation("complete")))
            stack.enter_context(patch.object(H, "mutation_command", lambda _rclone, _config, _environment, remote, _label: purges.append(remote)))
            stack.enter_context(patch.object(H, "repository_proof", lambda *_args, **_kwargs: planned["canonical"]))
            stack.enter_context(patch.dict(os.environ, {"PROTON_INCIDENT_RETIREMENT_CONFIRMED": f"retire-proton-incident-artifacts-{digest}-{'2' * 64}", "PROTON_INCIDENT_RETIREMENT_CONTRACT_SHA256": "1" * 64}))
            with redirect_stdout(io.StringIO()):
                H.apply(plan_path, root / "auth", root / "promotion", root / "recovery", root / "journal")
                receipt_path = root / "journals" / digest / "receipt.json"
                receipt, _ = H.B.load_private(receipt_path)
                stale_state = {**receipt, "status": "beta-fixture-retired"}
                H.B.write_private(root / "journals" / digest / "state.json", stale_state)
                H.apply(plan_path, root / "auth", root / "promotion", root / "recovery", root / "journal")
        receipt, _ = H.B.load_private(root / "journals" / digest / "receipt.json")
        assert purges == [H.DAMAGED_REMOTE, H.STABLE_REMOTE, H.BETA_REMOTE]
        assert receipt["status"] == "committed"
        assert receipt["canonical"]["full_read_data_check"] == "zero-errors"
        assert receipt["empty_trash"] is False
        assert receipt["permanent_delete"] is False


def test_expired_authorization_cannot_resume_mutation() -> None:
    digest = "4" * 64
    now = datetime.now(timezone.utc).replace(microsecond=0)
    value = {"format": H.AUTH_FORMAT, "plan_sha256": digest, "created_at": (now - timedelta(minutes=20)).isoformat().replace("+00:00", "Z"), "expires_at": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"), "confirmation": f"authorize-proton-incident-retirement-{digest}", "authorized": True}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); root.chmod(0o700); path = root / "authorization.json"; H.B.write_private(path, value, exclusive=True)
        try:
            H.validate_authorization(path, digest)
        except SystemExit as error:
            assert "fresh-authorization-required" in str(error)
        else:
            raise AssertionError("expired authorization accepted")


def test_plan_requires_40_character_git_commit() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    base = {"format": H.PLAN_FORMAT, "commit": "1" * 40, "contract_sha256": "2" * 64, "deployed_policy_sha256": "3" * 64, "created_at": now.isoformat().replace("+00:00", "Z"), "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"), "host_observation": observation(), "promotion_receipt_sha256": H.PROMOTION_SHA256, "recovery_evidence_sha256": H.RECOVERY_SHA256, "recovery_journal_sha256": H.RECOVERY_JOURNAL_SHA256, "action": C.action(), "blockers": ["exact-destructive-authorization-required"], "authorized": False}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); root.chmod(0o700)
        for commit, accepted in (("1" * 40, True), ("1" * 64, False)):
            value = {**base, "commit": commit}; raw = H.B.canonical(value); digest = H.B.sha(raw); path = root / f"proton-incident-retirement-{digest}.json"; H.B.write_private(path, value, exclusive=True)
            try:
                H.validate_plan(path)
            except SystemExit:
                if accepted:
                    raise
            else:
                if not accepted:
                    raise AssertionError("64-character commit accepted")


def main() -> None:
    test_controller_requires_exact_live_boundary()
    test_service_state_parses_named_properties_without_order_dependency()
    test_mutation_surface_and_playbook_locking()
    test_apply_commits_only_after_three_exact_purges_and_full_check()
    test_expired_authorization_cannot_resume_mutation()
    test_plan_requires_40_character_git_commit()
    print("Proton incident retirement safety fixtures passed")


if __name__ == "__main__":
    main()
