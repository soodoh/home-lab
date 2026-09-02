#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
os.environ["HOME_LAB_PROTON_PROMOTION_TESTING"] = "1"
os.environ["HOME_LAB_PROTON_PROMOTION_BASE"] = str(ROOT / "scripts/cleanup-damaged-proton-restic-v1")
H = SourceFileLoader("qualified_proton_promotion_host_test", str(ROOT / "scripts/promote-qualified-proton-restic")).load_module()
C = SourceFileLoader("qualified_proton_promotion_controller_test", str(ROOT / "scripts/controller/qualified-proton-promotion.py")).load_module()


def observation() -> dict:
    return {
        "format":"home-lab-qualified-proton-promotion-observation-v1","helper_sha256":C.C.sha(C.HELPER.read_bytes()),"base_helper_sha256":"a"*64,"policy_sha256":"b"*64,
        "installed_rclone_sha256":H.STABLE_SHA256,"beta_sha256":H.BETA_SHA256,
        "candidate":{"repository_id":H.SOURCE_ID,"chunker_polynomial":"poly","snapshot_id":H.SOURCE_SNAPSHOT,"original_snapshot_id":H.ORIGINAL_SNAPSHOT,"full_read_data_check":"zero-errors"},
        "candidate_state":{"sha256":"c"*64,"status":"verified","repository_id":H.SOURCE_ID,"snapshot_id":H.SOURCE_SNAPSHOT,"source_snapshot_id":H.ORIGINAL_SNAPSHOT,"beta_sha256":H.BETA_SHA256,"full_read_data_check":"zero-errors"},
        "failed_canonical":{"repository_id":H.TARGET_FAILED_ID,"broken_pack":H.TARGET_BROKEN_PACK,"check_summary":{}},
        "damaged_v2":{"repository_id":H.V2_ID,"broken_pack":H.V2_BROKEN_PACK,"check_summary":{}},
        "trash_state":{"path":str(H.TRASH_STATE),"sha256":"d"*64,"status":"cleanup-started"},
        "canonical_state":{"path":str(H.CANONICAL_STATE),"sha256":"e"*64,"status":"copied"},
        "timers":[{"unit":"home-lab-restic-daily.timer","active":"inactive","unit_file":"enabled"},{"unit":"home-lab-restic-maintenance.timer","active":"inactive","unit_file":"enabled"}],
    }


def test_controller_binds_exact_action() -> None:
    contract,_=C.contract_policy(); C.validate_observation(observation(),contract)
    deployed=observation(); deployed["installed_rclone_sha256"]=H.BETA_SHA256
    for timer in deployed["timers"]: timer["unit_file"]="disabled"
    C.validate_observation(deployed,contract)
    assert C.deployed_policy_sha256(contract)=="e92714ac84ae686bca9ae6ba06cd8ec215c5ef66df28b715a2e2b1eaec168456"
    assert C.action()=={"kind":"promote-qualified-proton-repository","install_rclone_sha256":H.BETA_SHA256,"retire_to_trash":H.TARGET,"move_from":H.SOURCE,"move_to":H.TARGET,"preserve":H.V2}
    changed=observation(); changed["candidate"]["repository_id"]="f"*64
    try: C.validate_observation(changed,contract)
    except SystemExit: pass
    else: raise AssertionError("candidate drift accepted")


def test_mutation_scope_and_order() -> None:
    source=(ROOT/"scripts/promote-qualified-proton-restic").read_text()
    purge='[rclone, "purge", "--config", str(config), TARGET_REMOTE]'
    move='[rclone, "moveto", "--config", str(config), SOURCE_REMOTE, TARGET_REMOTE]'
    assert purge in source and move in source and source.index(purge)<source.index(move)
    try: H.mutation_command("rclone", Path("/config"), {}, ["rclone","purge","remote:wrong"], "bad")
    except SystemExit as error: assert "mutation-command-scope" in str(error)
    else: raise AssertionError("out-of-scope direct rclone mutation accepted")
    assert "shell=True" not in source
    freshness=source.index('fail("fresh-authorization-required")'); assert freshness<source.index('mutation_command(rclone, config, environment, '+purge, freshness)<source.index('mutation_command(rclone, config, environment, '+move, freshness)
    assert "require_directory_absent" in source and "directory_entries" in source
    for forbidden in ('"cleanup"','"repair"','"prune"','"forget"','"EmptyTrash"'):
        assert forbidden not in source


def test_exact_absence_rejects_provider_failure() -> None:
    class Module:
        @staticmethod
        def rooted(path): return Path(path)
        @staticmethod
        def run(_argv, **_kwargs): return subprocess.CompletedProcess([], 1, "", "provider failure")
    try: H.require_directory_absent(Module(), "rclone", {}, "remote:parent", "target/", "still-present")
    except SystemExit as error: assert "directory-listing" in str(error)
    else: raise AssertionError("provider failure was accepted as absence")

    class ListingModule(Module):
        @staticmethod
        def run(_argv, **_kwargs): return subprocess.CompletedProcess([], 0, "other/\n", "")
    H.require_directory_absent(ListingModule(), "rclone", {}, "remote:parent", "target/", "still-present")


def test_interrupted_mutations_have_exact_adoption_states() -> None:
    assert H.mutation_disposition("canonical-retirement-started", True, True)=="execute"
    assert H.mutation_disposition("canonical-retirement-started", False, True)=="adopt"
    assert H.mutation_disposition("candidate-move-started", False, True)=="execute"
    assert H.mutation_disposition("candidate-move-started", True, False)=="adopt"
    for value in (("canonical-retirement-started",False,False),("candidate-move-started",True,True)):
        try: H.mutation_disposition(*value)
        except SystemExit: pass
        else: raise AssertionError("ambiguous interrupted namespace accepted")


def write_plan(directory: Path, **changes) -> Path:
    created=datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=1)
    plan={"format":H.PLAN_FORMAT,"commit":"a"*40,"contract_sha256":"b"*64,"deployed_policy_sha256":"c"*64,"created_at":created.isoformat().replace("+00:00","Z"),"expires_at":(created+timedelta(hours=1)).isoformat().replace("+00:00","Z"),"host_observation":{},"action":C.action(),"blockers":["exact-proton-promotion-authorization-required"],"authorized":False,**changes}
    raw=H.B.canonical(plan); path=directory/f"qualified-proton-promotion-{H.B.sha(raw)}.json"; path.write_bytes(raw); os.chmod(path,0o600); return path


def test_host_plan_time_and_identity_boundaries() -> None:
    with tempfile.TemporaryDirectory() as name:
        directory=Path(name); H.validate_plan(write_plan(directory))
        now=datetime.now(timezone.utc).replace(microsecond=0)
        expired=write_plan(directory,created_at=(now-timedelta(hours=2)).isoformat().replace("+00:00","Z"),expires_at=(now-timedelta(hours=1)).isoformat().replace("+00:00","Z"))
        try: H.validate_plan(expired)
        except SystemExit: pass
        else: raise AssertionError("expired plan accepted for mutation")
        H.validate_plan(expired,allow_expired=True)
        invalid=(
            {"commit":"bad"},
            {"commit":"a"*64},
            {"contract_sha256":"bad"},
            {"deployed_policy_sha256":"bad"},
            {"created_at":(now+timedelta(minutes=1)).isoformat().replace("+00:00","Z"),"expires_at":(now+timedelta(hours=1)).isoformat().replace("+00:00","Z")},
            {"created_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now-timedelta(minutes=1)).isoformat().replace("+00:00","Z")},
            {"created_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now+timedelta(hours=25)).isoformat().replace("+00:00","Z")},
        )
        for changes in invalid:
            try: H.validate_plan(write_plan(directory,**changes))
            except SystemExit: pass
            else: raise AssertionError("invalid host plan accepted")


def test_receipt_ahead_is_adoptable() -> None:
    receipt={"format":H.RECEIPT_FORMAT,"status":"committed","plan_sha256":"a"*64,"authorization_sha256":"b"*64,"started_at":"2026-09-02T12:00:00Z","retired_at":"2026-09-02T12:01:00Z","moved_at":"2026-09-02T12:02:00Z","committed_at":"2026-09-02T12:03:00Z","target":{"repository_id":H.SOURCE_ID,"chunker_polynomial":"poly","snapshot_id":H.SOURCE_SNAPSHOT,"original_snapshot_id":H.ORIGINAL_SNAPSHOT},"source_absent":True,"structural_check":"zero-errors","full_read_data_check":"zero-errors","damaged_v2_preserved":{"repository_id":H.V2_ID,"broken_pack":H.V2_BROKEN_PACK}}
    H.validate_receipt(receipt,"a"*64)
    source=(ROOT/"scripts/promote-qualified-proton-restic").read_text(); branch=source.index("if os.path.lexists(receipt_path):")
    assert source.index('if state != receipt:',branch)<source.index('B.write_private(journal / "state.json", receipt)',branch)


def test_retained_boundaries_and_canaries() -> None:
    source=(ROOT/"scripts/promote-qualified-proton-restic").read_text()
    assert "retained_postconditions(module, restic, environment, prior)" in source
    assert '[*restic_prefix(restic, TARGET), "check", "--json", "--read-data"]' in source
    assert 'B.write_private(receipt_path, receipt, exclusive=True)' in source
    assert 'plan.get("deployed_policy_sha256") != policy_sha256' in source


def test_playbook_keeps_incident_suspended_and_adopts_lock() -> None:
    source=(ROOT/"ansible/playbooks/qualified-proton-promotion.yml").read_text()
    assert "infrastructure/contract/home-lab.yml" in source and "group_vars/docker_host.yml" in source
    assert source.index("name: restic_backup")<source.index("Execute explicitly authorized qualified Proton promotion")
    assert "Require exact beta identity and suspended timers after promotion" in source
    assert "[['inactive', 'disabled'], ['inactive', 'disabled']]" in source
    assert "'adopt' if qualified_proton_apply_lock.stat.exists else 'acquire'" in source
    assert "qualified-proton-promotion-{{ qualified_proton_plan_sha256 }}" in source
    assert "apply_lock_expected_owner_sha256" in source and "apply_lock_action: release" in source
    assert "Persist protected qualified Proton receipt durably" in source and "os.O_NOFOLLOW" in source
    assert "ansible.builtin.shell" not in source


def main() -> None:
    test_controller_binds_exact_action(); test_mutation_scope_and_order(); test_exact_absence_rejects_provider_failure(); test_interrupted_mutations_have_exact_adoption_states(); test_host_plan_time_and_identity_boundaries(); test_receipt_ahead_is_adoptable(); test_retained_boundaries_and_canaries(); test_playbook_keeps_incident_suspended_and_adopts_lock()
    print("Qualified Proton promotion safety fixtures passed")

if __name__=="__main__": main()
