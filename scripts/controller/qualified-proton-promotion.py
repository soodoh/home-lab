#!/usr/bin/env python3
"""Plan, authorize, and execute exact qualified Proton repository promotion."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("HOME_LAB_PROTON_PROMOTION_TESTING", "1")
os.environ.setdefault("HOME_LAB_PROTON_PROMOTION_BASE", str(ROOT / "scripts/cleanup-damaged-proton-restic-v1"))
C = SourceFileLoader("proton_promotion_controller_base", str(ROOT / "scripts/controller/proton-v1-cleanup.py")).load_module()
H = SourceFileLoader("qualified_proton_promotion_host", str(ROOT / "scripts/promote-qualified-proton-restic")).load_module()
HELPER = ROOT / "scripts/promote-qualified-proton-restic"
PLAYBOOK = ROOT / "ansible/playbooks/qualified-proton-promotion.yml"
OUTPUT = ROOT / ".local/qualified-proton-promotion"


def action() -> dict:
    return {"kind":"promote-qualified-proton-repository","install_rclone_sha256":H.BETA_SHA256,"retire_to_trash":H.TARGET,"move_from":H.SOURCE,"move_to":H.TARGET,"preserve":H.V2}


def run_playbook(extra: dict) -> None:
    descriptor, name = tempfile.mkstemp(prefix="qualified-proton-promotion-", suffix=".json")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(C.canonical(extra)); handle.flush(); os.fchmod(handle.fileno(), 0o600); os.fsync(handle.fileno())
        result = subprocess.run(["ansible-playbook","-i",str(C.INVENTORY),str(PLAYBOOK),"--extra-vars",f"@{name}"],cwd=ROOT/"ansible",timeout=18000)
        if result.returncode: raise SystemExit("qualified Proton promotion playbook failed")
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass


def install() -> None:
    run_playbook({"qualified_proton_operation":"install","qualified_proton_expected_helper_sha256":C.sha(HELPER.read_bytes())})


def observe_host() -> dict:
    OUTPUT.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(OUTPUT,0o700)
    descriptor,name=tempfile.mkstemp(prefix="qualified-proton-observation-",suffix=".json",dir=OUTPUT); os.close(descriptor); os.unlink(name); path=Path(name)
    try:
        run_playbook({"qualified_proton_operation":"observe","qualified_proton_expected_helper_sha256":C.sha(HELPER.read_bytes()),"qualified_proton_controller_output":str(path)})
        return C.load_private(path)[0]
    finally:
        try: path.unlink()
        except FileNotFoundError: pass


def validate_observation(value: dict, contract: dict) -> None:
    expected_keys={"format","helper_sha256","base_helper_sha256","policy_sha256","installed_rclone_sha256","beta_sha256","candidate","candidate_state","failed_canonical","damaged_v2","trash_state","canonical_state","timers"}
    candidate=value.get("candidate",{}); failed=value.get("failed_canonical",{}); v2=value.get("damaged_v2",{})
    if (set(value)!=expected_keys or value.get("format")!="home-lab-qualified-proton-promotion-observation-v1" or value.get("helper_sha256")!=C.sha(HELPER.read_bytes())
        or value.get("installed_rclone_sha256")!=H.STABLE_SHA256 or value.get("beta_sha256")!=H.BETA_SHA256
        or contract["backups"]["restic"]["tools"]["rclone"]["installed_sha256"]!=H.BETA_SHA256 or contract["backups"]["restic"]["schedule"]["state"]!="incident-suspended"
        or candidate.get("repository_id")!=H.SOURCE_ID or candidate.get("snapshot_id")!=H.SOURCE_SNAPSHOT or candidate.get("original_snapshot_id")!=H.ORIGINAL_SNAPSHOT or candidate.get("full_read_data_check")!="zero-errors"
        or value.get("candidate_state",{}).get("repository_id")!=H.SOURCE_ID or value.get("candidate_state",{}).get("status")!="verified"
        or failed.get("repository_id")!=H.TARGET_FAILED_ID or failed.get("broken_pack")!=H.TARGET_BROKEN_PACK
        or v2.get("repository_id")!=H.V2_ID or v2.get("broken_pack")!=H.V2_BROKEN_PACK
        or value.get("trash_state",{}).get("status")!="cleanup-started" or value.get("canonical_state",{}).get("status")!="copied"
        or value.get("timers")!=[{"unit":"home-lab-restic-daily.timer","active":"inactive","unit_file":"enabled"},{"unit":"home-lab-restic-maintenance.timer","active":"inactive","unit_file":"enabled"}]):
        raise SystemExit("qualified Proton promotion observation differs")


def create_plan() -> None:
    commit=C.clean_pushed_commit(); contract,raw=C.contract_policy(); observed=observe_host(); validate_observation(observed,contract); created=datetime.now(timezone.utc).replace(microsecond=0)
    plan={"format":H.PLAN_FORMAT,"commit":commit,"contract_sha256":C.sha(raw),"created_at":created.isoformat().replace("+00:00","Z"),"expires_at":(created+timedelta(hours=24)).isoformat().replace("+00:00","Z"),"host_observation":observed,"action":action(),"blockers":["exact-proton-promotion-authorization-required"],"authorized":False}
    plan_raw=C.canonical(plan); digest=C.sha(plan_raw); path=OUTPUT/f"qualified-proton-promotion-{digest}.json"; C.write_private(path,plan_raw)
    print(json.dumps({"plan_sha256":digest,"path":str(path),"action":action(),"blockers":plan["blockers"]},sort_keys=True))


def load_plan(path: Path, *, allow_expired: bool=False) -> tuple[dict,str]:
    plan,raw=C.load_private(path); digest=C.sha(raw)
    try: expires=datetime.fromisoformat(plan["expires_at"].replace("Z","+00:00"))
    except (KeyError,TypeError,ValueError) as error: raise SystemExit("qualified Proton plan time differs") from error
    if plan.get("format")!=H.PLAN_FORMAT or path.name!=f"qualified-proton-promotion-{digest}.json" or plan.get("commit")!=C.clean_pushed_commit() or plan.get("contract_sha256")!=C.sha(C.CONTRACT.read_bytes()) or plan.get("action")!=action() or plan.get("blockers")!=["exact-proton-promotion-authorization-required"] or plan.get("authorized") is not False or (not allow_expired and datetime.now(timezone.utc)>expires): raise SystemExit("qualified Proton plan binding differs")
    validate_observation(plan.get("host_observation",{}),C.contract_policy()[0]); return plan,digest


def authorize(path: Path) -> None:
    plan,digest=load_plan(path); confirmation=f"authorize-qualified-proton-promotion-{digest}"
    if os.environ.get("QUALIFIED_PROTON_AUTHORIZATION_CONFIRMED")!=confirmation: raise SystemExit(f"exact confirmation required: {confirmation}")
    created=datetime.now(timezone.utc).replace(microsecond=0); expires=min(created+timedelta(minutes=15),datetime.fromisoformat(plan["expires_at"].replace("Z","+00:00")))
    value={"format":H.AUTH_FORMAT,"plan_sha256":digest,"created_at":created.isoformat().replace("+00:00","Z"),"expires_at":expires.isoformat().replace("+00:00","Z"),"confirmation":confirmation,"authorized":True}
    raw=C.canonical(value); auth_digest=C.sha(raw); output=OUTPUT/f"authorization-{auth_digest}.json"; C.write_private(output,raw)
    print(json.dumps({"plan_sha256":digest,"authorization_sha256":auth_digest,"path":str(output),"expires_at":value["expires_at"]},sort_keys=True))


def apply(path: Path, authorization_path: Path) -> None:
    _,digest=load_plan(path,allow_expired=True); authorization,auth_raw=C.load_private(authorization_path); auth_digest=C.sha(auth_raw)
    expected={"format":H.AUTH_FORMAT,"plan_sha256":digest,"created_at":authorization.get("created_at"),"expires_at":authorization.get("expires_at"),"confirmation":f"authorize-qualified-proton-promotion-{digest}","authorized":True}
    if authorization!=expected: raise SystemExit("qualified Proton authorization differs")
    receipt_path=OUTPUT/f"receipt-{digest}.json"
    if receipt_path.exists(): receipt_path.unlink()
    run_playbook({"qualified_proton_operation":"apply","qualified_proton_expected_helper_sha256":C.sha(HELPER.read_bytes()),"qualified_proton_plan_sha256":digest,"qualified_proton_authorization_sha256":auth_digest,"qualified_proton_confirmation":f"promote-qualified-proton-repository-{digest}-{auth_digest}","qualified_proton_plan_source":str(path),"qualified_proton_authorization_source":str(authorization_path),"qualified_proton_controller_output":str(receipt_path)})
    receipt,raw=C.load_private(receipt_path)
    if receipt.get("format")!=H.RECEIPT_FORMAT or receipt.get("status")!="committed" or receipt.get("plan_sha256")!=digest or C.HEX.fullmatch(str(receipt.get("authorization_sha256", ""))) is None or receipt.get("target",{}).get("repository_id")!=H.SOURCE_ID or receipt.get("target",{}).get("snapshot_id")!=H.SOURCE_SNAPSHOT or receipt.get("source_absent") is not True or receipt.get("full_read_data_check")!="zero-errors" or receipt.get("damaged_v2_preserved")!={"repository_id":H.V2_ID,"broken_pack":H.V2_BROKEN_PACK}: raise SystemExit("qualified Proton receipt differs")
    print(json.dumps({"status":"committed","plan_sha256":digest,"receipt_sha256":C.sha(raw),"path":str(receipt_path),"target":receipt["target"]},sort_keys=True))


def main() -> None:
    parser=argparse.ArgumentParser(); commands=parser.add_subparsers(dest="command",required=True); commands.add_parser("install"); commands.add_parser("plan"); auth=commands.add_parser("authorize"); auth.add_argument("plan",type=Path); execute=commands.add_parser("apply"); execute.add_argument("plan",type=Path); execute.add_argument("authorization",type=Path); args=parser.parse_args()
    if args.command=="install": install()
    elif args.command=="plan": create_plan()
    elif args.command=="authorize": authorize(args.plan.resolve())
    else: apply(args.plan.resolve(),args.authorization.resolve())

if __name__=="__main__": main()
