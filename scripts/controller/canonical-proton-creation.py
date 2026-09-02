#!/usr/bin/env python3
"""Plan, authorize, and create the canonical Proton Restic repository."""
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
os.environ.setdefault("HOME_LAB_CANONICAL_PROTON_TESTING", "1")
os.environ.setdefault("HOME_LAB_CANONICAL_PROTON_BASE", str(ROOT / "scripts/cleanup-damaged-proton-restic-v1"))
C = SourceFileLoader("proton_v1_controller", str(ROOT / "scripts/controller/proton-v1-cleanup.py")).load_module()
H = SourceFileLoader("canonical_proton_host", str(ROOT / "scripts/create-canonical-proton-restic")).load_module()
HELPER = ROOT / "scripts/create-canonical-proton-restic"
BASE_HELPER = ROOT / "scripts/cleanup-damaged-proton-restic-v1"
PLAYBOOK = ROOT / "ansible/playbooks/canonical-proton-creation.yml"
OUTPUT = ROOT / ".local/canonical-proton-creation"
PLAN_FORMAT = H.PLAN_FORMAT
AUTH_FORMAT = H.AUTH_FORMAT
RECEIPT_FORMAT = H.RECEIPT_FORMAT


def action() -> dict:
    return {"kind": "create-canonical-proton-repository", "target": H.TARGET_REPOSITORY, "source_repository_id": H.SOURCE_ID, "source_snapshot_id": H.SOURCE_SNAPSHOT, "preserve_damaged_repository": H.DAMAGED_REPOSITORY}


def run_playbook(extra: dict) -> None:
    descriptor, name = tempfile.mkstemp(prefix="canonical-proton-creation-", suffix=".json")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(C.canonical(extra)); handle.flush(); os.fchmod(handle.fileno(), 0o600); os.fsync(handle.fileno())
        result = subprocess.run(["ansible-playbook", "-i", str(C.INVENTORY), str(PLAYBOOK), "--extra-vars", f"@{name}"], cwd=ROOT / "ansible", timeout=18000)
        if result.returncode:
            raise SystemExit("canonical Proton creation playbook failed")
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass


def observe_host() -> dict:
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(OUTPUT, 0o700)
    descriptor, name = tempfile.mkstemp(prefix="canonical-proton-observation-", suffix=".json", dir=OUTPUT)
    os.close(descriptor); os.unlink(name); path = Path(name)
    try:
        run_playbook({"canonical_proton_operation": "observe", "canonical_proton_expected_helper_sha256": C.sha(HELPER.read_bytes()), "canonical_proton_controller_output": str(path)})
        return C.load_private(path)[0]
    finally:
        try: path.unlink()
        except FileNotFoundError: pass


def validate_observation(value: dict, contract: dict, *, target_absent: bool = True) -> None:
    expected_keys = {"format", "helper_sha256", "base_helper_sha256", "runner_sha256", "policy_sha256", "active_directories", "active_directories_sha256", "target", "source", "damaged", "trash_transaction", "stopped_timers"}
    source = value.get("source", {})
    damaged = value.get("damaged", {})
    if (set(value) != expected_keys or value.get("format") != "home-lab-canonical-proton-creation-observation-v1"
        or value.get("helper_sha256") != C.sha(HELPER.read_bytes()) or value.get("base_helper_sha256") != C.sha(BASE_HELPER.read_bytes())
        or value.get("runner_sha256") != contract["backups"]["restic"]["runner"]["sha256"]
        or value.get("active_directories") != [H.DAMAGED_DIRECTORY] or C.HEX.fullmatch(value.get("active_directories_sha256", "")) is None
        or (target_absent and value.get("target") != {"present": False})
        or source.get("repository_id") != H.SOURCE_ID or source.get("snapshot_id") != H.SOURCE_SNAPSHOT or source.get("full_read_data_check") != "zero-errors" or not isinstance(source.get("chunker_polynomial"), str)
        or damaged.get("repository") != H.DAMAGED_REPOSITORY or damaged.get("repository_id") != H.DAMAGED_ID or damaged.get("broken_pack") != H.BROKEN_PACK
        or damaged.get("check_summary") != {"message_type": "summary", "num_errors": 1, "broken_packs": [H.BROKEN_PACK], "suggest_repair_index": False, "suggest_prune": False}
        or value.get("trash_transaction", {}).get("plan_sha256") != H.TRASH_PLAN or value.get("trash_transaction", {}).get("status") != "cleanup-started" or C.HEX.fullmatch(value.get("trash_transaction", {}).get("state_sha256", "")) is None
        or value.get("stopped_timers") != ["home-lab-restic-daily.timer", "home-lab-restic-maintenance.timer"]):
        raise SystemExit("canonical Proton observation differs")


def create_plan() -> None:
    commit = C.clean_pushed_commit(); contract, contract_raw = C.contract_policy(); observed = observe_host(); validate_observation(observed, contract)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    plan = {"format": PLAN_FORMAT, "commit": commit, "contract_sha256": C.sha(contract_raw), "created_at": created.isoformat().replace("+00:00", "Z"), "expires_at": (created+timedelta(hours=24)).isoformat().replace("+00:00", "Z"), "host_observation": observed, "action": action(), "blockers": ["remote-repository-creation-authorization-required"], "authorized": False}
    raw = C.canonical(plan); digest = C.sha(raw); path = OUTPUT / f"canonical-proton-creation-{digest}.json"; C.write_private(path, raw)
    print(json.dumps({"plan_sha256": digest, "path": str(path), "action": plan["action"], "blockers": plan["blockers"]}, sort_keys=True))


def load_plan(path: Path, *, allow_expired: bool = False) -> tuple[dict, str]:
    plan, raw = C.load_private(path); digest = C.sha(raw)
    try: expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error: raise SystemExit("canonical Proton plan time differs") from error
    if (plan.get("format") != PLAN_FORMAT or path.name != f"canonical-proton-creation-{digest}.json" or plan.get("commit") != C.clean_pushed_commit()
        or plan.get("contract_sha256") != C.sha(C.CONTRACT.read_bytes()) or plan.get("action") != action() or plan.get("blockers") != ["remote-repository-creation-authorization-required"]
        or plan.get("authorized") is not False or (not allow_expired and datetime.now(timezone.utc) > expires)):
        raise SystemExit("canonical Proton plan binding differs")
    validate_observation(plan.get("host_observation", {}), C.contract_policy()[0])
    return plan, digest


def authorize(path: Path) -> None:
    plan, digest = load_plan(path); confirmation = f"authorize-create-canonical-proton-repository-{digest}"
    if os.environ.get("CANONICAL_PROTON_AUTHORIZATION_CONFIRMED") != confirmation: raise SystemExit(f"exact confirmation required: {confirmation}")
    created = datetime.now(timezone.utc).replace(microsecond=0); expires = min(created+timedelta(minutes=15), datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")))
    value = {"format": AUTH_FORMAT, "plan_sha256": digest, "created_at": created.isoformat().replace("+00:00", "Z"), "expires_at": expires.isoformat().replace("+00:00", "Z"), "confirmation": confirmation, "authorized": True}
    raw = C.canonical(value); auth_digest = C.sha(raw); output = OUTPUT / f"authorization-{auth_digest}.json"; C.write_private(output, raw)
    print(json.dumps({"plan_sha256": digest, "authorization_sha256": auth_digest, "path": str(output), "expires_at": value["expires_at"]}, sort_keys=True))


def apply(path: Path, authorization_path: Path) -> None:
    plan, digest = load_plan(path, allow_expired=True); authorization, auth_raw = C.load_private(authorization_path); auth_digest = C.sha(auth_raw)
    expected = {"format": AUTH_FORMAT, "plan_sha256": digest, "created_at": authorization.get("created_at"), "expires_at": authorization.get("expires_at"), "confirmation": f"authorize-create-canonical-proton-repository-{digest}", "authorized": True}
    if authorization != expected: raise SystemExit("canonical Proton authorization differs")
    receipt_path = OUTPUT / f"receipt-{digest}.json"
    if receipt_path.exists(): receipt_path.unlink()
    run_playbook({"canonical_proton_operation": "apply", "canonical_proton_expected_helper_sha256": C.sha(HELPER.read_bytes()), "canonical_proton_plan_sha256": digest, "canonical_proton_authorization_sha256": auth_digest, "canonical_proton_confirmation": f"create-canonical-proton-repository-{digest}-{auth_digest}", "canonical_proton_plan_source": str(path), "canonical_proton_authorization_source": str(authorization_path), "canonical_proton_controller_output": str(receipt_path)})
    receipt, raw = C.load_private(receipt_path)
    if receipt.get("format") != RECEIPT_FORMAT or receipt.get("status") != "committed" or receipt.get("plan_sha256") != digest or receipt.get("authorization_sha256") != auth_digest or receipt.get("source") != {"repository_id": H.SOURCE_ID, "snapshot_id": H.SOURCE_SNAPSHOT} or receipt.get("damaged_repository_preserved", {}).get("broken_pack") != H.BROKEN_PACK or receipt.get("structural_check") != "zero-errors" or receipt.get("full_read_data_check") != "zero-errors" or C.HEX.fullmatch(receipt.get("target", {}).get("repository_id", "")) is None or C.HEX.fullmatch(receipt.get("target", {}).get("snapshot_id", "")) is None:
        raise SystemExit("canonical Proton receipt differs")
    print(json.dumps({"status": "committed", "plan_sha256": digest, "receipt_sha256": C.sha(raw), "path": str(receipt_path), "target": receipt["target"]}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True); commands.add_parser("plan")
    auth = commands.add_parser("authorize"); auth.add_argument("plan", type=Path)
    execute = commands.add_parser("apply"); execute.add_argument("plan", type=Path); execute.add_argument("authorization", type=Path)
    args = parser.parse_args()
    if args.command == "plan": create_plan()
    elif args.command == "authorize": authorize(args.plan.resolve())
    else: apply(args.plan.resolve(), args.authorization.resolve())


if __name__ == "__main__": main()
