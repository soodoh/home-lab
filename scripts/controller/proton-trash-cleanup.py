#!/usr/bin/env python3
"""Plan, authorize, and apply account-wide Proton Trash deletion."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

BASE = Path(__file__).resolve().parents[2]
C = SourceFileLoader("proton_v1_cleanup_controller", str(BASE / "scripts/controller/proton-v1-cleanup.py")).load_module()
HELPER = BASE / "scripts/empty-proton-trash"
BASE_HELPER = BASE / "scripts/cleanup-damaged-proton-restic-v1"
PLAYBOOK = BASE / "ansible/playbooks/proton-trash-cleanup.yml"
OUTPUT = BASE / ".local/proton-trash-cleanup"
PLAN_FORMAT = "home-lab-proton-trash-cleanup-plan-v1"
AUTH_FORMAT = "home-lab-proton-trash-cleanup-authorization-v1"
RECEIPT_FORMAT = "home-lab-proton-trash-cleanup-receipt-v1"
V1_PLAN = "b8da0f1ecfa0faaaac08e317d97c2c9113f6006dc20863cfef87ad956e482e7a"
V1_RECEIPT_SHA256 = "143beaab3513af31e91ed15ef5d268ddb059ac8550e4fc199113e8e232d0e77b"


def action() -> dict:
    return {"kind": "empty-entire-proton-trash", "scope": "entire-account-trash-at-authorized-execution", "enumerable": False, "permanent_delete": True}


def run_playbook(extra: dict) -> None:
    descriptor, name = tempfile.mkstemp(prefix="proton-trash-cleanup-", suffix=".json")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(C.canonical(extra))
            handle.flush()
            os.fchmod(handle.fileno(), 0o600)
            os.fsync(handle.fileno())
        result = subprocess.run(["ansible-playbook", "-i", str(C.INVENTORY), str(PLAYBOOK), "--extra-vars", f"@{name}"], cwd=BASE / "ansible", timeout=18000)
        if result.returncode:
            raise SystemExit("Proton Trash cleanup playbook failed")
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def observe_host() -> dict:
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(OUTPUT, 0o700)
    descriptor, name = tempfile.mkstemp(prefix="proton-trash-observation-", suffix=".json", dir=OUTPUT)
    os.close(descriptor)
    os.unlink(name)
    path = Path(name)
    try:
        run_playbook({"proton_trash_cleanup_operation": "observe", "proton_trash_cleanup_expected_helper_sha256": C.sha(HELPER.read_bytes()), "proton_trash_cleanup_controller_output": str(path)})
        observed, _ = C.load_private(path)
        return observed
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def validate_observation(value: dict, contract: dict) -> None:
    expected_keys = {"format", "helper_sha256", "base_helper_sha256", "runner_sha256", "policy_sha256", "active_directories", "replacement", "migration", "v1_cleanup", "usage", "trash_scope"}
    usage = value.get("usage", {})
    if (
        set(value) != expected_keys
        or value.get("format") != "home-lab-proton-trash-cleanup-observation-v1"
        or value.get("helper_sha256") != C.sha(HELPER.read_bytes())
        or value.get("base_helper_sha256") != C.sha(BASE_HELPER.read_bytes())
        or value.get("runner_sha256") != contract["backups"]["restic"]["runner"]["sha256"]
        or value.get("active_directories") != ["home-lab-restic-v2/"]
        or value.get("replacement") != {"repository_id": C.NEW_ID, "snapshot_id": C.NEW_SNAPSHOT, "original_snapshot_id": C.ORIGINAL_SNAPSHOT}
        or value.get("migration") != {"sha256": "3213ceff96d067da22c5b243a213f39a00e7f9cce74905fc53c5d5229ac1f4a5", "full_read_data_check": True}
        or value.get("v1_cleanup") != {"plan_sha256": V1_PLAN, "receipt_sha256": V1_RECEIPT_SHA256}
        or value.get("trash_scope") != "entire-account-trash-unenumerable"
        or set(usage) != {"total", "used", "free"}
        or not all(isinstance(usage[key], int) and usage[key] >= 0 for key in usage)
        or usage["used"] + usage["free"] != usage["total"]
    ):
        raise SystemExit("Proton Trash observation differs")


def create_plan() -> None:
    commit = C.clean_pushed_commit()
    contract, contract_raw = C.contract_policy()
    C.recovery_proof()
    observed = observe_host()
    validate_observation(observed, contract)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    plan = {
        "format": PLAN_FORMAT,
        "commit": commit,
        "contract_sha256": C.sha(contract_raw),
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "expires_at": (created + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        "host_observation": observed,
        "recovery_evidence_sha256": C.RECOVERY_SHA256,
        "recovery_journal_sha256": C.RECOVERY_JOURNAL_SHA256,
        "action": action(),
        "blockers": ["entire-trash-irreversible-acknowledgement-required", "separate-authorization-required"],
        "authorized": False,
    }
    raw = C.canonical(plan)
    digest = C.sha(raw)
    path = OUTPUT / f"proton-trash-cleanup-{digest}.json"
    C.write_private(path, raw)
    print(json.dumps({"plan_sha256": digest, "path": str(path), "action": plan["action"], "blockers": plan["blockers"]}, sort_keys=True))


def load_plan(path: Path, *, allow_expired: bool = False) -> tuple[dict, str]:
    plan, raw = C.load_private(path)
    digest = C.sha(raw)
    try:
        expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("Proton Trash plan timestamp differs") from error
    if (
        plan.get("format") != PLAN_FORMAT
        or path.name != f"proton-trash-cleanup-{digest}.json"
        or plan.get("commit") != C.clean_pushed_commit()
        or plan.get("contract_sha256") != C.sha(C.CONTRACT.read_bytes())
        or plan.get("action") != action()
        or plan.get("blockers") != ["entire-trash-irreversible-acknowledgement-required", "separate-authorization-required"]
        or plan.get("authorized") is not False
        or (not allow_expired and datetime.now(timezone.utc) > expires)
    ):
        raise SystemExit("Proton Trash plan binding differs")
    contract, _ = C.contract_policy()
    validate_observation(plan.get("host_observation", {}), contract)
    return plan, digest


def authorize(path: Path) -> None:
    plan, digest = load_plan(path)
    C.recovery_proof()
    confirmation = f"authorize-empty-entire-proton-trash-{digest}"
    if os.environ.get("PROTON_TRASH_AUTHORIZATION_CONFIRMED") != confirmation:
        raise SystemExit(f"exact confirmation required: {confirmation}")
    created = datetime.now(timezone.utc).replace(microsecond=0)
    expires = min(created + timedelta(minutes=15), datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")))
    value = {"format": AUTH_FORMAT, "plan_sha256": digest, "created_at": created.isoformat().replace("+00:00", "Z"), "expires_at": expires.isoformat().replace("+00:00", "Z"), "confirmation": confirmation, "authorized": True}
    raw = C.canonical(value)
    auth_digest = C.sha(raw)
    output = OUTPUT / f"authorization-{auth_digest}.json"
    C.write_private(output, raw)
    print(json.dumps({"plan_sha256": digest, "authorization_sha256": auth_digest, "path": str(output), "expires_at": value["expires_at"]}, sort_keys=True))


def apply(path: Path, auth_path: Path) -> None:
    plan, digest = load_plan(path, allow_expired=True)
    authorization, auth_raw = C.load_private(auth_path)
    auth_digest = C.sha(auth_raw)
    expected = {"format": AUTH_FORMAT, "plan_sha256": digest, "created_at": authorization.get("created_at"), "expires_at": authorization.get("expires_at"), "confirmation": f"authorize-empty-entire-proton-trash-{digest}", "authorized": True}
    if authorization != expected:
        raise SystemExit("Proton Trash authorization differs")
    C.recovery_proof()
    receipt_path = OUTPUT / f"receipt-{digest}.json"
    if receipt_path.exists():
        receipt_path.unlink()
    run_playbook({
        "proton_trash_cleanup_operation": "apply",
        "proton_trash_cleanup_expected_helper_sha256": C.sha(HELPER.read_bytes()),
        "proton_trash_cleanup_plan_sha256": digest,
        "proton_trash_cleanup_authorization_sha256": auth_digest,
        "proton_trash_cleanup_confirmation": f"empty-entire-proton-trash-{digest}-{auth_digest}",
        "proton_trash_cleanup_plan_source": str(path),
        "proton_trash_cleanup_authorization_source": str(auth_path),
        "proton_trash_cleanup_recovery_source": str(C.RECOVERY),
        "proton_trash_cleanup_recovery_journal_source": str(C.RECOVERY_JOURNAL),
        "proton_trash_cleanup_controller_output": str(receipt_path),
    })
    receipt, raw = C.load_private(receipt_path)
    before = plan["host_observation"]["usage"]
    after = receipt.get("after_usage", {})
    execution = receipt.get("execution_usage", {})
    history = receipt.get("authorization_history")
    if (
        receipt.get("format") != RECEIPT_FORMAT
        or receipt.get("status") != "committed"
        or receipt.get("plan_sha256") != digest
        or receipt.get("authorization_sha256") != auth_digest
        or not isinstance(history, list)
        or not history
        or history[-1] != auth_digest
        or receipt.get("scope") != "entire-account-trash"
        or receipt.get("permanent_delete") is not True
        or receipt.get("v1_cleanup_receipt_sha256") != V1_RECEIPT_SHA256
        or receipt.get("active_directories") != ["home-lab-restic-v2/"]
        or receipt.get("replacement_check") != "full-read-data-zero-errors"
        or receipt.get("before_usage") != before
        or set(execution) != {"total", "used", "free"}
        or set(after) != {"total", "used", "free"}
        or after["total"] != execution["total"]
        or after["used"] > execution["used"]
        or receipt.get("recovery_evidence_sha256") != C.RECOVERY_SHA256
        or receipt.get("recovery_journal_sha256") != C.RECOVERY_JOURNAL_SHA256
    ):
        raise SystemExit("Proton Trash receipt differs")
    print(json.dumps({"status": "committed", "plan_sha256": digest, "receipt_sha256": C.sha(raw), "path": str(receipt_path)}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan")
    authorize_parser = commands.add_parser("authorize")
    authorize_parser.add_argument("plan", type=Path)
    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("plan", type=Path)
    apply_parser.add_argument("authorization", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "plan":
        create_plan()
    elif arguments.command == "authorize":
        authorize(arguments.plan.resolve())
    else:
        apply(arguments.plan.resolve(), arguments.authorization.resolve())


if __name__ == "__main__":
    main()
