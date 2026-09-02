#!/usr/bin/env python3
"""Plan, authorize, and apply exact Proton incident artifact retirement."""
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
os.environ.setdefault("HOME_LAB_PROTON_RETIREMENT_TESTING", "1")
os.environ.setdefault("HOME_LAB_PROTON_RETIREMENT_BASE", str(ROOT / "scripts/cleanup-damaged-proton-restic-v1"))
C = SourceFileLoader("proton_incident_retirement_controller_base", str(ROOT / "scripts/controller/proton-v1-cleanup.py")).load_module()
H = SourceFileLoader("proton_incident_retirement_host", str(ROOT / "scripts/retire-proton-incident-artifacts")).load_module()
HELPER = ROOT / "scripts/retire-proton-incident-artifacts"
PLAYBOOK = ROOT / "ansible/playbooks/proton-incident-retirement.yml"
OUTPUT = ROOT / ".local/proton-incident-retirement"
PROMOTION = ROOT / "infrastructure/evidence/proton-qualified-promotion.json"
RECOVERY = ROOT / "infrastructure/evidence/proton-canonical-recovery-vm.json"
RECOVERY_JOURNAL = ROOT / ".reconcile/restic-recovery-vm/72909b5723ae8d586f5b3db428b7d73f6c610e97/journal.json"


def action() -> dict:
    return {"kind": "retire-proton-incident-artifacts", "purge_to_trash": [H.DAMAGED_REMOTE, H.STABLE_REMOTE, H.BETA_REMOTE], "empty_trash": False, "preserve": H.CANONICAL}


def contract_policy() -> tuple[dict, bytes]:
    raw = C.CONTRACT.read_bytes()
    parsed = subprocess.run(["node", "-e", "const fs=require('node:fs'),yaml=require('js-yaml');const c=yaml.load(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(JSON.stringify(c.backups.restic));", str(C.CONTRACT)], cwd=ROOT, capture_output=True, text=True, check=True)
    return {"backups": {"restic": json.loads(parsed.stdout)}}, raw


def deployed_policy_sha256(contract: dict) -> str:
    return C.sha((json.dumps(contract["backups"]["restic"], indent=4, sort_keys=True) + "\n").encode())


def run_playbook(extra: dict) -> None:
    descriptor, name = tempfile.mkstemp(prefix="proton-incident-retirement-", suffix=".json")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(C.canonical(extra))
            handle.flush()
            os.fchmod(handle.fileno(), 0o600)
            os.fsync(handle.fileno())
        result = subprocess.run(["ansible-playbook", "-i", str(C.INVENTORY), str(PLAYBOOK), "--extra-vars", f"@{name}"], cwd=ROOT / "ansible", timeout=21600)
        if result.returncode:
            raise SystemExit("Proton incident retirement playbook failed")
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def install() -> None:
    run_playbook({"proton_incident_retirement_operation": "install", "proton_incident_retirement_expected_helper_sha256": C.sha(HELPER.read_bytes())})


def observe_host() -> dict:
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(OUTPUT, 0o700)
    descriptor, name = tempfile.mkstemp(prefix="observation-", suffix=".json", dir=OUTPUT)
    os.close(descriptor)
    os.unlink(name)
    path = Path(name)
    try:
        run_playbook({"proton_incident_retirement_operation": "observe", "proton_incident_retirement_expected_helper_sha256": C.sha(HELPER.read_bytes()), "proton_incident_retirement_controller_output": str(path)})
        return C.load_private(path)[0]
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def validate_inventory(value: dict, *, fixture: bool) -> None:
    required = {"objects", "bytes", "zero_byte_objects", "inventory_sha256", "directories_sha256", "nested_directories"}
    if set(value) != required or not isinstance(value["objects"], int) or value["objects"] <= 0 or not isinstance(value["bytes"], int) or value["bytes"] <= 0 or not isinstance(value["zero_byte_objects"], int) or value["zero_byte_objects"] < 0 or value["zero_byte_objects"] > value["objects"] or C.HEX.fullmatch(str(value["inventory_sha256"])) is None or C.HEX.fullmatch(str(value["directories_sha256"])) is None or not isinstance(value["nested_directories"], list):
        raise SystemExit("Proton retirement inventory differs")
    if fixture and (value["objects"] != 8 or value["bytes"] != 167772160 or value["nested_directories"]):
        raise SystemExit("Proton diagnostic fixture inventory differs")


def validate_observation(value: dict, contract: dict, *, require_present: bool = True) -> None:
    expected_keys = {"format", "helper_sha256", "base_helper_sha256", "runner_sha256", "policy_sha256", "rclone_sha256", "canonical", "damaged_v2", "diagnostic_fixtures", "namespace_listings", "retained_states", "timers", "services"}
    policy = contract["backups"]["restic"]
    canonical = value.get("canonical", {})
    damaged = value.get("damaged_v2", {})
    fixtures = value.get("diagnostic_fixtures", {})
    namespaces = value.get("namespace_listings", {})
    retained = value.get("retained_states", {})
    timers = [{"unit": "home-lab-restic-daily.timer", "active": "active", "unit_file": "enabled"}, {"unit": "home-lab-restic-maintenance.timer", "active": "active", "unit_file": "enabled"}]
    services = [{"unit": "home-lab-restic-daily-proton.service", "active": "inactive", "result": "success"}, {"unit": "home-lab-restic-maintenance-proton.service", "active": "inactive", "result": "success"}]
    if (
        set(value) != expected_keys
        or value.get("format") != "home-lab-proton-incident-retirement-observation-v1"
        or value.get("helper_sha256") != C.sha(HELPER.read_bytes())
        or value.get("base_helper_sha256") != C.sha((ROOT / "scripts/cleanup-damaged-proton-restic-v1").read_bytes())
        or value.get("runner_sha256") != policy["runner"]["sha256"]
        or value.get("policy_sha256") != deployed_policy_sha256(contract)
        or value.get("rclone_sha256") != H.RCLONE_SHA256
        or policy["repositories"]["proton"]["path"] != H.CANONICAL
        or policy["repositories"]["proton"]["id"] != H.CANONICAL_ID
        or policy["schedule"]["state"] != "active"
        or value.get("timers") != timers
        or value.get("services") != services
        or canonical.get("repository_id") != H.CANONICAL_ID
        or canonical.get("snapshot_id") != H.CANONICAL_SNAPSHOT
        or canonical.get("original_snapshot_id") != H.ORIGINAL_SNAPSHOT
        or canonical.get("chunker_polynomial") != "255a608adc8769"
        or canonical.get("structural_check") != "zero-errors"
        or canonical.get("full_read_data_check") != "zero-errors"
        or retained.get("trash", {}).get("status") != "cleanup-started"
        or retained.get("canonical_creation", {}).get("status") != "copied"
        or C.HEX.fullmatch(str(retained.get("trash", {}).get("sha256", ""))) is None
        or C.HEX.fullmatch(str(retained.get("canonical_creation", {}).get("sha256", ""))) is None
        or C.HEX.fullmatch(str(namespaces.get("backups_sha256", ""))) is None
        or C.HEX.fullmatch(str(namespaces.get("diagnostics_sha256", ""))) is None
        or "home-lab-restic/" not in namespaces.get("backups", [])
    ):
        raise SystemExit("Proton incident retirement observation differs")
    if require_present:
        if damaged.get("present") is not True or damaged.get("repository_id") != H.DAMAGED_ID or damaged.get("broken_pack") != H.DAMAGED_PACK or fixtures.get("present") is not True or fixtures.get("parent_present") is not True or fixtures.get("children") != H.DIAGNOSTIC_CHILDREN:
            raise SystemExit("Proton incident targets differ")
        validate_inventory({key: damaged[key] for key in ("objects", "bytes", "zero_byte_objects", "inventory_sha256", "directories_sha256", "nested_directories")}, fixture=False)
        validate_inventory(fixtures.get("stable", {}), fixture=True)
        validate_inventory(fixtures.get("beta", {}), fixture=True)


def create_plan() -> None:
    commit = C.clean_pushed_commit()
    contract, contract_raw = contract_policy()
    for path, digest in ((PROMOTION, H.PROMOTION_SHA256), (RECOVERY, H.RECOVERY_SHA256), (RECOVERY_JOURNAL, H.RECOVERY_JOURNAL_SHA256)):
        if C.sha(path.read_bytes()) != digest:
            raise SystemExit(f"qualified evidence differs: {path}")
    observed = observe_host()
    validate_observation(observed, contract)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    plan = {"format": H.PLAN_FORMAT, "commit": commit, "contract_sha256": C.sha(contract_raw), "deployed_policy_sha256": deployed_policy_sha256(contract), "created_at": created.isoformat().replace("+00:00", "Z"), "expires_at": (created + timedelta(hours=24)).isoformat().replace("+00:00", "Z"), "host_observation": observed, "promotion_receipt_sha256": H.PROMOTION_SHA256, "recovery_evidence_sha256": H.RECOVERY_SHA256, "recovery_journal_sha256": H.RECOVERY_JOURNAL_SHA256, "action": action(), "blockers": ["exact-destructive-authorization-required"], "authorized": False}
    raw = C.canonical(plan)
    digest = C.sha(raw)
    path = OUTPUT / f"proton-incident-retirement-{digest}.json"
    C.write_private(path, raw)
    print(json.dumps({"plan_sha256": digest, "path": str(path), "action": action(), "blockers": plan["blockers"]}, sort_keys=True))


def load_plan(path: Path, *, allow_expired: bool = False) -> tuple[dict, str]:
    plan, raw = C.load_private(path)
    digest = C.sha(raw)
    try:
        expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("Proton incident retirement plan time differs") from error
    contract, contract_raw = contract_policy()
    if plan.get("format") != H.PLAN_FORMAT or path.name != f"proton-incident-retirement-{digest}.json" or plan.get("commit") != C.clean_pushed_commit() or plan.get("contract_sha256") != C.sha(contract_raw) or plan.get("deployed_policy_sha256") != deployed_policy_sha256(contract) or plan.get("action") != action() or plan.get("blockers") != ["exact-destructive-authorization-required"] or plan.get("authorized") is not False or (not allow_expired and datetime.now(timezone.utc) > expires):
        raise SystemExit("Proton incident retirement plan binding differs")
    validate_observation(plan.get("host_observation", {}), contract)
    return plan, digest


def authorize(path: Path, *, resume: bool) -> None:
    _, digest = load_plan(path, allow_expired=resume)
    confirmation = f"authorize-proton-incident-retirement-{digest}"
    if os.environ.get("PROTON_INCIDENT_RETIREMENT_AUTHORIZATION_CONFIRMED") != confirmation:
        raise SystemExit(f"exact confirmation required: {confirmation}")
    created = datetime.now(timezone.utc).replace(microsecond=0)
    expires = created + timedelta(minutes=15)
    value = {"format": H.AUTH_FORMAT, "plan_sha256": digest, "created_at": created.isoformat().replace("+00:00", "Z"), "expires_at": expires.isoformat().replace("+00:00", "Z"), "confirmation": confirmation, "authorized": True}
    raw = C.canonical(value)
    auth_digest = C.sha(raw)
    output = OUTPUT / f"authorization-{auth_digest}.json"
    C.write_private(output, raw)
    print(json.dumps({"plan_sha256": digest, "authorization_sha256": auth_digest, "path": str(output), "expires_at": value["expires_at"]}, sort_keys=True))


def apply(path: Path, authorization_path: Path) -> None:
    _, digest = load_plan(path, allow_expired=True)
    authorization, auth_raw = C.load_private(authorization_path)
    auth_digest = C.sha(auth_raw)
    try:
        auth_expires = datetime.fromisoformat(authorization["expires_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("Proton incident retirement authorization time differs") from error
    expected = {"format": H.AUTH_FORMAT, "plan_sha256": digest, "created_at": authorization.get("created_at"), "expires_at": authorization.get("expires_at"), "confirmation": f"authorize-proton-incident-retirement-{digest}", "authorized": True}
    if authorization != expected or datetime.now(timezone.utc) > auth_expires:
        raise SystemExit("fresh Proton incident retirement authorization required")
    receipt_path = OUTPUT / f"receipt-{digest}.json"
    if receipt_path.exists():
        receipt_path.unlink()
    run_playbook({"proton_incident_retirement_operation": "apply", "proton_incident_retirement_expected_helper_sha256": C.sha(HELPER.read_bytes()), "proton_incident_retirement_plan_sha256": digest, "proton_incident_retirement_authorization_sha256": auth_digest, "proton_incident_retirement_confirmation": f"retire-proton-incident-artifacts-{digest}-{auth_digest}", "proton_incident_retirement_contract_sha256": C.sha(C.CONTRACT.read_bytes()), "proton_incident_retirement_plan_source": str(path), "proton_incident_retirement_authorization_source": str(authorization_path), "proton_incident_retirement_promotion_source": str(PROMOTION), "proton_incident_retirement_recovery_source": str(RECOVERY), "proton_incident_retirement_recovery_journal_source": str(RECOVERY_JOURNAL), "proton_incident_retirement_controller_output": str(receipt_path)})
    receipt, raw = C.load_private(receipt_path)
    if receipt.get("format") != H.RECEIPT_FORMAT or receipt.get("status") != "committed" or receipt.get("plan_sha256") != digest or C.HEX.fullmatch(str(receipt.get("authorization_sha256", ""))) is None or receipt.get("after", {}).get("damaged_v2") != {"present": False} or receipt.get("after", {}).get("diagnostic_fixtures", {}).get("present") is not False or receipt.get("canonical", {}).get("repository_id") != H.CANONICAL_ID or receipt.get("canonical", {}).get("full_read_data_check") != "zero-errors" or receipt.get("empty_trash") is not False or receipt.get("permanent_delete") is not False:
        raise SystemExit("Proton incident retirement receipt differs")
    print(json.dumps({"status": "committed", "plan_sha256": digest, "receipt_sha256": C.sha(raw), "path": str(receipt_path)}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("install")
    commands.add_parser("plan")
    auth = commands.add_parser("authorize")
    auth.add_argument("plan", type=Path)
    auth.add_argument("--resume", action="store_true")
    execute = commands.add_parser("apply")
    execute.add_argument("plan", type=Path)
    execute.add_argument("authorization", type=Path)
    args = parser.parse_args()
    if args.command == "install":
        install()
    elif args.command == "plan":
        create_plan()
    elif args.command == "authorize":
        authorize(args.plan.resolve(), resume=args.resume)
    else:
        apply(args.plan.resolve(), args.authorization.resolve())


if __name__ == "__main__":
    main()
