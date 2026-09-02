#!/usr/bin/env python3
"""Plan, authorize, and apply exact deletion of the damaged Proton Restic v1 repository."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
INVENTORY = ROOT / "ansible/inventory/production.yml"
PLAYBOOK = ROOT / "ansible/playbooks/proton-v1-cleanup.yml"
HELPER = ROOT / "scripts/cleanup-damaged-proton-restic-v1"
OUTPUT = ROOT / ".local/proton-v1-cleanup"
RECOVERY_COMMIT = "e6e4a2f5fd0613e703d36c0a53c95f80c741608c"
RECOVERY = ROOT / f".reconcile/restic-recovery-vm/{RECOVERY_COMMIT}/run-evidence.json"
RECOVERY_JOURNAL = RECOVERY.parent / "journal.json"
RECOVERY_SHA256 = "82537efde96231435da520e0f0dc472f1808e0c24dad0fef8b7b659c6c2ba1cc"
RECOVERY_JOURNAL_SHA256 = "6ec32081ddd4283cec6329695daf74670d83ac0fbecd7cb95f437cd81b0a6a15"
OLD_REMOTE = "proton-backup:Backups/home-lab-restic"
OLD_ID = "d1faa9cd772dd13275b8d4db376c2bbba0b82a9415a28b0d03a8b17e37b7fb7e"
NEW_ID = "98d792c009c01e06b8b39aab5112f0392050e9c533d1882e9c0d87727884ea25"
NEW_SNAPSHOT = "e0ac47b09716b3a1632a9fce21ada5f53b82980ecce6723fa7a682b9117fc139"
ORIGINAL_SNAPSHOT = "edd4f507cec382e6fae48e2690ffa53ae7ef7a61e24581983975631cbe5a32e2"
PLAN_FORMAT = "home-lab-proton-v1-cleanup-plan-v1"
AUTH_FORMAT = "home-lab-proton-v1-cleanup-authorization-v1"
RECEIPT_FORMAT = "home-lab-proton-v1-cleanup-receipt-v1"
HEX = re.compile(r"^[0-9a-f]{64}$")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()



def cleanup_action() -> dict:
    return {
        "kind": "purge-exact-damaged-proton-v1",
        "remote": OLD_REMOTE,
        "repository_id": OLD_ID,
        "provider_effect": "move-exact-directory-to-proton-trash",
        "permanent_delete": False,
    }


def write_private(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fchmod(handle.fileno(), 0o600)
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load_private(path: Path) -> tuple[dict, bytes]:
    info = path.lstat()
    raw = path.read_bytes()
    value = json.loads(raw)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or raw != canonical(value)
    ):
        raise SystemExit(f"protected artifact differs: {path}")
    return value, raw


def clean_pushed_commit() -> str:
    if subprocess.run(["git", "diff", "--quiet"], cwd=ROOT).returncode or subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT).returncode:
        raise SystemExit("clean committed HEAD required")
    if subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, capture_output=True, text=True, check=True).stdout:
        raise SystemExit("clean committed HEAD required")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    remote = subprocess.run(["git", "rev-parse", "origin/main"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    if commit != remote:
        raise SystemExit("pushed main HEAD required")
    return commit


def contract_policy() -> tuple[dict, bytes]:
    raw = CONTRACT.read_bytes()
    parsed = subprocess.run(
        [
            "node",
            "-e",
            "const fs=require('node:fs'),yaml=require('js-yaml');const c=yaml.load(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(JSON.stringify(c.backups.restic));",
            str(CONTRACT),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    value = {"backups": {"restic": json.loads(parsed.stdout)}}
    repository = value["backups"]["restic"]["repositories"]["proton"]
    if repository != {
        "path": "rclone:proton-backup:Backups/home-lab-restic-v2",
        "id": NEW_ID,
        "remote": "proton-backup",
        "remote_path": "Backups/home-lab-restic-v2",
        "account_ref": "dedicated-proton-family-backup-member",
        "minimum_allocated_bytes": 1000000000000,
        "password": "proton",
        "copy_chunker_params_from": "games",
        "recovery_snapshot_id": NEW_SNAPSHOT,
        "recovery_original_snapshot_id": ORIGINAL_SNAPSHOT,
        "damaged_predecessor": {"path": "rclone:proton-backup:Backups/home-lab-restic", "id": OLD_ID},
    }:
        raise SystemExit("contract Proton repository boundary differs")
    return value, raw


def recovery_proof() -> None:
    evidence, raw = load_private(RECOVERY)
    journal, journal_raw = load_private(RECOVERY_JOURNAL)
    restore = evidence.get("restore", {})
    if (
        sha(raw) != RECOVERY_SHA256
        or evidence.get("state") != "restored-verified"
        or evidence.get("vmid") != 9900
        or restore.get("state") != "restored-verified"
        or restore.get("repository_id") != NEW_ID
        or restore.get("snapshot_id") != NEW_SNAPSHOT
        or restore.get("original_snapshot_id") != ORIGINAL_SNAPSHOT
        or evidence.get("service_validation", {}).get("state") != "validated"
        or sha(journal_raw) != RECOVERY_JOURNAL_SHA256
        or journal.get("state") != "destroy-applied"
        or journal.get("commit") != RECOVERY_COMMIT
    ):
        raise SystemExit("qualified v2 recovery evidence differs")


def run_playbook(extra: dict) -> None:
    descriptor, name = tempfile.mkstemp(prefix="proton-v1-cleanup-", suffix=".json")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical(extra))
            handle.flush()
            os.fchmod(handle.fileno(), 0o600)
            os.fsync(handle.fileno())
        result = subprocess.run(
            ["ansible-playbook", "-i", str(INVENTORY), str(PLAYBOOK), "--extra-vars", f"@{name}"],
            cwd=ROOT / "ansible",
            timeout=10800,
        )
        if result.returncode:
            raise SystemExit("Proton v1 cleanup playbook failed")
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def observe_host() -> dict:
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(OUTPUT, 0o700)
    descriptor, name = tempfile.mkstemp(prefix="proton-v1-observation-", suffix=".json", dir=OUTPUT)
    os.close(descriptor)
    os.unlink(name)
    path = Path(name)
    try:
        run_playbook({
            "proton_v1_cleanup_operation": "observe",
            "proton_v1_cleanup_expected_helper_sha256": sha(HELPER.read_bytes()),
            "proton_v1_cleanup_controller_output": str(path),
        })
        observed, _ = load_private(path)
        return observed
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def validate_observation(observed: dict, contract: dict) -> bool:
    expected_keys = {"format", "helper_sha256", "runner_sha256", "policy_sha256", "parent_directories", "damaged", "replacement", "migration"}
    if (
        set(observed) != expected_keys
        or observed.get("format") != "home-lab-proton-v1-cleanup-observation-v1"
        or observed.get("helper_sha256") != sha(HELPER.read_bytes())
        or observed.get("runner_sha256") != contract["backups"]["restic"]["runner"]["sha256"]
        or HEX.fullmatch(observed.get("policy_sha256", "")) is None
        or observed.get("replacement") != {"repository_id": NEW_ID, "snapshot_id": NEW_SNAPSHOT, "original_snapshot_id": ORIGINAL_SNAPSHOT}
        or observed.get("migration") != {"sha256": "3213ceff96d067da22c5b243a213f39a00e7f9cce74905fc53c5d5229ac1f4a5", "full_read_data_check": True}
    ):
        raise SystemExit("host Proton cleanup observation differs")
    damaged = observed["damaged"]
    if damaged == {"present": False}:
        if observed["parent_directories"] != ["home-lab-restic-v2/"]:
            raise SystemExit("post-cleanup parent boundary differs")
        return False
    if (
        observed["parent_directories"] != ["home-lab-restic-v2/", "home-lab-restic/"]
        or set(damaged) != {"present", "repository_id", "bytes", "objects", "sizeless", "inventory_sha256"}
        or damaged.get("present") is not True
        or damaged.get("repository_id") != OLD_ID
        or not isinstance(damaged.get("bytes"), int)
        or damaged["bytes"] <= 0
        or not isinstance(damaged.get("objects"), int)
        or damaged["objects"] <= 0
        or not isinstance(damaged.get("sizeless"), int)
        or damaged["sizeless"] < 0
        or HEX.fullmatch(damaged.get("inventory_sha256", "")) is None
    ):
        raise SystemExit("damaged Proton repository inventory differs")
    return True


def create_plan() -> None:
    commit = clean_pushed_commit()
    contract, contract_raw = contract_policy()
    recovery_proof()
    observed = observe_host()
    present = validate_observation(observed, contract)
    created = datetime.now(timezone.utc).replace(microsecond=0)
    plan = {
        "format": PLAN_FORMAT,
        "commit": commit,
        "contract_sha256": sha(contract_raw),
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "expires_at": (created + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        "host_observation": observed,
        "recovery_evidence_sha256": RECOVERY_SHA256,
        "recovery_journal_sha256": RECOVERY_JOURNAL_SHA256,
        "action": cleanup_action() if present else None,
        "blockers": ["irreversible-deletion-acknowledgement-required", "separate-authorization-required"] if present else [],
        "authorized": False,
    }
    raw = canonical(plan)
    digest = sha(raw)
    path = OUTPUT / f"proton-v1-cleanup-{digest}.json"
    write_private(path, raw)
    print(json.dumps({"plan_sha256": digest, "path": str(path), "action": plan["action"], "blockers": plan["blockers"]}, sort_keys=True))


def load_plan(path: Path, *, allow_expired: bool = False) -> tuple[dict, bytes, str]:
    plan, raw = load_private(path)
    digest = sha(raw)
    try:
        expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit("cleanup plan timestamp differs") from error
    if (
        plan.get("format") != PLAN_FORMAT
        or path.name != f"proton-v1-cleanup-{digest}.json"
        or plan.get("commit") != clean_pushed_commit()
        or plan.get("contract_sha256") != sha(CONTRACT.read_bytes())
        or (not allow_expired and datetime.now(timezone.utc) > expires)
    ):
        raise SystemExit("cleanup plan binding differs")
    contract, _ = contract_policy()
    validate_observation(plan.get("host_observation", {}), contract)
    return plan, raw, digest


def authorize(path: Path) -> None:
    plan, _, digest = load_plan(path)
    recovery_proof()
    if plan.get("action") != cleanup_action() or plan.get("blockers") != ["irreversible-deletion-acknowledgement-required", "separate-authorization-required"] or plan.get("authorized") is not False:
        raise SystemExit("cleanup plan is not authorization eligible")
    confirmation = f"authorize-proton-v1-cleanup-{digest}"
    if os.environ.get("PROTON_V1_CLEANUP_AUTHORIZATION_CONFIRMED") != confirmation:
        raise SystemExit(f"exact confirmation required: {confirmation}")
    created = datetime.now(timezone.utc).replace(microsecond=0)
    plan_expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    expires = min(created + timedelta(minutes=15), plan_expires)
    authorization = {
        "format": AUTH_FORMAT,
        "plan_sha256": digest,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "confirmation": confirmation,
        "authorized": True,
    }
    raw = canonical(authorization)
    auth_digest = sha(raw)
    output = OUTPUT / f"authorization-{auth_digest}.json"
    write_private(output, raw)
    print(json.dumps({"plan_sha256": digest, "authorization_sha256": auth_digest, "path": str(output), "expires_at": authorization["expires_at"]}, sort_keys=True))


def apply(path: Path, authorization_path: Path) -> None:
    plan, _, digest = load_plan(path, allow_expired=True)
    authorization, authorization_raw = load_private(authorization_path)
    auth_digest = sha(authorization_raw)
    expected = {
        "format": AUTH_FORMAT,
        "plan_sha256": digest,
        "created_at": authorization.get("created_at"),
        "expires_at": authorization.get("expires_at"),
        "confirmation": f"authorize-proton-v1-cleanup-{digest}",
        "authorized": True,
    }
    if authorization != expected:
        raise SystemExit("cleanup authorization differs")
    recovery_proof()
    receipt_path = OUTPUT / f"receipt-{digest}.json"
    if receipt_path.exists():
        receipt_path.unlink()
    run_playbook({
        "proton_v1_cleanup_operation": "apply",
        "proton_v1_cleanup_expected_helper_sha256": sha(HELPER.read_bytes()),
        "proton_v1_cleanup_plan_sha256": digest,
        "proton_v1_cleanup_authorization_sha256": auth_digest,
        "proton_v1_cleanup_confirmation": f"delete-damaged-proton-v1-{digest}-{auth_digest}",
        "proton_v1_cleanup_plan_source": str(path),
        "proton_v1_cleanup_authorization_source": str(authorization_path),
        "proton_v1_cleanup_recovery_source": str(RECOVERY),
        "proton_v1_cleanup_recovery_journal_source": str(RECOVERY_JOURNAL),
        "proton_v1_cleanup_controller_output": str(receipt_path),
    })
    receipt, raw = load_private(receipt_path)
    if (
        receipt.get("format") != RECEIPT_FORMAT
        or receipt.get("status") != "committed"
        or receipt.get("plan_sha256") != digest
        or receipt.get("authorization_sha256") != auth_digest
        or receipt.get("before") != plan["host_observation"]["damaged"]
        or receipt.get("after") != {"present": False, "parent_directories": ["home-lab-restic-v2/"]}
        or receipt.get("provider_effect") != "moved-exact-directory-to-proton-trash"
        or receipt.get("permanent_delete") is not False
        or receipt.get("space_reclamation") != "blocked-global-trash-scope"
        or receipt.get("replacement_check") != "full-read-data-zero-errors"
        or receipt.get("recovery_evidence_sha256") != RECOVERY_SHA256
        or receipt.get("recovery_journal_sha256") != RECOVERY_JOURNAL_SHA256
    ):
        raise SystemExit("cleanup receipt differs")
    print(json.dumps({"status": "committed", "plan_sha256": digest, "receipt_sha256": sha(raw), "path": str(receipt_path)}, sort_keys=True))


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
