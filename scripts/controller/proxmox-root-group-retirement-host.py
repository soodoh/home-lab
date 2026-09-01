#!/usr/bin/env python3
"""Execute the exact root/apex membership retirement from a physical Proxmox console."""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import grp
import re
import stat
import subprocess

REPO = Path("/root/home-lab")
BASE_SOURCE = Path(__file__).with_name("proxmox-tofu-identity-retirement-host.py")
if not BASE_SOURCE.exists():
    BASE_SOURCE = REPO / "scripts/controller/proxmox-tofu-identity-retirement-host.py"
SPEC = importlib.util.spec_from_file_location("tofu_retirement_base", BASE_SOURCE)
BASE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(BASE)

CONTRACT = REPO / "infrastructure/contract/home-lab.yml"
INVENTORY = REPO / "ansible/inventory/production.yml"
JOURNAL_ROOT = Path("/var/lib/home-lab/root-group-retirement")
LOCK = Path("/run/lock/home-lab-root-group-retirement.lock")
WATCHDOG_SECONDS = 900
FINGERPRINT = "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ"
TARGET_GROUP = "apex"
DATABASE_PATHS = ("/etc/group", "/etc/gshadow")
PROTECTED_LOCKS = (
    "/var/lib/iac-ansible-production.lock", "/var/lock/home-lab-compose.lock",
    "/run/lock/home-lab-restic-backup.lock", "/run/lock/home-lab-apt.lock", "/run/lock/home-lab-pve-firewall.lock",
)
EXPECTED_RETAINED = {
    "/root/.ssh/authorized_keys", "/etc/pve/priv/authorized_keys", "/root/.config/home-lab/proxmox-plan-token.env",
    "/root/.config/home-lab/proxmox-apply-token.env", "/home/firewall-apply/.ssh/authorized_keys",
    "/etc/sudoers.d/firewall-apply", "/usr/local/libexec/home-lab/proxmox-firewall-transport",
    "/usr/local/libexec/home-lab/proxmox-private-preparer", "/usr/local/libexec/home-lab/proxmox-activator",
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/60-home-lab.conf",
}
EXPECTED_TOKENS = [{"privsep": 1, "tokenid": "tofu-apply"}, {"privsep": 1, "tokenid": "tofu-plan"}]
EXPECTED_EXCLUSIONS = {"delete_apex_group": False, "delete_root_account": False, "root_authorized_keys": True,
                       "openssh_policy": True, "pve_api_tokens": ["tofu-plan", "tofu-apply"],
                       "firewall_recovery": True, "tofu_ssh_identities": "already-retired"}
EXPECTED_RETAINED_METADATA = {
    "/root/.ssh/authorized_keys": {"uid": 0, "gid": 0, "mode": "0777", "regular": False, "symlink": True, "nlink": 1, "symlink_target": "/etc/pve/priv/authorized_keys"},
    "/etc/pve/priv/authorized_keys": {"uid": 0, "gid": 33, "mode": "0600", "regular": True, "symlink": False, "nlink": 1},
    "/root/.config/home-lab/proxmox-plan-token.env": {"uid": 0, "gid": 0, "mode": "0600", "regular": True, "symlink": False, "nlink": 1},
    "/root/.config/home-lab/proxmox-apply-token.env": {"uid": 0, "gid": 0, "mode": "0600", "regular": True, "symlink": False, "nlink": 1},
    "/home/firewall-apply/.ssh/authorized_keys": {"uid": 1003, "gid": 1004, "mode": "0600", "regular": True, "symlink": False, "nlink": 1},
    "/etc/sudoers.d/firewall-apply": {"uid": 0, "gid": 0, "mode": "0440", "regular": True, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-firewall-transport": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-private-preparer": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "symlink": False, "nlink": 1},
    "/usr/local/libexec/home-lab/proxmox-activator": {"uid": 0, "gid": 0, "mode": "0755", "regular": True, "symlink": False, "nlink": 1},
    "/etc/ssh/sshd_config": {"uid": 0, "gid": 0, "mode": "0644", "regular": True, "symlink": False, "nlink": 1},
    "/etc/ssh/sshd_config.d/60-home-lab.conf": {"uid": 0, "gid": 0, "mode": "0644", "regular": True, "symlink": False, "nlink": 1},
}

canonical = BASE.canonical
sha = BASE.sha
write_private = BASE.write_private
replace_private = BASE.replace_private
load_private = BASE.load_private
metadata = BASE.metadata
require_root_console = BASE.require_root_console
access_state = BASE.access_state
access_proofs_complete = BASE.access_proofs_complete


def retained_metadata(path: str) -> dict:
    value = metadata(path)
    if value.get("symlink") is True: value["symlink_target"] = os.readlink(path)
    return value


def retained_metadata_valid(paths: dict) -> bool:
    if set(paths) != set(EXPECTED_RETAINED_METADATA): return False
    return all(paths[path].get("exists") is True and all(paths[path].get(key) == expected for key, expected in metadata_expected.items()) and (not metadata_expected["regular"] or isinstance(paths[path].get("sha256"), str)) for path, metadata_expected in EXPECTED_RETAINED_METADATA.items())


def acquire_lock(*, blocking: bool = False) -> int:
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_nlink != 1:
        os.close(descriptor); raise SystemExit("root group retirement lock metadata differs")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor); raise SystemExit("root group retirement lock is active") from error
    return descriptor


def reject_protected_locks() -> None:
    if any(os.path.lexists(path) for path in PROTECTED_LOCKS):
        raise SystemExit("a protected lifecycle lock is active")


def root_group_state() -> dict:
    root = pwd.getpwnam("root"); apex = grp.getgrnam(TARGET_GROUP)
    return {"root_groups": sorted(grp.getgrgid(gid).gr_name for gid in os.getgrouplist("root", root.pw_gid)),
            "apex": {"exists": True, "gid": apex.gr_gid, "members": sorted(apex.gr_mem)}}


def database_records() -> dict[str, str]:
    records = {}
    for path in DATABASE_PATHS:
        matches = [line for line in Path(path).read_text().splitlines() if line.split(":", 1)[0] == TARGET_GROUP]
        if len(matches) != 1:
            raise SystemExit("exact apex database record is unavailable")
        records[path] = matches[0]
    return records


def remove_member(line: str, member: str) -> str:
    fields = line.split(":")
    if len(fields) != 4 or fields[0] != TARGET_GROUP: raise SystemExit("apex database record is malformed")
    fields[3] = ",".join(value for value in fields[3].split(",") if value and value != member)
    return ":".join(fields)


def database_state() -> dict:
    return {path: {"line": line, "sha256": sha((line + "\n").encode())} for path, line in database_records().items()}


def logical_after(plan: dict) -> dict:
    return {"root_groups": plan["after"]["root_groups"], "apex": plan["after"]["apex"]}


def postcondition_matches(plan: dict) -> bool:
    return root_group_state() == logical_after(plan) and database_state() == plan["after"]["database_records"] and subprocess.run(("/usr/sbin/grpck", "-r"), capture_output=True).returncode == 0


def before_matches(plan: dict) -> bool:
    records = database_records()
    database_before = {path: {"count": 1, "line": line, "sha256": sha((line + "\n").encode())} for path, line in records.items()}
    retained = {item: retained_metadata(item) for item in plan["retained_assets_before"]}
    return root_group_state() == {"root_groups": plan["before"]["root_groups"], "apex": plan["before"]["apex"]} and database_before == plan["before"]["database_records"] and retained_metadata_valid(retained) and retained == plan["retained_assets_before"] and pve_tokens() == EXPECTED_TOKENS == plan["retained_pve_tokens"]


def restore_database_records(records: dict[str, str]) -> None:
    if set(records) != set(DATABASE_PATHS):
        raise SystemExit("apex rollback records are incomplete")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.lckpwdf() != 0:
        raise SystemExit("could not lock group databases")
    try:
        for path in DATABASE_PATHS:
            target = Path(path); info = target.stat(); lines = target.read_text().splitlines()
            retained = [line for line in lines if line.split(":", 1)[0] != TARGET_GROUP]
            raw = ("\n".join([*retained, records[path]]) + "\n").encode()
            temporary = target.with_name(f".{target.name}.root-group-{os.getpid()}")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IMODE(info.st_mode))
            with os.fdopen(descriptor, "wb") as handle:
                os.fchown(handle.fileno(), info.st_uid, info.st_gid); os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, target)
        directory = os.open("/etc", os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        libc.ulckpwdf()


def pve_tokens() -> list[dict]:
    raw = subprocess.check_output(("/usr/sbin/pveum", "user", "token", "list", "root@pam", "--output-format", "json"), text=True)
    return sorted(({"tokenid": item["tokenid"], "privsep": item["privsep"]} for item in json.loads(raw)), key=lambda item: item["tokenid"])


def validate_plan(path: Path) -> tuple[dict, bytes, str]:
    plan, raw = load_private(path); digest = sha(raw)
    if path.name != f"root-apex-{digest}.json" or plan.get("format") != "home-lab-proxmox-root-group-retirement-plan-v1" or plan.get("authorized") is not False:
        raise SystemExit("root group retirement plan filename or format differs")
    commit = subprocess.check_output(("/usr/bin/git", "-C", str(REPO), "rev-parse", "HEAD"), text=True).strip()
    contract_raw = CONTRACT.read_bytes()
    if plan.get("commit") != commit or plan.get("contract_sha256") != sha(contract_raw) or plan.get("inventory_sha256") != sha(INVENTORY.read_bytes()) or plan.get("host_key_fingerprint") != FINGERPRINT or access_state(contract_raw) != "ready" or plan.get("access_cutover_state") != "ready":
        raise SystemExit("root group retirement source binding differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("root group retirement plan expired")
    if plan.get("target_group") != TARGET_GROUP or plan.get("before", {}).get("root_groups") != ["apex", "root"] or plan["before"].get("apex") != {"exists": True, "gid": 1000, "members": ["root"]} or plan.get("after", {}).get("root_groups") != ["root"] or plan["after"].get("apex") != {"exists": True, "gid": 1000, "members": []}:
        raise SystemExit("root group retirement boundary differs")
    if root_group_state() != {"root_groups": plan["before"]["root_groups"], "apex": plan["before"]["apex"]}:
        raise SystemExit("root/apex state changed after planning")
    observed_records = database_records()
    if any(plan["before"]["database_records"].get(path) != {"count": 1, "line": observed_records[path], "sha256": sha((observed_records[path] + "\n").encode())} for path in DATABASE_PATHS):
        raise SystemExit("apex database records changed after planning")
    expected_after_records = {path: {"line": remove_member(line, "root")} for path, line in observed_records.items()}
    for item in expected_after_records.values(): item["sha256"] = sha((item["line"] + "\n").encode())
    if plan["after"].get("database_records") != expected_after_records:
        raise SystemExit("apex database postcondition differs")
    if set(plan.get("retained_assets_before", {})) != EXPECTED_RETAINED or plan.get("retained_pve_tokens") != EXPECTED_TOKENS or plan.get("explicit_exclusions") != EXPECTED_EXCLUSIONS:
        raise SystemExit("root group retained-authority allowlist differs")
    retained = {item: retained_metadata(item) for item in plan["retained_assets_before"]}
    if not retained_metadata_valid(retained) or retained != plan["retained_assets_before"] or pve_tokens() != plan["retained_pve_tokens"]:
        raise SystemExit("retained access authority changed after planning")
    return plan, raw, digest


def validate_approval(plan: dict, digest: str, evidence_path: Path, authorization_path: Path) -> None:
    evidence, evidence_raw = load_private(evidence_path); evidence_digest = sha(evidence_raw); authorization, _ = load_private(authorization_path)
    now = datetime.now(timezone.utc)
    if evidence.get("format") != "home-lab-proxmox-access-evidence-v1" or evidence.get("commit") != plan["commit"] or evidence.get("contract_sha256") != plan["contract_sha256"] or evidence.get("inventory_sha256") != plan["inventory_sha256"] or evidence.get("host_key_fingerprint") != FINGERPRINT or not access_proofs_complete(evidence) or now > datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("fresh complete console evidence differs")
    requirements = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
    expected = {"format": "home-lab-proxmox-root-group-retirement-authorization-v1", "authorized": True,
                "plan_sha256": digest, "console_evidence_sha256": evidence_digest, "commit": plan["commit"],
                "contract_sha256": plan["contract_sha256"], "inventory_sha256": plan["inventory_sha256"],
                "host_key_fingerprint": FINGERPRINT, "authorized_at": authorization.get("authorized_at"),
                "expires_at": authorization.get("expires_at"), "accepted_requirements": requirements}
    if plan.get("blockers") != requirements or authorization != expected or now > datetime.fromisoformat(authorization["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("root group retirement authorization differs")


def ensure_journal(path: Path) -> None:
    parent = JOURNAL_ROOT.parent; info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
        raise SystemExit("journal parent differs")
    if JOURNAL_ROOT.exists():
        info = JOURNAL_ROOT.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != 0:
            raise SystemExit("journal root differs")
    else:
        JOURNAL_ROOT.mkdir(mode=0o700)
    path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != 0:
        raise SystemExit("journal directory differs")


def state(journal: Path) -> dict:
    value, _ = load_private(journal / "state.json"); return value


def set_state(journal: Path, value: dict) -> None:
    replace_private(journal / "state.json", canonical(value))


def capture(journal: Path, plan: dict, plan_raw: bytes, digest: str) -> None:
    ensure_journal(journal); records = database_records()
    write_private(journal / "plan.json", plan_raw)
    before = {"format": "home-lab-proxmox-root-group-rollback-v1", "plan_sha256": digest,
              "database_records": records, "root_group_state": root_group_state()}
    before_raw = canonical(before); write_private(journal / "before.json", before_raw)
    source = Path(__file__).read_bytes(); base = BASE_SOURCE.read_bytes()
    write_private(journal / "rollback-executor.py", source); os.chmod(journal / "rollback-executor.py", 0o700)
    write_private(journal / "proxmox-tofu-identity-retirement-host.py", base); os.chmod(journal / "proxmox-tofu-identity-retirement-host.py", 0o700)
    set_state(journal, {"status": "prepared", "plan_sha256": digest, "before_sha256": sha(before_raw)})
    for item in (journal, JOURNAL_ROOT, JOURNAL_ROOT.parent):
        descriptor = os.open(item, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)


def unit_name(digest: str) -> str:
    return f"home-lab-root-group-{digest[:16]}"


def arm(journal: Path, digest: str) -> None:
    unit = unit_name(digest); service = Path(f"/etc/systemd/system/{unit}.service"); timer = Path(f"/etc/systemd/system/{unit}.timer")
    service_raw = f"[Unit]\nDescription=Rollback uncommitted root group retirement\nAfter=local-fs.target\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {journal}/rollback-executor.py rollback {journal}\n".encode()
    timer_raw = f"[Unit]\nDescription=Watchdog for root group retirement\n\n[Timer]\nOnActiveSec={WATCHDOG_SECONDS}s\nUnit={unit}.service\n\n[Install]\nWantedBy=timers.target\n".encode()
    for path, raw in ((service, service_raw), (timer, timer_raw)):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), check=True, capture_output=True)
    subprocess.run(("/usr/bin/systemctl", "enable", "--now", f"{unit}.timer"), check=True, capture_output=True)


def disarm(digest: str, *, stop_service: bool = True) -> None:
    unit = unit_name(digest); subprocess.run(("/usr/bin/systemctl", "disable", "--now", f"{unit}.timer"), capture_output=True)
    if stop_service: subprocess.run(("/usr/bin/systemctl", "stop", f"{unit}.service"), capture_output=True)
    for suffix in ("service", "timer"): Path(f"/etc/systemd/system/{unit}.{suffix}").unlink(missing_ok=True)
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), capture_output=True)


def restore_from_journal(journal: Path, current: dict) -> None:
    before, before_raw = load_private(journal / "before.json"); plan, _ = load_private(journal / "plan.json")
    if sha(before_raw) != current.get("before_sha256"): raise SystemExit("rollback bundle digest differs")
    restore_database_records(before["database_records"])
    if root_group_state() != before["root_group_state"] or database_records() != before["database_records"]:
        raise SystemExit("root group rollback differs")
    if subprocess.run(("/usr/sbin/grpck", "-r"), capture_output=True).returncode:
        raise SystemExit("group database validation failed after rollback")
    retained = {item: retained_metadata(item) for item in plan["retained_assets_before"]}
    if not retained_metadata_valid(retained) or retained != plan["retained_assets_before"] or pve_tokens() != EXPECTED_TOKENS or plan["retained_pve_tokens"] != EXPECTED_TOKENS:
        raise SystemExit("retained authority changed during rollback")


def rollback(journal: Path) -> None:
    if os.geteuid() != 0: raise SystemExit("rollback requires root")
    descriptor = acquire_lock(blocking=True)
    try:
        current = state(journal)
        if current.get("status") in {"committed", "rolled-back"}:
            disarm(current["plan_sha256"], stop_service=False); return
        if current.get("status") not in {"prepared", "mutation-started", "awaiting-canary"}:
            raise SystemExit("journal state cannot be rolled back")
        restore_from_journal(journal, current)
        set_state(journal, {**current, "status": "rolled-back", "rolled_back_at": datetime.now(timezone.utc).isoformat()})
        disarm(current["plan_sha256"], stop_service=False)
    finally: os.close(descriptor)


def apply(plan_path: Path, evidence_path: Path, authorization_path: Path) -> None:
    require_root_console(); descriptor = acquire_lock(); journal = None; digest = ""
    try:
        reject_protected_locks(); plan, raw, digest = validate_plan(plan_path); validate_approval(plan, digest, evidence_path, authorization_path)
        expected = f"apply-proxmox-root-apex-retirement-{digest}"
        if os.environ.get("PROXMOX_ROOT_GROUP_RETIREMENT_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
        journal = JOURNAL_ROOT / digest; capture(journal, plan, raw, digest)
        reject_protected_locks()
        if not before_matches(plan): raise SystemExit("root group preconditions changed before mutation")
        arm(journal, digest)
        set_state(journal, {**state(journal), "status": "mutation-started", "mutation_started_at": datetime.now(timezone.utc).isoformat()})
        try:
            result = subprocess.run(("/usr/bin/gpasswd", "--delete", "root", TARGET_GROUP), capture_output=True, text=True)
            if result.returncode or not postcondition_matches(plan): raise RuntimeError("root/apex mutation differs")
            retained = {item: retained_metadata(item) for item in plan["retained_assets_before"]}
            if not retained_metadata_valid(retained) or retained != plan["retained_assets_before"] or pve_tokens() != EXPECTED_TOKENS or plan["retained_pve_tokens"] != EXPECTED_TOKENS: raise RuntimeError("retained authority changed")
            set_state(journal, {**state(journal), "status": "awaiting-canary", "mutated_at": datetime.now(timezone.utc).isoformat(), "watchdog_seconds": WATCHDOG_SECONDS})
        except Exception:
            current = state(journal); restore_from_journal(journal, current)
            set_state(journal, {**current, "status": "rolled-back", "rolled_back_at": datetime.now(timezone.utc).isoformat()})
            disarm(digest); raise
    finally: os.close(descriptor)
    print(json.dumps({"status": "awaiting-canary", "journal": str(journal), "plan_sha256": digest, "watchdog_seconds": WATCHDOG_SECONDS}, sort_keys=True))


def validate_canary(receipt: dict, digest: str) -> None:
    required = {"ansible_plan", "ansible_deploy", "firewall_apply", "human_tailscale", "root_group_state", "retained_assets", "pve_tokens"}
    if receipt.get("format") != "home-lab-proxmox-root-group-canary-v1" or receipt.get("plan_sha256") != digest or set(receipt.get("checks", {})) != required or not all(receipt["checks"].values()):
        raise SystemExit("root group canary differs")
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(receipt["captured_at"].replace("Z", "+00:00"))).total_seconds()
    if age < 0 or age > 300: raise SystemExit("root group canary is stale")


def commit(journal: Path, canary_path: Path) -> None:
    require_root_console(); descriptor = acquire_lock()
    try:
        current = state(journal)
        if current.get("status") != "awaiting-canary": raise SystemExit("journal is not awaiting canary")
        plan, raw = load_private(journal / "plan.json"); digest = sha(raw); canary, canary_raw = load_private(canary_path); validate_canary(canary, digest)
        expected = f"commit-proxmox-root-apex-retirement-{digest}-{sha(canary_raw)}"
        if os.environ.get("PROXMOX_ROOT_GROUP_RETIREMENT_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
        retained = {item: retained_metadata(item) for item in plan["retained_assets_before"]}
        if not postcondition_matches(plan) or not retained_metadata_valid(retained) or retained != plan["retained_assets_before"] or pve_tokens() != EXPECTED_TOKENS or plan["retained_pve_tokens"] != EXPECTED_TOKENS:
            raise SystemExit("root group state changed before commit")
        write_private(journal / "canary.json", canary_raw)
        committed = {**current, "format": "home-lab-proxmox-root-group-retirement-receipt-v1", "status": "committed",
                     "canary_sha256": sha(canary_raw), "committed_at": datetime.now(timezone.utc).isoformat()}
        write_private(journal / "receipt.json", canonical(committed)); set_state(journal, committed); disarm(digest)
    finally: os.close(descriptor)
    print(json.dumps({"status": "committed", "plan_sha256": digest, "receipt": str(journal / "receipt.json")}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    apply_parser = commands.add_parser("apply"); apply_parser.add_argument("plan", type=Path); apply_parser.add_argument("evidence", type=Path); apply_parser.add_argument("authorization", type=Path)
    rollback_parser = commands.add_parser("rollback"); rollback_parser.add_argument("journal", type=Path)
    commit_parser = commands.add_parser("commit"); commit_parser.add_argument("journal", type=Path); commit_parser.add_argument("canary", type=Path)
    args = parser.parse_args()
    if args.command == "apply": apply(args.plan.resolve(), args.evidence.resolve(), args.authorization.resolve())
    elif args.command == "rollback": rollback(args.journal.resolve())
    else: commit(args.journal.resolve(), args.canary.resolve())


if __name__ == "__main__":
    main()
