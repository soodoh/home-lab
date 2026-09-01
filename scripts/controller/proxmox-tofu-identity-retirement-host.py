#!/usr/bin/env python3
"""Execute one saved tofu host-identity retirement from a physical Proxmox console."""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shutil
import stat
import subprocess

REPO = Path("/root/home-lab")
CONTRACT = REPO / "infrastructure/contract/home-lab.yml"
INVENTORY = REPO / "ansible/inventory/production.yml"
JOURNAL_ROOT = Path("/var/lib/home-lab/tofu-identity-retirement")
LOCK = Path("/run/lock/home-lab-tofu-identity-retirement.lock")
DATABASE_PATHS = ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow")
WATCHDOG_SECONDS = 900
PROTECTED_LOCKS = (
    "/var/lib/iac-ansible-production.lock", "/var/lock/home-lab-compose.lock",
    "/run/lock/home-lab-restic-backup.lock", "/run/lock/home-lab-apt.lock",
    "/run/lock/home-lab-pve-firewall.lock",
)
EXPECTED_HOST_ASSETS = {
    "tofu-plan": {"/home/tofu-plan", "/home/tofu-plan/.ssh", "/home/tofu-plan/.ssh/authorized_keys", "/etc/sudoers.d/tofu-plan"},
    "tofu-apply": {"/home/tofu-apply", "/home/tofu-apply/.ssh", "/home/tofu-apply/.ssh/authorized_keys", "/etc/sudoers.d/tofu-apply", "/usr/local/libexec/home-lab/proxmox-apply-transport"},
}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()




def write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def replace_private(path: Path, raw: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def load_private(path: Path, expected_uid: int = 0) -> tuple[dict, bytes]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != expected_uid or info.st_nlink != 1 or raw != canonical(value):
        raise SystemExit(f"protected artifact metadata differs: {path}")
    return value, raw


def require_root_console() -> None:
    if os.geteuid() != 0 or os.environ.get("SSH_CONNECTION") or not os.isatty(0) or not os.isatty(1):
        raise SystemExit("retirement must run directly as root from a physical console")
    tty = os.ttyname(0)
    if not re.fullmatch(r"/dev/tty[0-9]+", tty) or os.ttyname(1) != tty:
        raise SystemExit("retirement requires matching physical /dev/ttyN input and output")


def access_state(raw: bytes) -> str:
    text = raw.decode(); section = text.split("      access_cutover:\n", 1)
    if len(section) != 2:
        raise SystemExit("access cutover policy is unavailable")
    match = re.search(r"^        state: (pending|ready|complete)$", section[1].split("      domain_handoffs:\n", 1)[0], re.MULTILINE)
    if not match:
        raise SystemExit("access cutover state is unavailable")
    return match.group(1)


def metadata(path: str) -> dict:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {"exists": False}
    value = {
        "exists": True, "uid": info.st_uid, "gid": info.st_gid,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"), "nlink": info.st_nlink,
        "regular": stat.S_ISREG(info.st_mode), "directory": stat.S_ISDIR(info.st_mode),
        "symlink": stat.S_ISLNK(info.st_mode), "size": info.st_size,
    }
    if value["regular"]:
        with open(path, "rb") as handle:
            value["sha256"] = sha(handle.read())
    if value["directory"]:
        records = []
        for root, directories, files in os.walk(path, topdown=True, followlinks=False):
            directories.sort(); files.sort()
            for name in directories + files:
                item = os.path.join(root, name); item_info = os.lstat(item)
                record = {
                    "path": os.path.relpath(item, path), "uid": item_info.st_uid, "gid": item_info.st_gid,
                    "mode": format(stat.S_IMODE(item_info.st_mode), "04o"), "regular": stat.S_ISREG(item_info.st_mode),
                    "directory": stat.S_ISDIR(item_info.st_mode), "symlink": stat.S_ISLNK(item_info.st_mode), "size": item_info.st_size,
                }
                if record["regular"]:
                    with open(item, "rb") as handle:
                        record["sha256"] = sha(handle.read())
                records.append(record)
        value["tree_sha256"] = sha(canonical(records)); value["tree_entries"] = len(records)
    return value


def account(name: str) -> dict:
    try:
        item = pwd.getpwnam(name)
    except KeyError:
        return {"exists": False}
    status = subprocess.run(("/usr/bin/passwd", "--status", name), capture_output=True, text=True)
    fields = status.stdout.split()
    pids = subprocess.run(("/usr/bin/pgrep", "-u", name), capture_output=True, text=True)
    return {
        "exists": True, "uid": item.pw_uid, "gid": item.pw_gid, "home": item.pw_dir,
        "shell": item.pw_shell, "gecos": item.pw_gecos,
        "groups": sorted(grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name, item.pw_gid)),
        "password_locked": status.returncode == 0 and len(fields) > 1 and fields[1] in {"L", "LK"},
        "active_pids": sorted(int(value) for value in pids.stdout.split()),
    }


def group(name: str) -> dict:
    try:
        item = grp.getgrnam(name)
    except KeyError:
        return {"exists": False}
    return {"exists": True, "gid": item.gr_gid, "members": sorted(item.gr_mem)}


def identity_from_plan(plan: dict) -> str:
    match = re.fullmatch(r"host-(tofu-plan|tofu-apply)-retirement", plan.get("kind", ""))
    if not match or plan.get("scope") != "proxmox-host" or plan.get("sequence") not in {1, 2}:
        raise SystemExit("host retirement plan kind differs")
    return match.group(1)


def current_before(plan: dict, identity: str) -> dict:
    return {
        "account": account(identity), "group": group(identity),
        "assets": {path: metadata(path) for path in plan["before"]["assets"]},
    }


def validate_plan(path: Path) -> tuple[dict, bytes, str, str]:
    plan, raw = load_private(path); digest = sha(raw); identity = identity_from_plan(plan)
    if path.name != f"{plan['sequence']}-{plan['kind']}-{digest}.json" or plan.get("format") != "home-lab-proxmox-tofu-identity-retirement-plan-v1" or plan.get("authorized") is not False:
        raise SystemExit("host retirement plan filename or format differs")
    if plan.get("commit") != subprocess.check_output(("/usr/bin/git", "-C", str(REPO), "rev-parse", "HEAD"), text=True).strip():
        raise SystemExit("host retirement plan commit differs")
    contract_raw = CONTRACT.read_bytes()
    if plan.get("contract_sha256") != sha(contract_raw) or plan.get("inventory_sha256") != sha(INVENTORY.read_bytes()) or plan.get("host_key_fingerprint") != "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ" or access_state(contract_raw) != "ready" or plan.get("access_cutover_state") != "ready":
        raise SystemExit("host retirement lifecycle binding is not ready")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("host retirement plan expired")
    expected_exclusions = {
        "pve_api_identities": ["root@pam!tofu-plan", "root@pam!tofu-apply"],
        "protected_token_escrows": ["/root/.config/home-lab/proxmox-plan-token.env", "/root/.config/home-lab/proxmox-apply-token.env"],
        "root_authorized_keys": "/root/.ssh/authorized_keys", "firewall_recovery": True,
        "openssh_policy": True, "unrelated_accounts_and_groups": True,
    }
    if plan.get("explicit_exclusions") != expected_exclusions:
        raise SystemExit("host retirement exclusions differ")
    expected_assets = EXPECTED_HOST_ASSETS[identity]
    expected_shell = "/bin/bash" if identity == "tofu-plan" else "/usr/local/libexec/home-lab/proxmox-apply-transport"
    before = plan.get("before", {}); after = plan.get("after", {})
    if set(before.get("assets", {})) != expected_assets or set(after.get("assets", {})) != expected_assets or any(value != {"exists": False} for value in after["assets"].values()):
        raise SystemExit("host retirement asset allowlist differs")
    if before.get("account", {}).get("home") != f"/home/{identity}" or before["account"].get("shell") != expected_shell or before["account"].get("groups") != [identity] or before["account"].get("password_locked") is not True:
        raise SystemExit("host retirement account boundary differs")
    if after.get("account") != {"exists": False} or after.get("group") != {"exists": False} or expected_assets.intersection(plan.get("retained_host_assets_before", {})):
        raise SystemExit("host retirement postcondition or retained boundary differs")
    if current_before(plan, identity) != plan.get("before"):
        raise SystemExit("host retirement assets changed after planning")
    retained = {item: metadata(item) for item in plan["retained_host_assets_before"]}
    if retained != plan.get("retained_host_assets_before"):
        raise SystemExit("retained host assets changed after planning")
    if plan["before"]["account"].get("active_pids") != []:
        raise SystemExit("retiring identity has active processes")
    return plan, raw, digest, identity


def acquire_lock(*, blocking: bool = False) -> int:
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_nlink != 1:
        os.close(descriptor)
        raise SystemExit("tofu identity retirement lock metadata differs")
    operation = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
    try:
        fcntl.flock(descriptor, operation)
    except BlockingIOError as error:
        os.close(descriptor); raise SystemExit("tofu identity retirement lock is active") from error
    return descriptor


def journal_state(journal: Path) -> dict:
    value, _ = load_private(journal / "state.json")
    return value


def set_journal_state(journal: Path, value: dict) -> None:
    replace_private(journal / "state.json", canonical(value))


def backup_paths(plan: dict, identity: str) -> list[str]:
    assets = list(plan["before"]["assets"])
    home = f"/home/{identity}"
    selected = [home]
    selected.extend(path for path in assets if not path.startswith(f"{home}/") and path != home)
    return selected


def identity_database_records(identity: str) -> dict[str, str]:
    records = {}
    for path in DATABASE_PATHS:
        matches = [line for line in Path(path).read_text().splitlines() if line.split(":", 1)[0] == identity]
        if len(matches) != 1:
            raise SystemExit(f"exact identity database record is unavailable: {path}")
        records[path] = matches[0]
    return records


def restore_identity_database_records(identity: str, records: dict[str, str]) -> None:
    if set(records) != set(DATABASE_PATHS):
        raise SystemExit("identity database rollback records are incomplete")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.lckpwdf() != 0:
        raise SystemExit("could not lock account databases for rollback")
    try:
        for path in DATABASE_PATHS:
            target = Path(path); info = target.stat(); lines = target.read_text().splitlines()
            retained = [line for line in lines if line.split(":", 1)[0] != identity]
            raw = ("\n".join([*retained, records[path]]) + "\n").encode()
            temporary = target.with_name(f".{target.name}.tofu-retirement-{os.getpid()}")
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


def reject_protected_locks() -> None:
    if any(os.path.lexists(path) for path in PROTECTED_LOCKS):
        raise SystemExit("a protected lifecycle lock is active")


def ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != 0:
        raise SystemExit(f"protected journal directory metadata differs: {path}")


def validate_journal_parent(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
        raise SystemExit(f"journal parent metadata differs: {path}")

def access_proofs_complete(evidence: dict) -> bool:
    proofs = evidence.get("proofs", {})
    return proofs.get("strict_host_key") is True and \
        proofs.get("plan_observer", {}).get("positive") is True and proofs["plan_observer"].get("injection_rejected") is True and \
        proofs.get("deploy_transport", {}).get("positive") is True and proofs["deploy_transport"].get("injection_rejected") is True and \
        proofs.get("firewall_transport", {}).get("positive") is True and proofs["firewall_transport"].get("injection_rejected") is True and \
        proofs.get("human_session", {}).get("positive") is True and proofs.get("tailnet_policy", {}).get("tests_present") is True and \
        proofs["tailnet_policy"].get("live_plan_noop") is True and proofs.get("root_keys", {}).get("complete") is True and \
        proofs.get("console") == {"attested": True, "method": "physical-console-bootstrap-install-and-verify"}


def validate_approval(plan: dict, plan_digest: str, evidence_path: Path, authorization_path: Path) -> None:
    evidence, evidence_raw = load_private(evidence_path); evidence_digest = sha(evidence_raw)
    authorization, _ = load_private(authorization_path); now = datetime.now(timezone.utc)
    if evidence.get("format") != "home-lab-proxmox-access-evidence-v1" or evidence.get("commit") != plan.get("commit") or evidence.get("contract_sha256") != plan.get("contract_sha256") or evidence.get("inventory_sha256") != plan.get("inventory_sha256") or evidence.get("host_key_fingerprint") != plan.get("host_key_fingerprint") or not access_proofs_complete(evidence):
        raise SystemExit("fresh physical-console evidence binding differs")
    if now > datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("physical-console evidence expired")
    expected_blockers = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
    if plan.get("blockers") != expected_blockers:
        raise SystemExit("host retirement plan has unresolved blockers")
    if authorization != {
        "format": "home-lab-proxmox-tofu-retirement-authorization-v1", "authorized": True,
        "plan_sha256": plan_digest, "console_evidence_sha256": evidence_digest,
        "commit": plan["commit"], "contract_sha256": plan["contract_sha256"],
        "inventory_sha256": plan["inventory_sha256"], "host_key_fingerprint": plan["host_key_fingerprint"],
        "expires_at": authorization.get("expires_at"), "authorized_at": authorization.get("authorized_at"),
        "accepted_requirements": expected_blockers,
    }:
        raise SystemExit("separate retirement authorization binding differs")
    if now > datetime.fromisoformat(authorization["expires_at"].replace("Z", "+00:00")):
        raise SystemExit("retirement authorization expired")


def capture_rollback(journal: Path, plan: dict, plan_raw: bytes, digest: str, identity: str) -> None:
    validate_journal_parent(JOURNAL_ROOT.parent); ensure_private_directory(JOURNAL_ROOT)
    journal.mkdir(mode=0o700); ensure_private_directory(journal)
    write_private(journal / "plan.json", plan_raw)
    database_records = identity_database_records(identity)
    archive = journal / "rollback.tar"; temporary = journal / "rollback.tar.partial"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        command = ("/usr/bin/tar", "--acls", "--xattrs", "--numeric-owner", "-cpf", f"/proc/self/fd/{descriptor}", "-C", "/",
                   *(path.removeprefix("/") for path in backup_paths(plan, identity)))
        completed = subprocess.run(command, pass_fds=(descriptor,), capture_output=True, text=True)
        if completed.returncode:
            raise SystemExit("rollback archive capture failed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, archive); archive_digest = sha(archive.read_bytes())
    write_private(journal / "before.json", canonical({
        "identity": identity, "plan_sha256": digest, "before": plan["before"],
        "retained_host_assets_before": plan["retained_host_assets_before"],
        "identity_database_records": database_records, "rollback_archive_sha256": archive_digest,
    }))
    source = Path(__file__).read_bytes(); write_private(journal / "rollback-executor.py", source); os.chmod(journal / "rollback-executor.py", 0o700)
    set_journal_state(journal, {"status": "prepared", "plan_sha256": digest, "identity": identity,
                                "rollback_archive_sha256": archive_digest})
    for directory_path in (journal, JOURNAL_ROOT, JOURNAL_ROOT.parent):
        directory = os.open(directory_path, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)


def watchdog_unit(digest: str) -> str:
    return f"home-lab-tofu-retirement-{digest[:16]}"


def arm_watchdog(journal: Path, digest: str) -> None:
    unit = watchdog_unit(digest); service = Path(f"/etc/systemd/system/{unit}.service"); timer = Path(f"/etc/systemd/system/{unit}.timer")
    service_raw = ("[Unit]\nDescription=Rollback uncommitted home-lab tofu identity retirement\nAfter=local-fs.target\n\n"
                   "[Service]\nType=oneshot\n" +
                   f"ExecStart=/usr/bin/python3 {journal}/rollback-executor.py rollback-journal {journal}\n").encode()
    timer_raw = ("[Unit]\nDescription=Watchdog for home-lab tofu identity retirement\n\n[Timer]\n" +
                 f"OnActiveSec={WATCHDOG_SECONDS}s\nUnit={unit}.service\n\n[Install]\nWantedBy=timers.target\n").encode()
    for path, raw in ((service, service_raw), (timer, timer_raw)):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), check=True, capture_output=True)
    completed = subprocess.run(("/usr/bin/systemctl", "enable", "--now", f"{unit}.timer"), capture_output=True, text=True)
    if completed.returncode:
        raise SystemExit("retirement rollback watchdog could not be armed")


def disarm_watchdog(digest: str, *, stop_service: bool = True) -> None:
    unit = watchdog_unit(digest)
    subprocess.run(("/usr/bin/systemctl", "disable", "--now", f"{unit}.timer"), capture_output=True)
    if stop_service:
        subprocess.run(("/usr/bin/systemctl", "stop", f"{unit}.service"), capture_output=True)
    for suffix in ("service", "timer"):
        Path(f"/etc/systemd/system/{unit}.{suffix}").unlink(missing_ok=True)
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), capture_output=True)
    subprocess.run(("/usr/bin/systemctl", "reset-failed", f"{unit}.service"), capture_output=True)


def restore_archive(journal: Path) -> None:
    state = journal_state(journal); before, _ = load_private(journal / "before.json")
    archive = journal / "rollback.tar"; info = archive.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_nlink != 1 or sha(archive.read_bytes()) != state.get("rollback_archive_sha256") or before.get("rollback_archive_sha256") != state.get("rollback_archive_sha256"):
        raise SystemExit("rollback archive metadata or digest differs")
    completed = subprocess.run(("/usr/bin/tar", "--acls", "--xattrs", "--numeric-owner", "-xpf", str(archive), "-C", "/"), capture_output=True, text=True)
    if completed.returncode:
        raise SystemExit("tofu identity rollback extraction failed")
    restore_identity_database_records(before["identity"], before["identity_database_records"])
    if subprocess.run(("/usr/sbin/pwck", "-r"), capture_output=True).returncode:
        raise SystemExit("password database validation failed after rollback")
    if subprocess.run(("/usr/sbin/grpck", "-r"), capture_output=True).returncode:
        raise SystemExit("group database validation failed after rollback")


def rollback_journal(journal: Path) -> None:
    if os.geteuid() != 0:
        raise SystemExit("rollback requires root")
    descriptor = acquire_lock(blocking=True)
    try:
        state = journal_state(journal)
        if state.get("status") in {"committed", "rolled-back"}:
            disarm_watchdog(state["plan_sha256"], stop_service=False)
            return
        if state.get("status") not in {"prepared", "mutation-started", "awaiting-canary"}:
            raise SystemExit("retirement journal state is invalid for rollback")
        restore_archive(journal)
        plan, _ = load_private(journal / "plan.json"); identity = identity_from_plan(plan)
        if current_before(plan, identity) != plan["before"]:
            raise SystemExit("rollback did not restore exact identity state")
        retained = {item: metadata(item) for item in plan["retained_host_assets_before"]}
        if retained != plan["retained_host_assets_before"]:
            raise SystemExit("rollback changed a retained host asset")
        set_journal_state(journal, {**state, "status": "rolled-back", "rolled_back_at": datetime.now(timezone.utc).isoformat()})
        disarm_watchdog(state["plan_sha256"], stop_service=False)
    finally:
        os.close(descriptor)


def mutate(plan: dict, identity: str) -> None:
    home = f"/home/{identity}"
    for path in plan["before"]["assets"]:
        if path.startswith(f"{home}/") or path == home:
            continue
        Path(path).unlink()
    completed = subprocess.run(("/usr/sbin/userdel", identity), capture_output=True, text=True)
    if completed.returncode:
        raise RuntimeError("identity deletion failed")
    if group(identity).get("exists"):
        completed = subprocess.run(("/usr/sbin/groupdel", identity), capture_output=True, text=True)
        if completed.returncode:
            raise RuntimeError("identity group deletion failed")
    home_info = os.lstat(home)
    if not stat.S_ISDIR(home_info.st_mode) or stat.S_ISLNK(home_info.st_mode):
        raise RuntimeError("planned identity home changed type")
    shutil.rmtree(home)


def after_matches(plan: dict, identity: str) -> bool:
    after = {"account": account(identity), "group": group(identity),
             "assets": {path: metadata(path) for path in plan["after"]["assets"]}}
    return after == plan["after"]


def apply(plan_path: Path, evidence_path: Path, authorization_path: Path) -> None:
    require_root_console(); descriptor = acquire_lock(); journal = None; digest = ""
    try:
        reject_protected_locks()
        plan, raw, digest, identity = validate_plan(plan_path)
        validate_approval(plan, digest, evidence_path, authorization_path)
        expected = f"apply-proxmox-{plan['kind']}-{digest}"
        if os.environ.get("PROXMOX_TOFU_RETIREMENT_CONFIRMED") != expected:
            raise SystemExit(f"exact confirmation required: {expected}")
        journal = JOURNAL_ROOT / digest
        capture_rollback(journal, plan, raw, digest, identity)
        reject_protected_locks()
        if current_before(plan, identity) != plan["before"]:
            raise SystemExit("host retirement assets changed before mutation")
        retained_now = {item: metadata(item) for item in plan["retained_host_assets_before"]}
        if retained_now != plan["retained_host_assets_before"]:
            raise SystemExit("retained host assets changed before mutation")
        arm_watchdog(journal, digest)
        set_journal_state(journal, {**journal_state(journal), "status": "mutation-started",
                                    "mutation_started_at": datetime.now(timezone.utc).isoformat()})
        try:
            mutate(plan, identity)
            if not after_matches(plan, identity):
                raise RuntimeError("identity retirement postcondition differs")
            retained = {item: metadata(item) for item in plan["retained_host_assets_before"]}
            if retained != plan["retained_host_assets_before"]:
                raise RuntimeError("identity retirement changed a retained host asset")
            set_journal_state(journal, {**journal_state(journal), "status": "awaiting-canary",
                                        "watchdog_seconds": WATCHDOG_SECONDS,
                                        "mutated_at": datetime.now(timezone.utc).isoformat()})
        except Exception:
            restore_archive(journal)
            if current_before(plan, identity) != plan["before"]:
                raise RuntimeError("immediate rollback did not restore exact identity state")
            restored = {item: metadata(item) for item in plan["retained_host_assets_before"]}
            if restored != plan["retained_host_assets_before"]:
                raise RuntimeError("immediate rollback changed a retained host asset")
            set_journal_state(journal, {**journal_state(journal), "status": "rolled-back",
                                        "rolled_back_at": datetime.now(timezone.utc).isoformat()})
            disarm_watchdog(digest)
            raise
    finally:
        os.close(descriptor)
    print(json.dumps({"status": "awaiting-canary", "identity": identity, "journal": str(journal),
                      "plan_sha256": digest, "watchdog_seconds": WATCHDOG_SECONDS}, sort_keys=True))


def validate_canary(receipt: dict, digest: str, identity: str) -> None:
    if receipt.get("format") != "home-lab-proxmox-tofu-retirement-canary-v1" or receipt.get("plan_sha256") != digest or receipt.get("identity") != identity:
        raise SystemExit("retirement canary receipt binding differs")
    checks = receipt.get("checks")
    required = {"ansible_plan", "ansible_deploy", "firewall_apply", "human_tailscale", "retired_identity_rejected", "retained_assets_unchanged"}
    if set(checks or {}) != required or not all(checks.values()):
        raise SystemExit("retirement canary checks are incomplete")
    captured = datetime.fromisoformat(receipt["captured_at"].replace("Z", "+00:00"))
    age = (datetime.now(timezone.utc) - captured).total_seconds()
    if age < 0 or age > 300:
        raise SystemExit("retirement canary receipt is stale")


def commit(journal: Path, canary_path: Path) -> None:
    require_root_console(); descriptor = acquire_lock()
    try:
        state = journal_state(journal)
        if state.get("status") != "awaiting-canary":
            raise SystemExit("retirement journal is not awaiting canary")
        plan, raw = load_private(journal / "plan.json"); digest = sha(raw); identity = identity_from_plan(plan)
        receipt, receipt_raw = load_private(canary_path); validate_canary(receipt, digest, identity)
        expected = f"commit-proxmox-{plan['kind']}-{digest}-{sha(receipt_raw)}"
        if os.environ.get("PROXMOX_TOFU_RETIREMENT_CONFIRMED") != expected:
            raise SystemExit(f"exact confirmation required: {expected}")
        if not after_matches(plan, identity):
            raise SystemExit("retirement state changed before commit")
        retained = {item: metadata(item) for item in plan["retained_host_assets_before"]}
        if retained != plan["retained_host_assets_before"]:
            raise SystemExit("retained state changed before commit")
        write_private(journal / "canary.json", receipt_raw)
        committed = {**state, "format": "home-lab-proxmox-tofu-retirement-host-receipt-v1",
                     "status": "committed", "canary_sha256": sha(receipt_raw),
                     "committed_at": datetime.now(timezone.utc).isoformat()}
        write_private(journal / "receipt.json", canonical(committed))
        set_journal_state(journal, committed)
        disarm_watchdog(digest)
    finally:
        os.close(descriptor)
    print(json.dumps({"status": "committed", "identity": identity, "plan_sha256": digest,
                      "receipt": str(journal / "receipt.json")}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    apply_parser = commands.add_parser("apply"); apply_parser.add_argument("plan", type=Path); apply_parser.add_argument("evidence", type=Path); apply_parser.add_argument("authorization", type=Path)
    rollback_parser = commands.add_parser("rollback-journal"); rollback_parser.add_argument("journal", type=Path)
    commit_parser = commands.add_parser("commit"); commit_parser.add_argument("journal", type=Path); commit_parser.add_argument("canary", type=Path)
    args = parser.parse_args()
    if args.command == "apply": apply(args.plan.resolve(), args.evidence.resolve(), args.authorization.resolve())
    elif args.command == "rollback-journal": rollback_journal(args.journal.resolve())
    else: commit(args.journal.resolve(), args.canary.resolve())


if __name__ == "__main__":
    main()
