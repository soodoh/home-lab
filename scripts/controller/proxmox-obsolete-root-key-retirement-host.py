#!/usr/bin/env python3
"""Physical-console executor for exact obsolete Proxmox root-key retirement."""
from __future__ import annotations

import argparse
import fcntl
from datetime import datetime, timezone
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

REPO = Path("/root/home-lab")
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
PLANNER_SOURCE = SCRIPT_DIRECTORY / "proxmox-obsolete-root-key-retirement.py" if (SCRIPT_DIRECTORY / "proxmox-obsolete-root-key-retirement.py").exists() else REPO / "scripts/controller/proxmox-obsolete-root-key-retirement.py"
PLANNER_SPEC = importlib.util.spec_from_file_location("obsolete_root_key_planner", PLANNER_SOURCE)
PLANNER = importlib.util.module_from_spec(PLANNER_SPEC); PLANNER_SPEC.loader.exec_module(PLANNER)
CONTRACT = REPO / "infrastructure/contract/home-lab.yml"
INVENTORY = REPO / "ansible/inventory/production.yml"
KEY_PATH = Path(PLANNER.KEY_PATH)
JOURNAL_ROOT = Path("/var/lib/home-lab/obsolete-root-key-retirement")
LOCK_PATH = Path("/run/lock/home-lab-proxmox-obsolete-root-key-retirement.lock")
WATCHDOG_SECONDS = 900
EXPECTED_ACTION = [{"kind": "remove-obsolete-root-key-lines", "path": PLANNER.KEY_PATH, "fingerprints": PLANNER.TARGET_FINGERPRINTS}]
EXPECTED_EXCLUSIONS = {"delete_key_file_or_symlink": False, "delete_non_target_keys": False, "delete_root_or_apex": False, "pve_api_tokens": ["tofu-plan", "tofu-apply"], "firewall_recovery": True, "openssh_policy": True, "controller_keys": True, "final_conventional_key_absence": "not-authorized"}
retained_metadata_valid = PLANNER.retained_metadata_valid


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def replace_private(path: Path, raw: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp"); write_private(temporary, raw); os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def load_private(path: Path) -> tuple[dict, bytes]:
    info = path.lstat(); raw = path.read_bytes(); value = json.loads(raw)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_nlink != 1 or raw != canonical(value): raise SystemExit(f"protected artifact metadata differs: {path}")
    return value, raw


def metadata(path: str) -> dict:
    try: info = os.lstat(path)
    except FileNotFoundError: return {"exists": False}
    value = {"exists": True, "uid": info.st_uid, "gid": info.st_gid, "mode": format(stat.S_IMODE(info.st_mode), "04o"), "nlink": info.st_nlink, "regular": stat.S_ISREG(info.st_mode), "directory": stat.S_ISDIR(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode), "size": info.st_size}
    if value["regular"]: value["sha256"] = sha(Path(path).read_bytes())
    return value


def retained_metadata(path: str) -> dict:
    value = metadata(path)
    if value.get("symlink") is True: value["symlink_target"] = os.readlink(path)
    return value


def require_root_console() -> None:
    if os.geteuid() != 0 or os.environ.get("SSH_CONNECTION") or not os.isatty(0) or not os.isatty(1): raise SystemExit("retirement must run directly as root from a physical console")
    tty = os.ttyname(0)
    if not re.fullmatch(r"/dev/tty[0-9]+", tty) or os.ttyname(1) != tty: raise SystemExit("retirement requires matching physical /dev/ttyN input and output")


def access_state(raw: bytes) -> str:
    text = raw.decode(); section = text.split("      access_cutover:\n", 1)
    match = re.search(r"^        state: (pending|ready|complete)$", section[1].split("      domain_handoffs:\n", 1)[0], re.MULTILINE) if len(section) == 2 else None
    if match is None: raise SystemExit("access cutover state is unavailable")
    return match.group(1)


def access_proofs_complete(evidence: dict) -> bool:
    return PLANNER.complete_proofs(evidence)


def pve_tokens() -> list[dict]:
    items = json.loads(subprocess.run(("/usr/sbin/pveum", "user", "token", "list", "root@pam", "--output-format", "json"), capture_output=True, text=True, check=True).stdout)
    return sorted([{"tokenid": item["tokenid"], "privsep": item["privsep"]} for item in items], key=lambda item: item["tokenid"])


def root_group_state() -> dict:
    root = pwd.getpwnam("root"); apex = grp.getgrnam("apex")
    return {"root_groups": sorted(grp.getgrgid(gid).gr_name for gid in os.getgrouplist("root", root.pw_gid)), "apex": {"exists": True, "gid": apex.gr_gid, "members": sorted(apex.gr_mem)}}


def acquire_lock(*, blocking: bool = False) -> int:
    descriptor = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_nlink != 1: os.close(descriptor); raise SystemExit("obsolete root-key lock metadata differs")
    try: fcntl.flock(descriptor, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error: os.close(descriptor); raise SystemExit("obsolete root-key transaction is locked") from error
    return descriptor


def reject_protected_locks() -> None:
    active = [path for path in PLANNER.PROTECTED_LOCKS if os.path.lexists(path)]
    if active: raise SystemExit("protected infrastructure lock is active")


def target_metadata() -> dict:
    return metadata(str(KEY_PATH))


def key_snapshot() -> dict:
    raw = KEY_PATH.read_bytes(); value = target_metadata()
    if value.get("sha256") != sha(raw) or value.get("size") != len(raw): raise SystemExit("root-key bytes and metadata were not captured atomically")
    return {"metadata": value, "bytes_hex": raw.hex(), "records": PLANNER.parse_authorized_keys(raw)}


def sshd_policy() -> dict:
    result = subprocess.run(("/usr/sbin/sshd", "-T"), capture_output=True, text=True, check=True)
    selected = {"allow_users": [], "authorized_keys_file": [], "permit_root_login": None, "pubkey_authentication": None}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key == "allowusers": selected["allow_users"].append(value)
        elif key == "authorizedkeysfile": selected["authorized_keys_file"] = value.split()
        elif key == "permitrootlogin": selected["permit_root_login"] = value
        elif key == "pubkeyauthentication": selected["pubkey_authentication"] = value
    return selected


def tofu_absent() -> bool:
    program = "import grp,os,pwd\n"
    for name in ("tofu-plan", "tofu-apply"):
        try: __import__("pwd").getpwnam(name); return False
        except KeyError: pass
        try: __import__("grp").getgrnam(name); return False
        except KeyError: pass
        if os.path.lexists(f"/home/{name}") or os.path.lexists(f"/etc/sudoers.d/{name}"): return False
    return True


def retained_snapshot(plan: dict) -> dict:
    return {path: retained_metadata(path) for path in plan["retained_assets_before"]}


def retained_matches(plan: dict) -> bool:
    retained = retained_snapshot(plan)
    return retained_metadata_valid(retained) and retained == plan["retained_assets_before"] and pve_tokens() == PLANNER.EXPECTED_TOKENS == plan["retained_pve_tokens"] and sshd_policy() == plan["retained_sshd_policy"] and root_group_state() == plan["retained_root_group_state"] and tofu_absent()


def exact_before_matches(plan: dict) -> bool:
    return key_snapshot() == plan["before"] and retained_matches(plan)


def exact_after_matches(plan: dict) -> bool:
    current = key_snapshot()
    return current == plan["after"] and sorted(item["fingerprint"] for item in current["records"]) == sorted(PLANNER.RETAINED_FINGERPRINTS) and retained_matches(plan)


def validate_plan(path: Path) -> tuple[dict, bytes, str]:
    plan, raw = load_private(path); digest = sha(raw)
    if path.name != f"obsolete-root-keys-{digest}.json" or plan.get("format") != "home-lab-proxmox-obsolete-root-key-retirement-plan-v1" or plan.get("authorized") is not False: raise SystemExit("obsolete root-key plan filename or format differs")
    commit = subprocess.check_output(("/usr/bin/git", "-C", str(REPO), "rev-parse", "HEAD"), text=True).strip(); contract_raw = CONTRACT.read_bytes()
    if plan.get("commit") != commit or plan.get("contract_sha256") != sha(contract_raw) or plan.get("inventory_sha256") != sha(INVENTORY.read_bytes()) or plan.get("host_key_fingerprint") != PLANNER.FINGERPRINT or PLANNER.contract_policy(contract_raw) != ("ready", PLANNER.EXPECTED_ATTRIBUTIONS) or access_state(contract_raw) != "ready": raise SystemExit("obsolete root-key source binding differs")
    if datetime.now(timezone.utc) > datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00")): raise SystemExit("obsolete root-key plan expired")
    if plan.get("actions") != EXPECTED_ACTION or plan.get("target_fingerprints") != PLANNER.TARGET_FINGERPRINTS or plan.get("retained_fingerprints") != PLANNER.RETAINED_FINGERPRINTS or plan.get("explicit_exclusions") != EXPECTED_EXCLUSIONS: raise SystemExit("obsolete root-key mutation boundary differs")
    if set(plan.get("retained_assets_before", {})) != set(PLANNER.RETAINED_METADATA) or plan.get("retained_pve_tokens") != PLANNER.EXPECTED_TOKENS: raise SystemExit("obsolete root-key retained-authority allowlist differs")
    before_fingerprints = [item.get("fingerprint") for item in plan.get("before", {}).get("records", [])]
    before_metadata = plan.get("before", {}).get("metadata", {})
    if sorted(before_fingerprints) != sorted(PLANNER.EXPECTED_ATTRIBUTIONS) or len(before_fingerprints) != len(set(before_fingerprints)) or any(before_metadata.get(key) != value for key, value in {"exists": True, "uid": 0, "gid": 33, "mode": "0600", "regular": True, "directory": False, "symlink": False, "nlink": 1}.items()):
        raise SystemExit("obsolete root-key before-state boundary differs")
    expected_after = PLANNER.after_snapshot(plan["before"])
    if plan.get("after") != expected_after: raise SystemExit("obsolete root-key postcondition differs")
    if not exact_before_matches(plan): raise SystemExit("obsolete root-key state changed after planning")
    return plan, raw, digest


def validate_approval(plan: dict, digest: str, evidence_path: Path, authorization_path: Path) -> None:
    evidence, evidence_raw = load_private(evidence_path); evidence_digest = sha(evidence_raw); authorization, _ = load_private(authorization_path); now = datetime.now(timezone.utc)
    evidence_expires = datetime.fromisoformat(evidence["expires_at"].replace("Z", "+00:00")); plan_expires = datetime.fromisoformat(plan["expires_at"].replace("Z", "+00:00"))
    if evidence.get("format") != "home-lab-proxmox-access-evidence-v1" or evidence.get("commit") != plan["commit"] or evidence.get("contract_sha256") != plan["contract_sha256"] or evidence.get("inventory_sha256") != plan["inventory_sha256"] or evidence.get("host_key_fingerprint") != PLANNER.FINGERPRINT or not access_proofs_complete(evidence) or not PLANNER.evidence_keys_match(evidence, list(PLANNER.EXPECTED_ATTRIBUTIONS)) or now > evidence_expires:
        raise SystemExit("fresh complete console evidence differs")
    expected_confirmation = f"authorize-proxmox-obsolete-root-keys-{digest}-{evidence_digest}"; expected = {"format": "home-lab-proxmox-obsolete-root-key-retirement-authorization-v1", "plan_sha256": digest, "evidence_sha256": evidence_digest, "created_at": authorization.get("created_at"), "expires_at": authorization.get("expires_at"), "confirmation": expected_confirmation, "authorized": True}
    requirements = ["physical-console-attestation-required", "rollback-bundle-required", "separate-authorization-required"]
    try: created = datetime.fromisoformat(authorization["created_at"].replace("Z", "+00:00")); expires = datetime.fromisoformat(authorization["expires_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error: raise SystemExit("obsolete root-key authorization timestamps differ") from error
    if plan.get("blockers") != requirements or plan.get("findings") != [] or authorization != expected or created > now or expires <= created or (expires - created).total_seconds() > 900 or expires > min(plan_expires, evidence_expires) or now > expires:
        raise SystemExit("obsolete root-key authorization differs")


def ensure_journal(path: Path) -> None:
    parent = JOURNAL_ROOT.parent; info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0: raise SystemExit("journal parent differs")
    if JOURNAL_ROOT.exists():
        info = JOURNAL_ROOT.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != 0: raise SystemExit("journal root differs")
    else: JOURNAL_ROOT.mkdir(mode=0o700)
    path.mkdir(mode=0o700); info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != 0: raise SystemExit("journal directory differs")


def state(journal: Path) -> dict:
    value, _ = load_private(journal / "state.json"); return value


def set_state(journal: Path, value: dict) -> None:
    replace_private(journal / "state.json", canonical(value))


def capture(journal: Path, plan: dict, plan_raw: bytes, digest: str) -> None:
    ensure_journal(journal); before_raw = bytes.fromhex(plan["before"]["bytes_hex"]); write_private(journal / "plan.json", plan_raw); write_private(journal / "before.bin", before_raw)
    sources = {"rollback-executor.py": Path(__file__).read_bytes(), "proxmox-obsolete-root-key-retirement.py": PLANNER_SOURCE.read_bytes()}
    for name, raw in sources.items(): write_private(journal / name, raw); os.chmod(journal / name, 0o700)
    set_state(journal, {"status": "prepared", "plan_sha256": digest, "before_sha256": sha(before_raw)})
    for item in (journal, JOURNAL_ROOT, JOURNAL_ROOT.parent):
        descriptor = os.open(item, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)


def unit_name(digest: str) -> str:
    return f"home-lab-obsolete-root-key-{digest[:16]}"


def arm(journal: Path, digest: str) -> None:
    unit = unit_name(digest); service = Path(f"/etc/systemd/system/{unit}.service"); timer = Path(f"/etc/systemd/system/{unit}.timer")
    service_raw = f"[Unit]\nDescription=Rollback obsolete root-key retirement {digest}\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {journal}/rollback-executor.py rollback {journal}\nRestart=on-failure\nRestartSec=5s\n".encode(); timer_raw = f"[Unit]\nDescription=Watchdog for obsolete root-key retirement {digest}\n[Timer]\nOnActiveSec={WATCHDOG_SECONDS}s\nAccuracySec=1s\nUnit={unit}.service\n[Install]\nWantedBy=timers.target\n".encode()
    for path, raw in ((service, service_raw), (timer, timer_raw)):
        if path.exists(): raise SystemExit("obsolete root-key watchdog already exists")
        write_private(path, raw); os.chmod(path, 0o644); descriptor = os.open(path, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    unit_directory = Path("/etc/systemd/system"); descriptor = os.open(unit_directory, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), check=True); subprocess.run(("/usr/bin/systemctl", "enable", "--now", f"{unit}.timer"), check=True)
    wants = unit_directory / "timers.target.wants"
    for path in (unit_directory, wants):
        descriptor = os.open(path, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    enabled = subprocess.run(("/usr/bin/systemctl", "is-enabled", f"{unit}.timer"), capture_output=True, text=True); active = subprocess.run(("/usr/bin/systemctl", "is-active", f"{unit}.timer"), capture_output=True, text=True)
    if enabled.returncode or enabled.stdout.strip() != "enabled" or active.returncode or active.stdout.strip() != "active": raise SystemExit("obsolete root-key watchdog durability barrier differs")


def disarm(digest: str, stop_service: bool = False) -> None:
    unit = unit_name(digest); subprocess.run(("/usr/bin/systemctl", "disable", "--now", f"{unit}.timer"), capture_output=True)
    if stop_service: subprocess.run(("/usr/bin/systemctl", "stop", f"{unit}.service"), capture_output=True)
    for suffix in ("service", "timer"): Path(f"/etc/systemd/system/{unit}.{suffix}").unlink(missing_ok=True)
    subprocess.run(("/usr/bin/systemctl", "daemon-reload"), capture_output=True)


def fsync_key_directory() -> None:
    descriptor = os.open(KEY_PATH.parent, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def verify_exclusive_create_support(digest: str) -> None:
    probe = KEY_PATH.with_name(f"authorized_keys.home-lab-{digest}.probe")
    if os.path.lexists(probe): raise RuntimeError("root-key exclusive-create probe path exists")
    try:
        create_candidate(probe, b"probe")
        try: descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError: pass
        else:
            os.close(descriptor); raise RuntimeError("exclusive create overwrote an existing target")
        if probe.read_bytes() != b"probe": raise RuntimeError("exclusive-create probe differs")
    finally:
        probe.unlink(missing_ok=True); fsync_key_directory()


def transaction_paths(digest: str) -> tuple[Path, Path]:
    return KEY_PATH.with_name(f"authorized_keys.home-lab-{digest}.candidate"), KEY_PATH.with_name(f"authorized_keys.home-lab-{digest}.rollback")


def create_candidate(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle: handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    os.chmod(path, 0o600); info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 33 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or path.read_bytes() != raw: raise RuntimeError("root-key candidate differs")
    fsync_key_directory()


def verify_noreplace_support(digest: str) -> None:
    verify_exclusive_create_support(digest)


def install_candidate(plan: dict, digest: str) -> None:
    before = bytes.fromhex(plan["before"]["bytes_hex"]); after = bytes.fromhex(plan["after"]["bytes_hex"]); candidate, backup = transaction_paths(digest)
    if os.path.lexists(candidate) or os.path.lexists(backup): raise RuntimeError("root-key transaction path already exists")
    verify_exclusive_create_support(digest); create_candidate(candidate, after); os.rename(KEY_PATH, backup); fsync_key_directory()
    captured = backup.read_bytes()
    if captured != before:
        if not os.path.lexists(KEY_PATH): create_candidate(KEY_PATH, captured)
        candidate.unlink(missing_ok=True); fsync_key_directory(); raise RuntimeError("root-key bytes changed at transactional rename")
    try: create_candidate(KEY_PATH, candidate.read_bytes())
    except Exception:
        if not os.path.lexists(KEY_PATH): create_candidate(KEY_PATH, captured)
        fsync_key_directory(); raise
    candidate.unlink(); fsync_key_directory()
    if KEY_PATH.read_bytes() != after or backup.read_bytes() != before: raise RuntimeError("root-key transactional replacement differs")


def cleanup_transaction_files(plan: dict, digest: str) -> None:
    before = bytes.fromhex(plan["before"]["bytes_hex"]); candidate, backup = transaction_paths(digest)
    if candidate.exists(): candidate.unlink()
    if backup.exists():
        if backup.read_bytes() != before: raise SystemExit("root-key rollback artifact differs")
        backup.unlink()
    fsync_key_directory()


def restore_from_journal(journal: Path, current: dict) -> None:
    before_path = journal / "before.bin"; info = before_path.lstat(); before = before_path.read_bytes(); plan, _ = load_private(journal / "plan.json"); after = bytes.fromhex(plan["after"]["bytes_hex"]); candidate, backup = transaction_paths(current["plan_sha256"])
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_nlink != 1 or sha(before) != current.get("before_sha256"): raise SystemExit("obsolete root-key rollback bundle differs")
    target = KEY_PATH.read_bytes() if KEY_PATH.exists() else None; backup_value = backup.read_bytes() if backup.exists() else None; source = backup_value if backup_value is not None else before; captured_drift = source != before
    def is_prefix(value: bytes, expected: bytes) -> bool:
        return len(value) < len(expected) and expected.startswith(value)
    def known_install_artifact(value: bytes) -> bool:
        return value == after or is_prefix(value, after)
    def known_rollback_artifact(value: bytes) -> bool:
        return known_install_artifact(value) or value == source or is_prefix(value, source)
    def candidate_bytes() -> bytes | None:
        return candidate.read_bytes() if candidate.exists() else None
    def discard_known_candidate() -> None:
        value = candidate_bytes()
        if value is None: return
        if not known_rollback_artifact(value): raise SystemExit("unknown candidate drift is preserved")
        candidate.unlink(); fsync_key_directory()
    def move_owned_target(value: bytes) -> None:
        existing_candidate = candidate_bytes(); prefix_of_source = is_prefix(value, source)
        if existing_candidate is not None and not known_rollback_artifact(existing_candidate): raise SystemExit("unknown candidate drift is preserved")
        if prefix_of_source and existing_candidate is None: raise SystemExit("unproven partial rollback target is preserved")
        os.rename(KEY_PATH, candidate); fsync_key_directory(); moved = candidate.read_bytes()
        if moved != value or not known_rollback_artifact(moved):
            if not KEY_PATH.exists(): create_candidate(KEY_PATH, moved)
            raise SystemExit("root-key drift was preserved during rollback")
    if target is None:
        value = candidate_bytes()
        if value is not None and not known_rollback_artifact(value):
            create_candidate(KEY_PATH, value); raise SystemExit("unknown candidate drift was restored and preserved")
        create_candidate(KEY_PATH, source)
    elif target != source:
        if known_install_artifact(target) or (is_prefix(target, source) and candidate_bytes() is not None and known_rollback_artifact(candidate_bytes())):
            move_owned_target(target); create_candidate(KEY_PATH, source)
        else:
            raise SystemExit("unknown root-key drift blocks rollback")
    if KEY_PATH.read_bytes() != source: raise SystemExit("root-key restoration source differs")
    discard_known_candidate(); fsync_key_directory()
    if captured_drift: raise SystemExit("captured root-key drift was preserved instead of overwritten")
    if key_snapshot() != plan["before"] or not retained_matches(plan): raise SystemExit("obsolete root-key rollback differs")
    if backup.exists():
        if backup.read_bytes() != before: raise SystemExit("root-key rollback artifact differs")
        backup.unlink()
    fsync_key_directory()


def rollback(journal: Path) -> None:
    descriptor = acquire_lock(blocking=True)
    try:
        current = state(journal)
        if current.get("status") in {"committed", "rolled-back"}: return
        if current.get("status") not in {"prepared", "mutation-started", "awaiting-canary"}: raise SystemExit("obsolete root-key journal state is invalid for rollback")
        restore_from_journal(journal, current); rolled = {**current, "status": "rolled-back", "rolled_back_at": datetime.now(timezone.utc).isoformat()}; set_state(journal, rolled); disarm(current["plan_sha256"], stop_service=True)
    finally: os.close(descriptor)


def apply(plan_path: Path, evidence_path: Path, authorization_path: Path) -> None:
    require_root_console(); descriptor = acquire_lock()
    try:
        reject_protected_locks(); plan, raw, digest = validate_plan(plan_path); validate_approval(plan, digest, evidence_path, authorization_path); expected = f"apply-proxmox-obsolete-root-keys-{digest}"
        if os.environ.get("PROXMOX_OBSOLETE_ROOT_KEY_RETIREMENT_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
        journal = JOURNAL_ROOT / digest; capture(journal, plan, raw, digest); reject_protected_locks()
        if not exact_before_matches(plan): raise SystemExit("obsolete root-key preconditions changed before mutation")
        arm(journal, digest); set_state(journal, {**state(journal), "status": "mutation-started", "mutation_started_at": datetime.now(timezone.utc).isoformat()})
        try:
            install_candidate(plan, digest)
            if not exact_after_matches(plan): raise RuntimeError("obsolete root-key mutation differs")
            set_state(journal, {**state(journal), "status": "awaiting-canary", "mutated_at": datetime.now(timezone.utc).isoformat(), "watchdog_seconds": WATCHDOG_SECONDS})
        except (Exception, SystemExit):
            restore_from_journal(journal, state(journal)); set_state(journal, {**state(journal), "status": "rolled-back", "rolled_back_at": datetime.now(timezone.utc).isoformat()}); disarm(digest); raise
    finally: os.close(descriptor)
    print(json.dumps({"status": "awaiting-canary", "plan_sha256": digest, "journal": str(journal)}, sort_keys=True))


def validate_canary(receipt: dict, digest: str) -> None:
    expected = {"ansible_plan": True, "ansible_deploy": True, "firewall_apply": True, "human_tailscale": True, "root_lan_recovery": True, "obsolete_keys_absent": True, "retained_keys_exact": True, "retained_assets": True, "pve_tokens": True, "sshd_policy": True}
    if receipt.get("format") != "home-lab-proxmox-obsolete-root-key-canary-v1" or receipt.get("plan_sha256") != digest or receipt.get("checks") != expected: raise SystemExit("obsolete root-key canary differs")
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(receipt["captured_at"].replace("Z", "+00:00"))).total_seconds()
    if age < 0 or age > 300: raise SystemExit("obsolete root-key canary is stale")


def commit(journal: Path, canary_path: Path) -> None:
    require_root_console(); descriptor = acquire_lock()
    try:
        current = state(journal)
        if current.get("status") != "awaiting-canary": raise SystemExit("journal is not awaiting canary")
        plan, raw = load_private(journal / "plan.json"); digest = sha(raw); canary, canary_raw = load_private(canary_path); validate_canary(canary, digest); expected = f"commit-proxmox-obsolete-root-keys-{digest}-{sha(canary_raw)}"
        if os.environ.get("PROXMOX_OBSOLETE_ROOT_KEY_RETIREMENT_CONFIRMED") != expected: raise SystemExit(f"exact confirmation required: {expected}")
        if not exact_after_matches(plan): raise SystemExit("obsolete root-key state changed before commit")
        write_private(journal / "canary.json", canary_raw); committed = {**current, "format": "home-lab-proxmox-obsolete-root-key-retirement-receipt-v1", "status": "committed", "canary_sha256": sha(canary_raw), "committed_at": datetime.now(timezone.utc).isoformat()}; write_private(journal / "receipt.json", canonical(committed)); set_state(journal, committed); cleanup_transaction_files(plan, digest); disarm(digest)
    finally: os.close(descriptor)
    print(json.dumps({"status": "committed", "plan_sha256": digest, "receipt": str(journal / "receipt.json")}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True); apply_parser = commands.add_parser("apply"); apply_parser.add_argument("plan", type=Path); apply_parser.add_argument("evidence", type=Path); apply_parser.add_argument("authorization", type=Path); rollback_parser = commands.add_parser("rollback"); rollback_parser.add_argument("journal", type=Path); commit_parser = commands.add_parser("commit"); commit_parser.add_argument("journal", type=Path); commit_parser.add_argument("canary", type=Path); args = parser.parse_args()
    if args.command == "apply": apply(args.plan.resolve(), args.evidence.resolve(), args.authorization.resolve())
    elif args.command == "rollback": rollback(args.journal.resolve())
    else: commit(args.journal.resolve(), args.canary.resolve())


if __name__ == "__main__": main()
