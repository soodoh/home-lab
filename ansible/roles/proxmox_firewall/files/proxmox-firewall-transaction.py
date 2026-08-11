#!/usr/bin/env python3
"""Fixed, journaled PVE firewall transaction helper."""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Any

FORMAT_PLAN = "home-lab-proxmox-firewall-plan-v1"
FORMAT_INSPECTION = "home-lab-proxmox-firewall-inspection-v1"
FORMAT_BEGIN = "home-lab-proxmox-firewall-begin-v1"
FORMAT_RESULT = "home-lab-proxmox-firewall-result-v1"
FORMAT_JOURNAL = "home-lab-proxmox-firewall-journal-v1"
FORMAT_AUTHORIZE = "home-lab-proxmox-firewall-authorize-v1"
FORMAT_AUTHORIZATION = "home-lab-proxmox-firewall-authorization-v1"
AUTHORIZE_GATE = "AUTHORIZE EXACT REVIEWED PROXMOX FIREWALL PLAN"
ISOLATE_GATE = "ISOLATE TOFU APPLY FOR FIREWALL TRANSACTION"
RESTORE_GATE = "RESTORE TOFU APPLY AFTER TERMINAL FIREWALL TRANSACTION"
POLICY = Path("/usr/local/share/home-lab/proxmox-firewall-policy.json")
RUNTIME = Path("/var/lib/home-lab/firewall-transaction")
KEY = RUNTIME / "attestation.key"
JOURNAL = RUNTIME / "journal.json"
AUTHORIZATION = RUNTIME / "authorization.json"
ACCESS_SNAPSHOT = RUNTIME / "tofu-apply-access.json"
TOFU_KEYS = Path("/home/tofu-apply/.ssh/authorized_keys")
MUTEX = Path("/var/lib/home-lab/reconciliation/operation.lock")
OWNER_LOCK = Path("/var/lib/iac-ansible-production.lock")
NIX_LOCK = Path("/var/lib/home-lab/reconciliation/apply.lock")
HELPER = Path("/usr/local/libexec/home-lab/proxmox-firewall-transaction")
BOOT_HELPER = Path("/usr/local/libexec/home-lab/proxmox-firewall-boot-recovery")
TRANSPORT = Path("/usr/local/libexec/home-lab/proxmox-firewall-transport")
SYSTEMD = Path("/etc/systemd/system")
TIMER = "home-lab-proxmox-firewall-rollback.timer"
SERVICES = ("pve-firewall.service", "proxmox-firewall.service")
MAX_INPUT = 1024 * 1024
EXPECTED_UID = 0
EXPECTED_GID = 0
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RULE_KEYS = {"action", "destination_port", "direction", "log", "protocol", "source"}
FIXED_MUTATIONS = (
    "disable", "set-default-policies", "remove-before-rules", "create-reviewed-rules", "verify-staged", "enable", "verify-activated",
)
RELEASE_COMMIT = {"commit-release-pending", "commit-lock-released", "boot-commit-config-verified"}
RELEASE_ROLLBACK = {"rollback-verified", "rollback-release-pending", "rollback-lock-released", "boot-config-restored"}
TERMINAL = {"committed", "rolled-back"}
BOOT_OWNED = {"boot-recovery-active", "boot-config-restored", "boot-commit-config-verified"}
JOURNAL_STATES = TERMINAL | RELEASE_COMMIT | RELEASE_ROLLBACK | BOOT_OWNED | {"prepared", "defaults-staged", "staged",
    "activated", "rollback-started", "rollback-retry-pending"}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def digest(value: bytes | Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def format_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str) -> dt.datetime:
    if not isinstance(value, str) or TIME.fullmatch(value) is None:
        raise ValueError("invalid timestamp")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} structure differs")
    return value


def secure_file(path: Path, mode: int, maximum: int = MAX_INPUT, uid: int | None = None, gid: int | None = None) -> bytes:
    info = path.lstat()
    expected_uid=EXPECTED_UID if uid is None else uid; expected_gid=EXPECTED_GID if gid is None else gid
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != mode or info.st_uid != expected_uid or \
            info.st_gid != expected_gid or info.st_nlink != 1:
        raise ValueError(f"{path.name} metadata differs")
    if info.st_size > maximum:
        raise ValueError(f"{path.name} is oversized")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        if len(raw) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError(f"{path.name} changed while reading")
        return raw
    finally:
        os.close(fd)


def ensure_dir(path: Path, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != EXPECTED_UID or info.st_gid != EXPECTED_GID or stat.S_IMODE(info.st_mode) != mode:
        raise ValueError(f"{path.name} directory metadata differs")


def write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def atomic_json(path: Path, value: Any) -> None:
    raw = canonical(value)
    ensure_dir(path.parent, 0o700)
    temporary = path.parent / ("." + path.name + ".pending")
    with contextlib.suppress(FileNotFoundError):
        temporary.unlink()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        write_all(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def atomic_owned_file(path: Path, raw: bytes, mode: int, uid: int, gid: int) -> None:
    parent=path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode)!=0o700 or parent.st_uid!=uid or parent.st_gid!=gid: raise ValueError("restore directory metadata differs")
    temporary=path.parent/("."+path.name+".firewall-restore")
    if temporary.exists():
        info=temporary.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1: raise ValueError("restore temporary metadata differs")
        temporary.unlink(); fsync_dir(path.parent)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        write_all(fd,raw); os.fchmod(fd,mode); os.fchown(fd,uid,gid); os.fsync(fd)
    finally: os.close(fd)
    os.replace(temporary,path); fsync_dir(path.parent)


def load_json(path: Path) -> dict[str, Any]:
    raw = secure_file(path, 0o600)
    value = json.loads(raw)
    if raw != canonical(value) or not isinstance(value, dict):
        raise ValueError(f"{path.name} is noncanonical")
    return value


def load_journal() -> dict[str, Any]:
    value = load_json(JOURNAL)
    exact(value, {"checkpoint", "configurationId", "deadline", "decision", "format", "planSha256", "sessionId", "snapshot", "state", "timerToken", "updatedAt"}, "journal")
    snapshot = validate_public_state(value["snapshot"])
    if value["format"] != FORMAT_JOURNAL or value["state"] not in JOURNAL_STATES or value["decision"] not in {"none","commit","rollback"} or \
            not isinstance(value["configurationId"], str) or not isinstance(value["sessionId"], str) or \
            not isinstance(value["planSha256"], str) or HEX64.fullmatch(value["planSha256"]) is None:
        raise ValueError("journal value differs")
    parse_time(value["deadline"]); parse_time(value["updatedAt"])
    if value["timerToken"] is not None and (not isinstance(value["timerToken"],str) or re.fullmatch(r"[0-9]+",value["timerToken"]) is None): raise ValueError("timer binding differs")
    if value["checkpoint"] is not None:
        exact(value["checkpoint"], {"after", "before", "expected", "label", "phase"}, "rollback checkpoint")
        validate_public_state(value["checkpoint"]["before"]); validate_public_state(value["checkpoint"]["expected"])
        if value["checkpoint"]["after"] is not None: validate_public_state(value["checkpoint"]["after"])
        if value["checkpoint"]["phase"] not in {"before", "after"} or not isinstance(value["checkpoint"]["label"], str): raise ValueError("checkpoint differs")
    return value


def load_policy() -> dict[str, Any]:
    raw = secure_file(POLICY, 0o644)
    value = json.loads(raw)
    if raw != canonical(value):
        raise ValueError("policy is noncanonical")
    exact(value, {"activation", "options", "ownership", "rules"}, "policy")
    if value["activation"] != "pve-api" or value["ownership"] != "pve-api":
        raise ValueError("policy authority differs")
    exact(value["options"], {"enable", "policy_in", "policy_out"}, "options")
    if value["options"] != {"enable": True, "policy_in": "DROP", "policy_out": "ACCEPT"}:
        raise ValueError("policy options differ")
    rules = value["rules"]
    if not isinstance(rules, list) or len(rules) != 6:
        raise ValueError("policy rule count differs")
    normalized = [validate_policy_rule(rule) for rule in rules]
    udp = [rule for rule in normalized if rule["protocol"] == "udp" and rule["destination_port"] == 41641]
    if len(udp) != 1 or udp[0]["source"] != "0.0.0.0/0":
        raise ValueError("underlay policy differs")
    value["rules"] = normalized
    return value


def validate_policy_rule(value: Any) -> dict[str, Any]:
    rule = exact(value, RULE_KEYS, "rule")
    if rule["direction"] != "IN" or rule["action"] != "ACCEPT" or rule["protocol"] not in {"tcp", "udp"} or \
            rule["log"] != "nolog" or not isinstance(rule["destination_port"], int) or isinstance(rule["destination_port"], bool) or \
            not 1 <= rule["destination_port"] <= 65535 or not isinstance(rule["source"], str) or not rule["source"]:
        raise ValueError("rule value differs")
    return dict(rule)


def normalize_bool(value: Any, default: bool = False) -> bool | None:
    if value is None:
        return default
    if value in (True, 1, "1"):
        return True
    if value in (False, 0, "0"):
        return False
    return None


def normalize_rule(value: Any) -> dict[str, Any] | None:
    allowed = RULE_KEYS | {"comment", "dest", "digest", "dport", "enable", "iface", "ipversion", "macro", "pos", "proto", "type"}
    if not isinstance(value, dict) or not set(value).issubset(allowed):
        return None
    enabled = normalize_bool(value.get("enable"), True)
    direction = value.get("type", value.get("direction"))
    action = value.get("action")
    protocol = value.get("proto", value.get("protocol"))
    direction = direction.upper() if isinstance(direction, str) else direction
    action = action.upper() if isinstance(action, str) else action
    protocol = protocol.lower() if isinstance(protocol, str) else protocol
    port = value.get("dport", value.get("destination_port"))
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if enabled is not True or direction != "IN" or action != "ACCEPT" or protocol not in {"tcp", "udp"} or \
            value.get("source") is None or value.get("log", "nolog") != "nolog" or \
            ("digest" in value and (not isinstance(value["digest"], str) or HEX40.fullmatch(value["digest"]) is None)) or \
            value.get("ipversion") not in (None, 0, "0", 4, "4") or \
            any(value.get(name) not in (None, "") for name in ("comment", "iface", "macro", "dest")):
        return None
    return {"action": "ACCEPT", "destination_port": port, "direction": "IN", "log": "nolog",
            "protocol": protocol, "source": value["source"]}


class Runner:
    deadline: float | None = None

    def run(self, argv: tuple[str, ...], attempts: int = 2, timeout: int = 5, accepted: tuple[int, ...] = (0,), allow_stderr: bool = False) -> bytes:
        if not argv or argv[0] not in {"/usr/bin/pvesh", "/usr/bin/systemctl", "/usr/sbin/pve-firewall", "/usr/sbin/usermod", "/usr/bin/loginctl", "/usr/bin/pkill", "/usr/bin/pgrep"}:
            raise ValueError("command catalogue differs")
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                remaining = timeout if self.deadline is None else self.deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("fixed command aggregate deadline expired")
                result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        timeout=min(timeout, remaining), env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
                if result.returncode not in accepted or (result.stderr and not allow_stderr):
                    raise RuntimeError("fixed command failed")
                return result.stdout
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                last = error
                if attempt + 1 < attempts:
                    if self.deadline is not None and self.deadline - time.monotonic() <= 1:
                        break
                    time.sleep(1)
        raise RuntimeError("fixed command exhausted retries") from last


def observe(runner: Runner) -> dict[str, Any]:
    options = json.loads(runner.run(("/usr/bin/pvesh", "get", "/cluster/firewall/options", "--output-format", "json")))
    rules = json.loads(runner.run(("/usr/bin/pvesh", "get", "/cluster/firewall/rules", "--output-format", "json")))
    if not isinstance(options, dict) or not isinstance(rules, list):
        raise ValueError("PVE firewall response differs")
    state_rules = []
    positions = []
    rule_digests: set[str | None] = set()
    for value in rules:
        normalized = normalize_rule(value)
        if normalized is None or not isinstance(value.get("pos"), int):
            raise ValueError("PVE firewall rule differs")
        state_rules.append(normalized)
        positions.append(value["pos"])
        rule_digests.add(value.get("digest"))
    if len(state_rules) != len({canonical(rule) for rule in state_rules}):
        raise ValueError("duplicate PVE firewall rule")
    if len(rule_digests) > 1:
        raise ValueError("PVE firewall rule digests differ")
    rules_digest = next(iter(rule_digests), None)
    pve_digest = options.get("digest")
    if not isinstance(pve_digest, str) or HEX40.fullmatch(pve_digest) is None:
        raise ValueError("PVE digest differs")
    enabled = normalize_bool(options.get("enable"), False)
    normalized_options = {name: value for name, value in options.items() if name != "digest"}
    normalized_options.update({"enable": enabled, "policy_in": options.get("policy_in", "ACCEPT"), "policy_out": options.get("policy_out", "ACCEPT")})
    if enabled is None or normalized_options["policy_in"] not in {"ACCEPT", "DROP", "REJECT"} or \
            normalized_options["policy_out"] not in {"ACCEPT", "DROP", "REJECT"} or any(not isinstance(name, str) or not name or
            not isinstance(value, (str, int, bool)) or isinstance(value, float) for name, value in normalized_options.items()):
        raise ValueError("PVE options differ")
    return {"digest": pve_digest, "options": normalized_options, "positions": positions, "rules": state_rules, "rulesDigest": rules_digest}


def public_state(value: dict[str, Any]) -> dict[str, Any]:
    primary = {name: value["options"][name] for name in ("enable","policy_in","policy_out")}
    option_state = [{"name":name,"value":item} for name,item in sorted(value["options"].items()) if name not in primary]
    return {"digest": value["digest"], "options": primary, "optionState": option_state, "rules": value["rules"]}


def full_options(value: dict[str, Any]) -> dict[str, Any]:
    return {**value["options"], **{item["name"]:item["value"] for item in value["optionState"]}}


def validate_public_state(value: Any) -> dict[str, Any]:
    state = exact(value, {"digest", "options", "optionState", "rules"}, "public state")
    options = state["options"]
    if not isinstance(options, dict) or not {"enable","policy_in","policy_out"}.issubset(options) or \
            not isinstance(state["digest"], str) or HEX40.fullmatch(state["digest"]) is None or \
            not isinstance(options["enable"], bool) or options["policy_in"] not in {"ACCEPT", "DROP", "REJECT"} or \
            options["policy_out"] not in {"ACCEPT", "DROP", "REJECT"} or set(options) != {"enable","policy_in","policy_out"} or \
            not isinstance(state["optionState"],list) or any(not isinstance(item,dict) or set(item)!={"name","value"} or not isinstance(item["name"],str) or item["name"] in options or not isinstance(item["value"],(str,int,bool)) for item in state["optionState"]) or len({item["name"] for item in state["optionState"]}) != len(state["optionState"]) or not isinstance(state["rules"], list) or \
            any(validate_policy_rule(rule) != rule for rule in state["rules"]):
        raise ValueError("public state value differs")
    return state


def secure_key() -> bytes:
    key = secure_file(KEY, 0o600, 128)
    if len(key) != 32:
        raise ValueError("attestation key differs")
    return key


def self_hash() -> str:
    return digest(secure_file(HELPER, 0o755, 2 * 1024 * 1024))


def installed_units_hash() -> str:
    names = ("home-lab-proxmox-firewall-backend-stop.service", "home-lab-proxmox-firewall-config-recovery.service",
             "home-lab-proxmox-firewall-post-recovery.service", "home-lab-proxmox-firewall-rollback.service",
             "home-lab-proxmox-firewall-rollback.timer")
    values = {name: digest(secure_file(SYSTEMD / name, 0o644)) for name in names}
    values["proxmox-firewall-boot-recovery"] = digest(secure_file(BOOT_HELPER, 0o755))
    values["proxmox-firewall-transport"] = digest(secure_file(TRANSPORT,0o755))
    dropin = secure_file(SYSTEMD / "pve-firewall.service.d/50-home-lab-firewall-recovery.conf", 0o644)
    if dropin != secure_file(SYSTEMD / "proxmox-firewall.service.d/50-home-lab-firewall-recovery.conf", 0o644):
        raise ValueError("firewall drop-ins differ")
    values["50-home-lab-firewall-recovery.conf"] = digest(dropin)
    return digest(values)


def inspection(runner: Runner) -> dict[str, Any]:
    policy = load_policy()
    now = utcnow()
    value = {"challenge": secrets.token_urlsafe(32), "expiresAt": format_time(now + dt.timedelta(seconds=300)),
             "format": FORMAT_INSPECTION, "helperSha256": self_hash(), "observedAt": format_time(now),
             "policySha256": digest(policy), "state": public_state(observe(runner)), "unitsSha256": installed_units_hash()}
    value["attestation"] = hmac.new(secure_key(), canonical(value), hashlib.sha256).hexdigest()
    return value


def validate_inspection(value: Any) -> dict[str, Any]:
    record = exact(value, {"attestation", "challenge", "expiresAt", "format", "helperSha256", "observedAt",
                           "policySha256", "state", "unitsSha256"}, "inspection")
    supplied = record["attestation"]
    signing = dict(record)
    signing.pop("attestation")
    validate_public_state(record["state"])
    if record["format"] != FORMAT_INSPECTION or any(not isinstance(record[name], str) or HEX64.fullmatch(record[name]) is None
            for name in ("helperSha256", "policySha256", "unitsSha256")) or not isinstance(supplied, str) or not hmac.compare_digest(
            supplied, hmac.new(secure_key(), canonical(signing), hashlib.sha256).hexdigest()):
        raise ValueError("inspection attestation differs")
    if parse_time(record["expiresAt"]) <= utcnow() or parse_time(record["observedAt"]) > utcnow():
        raise ValueError("inspection expired")
    return record


def validate_plan(value: Any) -> dict[str, Any]:
    plan = exact(value, {"bindings", "blockers", "configuration", "createdAt", "expiresAt", "format", "git",
                         "inspection", "mutations", "planSha256", "status", "version"}, "plan")
    exact(plan["bindings"], {"controllerSha256", "helperSha256", "policySha256", "planSchemaSha256", "privateSchemaSha256", "requestSchemaSha256", "unitsSha256"}, "bindings")
    exact(plan["configuration"], {"canaryCount", "id"}, "configuration")
    exact(plan["git"], {"commit", "tree"}, "git")
    if plan["configuration"]["canaryCount"] != 6 or not isinstance(plan["configuration"]["id"], str) or \
            any(not isinstance(value, str) or HEX64.fullmatch(value) is None for value in plan["bindings"].values()) or \
            any(not isinstance(plan["git"][name], str) or re.fullmatch(r"[0-9a-f]{40}", plan["git"][name]) is None for name in ("commit", "tree")) or \
            not isinstance(plan["blockers"], list):
        raise ValueError("plan value differs")
    supplied = plan["planSha256"]
    signing = dict(plan)
    signing.pop("planSha256")
    if plan["format"] != FORMAT_PLAN or plan["version"] != 1 or not isinstance(supplied, str) or \
            digest(signing) != supplied or plan["mutations"] != list(FIXED_MUTATIONS) or plan["status"] != "ready" or plan["blockers"]:
        raise ValueError("plan binding differs")
    now=utcnow(); created=parse_time(plan["createdAt"]); expires=parse_time(plan["expiresAt"])
    if created > now or expires <= now or expires > now + dt.timedelta(seconds=300) or (expires-created).total_seconds() > 300:
        raise ValueError("plan freshness differs")
    inspected = validate_inspection(plan["inspection"])
    if expires > parse_time(inspected["expiresAt"]): raise ValueError("plan exceeds inspection freshness")
    policy = load_policy()
    if plan["bindings"].get("helperSha256") != self_hash() or plan["bindings"].get("policySha256") != digest(policy) or \
            inspected["helperSha256"] != self_hash() or inspected["policySha256"] != digest(policy) or \
            inspected["unitsSha256"] != installed_units_hash() or plan["bindings"]["unitsSha256"] != installed_units_hash():
        raise ValueError("installed binding differs")
    return plan


def services_active(runner: Runner) -> bool:
    try:
        return all(runner.run(("/usr/bin/systemctl", "is-active", service), attempts=1).decode().strip() == "active" for service in SERVICES)
    except RuntimeError:
        return False


def backend_matches(runner: Runner, enabled: bool) -> bool:
    states = [runner.run(("/usr/bin/systemctl", "is-active", service)).decode().strip() for service in SERVICES]
    status_line = runner.run(("/usr/sbin/pve-firewall", "status")).decode().strip()
    return states == ["active", "active"] and status_line == ("Status: enabled/running" if enabled else "Status: disabled/running")


def rule_set(rules: list[dict[str, Any]]) -> set[bytes]:
    return {canonical(rule) for rule in rules}


def desired_matches(state: dict[str, Any], policy: dict[str, Any], enabled: bool, base_options: dict[str, Any] | None = None) -> bool:
    expected_options = dict(state["options"] if base_options is None else base_options)
    expected_options.update({**policy["options"], "enable": enabled})
    return state["options"] == expected_options and rule_set(state["rules"]) == rule_set(policy["rules"]) and len(state["rules"]) == len(policy["rules"])


def acquire(path: Path, nonblocking: bool = True) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != EXPECTED_UID or info.st_gid != EXPECTED_GID or \
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ValueError("mutex metadata differs")
        flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
        fcntl.flock(fd, flags)
        return fd
    except Exception:
        os.close(fd)
        raise


def reject_locks() -> None:
    if NIX_LOCK.exists():
        raise ValueError("Nix ownership lock is retained")
    if OWNER_LOCK.exists():
        raise ValueError("Ansible ownership lock is retained")


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def create_owner(session: str) -> None:
    if OWNER_LOCK.exists():
        if not (OWNER_LOCK / "owner").exists(): OWNER_LOCK.rmdir(); fsync_dir(OWNER_LOCK.parent)
        elif orphan_owner_session() == session: return
        else: raise ValueError("ownership lock is retained")
    os.mkdir(OWNER_LOCK, 0o700)
    fsync_dir(OWNER_LOCK.parent)
    fd = os.open(OWNER_LOCK / "owner", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        write_all(fd, f"controller=proxmox-firewall-controller\noperation=proxmox-firewall\nsession={session}\n".encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(OWNER_LOCK)


def orphan_owner_session() -> str | None:
    if not OWNER_LOCK.exists():
        return None
    info = OWNER_LOCK.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != EXPECTED_UID or info.st_gid != EXPECTED_GID or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("ownership lock metadata differs")
    raw = secure_file(OWNER_LOCK / "owner", 0o600, 1024)
    lines = raw.decode("ascii", "strict").splitlines()
    if len(lines) != 3 or lines[0] != "controller=proxmox-firewall-controller" or lines[1] != "operation=proxmox-firewall" or \
            not lines[2].startswith("session=") or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", lines[2][8:]) is None:
        raise ValueError("ownership lock content differs")
    return lines[2][8:]


def release_owner(session: str) -> None:
    if OWNER_LOCK.exists() and not (OWNER_LOCK / "owner").exists():
        OWNER_LOCK.rmdir(); fsync_dir(OWNER_LOCK.parent); return
    existing = orphan_owner_session()
    if existing is None: return
    if existing != session: raise ValueError("ownership lock session differs")
    (OWNER_LOCK / "owner").unlink(); fsync_dir(OWNER_LOCK)
    OWNER_LOCK.rmdir(); fsync_dir(OWNER_LOCK.parent)


def remove_authorization(session: str | None = None) -> None:
    if not AUTHORIZATION.exists(): return
    value = load_json(AUTHORIZATION)
    exact(value, {"expiresAt","format","planSha256","sessionId","state"}, "authorization")
    if session is not None and value["sessionId"] != session: raise ValueError("authorization session differs")
    AUTHORIZATION.unlink(); fsync_dir(AUTHORIZATION.parent)


def authorize(request: dict[str, Any], runner: Runner) -> dict[str, Any]:
    exact(request, {"approvePlanSha","format","gate","plan"}, "authorization request")
    if request["format"] != FORMAT_AUTHORIZE or request["gate"] != AUTHORIZE_GATE: raise ValueError("authorization gate differs")
    plan = validate_plan(request["plan"])
    require_isolated_access()
    if request["approvePlanSha"] != plan["planSha256"]: raise ValueError("authorization plan differs")
    mutex = acquire(MUTEX)
    try:
        if AUTHORIZATION.exists():
            prior = load_json(AUTHORIZATION)
            if not JOURNAL.exists() and prior.get("state") == "consumed" and prior.get("planSha256") == plan["planSha256"] and isinstance(prior.get("sessionId"),str):
                release_owner(prior["sessionId"]); AUTHORIZATION.unlink(); fsync_dir(AUTHORIZATION.parent)
            elif not JOURNAL.exists() and prior.get("state")=="authorized" and parse_time(prior.get("expiresAt"))<=utcnow():
                AUTHORIZATION.unlink(); fsync_dir(AUTHORIZATION.parent)
            else: raise ValueError("authorization already exists")
        if JOURNAL.exists() and load_journal()["state"] not in TERMINAL: raise ValueError("transaction is active")
        value = {"expiresAt": plan["expiresAt"], "format": FORMAT_AUTHORIZATION, "planSha256": plan["planSha256"],
                 "sessionId": None, "state": "authorized"}
        atomic_json(AUTHORIZATION, value)
        return {"format": FORMAT_RESULT, "planSha256": plan["planSha256"], "sessionId": None, "status": "authorized"}
    finally: os.close(mutex)


def local_console() -> None:
    fd = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
    try:
        raw=Path("/proc/self/stat").read_text(encoding="ascii")
        fields=raw.rsplit(") ",1)[1].split(); device=int(fields[4])
        if os.major(device)!=4 or not 1<=os.minor(device)<=63: raise ValueError("Linux virtual console is required")
    except (IndexError,UnicodeError,ValueError):
        raise ValueError("Linux virtual console is required") from None
    finally: os.close(fd)


def access_request(request: dict[str, Any], gate: str) -> None:
    exact(request,{"format","gate"},"access request")
    if request != {"format":"home-lab-proxmox-firewall-access-v1","gate":gate}: raise ValueError("access gate differs")


def terminate_tofu_sessions(runner: Runner) -> None:
    runner.run(("/usr/bin/loginctl","terminate-user","tofu-apply"),attempts=1,accepted=(0,1),allow_stderr=True)
    runner.run(("/usr/bin/pkill","--signal","KILL","--uid","tofu-apply"),attempts=1,accepted=(0,1))
    for attempt in range(5):
        if not runner.run(("/usr/bin/pgrep","--uid","tofu-apply"),attempts=1,accepted=(0,1)).strip(): return
        if attempt<4: time.sleep(1)
    raise RuntimeError("tofu-apply processes remain")


def isolate_access(request: dict[str, Any], runner: Runner) -> dict[str, Any]:
    access_request(request,ISOLATE_GATE); mutex=acquire(MUTEX)
    try:
        if ACCESS_SNAPSHOT.exists(): snapshot=load_json(ACCESS_SNAPSHOT)
        else:
            account=pwd.getpwnam("tofu-apply"); info=TOFU_KEYS.lstat(); raw=secure_file(TOFU_KEYS,0o600,MAX_INPUT,info.st_uid,info.st_gid)
            snapshot={"format":"home-lab-proxmox-firewall-access-snapshot-v1","gid":info.st_gid,"keys":base64.b64encode(raw).decode(),"mode":stat.S_IMODE(info.st_mode),"shell":account.pw_shell,"state":"prepared","uid":info.st_uid}
            atomic_json(ACCESS_SNAPSHOT,snapshot)
        if snapshot["format"]!="home-lab-proxmox-firewall-access-snapshot-v1" or snapshot["state"] not in {"prepared","isolated"} or snapshot["shell"]=="/usr/sbin/nologin": raise ValueError("access snapshot differs")
        if TOFU_KEYS.exists(): TOFU_KEYS.unlink(); fsync_dir(TOFU_KEYS.parent)
        runner.run(("/usr/sbin/usermod","--shell","/usr/sbin/nologin","tofu-apply"))
        terminate_tofu_sessions(runner)
        if pwd.getpwnam("tofu-apply").pw_shell!="/usr/sbin/nologin" or TOFU_KEYS.exists() or runner.run(("/usr/bin/pgrep","--uid","tofu-apply"),attempts=1,accepted=(0,1)).strip(): raise RuntimeError("tofu-apply isolation differs")
        snapshot["state"]="isolated"; atomic_json(ACCESS_SNAPSHOT,snapshot)
        return {"format":FORMAT_RESULT,"planSha256":None,"sessionId":None,"status":"tofu-apply-isolated"}
    finally: os.close(mutex)


def restore_access(request: dict[str, Any], runner: Runner) -> dict[str, Any]:
    access_request(request,RESTORE_GATE); mutex=acquire(MUTEX)
    try:
        journal=load_journal() if JOURNAL.exists() else None; snapshot=load_json(ACCESS_SNAPSHOT)
        if journal is not None and journal["state"] not in TERMINAL: raise ValueError("terminal transaction is required")
        if journal is None and snapshot.get("state")!="restoring-unused":
            authorization=load_json(AUTHORIZATION)
            if authorization.get("state")!="authorized" or authorization.get("sessionId") is not None: raise ValueError("unused authorization is required")
            snapshot["state"]="restoring-unused"; atomic_json(ACCESS_SNAPSHOT,snapshot)
            AUTHORIZATION.unlink(); fsync_dir(AUTHORIZATION.parent)
        if snapshot.get("state") not in {"isolated","restoring","restoring-unused"}: raise ValueError("access snapshot differs")
        snapshot["state"]="restoring-unused" if journal is None else "restoring"; atomic_json(ACCESS_SNAPSHOT,snapshot)
        raw=base64.b64decode(snapshot["keys"],validate=True)
        matches=False
        if TOFU_KEYS.exists():
            with contextlib.suppress(ValueError): matches=secure_file(TOFU_KEYS,snapshot["mode"],MAX_INPUT,snapshot["uid"],snapshot["gid"])==raw
        if not matches: atomic_owned_file(TOFU_KEYS,raw,snapshot["mode"],snapshot["uid"],snapshot["gid"])
        runner.run(("/usr/sbin/usermod","--shell",snapshot["shell"],"tofu-apply"))
        if pwd.getpwnam("tofu-apply").pw_shell!=snapshot["shell"]: raise RuntimeError("tofu-apply shell restore differs")
        ACCESS_SNAPSHOT.unlink(); fsync_dir(ACCESS_SNAPSHOT.parent)
        return {"format":FORMAT_RESULT,"planSha256":None if journal is None else journal["planSha256"],"sessionId":None if journal is None else journal["sessionId"],"status":"tofu-apply-restored"}
    finally: os.close(mutex)


def require_isolated_access() -> None:
    snapshot=load_json(ACCESS_SNAPSHOT)
    exact(snapshot,{"format","gid","keys","mode","shell","state","uid"},"access snapshot")
    if snapshot["format"]!="home-lab-proxmox-firewall-access-snapshot-v1" or snapshot["state"]!="isolated" or TOFU_KEYS.exists() or pwd.getpwnam("tofu-apply").pw_shell!="/usr/sbin/nologin": raise ValueError("tofu-apply is not isolated")


def consume_authorization(plan: dict[str, Any], session: str) -> None:
    value = load_json(AUTHORIZATION)
    exact(value, {"expiresAt","format","planSha256","sessionId","state"}, "authorization")
    if value != {"expiresAt": plan["expiresAt"], "format": FORMAT_AUTHORIZATION, "planSha256": plan["planSha256"],
                 "sessionId": None, "state": "authorized"} or parse_time(value["expiresAt"]) <= utcnow():
        raise ValueError("authorization differs")
    value["state"] = "consumed"; value["sessionId"] = session
    atomic_json(AUTHORIZATION, value)


def write_state(journal: dict[str, Any], state: str) -> None:
    journal["state"] = state
    journal["updatedAt"] = format_time(utcnow())
    atomic_json(JOURNAL, journal)


def pvesh(runner: Runner, *arguments: str) -> None:
    runner.run(("/usr/bin/pvesh", *arguments))


def same_content(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return left["options"] == right["options"] and rule_set(left["rules"]) == rule_set(right["rules"]) and len(left["rules"]) == len(right["rules"])


def set_options(runner: Runner, state: dict[str, Any], *, enable: bool, policy_in: str, policy_out: str) -> dict[str, Any]:
    pvesh(runner, "set", "/cluster/firewall/options", "--digest", state["digest"], "--enable", "1" if enable else "0",
           "--policy_in", policy_in, "--policy_out", policy_out)
    current = observe(runner); expected = {"options": {**state["options"], "enable": enable, "policy_in": policy_in, "policy_out": policy_out}, "rules": state["rules"]}
    if not same_content(current, expected): raise RuntimeError("option intermediate state differs")
    return current


def delete_rules(runner: Runner, state: dict[str, Any]) -> dict[str, Any]:
    current = state
    for position in sorted(current["positions"], reverse=True):
        index = current["positions"].index(position); removed = current["rules"][index]
        pvesh(runner, "delete", f"/cluster/firewall/rules/{position}", "--digest", current["rulesDigest"] or current["digest"])
        observed = observe(runner); expected = {"options": current["options"], "rules": [rule for offset, rule in enumerate(current["rules"]) if offset != index]}
        if not same_content(observed, expected): raise RuntimeError("delete intermediate state differs")
        current = observed
    return current


def create_rules(runner: Runner, state: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    current = state
    for rule in rules:
        pvesh(runner, "create", "/cluster/firewall/rules", "--digest", current["rulesDigest"] or current["digest"], "--type", rule["direction"].lower(),
               "--action", rule["action"], "--source", rule["source"], "--proto", rule["protocol"],
               "--dport", str(rule["destination_port"]), "--log", rule["log"], "--enable", "1")
        observed = observe(runner); expected = {"options": current["options"], "rules": current["rules"] + [rule]}
        if not same_content(observed, expected): raise RuntimeError("create intermediate state differs")
        current = observed
    return current


def timer_token(runner: Runner) -> str:
    if runner.run(("/usr/bin/systemctl","is-active",TIMER),attempts=1).decode().strip()!="active": raise RuntimeError("continuous rollback watchdog is inactive")
    token = runner.run(("/usr/bin/systemctl","show",TIMER,"--property=ActiveEnterTimestampMonotonic","--value")).decode().strip()
    if re.fullmatch(r"[1-9][0-9]*",token) is None: raise RuntimeError("rollback timer binding differs")
    return token


def checkpointed(journal: dict[str, Any], label: str, current: dict[str, Any], expected: dict[str, Any], operation: Any) -> dict[str, Any]:
    expected_public=public_state({"digest":"0"*40,"options":expected["options"],"rules":expected["rules"]})
    journal["checkpoint"] = {"after": None, "before": public_state(current), "expected":expected_public, "label": label, "phase": "before"}; write_state(journal, "rollback-started")
    observed = operation()
    if not same_content(observed, expected): raise RuntimeError("rollback intermediate state differs")
    journal["checkpoint"]["phase"] = "after"; journal["checkpoint"]["after"] = public_state(observed); write_state(journal, "rollback-started")
    return observed


def rollback_config(journal: dict[str, Any], runner: Runner) -> None:
    if journal["decision"] == "commit": raise ValueError("commit decision is durable")
    journal["decision"]="rollback"; write_state(journal, "rollback-started")
    try:
        current = observe(runner)
        checkpoint=journal["checkpoint"]
        if checkpoint is not None:
            observed_public=public_state(current)
            if checkpoint["phase"]=="after" and observed_public!=checkpoint["after"]: raise RuntimeError("rollback checkpoint drift")
            if checkpoint["phase"]=="before" and observed_public!=checkpoint["before"]:
                if full_options(observed_public)!=full_options(checkpoint["expected"]) or rule_set(observed_public["rules"])!=rule_set(checkpoint["expected"]["rules"]): raise RuntimeError("rollback checkpoint resume differs")
                checkpoint["after"]=observed_public; checkpoint["phase"]="after"; write_state(journal,"rollback-started")
        snapshot = journal["snapshot"]; snapshot_options = full_options(snapshot); policy = load_policy()
        if current["options"]["enable"]:
            expected = {"options": {**current["options"], "enable": False}, "rules": current["rules"]}
            current = checkpointed(journal, "disable", current, expected, lambda: set_options(runner,current,enable=False,policy_in=current["options"]["policy_in"],policy_out=current["options"]["policy_out"]))
        candidates = rule_set(policy["rules"])
        while True:
            match = next(((index, rule) for index, rule in enumerate(current["rules"]) if canonical(rule) in candidates and canonical(rule) not in rule_set(snapshot["rules"])), None)
            if match is None: break
            index, rule = match; position = current["positions"][index]
            expected = {"options": current["options"], "rules": [item for offset,item in enumerate(current["rules"]) if offset != index]}
            def remove(position: int = position, state: dict[str, Any] = current) -> dict[str, Any]:
                pvesh(runner,"delete",f"/cluster/firewall/rules/{position}","--digest",state["rulesDigest"] or state["digest"]); return observe(runner)
            current = checkpointed(journal, "remove-candidate", current, expected, remove)
        expected_options = {**current["options"], **snapshot_options, "enable": False}
        if current["options"] != expected_options:
            expected = {"options": expected_options, "rules": current["rules"]}
            current = checkpointed(journal,"restore-options",current,expected,lambda: set_options(runner,current,enable=False,policy_in=snapshot_options["policy_in"],policy_out=snapshot_options["policy_out"]))
        for rule in snapshot["rules"]:
            if canonical(rule) in rule_set(current["rules"]): continue
            expected = {"options": current["options"], "rules": current["rules"]+[rule]}
            current = checkpointed(journal,"restore-snapshot-rule",current,expected,lambda rule=rule: create_rules(runner,current,[rule]))
        if current["options"]["enable"] != snapshot_options["enable"]:
            expected = {"options": {**current["options"],"enable":snapshot_options["enable"]}, "rules":current["rules"]}
            current = checkpointed(journal,"restore-enable",current,expected,lambda: set_options(runner,current,enable=snapshot_options["enable"],policy_in=snapshot_options["policy_in"],policy_out=snapshot_options["policy_out"]))
        if current["options"] != snapshot_options or rule_set(current["rules"]) != rule_set(snapshot["rules"]) or len(current["rules"]) != len(snapshot["rules"]): raise RuntimeError("rollback state differs")
        journal["checkpoint"] = None; write_state(journal, "rollback-verified")
    except Exception:
        write_state(journal, "rollback-retry-pending"); raise


def finish_rollback(journal: dict[str, Any], runner: Runner, verify_backend: bool = True) -> None:
    if journal["state"] not in RELEASE_ROLLBACK:
        rollback_config(journal, runner)
    restored = public_state(observe(runner)); snapshot = journal["snapshot"]
    if full_options(restored) != full_options(snapshot) or rule_set(restored["rules"]) != rule_set(snapshot["rules"]) or len(restored["rules"]) != len(snapshot["rules"]):
        write_state(journal, "rollback-retry-pending"); raise RuntimeError("rollback release state differs")
    if verify_backend and not backend_matches(runner, snapshot["options"]["enable"]):
        write_state(journal, "rollback-retry-pending")
        raise RuntimeError("rollback backend differs")
    write_state(journal, "rollback-release-pending")
    release_owner(journal["sessionId"])
    write_state(journal, "rollback-lock-released")
    write_state(journal, "rolled-back")
    remove_authorization(journal["sessionId"])


def finish_commit(journal: dict[str, Any], runner: Runner) -> None:
    if journal["decision"] == "rollback": raise ValueError("rollback decision is durable")
    journal["decision"]="commit"
    if journal["state"] not in RELEASE_COMMIT:
        write_state(journal, "commit-release-pending")
    release_owner(journal["sessionId"])
    write_state(journal, "commit-lock-released")
    write_state(journal, "committed")
    remove_authorization(journal["sessionId"])


def begin(request: dict[str, Any], runner: Runner) -> dict[str, Any]:
    exact(request, {"format", "plan"}, "begin request")
    if request["format"] != FORMAT_BEGIN:
        raise ValueError("begin request format differs")
    plan = validate_plan(request["plan"])
    mutex = acquire(MUTEX)
    prior_deadline = getattr(runner, "deadline", None)
    runner.deadline = time.monotonic() + 60
    try:
        reject_locks()
        require_isolated_access()
        live = observe(runner)
        if public_state(live) != plan["inspection"]["state"] or live["options"]["enable"] or live["rules"]:
            raise ValueError("before-state changed")
        watchdog_token=timer_token(runner)
        session = secrets.token_urlsafe(32)
        consume_authorization(plan, session)
        create_owner(session)
        journal = {"checkpoint": None, "configurationId": plan["configuration"]["id"], "decision": "none", "deadline": format_time(utcnow() + dt.timedelta(seconds=300)), "format": FORMAT_JOURNAL,
                   "planSha256": plan["planSha256"], "sessionId": session, "snapshot": public_state(live),
                   "state": "prepared", "timerToken": watchdog_token, "updatedAt": format_time(utcnow())}
        atomic_json(JOURNAL, journal)
        try:
            policy = load_policy()
            current = set_options(runner, live, enable=False, policy_in="DROP", policy_out="ACCEPT")
            write_state(journal, "defaults-staged")
            current = delete_rules(runner, current)
            current = create_rules(runner, current, policy["rules"])
            if not desired_matches(current, policy, False, live["options"]):
                raise RuntimeError("staged policy differs")
            write_state(journal, "staged")
            current = set_options(runner, current, enable=True, policy_in="DROP", policy_out="ACCEPT")
            if not desired_matches(current, policy, True, live["options"]):
                raise RuntimeError("activated API policy differs")
            if not backend_matches(runner, True):
                raise RuntimeError("activated backend policy differs")
            write_state(journal, "activated")
            return {"deadline": journal["deadline"], "format": FORMAT_RESULT, "planSha256": plan["planSha256"],
                    "sessionId": session, "status": "activated"}
        except Exception:
            with contextlib.suppress(Exception):
                finish_rollback(journal, runner)
            raise
    finally:
        runner.deadline = prior_deadline
        os.close(mutex)


def commit(request: dict[str, Any], runner: Runner) -> dict[str, Any]:
    exact(request, {"canaries", "configurationId", "format", "planSha256", "sessionId"}, "commit request")
    if request["format"] != FORMAT_RESULT or set(request["canaries"]) != {"archNfs", "lanSsh", "lanTls", "tailscaleDirect", "tailnetSsh", "tailnetTls"} or \
            any(value is not True for value in request["canaries"].values()):
        raise ValueError("commit canaries differ")
    mutex = acquire(MUTEX)
    prior_deadline = getattr(runner, "deadline", None)
    runner.deadline = time.monotonic() + 30
    try:
        journal = load_journal()
        if request["sessionId"] != journal["sessionId"] or request["planSha256"] != journal["planSha256"] or \
                request["configurationId"] != journal["configurationId"]:
            raise ValueError("commit session differs")
        if journal["state"] in TERMINAL:
            release_owner(journal["sessionId"]); remove_authorization(journal["sessionId"])
            return {"format": FORMAT_RESULT, "planSha256": journal["planSha256"], "sessionId": journal["sessionId"], "status": journal["state"]}
        if journal["state"] in RELEASE_COMMIT:
            finish_commit(journal, runner)
        else:
            if journal["state"] != "activated" or (parse_time(journal["deadline"]) - utcnow()).total_seconds() < 120:
                raise ValueError("commit deadline differs")
            policy = load_policy()
            if not desired_matches(observe(runner), policy, True, full_options(journal["snapshot"])) or not backend_matches(runner, True):
                raise RuntimeError("commit postcondition differs")
            finish_commit(journal, runner)
        return {"format": FORMAT_RESULT, "planSha256": journal["planSha256"], "sessionId": journal["sessionId"], "status": "committed"}
    finally:
        runner.deadline = prior_deadline
        os.close(mutex)


def rollback(request: dict[str, Any] | None, runner: Runner, mode: str = "ordinary") -> dict[str, Any]:
    if mode not in {"ordinary", "timer", "boot-config", "boot-post"}: raise ValueError("rollback mode differs")
    mutex = acquire(MUTEX)
    prior_deadline = getattr(runner, "deadline", None)
    runner.deadline = time.monotonic() + 60
    try:
        if not JOURNAL.exists():
            if request is not None:
                raise ValueError("no active transaction")
            return {"format": FORMAT_RESULT, "planSha256": None, "sessionId": None, "status": "idle"}
        journal = load_journal()
        if mode == "timer" and journal["state"] not in TERMINAL | BOOT_OWNED:
            if journal["timerToken"] is not None and journal["timerToken"] != timer_token(runner): raise BlockingIOError("stale timer delivery")
            if utcnow() < parse_time(journal["deadline"]): raise BlockingIOError("rollback deadline has not elapsed")
        if request is not None:
            exact(request, {"format", "planSha256", "sessionId"}, "rollback request")
            if request["format"] != FORMAT_RESULT or request["sessionId"] != journal["sessionId"] or request["planSha256"] != journal["planSha256"]:
                raise ValueError("rollback session differs")
        if mode == "boot-config":
            prior_state = journal["state"]
            write_state(journal, "boot-recovery-active")
            if journal["decision"] == "commit" or prior_state in RELEASE_COMMIT | {"committed", "boot-commit-config-verified"}:
                policy = load_policy()
                if not desired_matches(observe(runner), policy, True, full_options(journal["snapshot"])): raise RuntimeError("boot commit configuration differs")
                write_state(journal, "boot-commit-config-verified"); status = "boot-commit-config-verified"
            else:
                rollback_config(journal, runner); write_state(journal, "boot-config-restored"); status = "boot-config-restored"
        elif mode == "boot-post":
            if journal["state"] == "boot-commit-config-verified":
                if not desired_matches(observe(runner), load_policy(), True, full_options(journal["snapshot"])) or not backend_matches(runner, True): raise RuntimeError("boot commit backend differs")
                finish_commit(journal, runner); status = "committed"
            elif journal["state"] == "boot-config-restored":
                snapshot = journal["snapshot"]
                observed = public_state(observe(runner))
                if full_options(observed) != full_options(snapshot) or rule_set(observed["rules"]) != rule_set(snapshot["rules"]) or len(observed["rules"]) != len(snapshot["rules"]) or not backend_matches(runner, snapshot["options"]["enable"]): raise RuntimeError("boot rollback backend differs")
                finish_rollback(journal, runner); status = "rolled-back"
            elif journal["state"] in TERMINAL: status = journal["state"]
            else: raise BlockingIOError("boot configuration phase incomplete")
        elif journal["state"] in BOOT_OWNED:
            raise BlockingIOError("boot recovery owns transaction")
        elif journal["state"] in TERMINAL:
            if journal["state"] == "rolled-back":
                snapshot = journal["snapshot"]; observed = public_state(observe(runner))
                if full_options(observed) != full_options(snapshot) or rule_set(observed["rules"]) != rule_set(snapshot["rules"]) or len(observed["rules"]) != len(snapshot["rules"]): raise RuntimeError("terminal rollback state differs")
            release_owner(journal["sessionId"]); remove_authorization(journal["sessionId"])
            status = journal["state"]
        elif journal["state"] in RELEASE_COMMIT:
            finish_commit(journal, runner); status = "committed"
        else:
            finish_rollback(journal, runner); status = "rolled-back"
        return {"format": FORMAT_RESULT, "planSha256": journal["planSha256"], "sessionId": journal["sessionId"], "status": status}
    finally:
        runner.deadline = prior_deadline
        os.close(mutex)


def status(runner: Runner) -> dict[str, Any]:
    if not JOURNAL.exists():
        firewall_owner=False
        if OWNER_LOCK.exists():
            if not (OWNER_LOCK/"owner").exists(): firewall_owner=True
            else:
                try: firewall_owner=orphan_owner_session() is not None
                except ValueError: firewall_owner=False
        try: timer_active=runner.run(("/usr/bin/systemctl","is-active",TIMER),attempts=1).decode().strip()=="active"
        except RuntimeError: timer_active=False
        state="orphaned" if AUTHORIZATION.exists() or ACCESS_SNAPSHOT.exists() or firewall_owner or not timer_active else "idle"
        return {"format": FORMAT_RESULT, "planSha256": None, "sessionId": None, "status": state}
    journal = load_journal()
    if journal["state"] == "committed":
        if not desired_matches(observe(runner),load_policy(),True,full_options(journal["snapshot"])) or not backend_matches(runner,True): raise RuntimeError("committed audit differs")
    elif journal["state"] == "rolled-back":
        snapshot=journal["snapshot"]; observed=public_state(observe(runner))
        if full_options(observed)!=full_options(snapshot) or rule_set(observed["rules"])!=rule_set(snapshot["rules"]) or len(observed["rules"])!=len(snapshot["rules"]) or not backend_matches(runner,snapshot["options"]["enable"]): raise RuntimeError("rollback audit differs")
    return {"format": FORMAT_RESULT, "planSha256": journal["planSha256"], "sessionId": journal["sessionId"], "status": journal["state"]}


def read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("request is oversized")
    value = json.loads(raw)
    if raw != canonical(value) or not isinstance(value, dict):
        raise ValueError("request is noncanonical")
    return value


def main() -> int:
    if os.geteuid() != 0:
        raise ValueError("root is required")
    if len(sys.argv) != 2 or sys.argv[1] not in {"authorize", "isolate-tofu-apply", "restore-tofu-apply", "inspect", "begin", "status", "commit", "rollback", "rollback-if-pending", "boot-config-recover", "boot-post-recover"}:
        print("usage: proxmox-firewall-transaction <authorize|isolate-tofu-apply|restore-tofu-apply|inspect|begin|status|commit|rollback|rollback-if-pending|boot-config-recover|boot-post-recover>", file=sys.stderr)
        return 64
    ensure_dir(RUNTIME, 0o700)
    runner = Runner()
    command = sys.argv[1]
    if command == "authorize":
        local_console(); result = authorize(read_request(), runner)
    elif command == "isolate-tofu-apply":
        local_console(); result = isolate_access(read_request(),runner)
    elif command == "restore-tofu-apply":
        local_console(); result = restore_access(read_request(),runner)
    elif command == "inspect":
        result = inspection(runner)
    elif command == "status":
        result = status(runner)
    elif command == "begin":
        result = begin(read_request(), runner)
    elif command == "commit":
        result = commit(read_request(), runner)
    elif command == "rollback":
        result = rollback(read_request(), runner)
    elif command == "rollback-if-pending":
        try: result = rollback(None, runner, mode="timer")
        except BlockingIOError: return 75
    elif command == "boot-config-recover":
        try: result = rollback(None, runner, mode="boot-config")
        except BlockingIOError: return 75
    else:
        try: result = rollback(None, runner, mode="boot-post")
        except BlockingIOError: return 75
    write_all(1, canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BlockingIOError, RuntimeError, ValueError, OSError, json.JSONDecodeError):
        print("proxmox-firewall-transaction: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
