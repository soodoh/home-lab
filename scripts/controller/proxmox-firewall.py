#!/usr/bin/env python3
"""Fixed controller for the reviewed Proxmox firewall transaction."""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PLAN_DIR = ROOT / ".reconcile/proxmox-firewall"
CONFIG = Path.home() / ".config/home-lab/controller/proxmox-firewall-canaries.json"
KEY = Path.home() / ".config/home-lab/controller/proxmox-firewall-controller.key"
LOCK = ROOT / ".reconcile/controller-apply.lock"
HELPER_SOURCE = ROOT / "ansible/roles/proxmox_firewall/files/proxmox-firewall-transaction.py"
POLICY_SOURCE = ROOT / "nix/proxmox/projection.json"
PLAN_SCHEMA = ROOT / "infrastructure/policy/proxmox-firewall-plan.schema.json"
PRIVATE_SCHEMA = ROOT / "infrastructure/policy/proxmox-firewall-private.schema.json"
REQUEST_SCHEMA = ROOT / "infrastructure/policy/proxmox-firewall-request.schema.json"
HOST_HELPER = "/usr/local/libexec/home-lab/proxmox-firewall-transaction"
SSH = "/usr/bin/ssh"
SSH_CONFIG = "/dev/null"
KNOWN_HOSTS = str(Path.home() / ".ssh/known_hosts")
PVE_IDENTITY = str(Path.home() / ".ssh/home-lab-proxmox-firewall")
PVE_SSH_TARGET = "firewall-apply@192.168.0.123"
LAN_CANARY_IDENTITY = str(Path.home() / ".ssh/home-lab-proxmox-lan-canary")
TAILNET_CANARY_IDENTITY = str(Path.home() / ".ssh/home-lab-proxmox-tailnet-canary")
ARCH_IDENTITY = str(Path.home() / ".ssh/home-lab-arch-ansible")
TAILSCALE = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
PROTECTED_UID = 0
PROTECTED_GID = 0
FORMAT_PLAN = "home-lab-proxmox-firewall-plan-v1"
FORMAT_PRIVATE = "home-lab-proxmox-firewall-private-v1"
FORMAT_BEGIN = "home-lab-proxmox-firewall-begin-v1"
FORMAT_RESULT = "home-lab-proxmox-firewall-result-v1"
MUTATIONS = ["disable", "set-default-policies", "remove-before-rules", "create-reviewed-rules", "verify-staged", "enable", "verify-activated"]
CHECKS = ("archNfs", "lanSsh", "lanTls", "tailscaleDirect", "tailnetSsh", "tailnetTls")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_PRIVATE = 1024 * 1024


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
        raise ValueError("timestamp differs")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} structure differs")
    return value


def validate_schema(value: Any, schema_path: Path) -> None:
    schema = json.loads(schema_path.read_bytes())
    def check(item: Any, rule: dict[str, Any], label: str) -> None:
        if "$ref" in rule:
            check(item, json.loads((schema_path.parent / rule["$ref"]).read_bytes()), label); return
        if "oneOf" in rule:
            matches = 0
            for alternative in rule["oneOf"]:
                try: check(item, alternative, label); matches += 1
                except ValueError: pass
            if matches != 1: raise ValueError(f"{label} schema differs")
            return
        kind = rule.get("type")
        valid = kind is None or (kind == "object" and isinstance(item, dict)) or (kind == "array" and isinstance(item, list)) or \
            (kind == "string" and isinstance(item, str)) or (kind == "boolean" and isinstance(item, bool)) or \
            (kind == "integer" and isinstance(item, int) and not isinstance(item, bool))
        if not valid or ("const" in rule and item != rule["const"]) or ("enum" in rule and item not in rule["enum"]):
            raise ValueError(f"{label} schema differs")
        if isinstance(item, str) and (("pattern" in rule and re.fullmatch(rule["pattern"], item) is None) or len(item) < rule.get("minLength",0) or len(item) > rule.get("maxLength",len(item))): raise ValueError(f"{label} schema differs")
        if isinstance(item, int) and (item < rule.get("minimum", item) or item > rule.get("maximum", item)): raise ValueError(f"{label} schema differs")
        if isinstance(item, dict):
            properties = rule.get("properties", {}); required = set(rule.get("required", []))
            if not required.issubset(item) or (rule.get("additionalProperties") is False and not set(item).issubset(properties)): raise ValueError(f"{label} schema differs")
            for name, child in item.items():
                if name in properties: check(child, properties[name], f"{label}.{name}")
        if isinstance(item, list) and "items" in rule:
            for child in item: check(child, rule["items"], label)
    check(value, schema, schema_path.name)


def run(argv: tuple[str, ...], *, stdin: bytes | None = None, timeout: int = 30, allowed=(0,)) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                            env={**os.environ, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    if result.returncode not in allowed or result.stderr:
        raise RuntimeError("fixed controller command failed")
    return result


def git_identity() -> tuple[str, str]:
    if run(("/usr/bin/git", "status", "--porcelain", "--untracked-files=all")).stdout:
        raise ValueError("worktree is not clean")
    commit = run(("/usr/bin/git", "rev-parse", "HEAD")).stdout.decode().strip()
    origin = run(("/usr/bin/git", "rev-parse", "refs/remotes/origin/main")).stdout.decode().strip()
    tree = run(("/usr/bin/git", "rev-parse", "HEAD^{tree}")).stdout.decode().strip()
    if commit != origin or HEX40.fullmatch(commit) is None or HEX40.fullmatch(tree) is None:
        raise ValueError("Git identity differs")
    return commit, tree


def secure_read(path: Path, mode: int, maximum: int = MAX_PRIVATE, owner: int | None = None) -> bytes:
    info = path.lstat()
    expected_owner = os.getuid() if owner is None else owner
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != mode or info.st_uid != expected_owner or \
            (owner is not None and info.st_gid != PROTECTED_GID) or info.st_nlink != 1 or info.st_size > maximum:
        raise ValueError(f"{path.name} metadata differs")
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


def ensure_plan_dir() -> None:
    for path in (ROOT / ".reconcile", PLAN_DIR):
        path.mkdir(exist_ok=True, mode=0o700)
        path.chmod(0o700)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("plan directory metadata differs")


def exclusive_write(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load_config() -> dict[str, str]:
    raw = secure_read(CONFIG, 0o600, owner=PROTECTED_UID)
    value = json.loads(raw)
    keys = {"archNfsSshTarget", "lanSshTarget", "lanTlsUrl", "pveCaPem", "tailscalePingTarget", "tailnetSshTarget", "tailnetTlsUrl"}
    exact(value, keys, "protected configuration")
    scalar_keys = keys - {"pveCaPem"}
    if raw != canonical(value) or any(not isinstance(value[name], str) or not value[name] or "\n" in value[name] for name in scalar_keys) or \
            not isinstance(value["pveCaPem"], str) or not value["pveCaPem"].startswith("-----BEGIN CERTIFICATE-----\n") or \
            not value["pveCaPem"].rstrip().endswith("-----END CERTIFICATE-----") or \
            any(not value[name].startswith("https://") for name in ("lanTlsUrl", "tailnetTlsUrl")) or \
            any(re.fullmatch(r"[A-Za-z0-9_.@-]+", value[name]) is None for name in
                ("archNfsSshTarget", "lanSshTarget", "tailscalePingTarget", "tailnetSshTarget")):
        raise ValueError("protected configuration differs")
    from urllib.parse import urlsplit
    lan_host, tail_host = urlsplit(value["lanTlsUrl"]).hostname, urlsplit(value["tailnetTlsUrl"]).hostname
    lan_ssh, tail_ssh = value["lanSshTarget"].rsplit("@", 1)[-1], value["tailnetSshTarget"].rsplit("@", 1)[-1]
    if not lan_host or not tail_host or lan_host == tail_host or lan_ssh == tail_ssh or value["lanSshTarget"] == value["tailnetSshTarget"]:
        raise ValueError("protected endpoints are not distinct")
    return value


def controller_key() -> bytes:
    key = secure_read(KEY, 0o600, 128, owner=PROTECTED_UID)
    if len(key) != 32:
        raise ValueError("controller key differs")
    return key


def host(command: str, request: dict[str, Any] | None = None) -> dict[str, Any]:
    if command not in {"inspect", "begin", "status", "commit", "rollback"}:
        raise ValueError("host command differs")
    argv = (SSH, "-F", SSH_CONFIG, "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
            "-o", "RequestTTY=no", "-o", "IdentitiesOnly=yes", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", "-i", PVE_IDENTITY,
            PVE_SSH_TARGET, command)
    result = run(argv, stdin=None if request is None else canonical(request), timeout=75)
    value = json.loads(result.stdout)
    if result.stdout != canonical(value) or not isinstance(value, dict):
        raise ValueError("host response differs")
    return value


def unit_binding() -> str:
    directory = ROOT / "ansible/roles/proxmox_firewall/files"
    names = sorted(path.name for path in directory.iterdir() if path.name.endswith((".service", ".timer", ".conf")) or
                   path.name in {"proxmox-firewall-boot-recovery","proxmox-firewall-transport"})
    return digest({name: digest((directory / name).read_bytes()) for name in names})


def bindings(policy: dict[str, Any]) -> dict[str, str]:
    return {"controllerSha256": digest(Path(__file__).read_bytes()), "helperSha256": digest(HELPER_SOURCE.read_bytes()),
            "policySha256": digest(policy), "planSchemaSha256": digest(PLAN_SCHEMA.read_bytes()),
            "privateSchemaSha256": digest(PRIVATE_SCHEMA.read_bytes()),
            "requestSchemaSha256": digest(REQUEST_SCHEMA.read_bytes()), "unitsSha256": unit_binding()}


def check_ssh(target: str, identity: str, arch: bool = False, deadline: float | None = None) -> bool:
    remote = "sudo -n -- /usr/local/libexec/home-lab/proxmox-firewall-nfs-canary check" if arch else "sudo -n true"
    for attempt in range(3):
        try:
            remaining = 30 if deadline is None else deadline - time.monotonic()
            if remaining <= 0: return False
            budget = 8 if arch else 5
            result = run((SSH, "-F", SSH_CONFIG, "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
                          "-o", "RequestTTY=no", "-o", "IdentitiesOnly=yes", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", "-i", identity,
                          "-o", "ConnectTimeout=5", target, remote), timeout=min(budget, remaining))
            if (arch and result.stdout == b"proxmox-firewall-nfs-canary=passed\n") or (not arch and not result.stdout):
                return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            pass
        if attempt < 2 and (deadline is None or deadline - time.monotonic() > 1):
            time.sleep(1)
    return False


def check_tls(url: str, ca: str, deadline: float | None = None) -> bool:
    for attempt in range(3):
        try:
            remaining = 30 if deadline is None else deadline - time.monotonic()
            if remaining <= 0: return False
            context = ssl.create_default_context(cadata=ca)
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
            with opener.open(url, timeout=min(5, remaining)) as response:
                if response.status == 200 and len(response.read(4097)) <= 4096:
                    return True
        except urllib.error.HTTPError as error:
            if error.code == 401 and len(error.read(4097)) <= 4096:
                return True
        except Exception:
            pass
        if attempt < 2 and (deadline is None or deadline - time.monotonic() > 1):
            time.sleep(1)
    return False


def check_direct(target: str, deadline: float | None = None) -> bool:
    for attempt in range(3):
        try:
            remaining = 30 if deadline is None else deadline - time.monotonic()
            if remaining <= 0: return False
            result = run((TAILSCALE, "ping", "--c", "1", "--timeout", "5s", target), timeout=min(5, remaining))
            text = result.stdout.decode("utf-8", "strict").strip()
            if re.fullmatch(r"pong from [^\r\n]+ \([^\r\n]+\) via (?:\d{1,3}\.){3}\d{1,3}:\d+ in [0-9.]+(?:ms|s)", text) is not None:
                return True
        except (OSError, RuntimeError, UnicodeError, subprocess.TimeoutExpired):
            pass
        if attempt < 2 and (deadline is None or deadline - time.monotonic() > 1):
            time.sleep(1)
    return False


def canaries(config: dict[str, str]) -> dict[str, bool]:
    deadline = time.monotonic() + 30
    jobs = {"lanSsh": (check_ssh, (config["lanSshTarget"], LAN_CANARY_IDENTITY, False, deadline)),
            "lanTls": (check_tls, (config["lanTlsUrl"], config["pveCaPem"], deadline)),
            "tailnetSsh": (check_ssh, (config["tailnetSshTarget"], TAILNET_CANARY_IDENTITY, False, deadline)),
            "tailnetTls": (check_tls, (config["tailnetTlsUrl"], config["pveCaPem"], deadline)),
            "archNfs": (check_ssh, (config["archNfsSshTarget"], ARCH_IDENTITY, True, deadline)),
            "tailscaleDirect": (check_direct, (config["tailscalePingTarget"], deadline))}
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=6)
    futures = {name: executor.submit(function, *arguments) for name, (function, arguments) in jobs.items()}
    try:
        done, pending = concurrent.futures.wait(futures.values(), timeout=max(0, deadline - time.monotonic()))
        for future in pending: future.cancel()
        return {name: future in done and future.exception() is None and future.result() is True for name, future in futures.items()}
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def validate_inspection(value: Any) -> dict[str, Any]:
    record = exact(value, {"attestation", "challenge", "expiresAt", "format", "helperSha256", "observedAt", "policySha256", "state", "unitsSha256"}, "inspection")
    state = exact(record["state"], {"digest", "options", "optionState", "rules"}, "inspection state")
    if not isinstance(state["options"], dict) or not {"enable", "policy_in", "policy_out"}.issubset(state["options"]):
        raise ValueError("inspection options differ")
    if record["format"] != "home-lab-proxmox-firewall-inspection-v1" or \
            any(not isinstance(record[name], str) or HEX64.fullmatch(record[name]) is None for name in ("attestation", "helperSha256", "policySha256", "unitsSha256")) or \
            not isinstance(state["digest"], str) or HEX40.fullmatch(state["digest"]) is None or not isinstance(state["rules"], list):
        raise ValueError("inspection value differs")
    parse_time(record["observedAt"]); parse_time(record["expiresAt"])
    return record


def load_projection_policy() -> dict[str, Any]:
    projection = json.loads(POLICY_SOURCE.read_bytes())
    return projection["apiIntent"]["pveFirewall"]


def make_plan() -> str:
    commit, tree = git_identity()
    ensure_plan_dir()
    config = load_config()
    inspected = validate_inspection(host("inspect"))
    now = utcnow()
    expires = min(now + dt.timedelta(seconds=300), parse_time(inspected["expiresAt"]))
    baseline = canaries(config)
    blockers = [name for name, matched in baseline.items() if not matched]
    configuration_id = secrets.token_urlsafe(32)
    policy = load_projection_policy()
    expected_bindings = bindings(policy)
    if inspected["helperSha256"] != expected_bindings["helperSha256"] or inspected["policySha256"] != expected_bindings["policySha256"] or \
            inspected["unitsSha256"] != expected_bindings["unitsSha256"]:
        blockers.append("installed-bindings")
    if inspected["state"]["options"].get("enable") is not False or inspected["state"]["rules"]:
        blockers.append("before-state")
    if parse_time(inspected["expiresAt"]) <= now:
        blockers.append("inspection-expired")
    blockers = sorted(set(blockers))
    value = {"bindings": expected_bindings, "blockers": blockers, "configuration": {"canaryCount": 6, "id": configuration_id},
             "createdAt": format_time(now), "expiresAt": format_time(expires), "format": FORMAT_PLAN,
             "git": {"commit": commit, "tree": tree}, "inspection": inspected, "mutations": MUTATIONS,
             "status": "ready" if not blockers else "blocked", "version": 1}
    value["planSha256"] = digest(value)
    sidecar = {"configuration": config, "configurationId": configuration_id, "createdAt": value["createdAt"],
               "expiresAt": value["expiresAt"], "format": FORMAT_PRIVATE, "planSha256": value["planSha256"], "preflight": baseline}
    sidecar["mac"] = hmac.new(controller_key(), canonical(sidecar), hashlib.sha256).hexdigest()
    validate_schema(value, PLAN_SCHEMA); validate_schema(sidecar, PRIVATE_SCHEMA)
    plan_path = PLAN_DIR / f"{value['planSha256']}.json"
    private_path = PLAN_DIR / f"{value['planSha256']}.private.json"
    exclusive_write(plan_path, canonical(value))
    exclusive_write(private_path, canonical(sidecar))
    return f"status={value['status']} blockers={len(blockers)} planSha256={value['planSha256']}"


def load_plan(plan_sha: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if HEX64.fullmatch(plan_sha) is None:
        raise ValueError("plan SHA differs")
    plan_raw = secure_read(PLAN_DIR / f"{plan_sha}.json", 0o600)
    private_raw = secure_read(PLAN_DIR / f"{plan_sha}.private.json", 0o600)
    plan, sidecar = json.loads(plan_raw), json.loads(private_raw)
    validate_schema(plan, PLAN_SCHEMA); validate_schema(sidecar, PRIVATE_SCHEMA)
    exact(plan, {"bindings", "blockers", "configuration", "createdAt", "expiresAt", "format", "git", "inspection",
                 "mutations", "planSha256", "status", "version"}, "saved plan")
    exact(sidecar, {"configuration", "configurationId", "createdAt", "expiresAt", "format", "mac", "planSha256", "preflight"}, "private sidecar")
    exact(sidecar["configuration"], {"archNfsSshTarget", "lanSshTarget", "lanTlsUrl", "pveCaPem", "tailscalePingTarget",
                                    "tailnetSshTarget", "tailnetTlsUrl"}, "private configuration")
    if plan_raw != canonical(plan) or private_raw != canonical(sidecar) or plan.get("planSha256") != plan_sha or \
            plan.get("format") != FORMAT_PLAN or plan.get("version") != 1 or sidecar.get("format") != FORMAT_PRIVATE:
        raise ValueError("saved plan differs")
    signing = dict(plan)
    signing.pop("planSha256")
    if digest(signing) != plan_sha or plan.get("status") != "ready" or plan.get("blockers") or plan.get("mutations") != MUTATIONS:
        raise ValueError("plan is not ready")
    supplied = sidecar.get("mac")
    private_signing = dict(sidecar)
    private_signing.pop("mac", None)
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, hmac.new(controller_key(), canonical(private_signing), hashlib.sha256).hexdigest()) or \
            sidecar.get("planSha256") != plan_sha or sidecar.get("configurationId") != plan["configuration"]["id"] or \
            sidecar.get("createdAt") != plan.get("createdAt") or sidecar.get("expiresAt") != plan.get("expiresAt") or \
            set(sidecar.get("preflight", {})) != set(CHECKS) or any(value is not True for value in sidecar["preflight"].values()):
        raise ValueError("private sidecar differs")
    if parse_time(plan["expiresAt"]) <= utcnow() or parse_time(sidecar["expiresAt"]) <= utcnow() or \
            parse_time(sidecar["createdAt"]) > utcnow() or (parse_time(plan["expiresAt"]) - parse_time(plan["createdAt"])).total_seconds() > 300:
        raise ValueError("plan expired")
    commit, tree = git_identity()
    if plan["git"] != {"commit": commit, "tree": tree} or plan["bindings"] != bindings(load_projection_policy()):
        raise ValueError("plan repository binding differs")
    return plan, sidecar


def controller_lock() -> int:
    LOCK.parent.mkdir(exist_ok=True, mode=0o700)
    parent = LOCK.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("controller lock directory differs")
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ValueError("controller lock metadata differs")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except Exception:
        os.close(fd)
        raise


def release_controller_lock(fd: int) -> None:
    try:
        path_info = LOCK.lstat()
        file_info = os.fstat(fd)
        if not stat.S_ISREG(path_info.st_mode) or (path_info.st_dev, path_info.st_ino) != (file_info.st_dev, file_info.st_ino):
            raise ValueError("controller lock identity differs")
        LOCK.unlink()
        directory = os.open(LOCK.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)


def apply(plan_sha: str, approved: str) -> str:
    if plan_sha != approved:
        raise ValueError("explicit plan approval differs")
    plan, sidecar = load_plan(plan_sha)
    lock = controller_lock()
    try:
        fresh_baseline = canaries(sidecar["configuration"])
        if set(fresh_baseline) != set(CHECKS) or any(value is not True for value in fresh_baseline.values()):
            raise RuntimeError("fresh pre-activation baseline failed")
        try:
            begun = host("begin", {"format": FORMAT_BEGIN, "plan": plan})
            session = begun.get("sessionId")
            if begun.get("status") != "activated" or begun.get("planSha256") != plan_sha or not isinstance(session, str) or re.fullmatch(r"[A-Za-z0-9_-]{32,128}",session) is None:
                raise RuntimeError("host activation response differs")
        except Exception:
            try:
                current=host("status"); recovery_session=current.get("sessionId")
                if current.get("planSha256")==plan_sha and isinstance(recovery_session,str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}",recovery_session):
                    host("rollback",{"format":FORMAT_RESULT,"planSha256":plan_sha,"sessionId":recovery_session})
            except Exception: pass
            raise
        rollback_request = {"format": FORMAT_RESULT, "planSha256": plan_sha, "sessionId": session}
        try:
            results = canaries(sidecar["configuration"])
            if set(results) != set(CHECKS) or any(value is not True for value in results.values()):
                raise RuntimeError("post-activation canary failed")
            request = {"canaries": results, "configurationId": sidecar["configurationId"], "format": FORMAT_RESULT,
                       "planSha256": plan_sha, "sessionId": session}
            validate_schema(request, REQUEST_SCHEMA)
            committed = host("commit", request)
            if committed.get("status") != "committed" or committed.get("planSha256") != plan_sha or committed.get("sessionId") != session:
                raise RuntimeError("host commit response differs")
        except Exception:
            host("rollback", rollback_request)
            raise
        return f"status=committed planSha256={plan_sha}"
    finally:
        release_controller_lock(lock)


def rollback_session(session: str) -> str:
    if not isinstance(session, str) or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", session) is None:
        raise ValueError("session differs")
    current = host("status")
    if current.get("sessionId") != session or not isinstance(current.get("planSha256"), str):
        raise ValueError("active session differs")
    result = host("rollback", {"format": FORMAT_RESULT, "planSha256": current["planSha256"], "sessionId": session})
    return f"status={result['status']} planSha256={result['planSha256']}"


def main() -> int:
    parser = argparse.ArgumentParser(prog="proxmox-firewall.py", allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", allow_abbrev=False)
    apply_parser = sub.add_parser("apply", allow_abbrev=False)
    apply_parser.add_argument("--plan-sha", required=True)
    apply_parser.add_argument("--approve-plan-sha", required=True)
    sub.add_parser("status", allow_abbrev=False)
    rollback_parser = sub.add_parser("rollback", allow_abbrev=False)
    rollback_parser.add_argument("--session-id", required=True)
    args = parser.parse_args()
    if args.command == "plan":
        result = make_plan()
    elif args.command == "apply":
        result = apply(args.plan_sha, args.approve_plan_sha)
    elif args.command == "status":
        result = json.dumps(host("status"), separators=(",", ":"), sort_keys=True)
    else:
        result = rollback_session(args.session_id)
    print(result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BlockingIOError, OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        print("proxmox-firewall: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
