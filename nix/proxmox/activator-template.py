#!/usr/bin/python3
"""Fixed, bundle-specific Proxmox activator (template input).

The generated helper accepts only closed protocol-v4 session envelopes.  Desired
bytes, target paths, identities, and native commands come from the embedded
catalog; none can be supplied by the caller.
"""

import base64
import datetime as dt
import fcntl
import grp
import hashlib
import hmac
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path

PROTOCOL = 4
SPEC = json.loads('@ACTIVATION_SPEC@')
MAX_STDIN_BYTES = 256 * 1024
MAX_COMMAND_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_ROLLBACK_RAW_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 48 * 1024 * 1024
MIN_FREE_BYTES = 128 * 1024 * 1024
MAX_RETAINED_SESSIONS = 8
SESSION_ROOT = Path("/var/lib/home-lab/reconciliation")
ROLLBACK_ROOT = SESSION_ROOT / "rollback"
LOCK_PATH = SESSION_ROOT / "apply.lock"
OPERATION_LOCK_PATH = SESSION_ROOT / "operation.lock"
ANSIBLE_LOCK_PATH = Path("/var/lib/iac-ansible-production.lock")
KEY_PATH = SESSION_ROOT / "session.key"
ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
HEX40_64 = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(label + " has an unknown or missing field")
    return value


def parse_time(value):
    if not isinstance(value, str) or not TIME.fullmatch(value):
        raise ValueError("invalid UTC timestamp")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def read_canonical_stdin():
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        raise ValueError("session envelope exceeds the fixed limit")
    value = json.loads(raw)
    if raw != canonical(value):
        raise ValueError("session envelope is not canonical JSON")
    return value


def self_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def ensure_fixed_root(path, mode):
    """Create/traverse a fixed absolute directory without following links."""
    if not hasattr(os, "O_NOFOLLOW") or not path.is_absolute():
        raise ValueError("no-follow traversal is unavailable")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        components = path.parts[1:]
        for index, component in enumerate(components):
            try:
                os.mkdir(component, mode, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            permissions = stat.S_IMODE(info.st_mode)
            final = index == len(components) - 1
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or \
                    (final and permissions != mode) or (not final and permissions & 0o022):
                os.close(child)
                raise ValueError("fixed runtime root ownership or mode is invalid")
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def open_fixed_parent(path):
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise ValueError("unsafe fixed target")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise ValueError("target parent is not a directory")
            os.close(fd)
            fd = child
        return fd, path.name
    except Exception:
        os.close(fd)
        raise


def lstat_fixed(path):
    parent, name = open_fixed_parent(path)
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    finally:
        os.close(parent)


def stable_fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_mtime_ns, info.st_ctime_ns)


def inspect_fixed(path, maximum=MAX_CAPTURE_BYTES):
    """Return one stable no-follow snapshot of a regular file or symlink."""
    parent, name = open_fixed_parent(path)
    try:
        first = os.stat(name, dir_fd=parent, follow_symlinks=False)
        first_fingerprint = stable_fingerprint(first)
        if stat.S_ISREG(first.st_mode):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                before = os.fstat(fd)
                if stable_fingerprint(before) != first_fingerprint or before.st_nlink != 1 or before.st_size > maximum:
                    raise ValueError("target changed during no-follow inspection")
                chunks = []
                total = 0
                while total <= maximum:
                    block = os.read(fd, min(65536, maximum + 1 - total))
                    if not block:
                        break
                    chunks.append(block)
                    total += len(block)
                if total > maximum:
                    raise ValueError("target exceeds capture limit")
                after = os.fstat(fd)
                if stable_fingerprint(after) != stable_fingerprint(before):
                    raise ValueError("target changed during no-follow inspection")
                return after, b"".join(chunks), None
            finally:
                os.close(fd)
        if stat.S_ISLNK(first.st_mode):
            link = os.readlink(name, dir_fd=parent)
            second = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stable_fingerprint(second) != first_fingerprint:
                raise ValueError("symlink changed during no-follow inspection")
            return second, None, link
        return first, None, None
    finally:
        os.close(parent)


def read_fixed_file(path, maximum=MAX_CAPTURE_BYTES):
    info, data, _ = inspect_fixed(path, maximum)
    if not stat.S_ISREG(info.st_mode) or data is None:
        raise ValueError("target is not a bounded single-link regular file")
    return data, info


def catalog_key(domain, target):
    name = target.get("path") if isinstance(target, dict) else None
    if domain == "services" and isinstance(target, dict):
        name = target.get("name")
    if not isinstance(name, str):
        raise ValueError("action target is invalid")
    return domain + "\0" + name


def catalog_item(action):
    exact(action, {"after", "approvalRequired", "before", "dependsOn", "domain", "id", "kind", "postconditions",
                   "preconditionSha256", "rebootRequired", "safetyClass", "sequence", "target", "watchdogRequired"}, "action")
    if not isinstance(action["sequence"], int) or isinstance(action["sequence"], bool) or action["sequence"] < 1:
        raise ValueError("action sequence is invalid")
    item = SPEC["catalog"].get(catalog_key(action["domain"], action["target"]))
    if item is None:
        raise ValueError("action is not in the fixed automatic catalog")
    fixed = {key: action[key] for key in ("domain", "kind", "target", "after", "approvalRequired", "rebootRequired", "safetyClass", "watchdogRequired")}
    if fixed != item["action"]:
        raise ValueError("action differs from the fixed catalog")
    if action["watchdogRequired"] or action["safetyClass"] in {"access-critical", "data-critical", "protected-session"}:
        raise ValueError("protected or watchdog action is closed until bootstrap qualification")
    if action["domain"] not in {"managed-files", "managed-fragments", "managed-artifacts", "services"}:
        raise ValueError("action domain is not dispatchable")
    before = action["before"]
    if not isinstance(before, dict) or before.get("state") not in {"absent", "present"}:
        raise ValueError("action before-state is invalid")
    target_name = action["target"].get("path", action["target"].get("name"))
    expected_precondition = hashlib.sha256(canonical({"before": before, "domain": action["domain"], "target": target_name})).hexdigest()
    expected_id = hashlib.sha256(canonical({"after": action["after"], "before": before, "domain": action["domain"],
                                            "kind": action["kind"], "target": target_name})).hexdigest()
    if action["preconditionSha256"] != expected_precondition or action["id"] != expected_id:
        raise ValueError("action identifiers are invalid")
    if action["postconditions"] != [{"expected": action["after"], "type": "state-equals"}]:
        raise ValueError("action postcondition is invalid")
    expected_dependencies = [] if action["sequence"] == 1 else None
    if expected_dependencies is not None and action["dependsOn"] != expected_dependencies:
        raise ValueError("first action dependencies are invalid")
    if action["sequence"] > 1 and (not isinstance(action["dependsOn"], list) or len(action["dependsOn"]) != 1 or not HEX64.fullmatch(action["dependsOn"][0])):
        raise ValueError("action dependencies are invalid")
    return item


def state_from_inspection(item, info, data, link):
    path = Path(item["path"])
    record = {"state": "present", "type": "file" if stat.S_ISREG(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "other",
              "ownerMatches": pwd.getpwuid(info.st_uid).pw_name == item["owner"],
              "groupMatches": grp.getgrgid(info.st_gid).gr_name == item["group"],
              "mode": "0%03o" % stat.S_IMODE(info.st_mode), "contentMatches": False}
    if stat.S_ISREG(info.st_mode) and data is not None:
        record["contentMatches"] = hashlib.sha256(data).hexdigest() == item["sha256"]
    elif stat.S_ISLNK(info.st_mode) and item.get("symlinkTarget"):
        record["symlinkTargetMatches"] = link == item["symlinkTarget"]
        if record["symlinkTargetMatches"]:
            target_data, target_info = read_fixed_file(path.parent / link)
            record["contentMatches"] = hashlib.sha256(target_data).hexdigest() == item["sha256"]
            record["ownerMatches"] = pwd.getpwuid(target_info.st_uid).pw_name == item["owner"]
            record["groupMatches"] = grp.getgrgid(target_info.st_gid).gr_name == item["group"]
            record["mode"] = "0%03o" % stat.S_IMODE(target_info.st_mode)
    if "symlinkTargetMatches" in item["after"] and "symlinkTargetMatches" not in record:
        record["symlinkTargetMatches"] = item.get("symlinkTarget") is None
    return record


def file_snapshot(item):
    try:
        info, data, link = inspect_fixed(Path(item["path"]))
        return state_from_inspection(item, info, data, link), data, (info.st_dev, info.st_ino)
    except FileNotFoundError:
        return {"state": "absent"}, None, None


def file_state(item):
    return file_snapshot(item)[0]


def fragment_state(item):
    state, data, _ = file_snapshot(item)
    if state["state"] == "absent":
        return state
    state.pop("contentMatches", None)
    count = 0
    if state["type"] == "file" and data is not None:
        text = data.decode("utf-8", "strict")
        count = sum(1 for line in text.splitlines() if line == item["line"])
    state["matchCount"] = count
    return state


def run_native(arguments, accepted=(0,)):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=30)
    if result.returncode not in accepted or result.stderr or len(result.stdout) > MAX_COMMAND_BYTES:
        raise ValueError("fixed native command failed")
    return result.stdout


def service_state(item):
    enabled = run_native(("/usr/bin/systemctl", "is-enabled", item["name"]), (0, 1, 3, 4)).strip() == b"enabled"
    active = run_native(("/usr/bin/systemctl", "is-active", item["name"]), (0, 3, 4)).strip() == b"active"
    return {"state": "present", "active": active, "enabled": enabled}


def observe_item(item):
    if item["domain"] == "managed-fragments":
        return fragment_state(item)
    if item["domain"] == "services":
        return service_state(item)
    return file_state(item)


def session_paths(plan_sha):
    return ROLLBACK_ROOT / plan_sha, ROLLBACK_ROOT / plan_sha / "manifest.json"


def read_lock():
    raw, info = read_fixed_file(LOCK_PATH, 65536)
    if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("host lock metadata is not root mode-0600")
    value = json.loads(raw)
    if raw != canonical(value):
        raise ValueError("host lock metadata is not canonical")
    exact(value, {"activatorSha256", "bundleContentSha256", "gitCommit", "gitTree", "hostSessionId", "operation", "planSha256", "startedAt"}, "host lock")
    return value


def write_exclusive_fixed(path, content, mode=0o600):
    parent, name = open_fixed_parent(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def revalidate_identity(parent, name, expected_fingerprint):
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        actual = stable_fingerprint(info)
    except FileNotFoundError:
        actual = None
    if actual != expected_fingerprint:
        raise ValueError("target changed between capture and replacement")


def replace_fixed(path, content, owner, group, mode, expected_identity=None):
    parent, name = open_fixed_parent(path)
    temporary = ".home-lab-activate-%d" % os.getpid()
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            os.write(fd, content)
            os.fchmod(fd, int(mode, 8))
            os.fchown(fd, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)
            os.fsync(fd)
        finally:
            os.close(fd)
        revalidate_identity(parent, name, expected_identity)
        os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    except Exception:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(parent)


def read_canonical_root_file(path, maximum, label):
    raw, info = read_fixed_file(path, maximum)
    if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(label + " mode is invalid")
    value = json.loads(raw)
    if raw != canonical(value):
        raise ValueError(label + " is not canonical")
    return value


def replace_canonical_root_file(path, value):
    try:
        info = lstat_fixed(path)
        expected_identity = stable_fingerprint(info)
    except FileNotFoundError:
        expected_identity = None
    parent, name = open_fixed_parent(path)
    temporary = ".state-%d" % os.getpid()
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            os.write(fd, canonical(value))
            os.fchown(fd, 0, 0)
            os.fsync(fd)
        finally:
            os.close(fd)
        revalidate_identity(parent, name, expected_identity)
        os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    except Exception:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(parent)


def validate_manifest(value, plan_sha):
    exact(value, {"actionManifestSha256", "actions", "entries", "format", "planSha256"}, "rollback manifest")
    if value["format"] != "home-lab-proxmox-rollback-v2" or value["planSha256"] != plan_sha or \
            not isinstance(value["entries"], list) or validate_action_manifest(value["actions"]) != value["actionManifestSha256"]:
        raise ValueError("rollback manifest binding is invalid")
    for index, entry in enumerate(value["entries"], 1):
        common = {"actionId", "capturedFingerprint", "identity", "original", "sequence", "targetType"}
        if not isinstance(entry, dict) or frozenset(entry) not in {frozenset(common), frozenset(common | {"path"})}:
            raise ValueError("rollback entry shape is invalid")
        action = value["actions"][index - 1] if index <= len(value["actions"]) else None
        expected_identity = None if action is None else catalog_key(action["domain"], action["target"])
        expected_target_type = None if action is None else "service" if action["domain"] == "services" else "path"
        if action is None or entry["sequence"] != index or entry["actionId"] != action["id"] or \
                entry["identity"] != expected_identity or entry["targetType"] != expected_target_type:
            raise ValueError("rollback entry action binding is invalid")
        if entry["targetType"] == "service":
            if set(entry) != common or entry["capturedFingerprint"] is not None or \
                    not isinstance(entry["original"], dict) or set(entry["original"]) != {"active", "enabled", "state"} or \
                    entry["original"]["state"] != "present" or \
                    any(not isinstance(entry["original"][key], bool) for key in ("active", "enabled")):
                raise ValueError("service rollback entry is invalid")
        else:
            if set(entry) != common | {"path"} or entry["path"] != action["target"].get("path"):
                raise ValueError("path rollback entry is invalid")
            original = entry["original"]
            if not isinstance(original, dict) or original.get("type") not in {"absent", "file", "symlink"}:
                raise ValueError("path rollback original is invalid")
            if original["type"] == "absent":
                exact(original, {"type"}, "absent rollback original")
                if entry["capturedFingerprint"] is not None:
                    raise ValueError("absent rollback fingerprint is invalid")
            elif original["type"] == "file":
                exact(original, {"contentBase64", "gid", "mode", "type", "uid"}, "file rollback original")
                if not isinstance(original["uid"], int) or isinstance(original["uid"], bool) or \
                        not isinstance(original["gid"], int) or isinstance(original["gid"], bool) or \
                        not isinstance(original["mode"], str) or not re.fullmatch(r"0[0-7]{3}", original["mode"]):
                    raise ValueError("file rollback metadata is invalid")
                try:
                    base64.b64decode(original["contentBase64"], validate=True)
                except (ValueError, TypeError) as error:
                    raise ValueError("file rollback content is invalid") from error
            else:
                exact(original, {"target", "type"}, "symlink rollback original")
                if not isinstance(original["target"], str) or "/" in original["target"] or original["target"] in {".", ".."}:
                    raise ValueError("symlink rollback original is invalid")
            fingerprint = entry["capturedFingerprint"]
            if original["type"] != "absent" and (not isinstance(fingerprint, list) or len(fingerprint) != 9 or
                                                   any(not isinstance(item, int) or isinstance(item, bool) for item in fingerprint)):
                raise ValueError("rollback fingerprint is invalid")
    return value


def read_manifest(plan_sha):
    _, path = session_paths(plan_sha)
    return validate_manifest(read_canonical_root_file(path, MAX_MANIFEST_BYTES, "rollback manifest"), plan_sha)


def save_manifest(plan_sha, manifest):
    validate_manifest(manifest, plan_sha)
    if len(canonical(manifest)) > MAX_MANIFEST_BYTES:
        raise ValueError("serialized rollback manifest capacity exceeded")
    _, path = session_paths(plan_sha)
    replace_canonical_root_file(path, manifest)


def journal_path(plan_sha):
    session, _ = session_paths(plan_sha)
    return session / "journal.json"


def validate_journal(value, plan_sha):
    exact(value, {"actionManifestSha256", "challenge", "completed", "format", "hostSessionId", "nextSequence",
                  "ownership", "pendingTransition", "planSha256", "state", "terminalResult"}, "session journal")
    states = {"initializing", "begun", "applying", "action-pending", "action-retryable", "failed",
              "rollback-in-progress", "rollback-failed", "committed-release-pending", "recovered-release-pending",
              "released-committed", "released-recovered"}
    if value["format"] != "home-lab-proxmox-session-journal-v2" or value["planSha256"] != plan_sha or \
            value["state"] not in states or not HEX64.fullmatch(value["actionManifestSha256"]) or \
            not TOKEN.fullmatch(value["challenge"]) or not TOKEN.fullmatch(value["hostSessionId"]) or \
            not isinstance(value["completed"], list) or not isinstance(value["nextSequence"], int) or value["nextSequence"] < 1:
        raise ValueError("session journal binding is invalid")
    ownership = exact(value["ownership"], {"activatorSha256", "bundleContentSha256", "gitCommit", "gitTree",
                                           "hostSessionId", "operation", "planSha256", "startedAt"}, "journal ownership")
    if ownership["hostSessionId"] != value["hostSessionId"] or ownership["planSha256"] != plan_sha or \
            ownership["operation"] != "proxmox-guarded-apply" or not HEX64.fullmatch(ownership["activatorSha256"]) or \
            not HEX64.fullmatch(ownership["bundleContentSha256"]) or not HEX40_64.fullmatch(ownership["gitCommit"]) or \
            not HEX40_64.fullmatch(ownership["gitTree"]):
        raise ValueError("journal ownership binding is invalid")
    parse_time(ownership["startedAt"])
    for record in value["completed"]:
        exact(record, {"actionId", "operation", "requestSha256", "result"}, "completed transition")
        if record["operation"] not in {"begin", "action", "commit", "rollback"} or \
                not HEX64.fullmatch(record["requestSha256"]) or not isinstance(record["result"], dict) or \
                (record["operation"] == "action") != isinstance(record["actionId"], str):
            raise ValueError("completed transition is invalid")
        if isinstance(record["actionId"], str) and not HEX64.fullmatch(record["actionId"]):
            raise ValueError("completed action identifier is invalid")
    pending = value["pendingTransition"]
    if pending is not None:
        if not isinstance(pending, dict) or pending.get("operation") not in {"begin", "action", "rollback"} or \
                not HEX64.fullmatch(pending.get("requestSha256", "")):
            raise ValueError("pending transition is invalid")
        if pending["operation"] == "begin":
            exact(pending, {"operation", "requestSha256"}, "pending begin")
        elif pending["operation"] == "action":
            exact(pending, {"actionId", "operation", "requestSha256", "sequence", "stage"}, "pending action")
            if not HEX64.fullmatch(pending["actionId"]) or not isinstance(pending["sequence"], int) or \
                    pending["stage"] not in {"prepared", "postcondition-pending"}:
                raise ValueError("pending action is invalid")
        else:
            exact(pending, {"operation", "remainingActionIds", "requestSha256", "restoredActionIds"}, "pending rollback")
            for key in ("remainingActionIds", "restoredActionIds"):
                if not isinstance(pending[key], list) or any(not HEX64.fullmatch(item) for item in pending[key]):
                    raise ValueError("pending rollback progress is invalid")
    expected_pending = {"initializing": "begin", "action-pending": "action", "action-retryable": "action",
                        "failed": "action", "rollback-in-progress": "rollback", "rollback-failed": "rollback"}.get(value["state"])
    if (pending is None) != (expected_pending is None) or (pending is not None and pending["operation"] != expected_pending):
        raise ValueError("journal state and pending transition differ")
    return value


def read_journal(plan_sha):
    return validate_journal(read_canonical_root_file(journal_path(plan_sha), 2 * 1024 * 1024,
                                                     "session journal"), plan_sha)


def save_journal(plan_sha, journal):
    validate_journal(journal, plan_sha)
    replace_canonical_root_file(journal_path(plan_sha), journal)


def validate_session_consistency(journal, manifest):
    actions = manifest["actions"]
    entries = manifest["entries"]
    state = journal["state"]
    completed_count = journal["nextSequence"] - 1
    if journal["actionManifestSha256"] != manifest["actionManifestSha256"] or \
            completed_count < 0 or completed_count > len(actions) or len(entries) not in {completed_count, completed_count + 1}:
        raise ValueError("journal and rollback manifest differ")
    stable = {"initializing", "begun", "applying", "committed-release-pending", "released-committed"}
    if state in stable and len(entries) != completed_count:
        raise ValueError("stable journal has an uncompleted capture")

    begin_result = {"actionManifestSha256": journal["actionManifestSha256"],
                    "hostSessionId": journal["hostSessionId"], "planSha256": journal["planSha256"], "status": "begun"}
    expected_records = []
    if state != "initializing":
        expected_records.append(("begin", None, begin_result))
    for action in actions[:completed_count]:
        expected_records.append(("action", action["id"], {"actionId": action["id"],
            "hostSessionId": journal["hostSessionId"], "sequence": action["sequence"], "status": "applied"}))

    commit_state = state in {"committed-release-pending", "released-committed"}
    recovered_state = state in {"recovered-release-pending", "released-recovered"}
    terminal_result = None
    if commit_state:
        if completed_count != len(actions) or len(entries) != len(actions) or journal["pendingTransition"] is not None:
            raise ValueError("committed session is incomplete")
        terminal_result = {"hostSessionId": journal["hostSessionId"],
                           "planSha256": journal["planSha256"], "status": "committed"}
        expected_records.append(("commit", None, terminal_result))
    elif recovered_state:
        if journal["pendingTransition"] is not None:
            raise ValueError("recovered session retains a pending transition")
        terminal_result = {"hostSessionId": journal["hostSessionId"], "planSha256": journal["planSha256"],
                           "restoredActionIds": [entry["actionId"] for entry in reversed(entries)], "status": "recovered"}
        expected_records.append(("rollback", None, terminal_result))
    elif journal["terminalResult"] is not None:
        raise ValueError("nonterminal session has a terminal result")
    if journal["terminalResult"] != terminal_result:
        raise ValueError("terminal result differs from exact terminal transition")

    records = journal["completed"]
    if len(records) != len(expected_records):
        raise ValueError("completed transition count differs")
    for record, (operation, action_id, result) in zip(records, expected_records):
        if record["operation"] != operation or record["actionId"] != action_id or record["result"] != result:
            raise ValueError("completed transition result differs")

    pending = journal["pendingTransition"]
    if pending is not None and pending["operation"] == "action":
        if completed_count >= len(actions) or pending["actionId"] != actions[completed_count]["id"] or \
                pending["sequence"] != completed_count + 1:
            raise ValueError("pending action differs from next exact action")
    if pending is not None and pending["operation"] == "rollback":
        reverse_entries = [entry["actionId"] for entry in reversed(entries)]
        if pending["restoredActionIds"] + pending["remainingActionIds"] != reverse_entries:
            raise ValueError("pending rollback progress differs from captured actions")


def retain_diagnostic(plan_sha, operation, action_id=None):
    session, _ = session_paths(plan_sha)
    value = {"actionId": action_id, "operation": operation, "planSha256": plan_sha,
             "status": "inspection-required"}
    safe_operation = operation if operation in {"action-failed", "controller-requested-rollback", "rollback-verification-failed"} else "unknown"
    suffix = action_id if action_id is not None and HEX64.fullmatch(action_id) else "session"
    try:
        write_exclusive_fixed(session / ("diagnostic-" + safe_operation + "-" + suffix + ".json"), canonical(value))
    except FileExistsError:
        pass


def capture_once(plan_sha, action, item):
    manifest = read_manifest(plan_sha)
    identity = action["domain"] + "\0" + item.get("path", item.get("name"))
    if any(entry["identity"] == identity for entry in manifest["entries"]):
        raise ValueError("target was already captured by this exact plan")
    expected_identity = None
    if item["domain"] == "services":
        captured_state = observe_item(item)
        entry = {"actionId": action["id"], "capturedFingerprint": None, "identity": identity,
                 "original": captured_state, "sequence": action["sequence"], "targetType": "service"}
    else:
        path = Path(item["path"])
        try:
            info, data, link = inspect_fixed(path)
            expected_identity = stable_fingerprint(info)
            captured_state = state_from_inspection(item, info, data, link)
            if item["domain"] == "managed-fragments":
                captured_state.pop("contentMatches", None)
                captured_state["matchCount"] = sum(1 for line in (data or b"").decode("utf-8", "strict").splitlines()
                                                   if line == item["line"])
            if stat.S_ISREG(info.st_mode) and data is not None:
                current_bytes = sum(len(base64.b64decode(entry["original"].get("contentBase64", "")))
                                    for entry in manifest["entries"] if entry["targetType"] == "path")
                if current_bytes + len(data) > MAX_ROLLBACK_RAW_BYTES:
                    raise ValueError("rollback raw capture capacity exceeded")
                original = {"contentBase64": base64.b64encode(data).decode("ascii"), "gid": info.st_gid,
                            "mode": "0%03o" % stat.S_IMODE(info.st_mode), "type": "file", "uid": info.st_uid}
            elif stat.S_ISLNK(info.st_mode):
                if "/" in link or link in {".", ".."}:
                    raise ValueError("rollback refuses unsafe symlink target")
                original = {"target": link, "type": "symlink"}
            else:
                raise ValueError("rollback refuses unsupported target type")
        except FileNotFoundError:
            original = {"type": "absent"}
            captured_state = {"state": "absent"}
        entry = {"actionId": action["id"], "capturedFingerprint": list(expected_identity) if expected_identity is not None else None,
                 "identity": identity, "original": original, "path": item["path"],
                 "sequence": action["sequence"], "targetType": "path"}
    manifest["entries"].append(entry)
    if len(canonical(manifest)) > MAX_MANIFEST_BYTES:
        raise ValueError("serialized rollback manifest capacity exceeded")
    save_manifest(plan_sha, manifest)
    return expected_identity, captured_state


def run_post_write(item):
    operation = item.get("nativeOperation")
    if operation == "update-initramfs":
        run_native(("/usr/sbin/update-initramfs", "-u", "-k", "all"))
    elif operation == "update-grub":
        run_native(("/usr/sbin/update-grub",))
    elif operation is not None:
        raise ValueError("unknown fixed native operation")


def mutate_item(item, expected_identity=None):
    if item["domain"] == "managed-files":
        replace_fixed(Path(item["path"]), base64.b64decode(item["contentBase64"], validate=True), item["owner"], item["group"], item["mode"], expected_identity)
        run_post_write(item)
    elif item["domain"] == "managed-fragments":
        path = Path(item["path"])
        try:
            data, _ = read_fixed_file(path)
            lines = data.decode("utf-8", "strict").splitlines()
        except FileNotFoundError:
            lines = []
        lines = [line for line in lines if line != item["line"]] + [item["line"]]
        replace_fixed(path, ("\n".join(lines) + "\n").encode(), item["owner"], item["group"], item["mode"], expected_identity)
        run_post_write(item)
    elif item["domain"] == "managed-artifacts":
        path = Path(item["path"])
        if item.get("symlinkTarget"):
            parent, name = open_fixed_parent(path)
            temporary = ".home-lab-link-%d" % os.getpid()
            try:
                os.symlink(item["symlinkTarget"], temporary, dir_fd=parent)
                revalidate_identity(parent, name, expected_identity)
                os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
                os.close(parent)
        elif item.get("sourceUrl"):
            request = urllib.request.Request(item["sourceUrl"], method="GET")
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.geturl() != item["sourceUrl"]:
                    raise ValueError("artifact redirect is forbidden")
                content = response.read(MAX_CAPTURE_BYTES + 1)
            if len(content) > MAX_CAPTURE_BYTES or hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise ValueError("artifact content binding failed")
            replace_fixed(path, content, item["owner"], item["group"], item["mode"], expected_identity)
        else:
            content, _ = read_fixed_file(path)
            if hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise ValueError("bootstrap-required: fixed artifact content is unavailable")
            replace_fixed(path, content, item["owner"], item["group"], item["mode"], expected_identity)
    elif item["domain"] == "services":
        run_native(("/usr/bin/systemctl", "--quiet", "enable" if item["enabled"] else "disable", item["name"]))
        run_native(("/usr/bin/systemctl", "--quiet", "start" if item["active"] else "stop", item["name"]))
    else:
        raise ValueError("closed dispatcher rejected action")


def current_identity(path):
    try:
        info, _, _ = inspect_fixed(path)
        return stable_fingerprint(info)
    except FileNotFoundError:
        return None


def restore_entry(entry, item):
    original = entry["original"]
    if entry["targetType"] == "service":
        run_native(("/usr/bin/systemctl", "--quiet", "enable" if original["enabled"] else "disable", item["name"]))
        run_native(("/usr/bin/systemctl", "--quiet", "start" if original["active"] else "stop", item["name"]))
        return observe_item(item) == original
    path = Path(entry["path"])
    if original["type"] == "absent":
        expected_identity = current_identity(path)
        parent, name = open_fixed_parent(path)
        try:
            revalidate_identity(parent, name, expected_identity)
            try:
                os.unlink(name, dir_fd=parent)
                os.fsync(parent)
            except FileNotFoundError:
                pass
        finally:
            os.close(parent)
        run_post_write(item)
        try:
            lstat_fixed(path)
            return False
        except FileNotFoundError:
            return True
    if original["type"] == "file":
        replace_fixed(path, base64.b64decode(original["contentBase64"], validate=True),
                      pwd.getpwuid(original["uid"]).pw_name, grp.getgrgid(original["gid"]).gr_name, original["mode"],
                      current_identity(path))
        run_post_write(item)
        data, info = read_fixed_file(path)
        return data == base64.b64decode(original["contentBase64"]) and info.st_uid == original["uid"] and info.st_gid == original["gid"] and "0%03o" % stat.S_IMODE(info.st_mode) == original["mode"]
    if original["type"] == "symlink":
        parent, name = open_fixed_parent(path)
        temporary = ".home-lab-rollback-link-%d" % os.getpid()
        try:
            os.symlink(original["target"], temporary, dir_fd=parent)
            revalidate_identity(parent, name, current_identity(path))
            os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)
        run_post_write(item)
        parent, name = open_fixed_parent(path)
        try:
            return os.readlink(name, dir_fd=parent) == original["target"]
        finally:
            os.close(parent)
    return False


def load_key():
    raw, info = read_fixed_file(KEY_PATH, 4096)
    if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or not 32 <= len(raw) <= 128:
        raise ValueError("bootstrap-required: protected session key is unavailable")
    return raw


def verify_attestation(key, supplied, message):
    return hmac.compare_digest(supplied, hmac.new(key, canonical(message), hashlib.sha256).hexdigest())


def sidecar_signing_projection(value):
    projection = json.loads(canonical(value))
    projection["hostSession"].pop("sidecarMac", None)
    return projection


def validate_private(value, plan_sha, activator_sha, action_manifest_sha):
    exact(value, {"actionManifestSha256", "attestations", "bindings", "challenge", "createdAt", "format", "hostSession",
                  "operatorGates", "packageSession", "planSha256", "validUntil"}, "private preconditions")
    if value["format"] != "home-lab-proxmox-private-preconditions-v1" or value["planSha256"] != plan_sha or \
            value["actionManifestSha256"] != action_manifest_sha:
        raise ValueError("private plan or action-manifest binding failed")
    binding_keys = {"activationEnvelopeSchemaSha256", "activatorSha256", "bundleContentSha256", "flakeLockSha256",
                    "gitCommit", "gitTree", "observerSha256", "packageManifestSha256", "planSchemaSha256",
                    "privatePreconditionsSchemaSha256", "privatePreparationRequestSchemaSha256",
                    "privatePreparerSha256", "projectionSha256"}
    bindings = exact(value["bindings"], binding_keys, "private bindings")
    if bindings["activatorSha256"] != activator_sha:
        raise ValueError("private activator binding failed")
    for name, expected in SPEC["expectedBindings"].items():
        if bindings.get(name) != expected:
            raise ValueError("private fixed bundle input binding failed")
    if any(not HEX64.fullmatch(bindings[key]) for key in bindings if key not in {"gitCommit", "gitTree"}) or \
            not HEX40_64.fullmatch(bindings["gitCommit"]) or not HEX40_64.fullmatch(bindings["gitTree"]):
        raise ValueError("private binding hash is invalid")
    now = dt.datetime.now(dt.timezone.utc)
    created, expires = parse_time(value["createdAt"]), parse_time(value["validUntil"])
    if created > now or now > expires or (expires - created).total_seconds() > 300:
        raise ValueError("private preconditions are stale")
    if not TOKEN.fullmatch(value["challenge"]):
        raise ValueError("private challenge is invalid")
    host = exact(value["hostSession"], {"id", "sidecarMac"}, "host session")
    if not TOKEN.fullmatch(host["id"]) or not HEX64.fullmatch(host["sidecarMac"]):
        raise ValueError("host session is invalid")
    gates = exact(value["operatorGates"], {"backupsConfirmed", "consoleConfirmed", "lanRollbackConfirmed", "noConcurrentMutationConfirmed"}, "operator gates")
    if any(not isinstance(gates[name], bool) for name in gates) or not gates["noConcurrentMutationConfirmed"]:
        raise ValueError("required operator gate is absent")
    attestations = exact(value["attestations"], {"protectedAccess", "protectedHardware"}, "attestations")
    key = load_key()
    expected_sidecar_mac = hmac.new(key, canonical(sidecar_signing_projection(value)), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(host["sidecarMac"], expected_sidecar_mac):
        raise ValueError("complete private sidecar authentication failed")
    for name, expected_count in (("protectedAccess", SPEC["protectedAccessExpectedCount"]), ("protectedHardware", SPEC["protectedHardwareExpectedCount"])):
        record = exact(attestations[name], {"expectedCount", "keyedAttestation", "matches"}, name)
        if record["expectedCount"] != expected_count or record["matches"] is not True or not HEX64.fullmatch(record["keyedAttestation"]):
            raise ValueError("protected attestation summary failed")
        message = {"challenge": value["challenge"], "expectedCount": expected_count, "hostSessionId": host["id"],
                   "matches": True, "planSha256": plan_sha, "type": name}
        if not verify_attestation(key, record["keyedAttestation"], message):
            raise ValueError("protected keyed attestation failed")
    package = value["packageSession"]
    if package is not None:
        exact(package, {"completeInstalledMapSha256", "handle", "keyedSimulationAttestation", "validUntil"}, "package session")
        if not TOKEN.fullmatch(package["handle"]) or not HEX64.fullmatch(package["completeInstalledMapSha256"]) or \
                not HEX64.fullmatch(package["keyedSimulationAttestation"]) or parse_time(package["validUntil"]) < now:
            raise ValueError("package session is malformed or stale")
    return value


def validate_common(envelope):
    if not isinstance(envelope, dict) or envelope.get("protocol") != PROTOCOL or \
            not isinstance(envelope.get("planSha256"), str) or not HEX64.fullmatch(envelope["planSha256"]) or \
            not isinstance(envelope.get("hostSessionId"), str) or not TOKEN.fullmatch(envelope["hostSessionId"]):
        raise ValueError("session protocol or binding is invalid")


def validate_action_manifest(actions):
    if not isinstance(actions, list):
        raise ValueError("complete action manifest must be an array")
    previous = None
    previous_order = -1
    for sequence, action in enumerate(actions, 1):
        catalog_item(action)
        if action["sequence"] != sequence or action["dependsOn"] != ([] if previous is None else [previous]):
            raise ValueError("complete action manifest sequence or dependency is invalid")
        order = SPEC["catalogOrder"].index(catalog_key(action["domain"], action["target"]))
        if order <= previous_order:
            raise ValueError("complete action manifest order is invalid")
        previous, previous_order = action["id"], order
    return hashlib.sha256(canonical(actions)).hexdigest()


def validate_envelope_shape(envelope):
    """Manual closed-schema gate shared by every operation handler."""
    validate_common(envelope)
    operation = envelope.get("operation")
    common = {"hostSessionId", "operation", "planSha256", "protocol"}
    if operation == "begin":
        exact(envelope, common | {"actions", "bindings", "privatePreconditions", "startedAt"}, "begin envelope")
        parse_time(envelope["startedAt"])
        bindings = exact(envelope["bindings"], {"activatorSha256", "bundleContentSha256", "gitCommit", "gitTree"}, "begin bindings")
        if not HEX64.fullmatch(bindings["activatorSha256"]) or not HEX64.fullmatch(bindings["bundleContentSha256"]) or \
                not HEX40_64.fullmatch(bindings["gitCommit"]) or not HEX40_64.fullmatch(bindings["gitTree"]):
            raise ValueError("begin binding shape is invalid")
        exact(envelope["privatePreconditions"], {"actionManifestSha256", "attestations", "bindings", "challenge", "createdAt",
              "format", "hostSession", "operatorGates", "packageSession", "planSha256", "validUntil"}, "private preconditions")
        validate_action_manifest(envelope["actions"])
    elif operation == "action":
        exact(envelope, common | {"action"}, "action envelope")
        catalog_item(envelope["action"])
    elif operation == "commit":
        exact(envelope, common | {"verifiedActionIds"}, "commit envelope")
        values = envelope["verifiedActionIds"]
        if not isinstance(values, list) or any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in values):
            raise ValueError("commit action IDs are invalid")
    elif operation in {"rollback", "status"}:
        exact(envelope, common, operation + " envelope")
    else:
        raise ValueError("unknown session operation")
    return operation


def release_fixed_lock(path):
    parent, name = open_fixed_parent(path)
    try:
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def persistent_exists(path):
    try:
        os.stat(path, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def acquire_operation():
    """Acquire a process-lifetime mutex; a crash or reboot releases the flock."""
    parent, name = open_fixed_parent(OPERATION_LOCK_PATH)
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or \
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            os.close(fd)
            raise ValueError("operation mutex must be a root-owned mode-0600 single-link regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        return fd
    finally:
        os.close(parent)


def require_lock(envelope):
    validate_common(envelope)
    lock = read_lock()
    if lock["planSha256"] != envelope["planSha256"] or lock["hostSessionId"] != envelope["hostSessionId"] or \
            lock["activatorSha256"] != self_sha256():
        raise ValueError("host lock owner differs from session")
    return lock


def request_digest(envelope):
    return hashlib.sha256(canonical(envelope)).hexdigest()


def completed_retry(journal, envelope):
    operation = envelope["operation"]
    allowed = {
        "begin": {"begun", "applying", "action-pending", "action-retryable", "failed"},
        "action": {"applying", "action-pending", "action-retryable"},
        "commit": {"committed-release-pending", "released-committed"},
        "rollback": {"recovered-release-pending", "released-recovered"},
    }
    if journal["state"] not in allowed.get(operation, set()):
        return None
    digest_value = request_digest(envelope)
    return next((item["result"] for item in journal["completed"]
                 if item["operation"] == operation and item["requestSha256"] == digest_value), None)


def terminal_release(journal, terminal, result):
    plan_sha = journal["planSha256"]
    journal["pendingTransition"] = None
    journal["state"] = terminal + "-release-pending"
    journal["terminalResult"] = result
    save_journal(plan_sha, journal)
    release_fixed_lock(LOCK_PATH)
    journal["state"] = "released-" + terminal
    save_journal(plan_sha, journal)


def lock_matches_ownership(lock, ownership):
    return lock == ownership


def reconcile_initializing(journal):
    if journal["state"] != "initializing":
        return journal
    if journal["ownership"]["activatorSha256"] != self_sha256():
        raise ValueError("initializing journal belongs to a different activator")
    try:
        lock = read_lock()
    except FileNotFoundError:
        lock = None
    if lock is not None and not lock_matches_ownership(lock, journal["ownership"]):
        raise ValueError("initializing ownership differs from active host lock")
    if lock is None:
        write_exclusive_fixed(LOCK_PATH, canonical(journal["ownership"]))
    result = {"actionManifestSha256": journal["actionManifestSha256"],
              "hostSessionId": journal["hostSessionId"], "planSha256": journal["planSha256"], "status": "begun"}
    journal["completed"].append({"actionId": None, "operation": "begin",
                                 "requestSha256": journal["pendingTransition"]["requestSha256"], "result": result})
    journal["pendingTransition"] = None
    journal["state"] = "begun"
    save_journal(journal["planSha256"], journal)
    return journal


def reconcile_terminal_release(journal):
    terminal = next((name for name in ("committed", "recovered")
                     if journal["state"] == name + "-release-pending"), None)
    if terminal is None:
        return journal
    try:
        lock = read_lock()
    except FileNotFoundError:
        lock = None
    if lock is not None and not lock_matches_ownership(lock, journal["ownership"]):
        raise ValueError("pending terminal ownership differs")
    if lock is not None:
        release_fixed_lock(LOCK_PATH)
    journal["state"] = "released-" + terminal
    save_journal(journal["planSha256"], journal)
    return journal


def status_result(journal, manifest):
    validate_session_consistency(journal, manifest)
    pending = None if journal["pendingTransition"] is None else json.loads(canonical(journal["pendingTransition"]))
    begin_record = next(item for item in journal["completed"] if item["operation"] == "begin")
    return {"actionManifestSha256": journal["actionManifestSha256"],
            "beginRequestSha256": begin_record["requestSha256"],
            "capturedActionIds": [item["actionId"] for item in manifest["entries"]],
            "completedActionIds": [item["actionId"] for item in journal["completed"] if item["operation"] == "action"],
            "hostSessionId": journal["hostSessionId"], "nextSequence": journal["nextSequence"],
            "pendingTransition": pending, "planSha256": journal["planSha256"], "state": journal["state"],
            "status": "session-status"}


def retained_generations():
    generations = []
    for entry in os.scandir(ROLLBACK_ROOT):
        info = entry.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("rollback root contains an unsafe generation")
        generations.append(entry.name)
    return generations


def challenge_was_used(challenge):
    for plan_sha in retained_generations():
        if not HEX64.fullmatch(plan_sha):
            raise ValueError("rollback generation name is invalid")
        try:
            if read_journal(plan_sha)["challenge"] == challenge:
                return True
        except FileNotFoundError:
            # An unowned crash before the initialization journal is not a used challenge.
            continue
    return False


def cleanup_new_session(plan_sha):
    """Remove only known files from a session directory created by this begin."""
    parent, name = open_fixed_parent(ROLLBACK_ROOT / plan_sha)
    try:
        session_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(session_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("incomplete session directory is unsafe")
            for child in os.listdir(session_fd):
                if child not in {"manifest.json", "journal.json"} and not child.startswith(".state-"):
                    raise ValueError("incomplete session contains an unknown entry")
                child_info = os.stat(child, dir_fd=session_fd, follow_symlinks=False)
                if not stat.S_ISREG(child_info.st_mode) or child_info.st_uid != 0 or child_info.st_gid != 0 or \
                        stat.S_IMODE(child_info.st_mode) != 0o600 or child_info.st_nlink != 1:
                    raise ValueError("incomplete session entry is unsafe")
                os.unlink(child, dir_fd=session_fd)
            os.fsync(session_fd)
        finally:
            os.close(session_fd)
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def cleanup_unowned_incomplete_generations():
    try:
        read_lock()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("cannot clean incomplete generations while ownership is active")
    for plan_sha in retained_generations():
        if not HEX64.fullmatch(plan_sha):
            raise ValueError("rollback generation name is invalid")
        try:
            read_journal(plan_sha)
        except FileNotFoundError:
            cleanup_new_session(plan_sha)


def begin(envelope):
    validate_envelope_shape(envelope)
    action_manifest_sha = validate_action_manifest(envelope["actions"])
    bindings = exact(envelope["bindings"], {"activatorSha256", "bundleContentSha256", "gitCommit", "gitTree"}, "begin bindings")
    if bindings["activatorSha256"] != self_sha256() or not HEX64.fullmatch(bindings["bundleContentSha256"]) or \
            not HEX40_64.fullmatch(bindings["gitCommit"]) or not HEX40_64.fullmatch(bindings["gitTree"]):
        raise ValueError("begin helper or source binding failed")
    private = validate_private(envelope["privatePreconditions"], envelope["planSha256"], self_sha256(), action_manifest_sha)
    if private["hostSession"]["id"] != envelope["hostSessionId"] or private["bindings"]["bundleContentSha256"] != bindings["bundleContentSha256"] or \
            private["bindings"]["gitCommit"] != bindings["gitCommit"] or private["bindings"]["gitTree"] != bindings["gitTree"]:
        raise ValueError("begin private binding differs")
    if envelope["startedAt"] != private["createdAt"]:
        raise ValueError("begin timestamp differs from authenticated private preconditions")
    parse_time(envelope["startedAt"])
    plan_sha = envelope["planSha256"]
    session_root, manifest_path = session_paths(plan_sha)
    try:
        existing = read_journal(plan_sha)
        manifest = read_manifest(plan_sha)
        validate_session_consistency(existing, manifest)
        saved_ownership = existing["ownership"]
        if existing["hostSessionId"] != envelope["hostSessionId"] or existing["actionManifestSha256"] != action_manifest_sha or \
                saved_ownership["activatorSha256"] != self_sha256() or \
                saved_ownership["bundleContentSha256"] != bindings["bundleContentSha256"] or \
                saved_ownership["gitCommit"] != bindings["gitCommit"] or saved_ownership["gitTree"] != bindings["gitTree"] or \
                saved_ownership["startedAt"] != envelope["startedAt"]:
            raise ValueError("plan/session replay is forbidden")
        if existing["state"] == "initializing":
            pending = existing["pendingTransition"]
            if pending["requestSha256"] != request_digest(envelope):
                raise ValueError("initializing request differs")
            existing = reconcile_initializing(existing)
        retry = completed_retry(existing, envelope)
        if retry is None:
            raise ValueError("plan/session replay is forbidden")
        return retry
    except FileNotFoundError:
        pass
    try:
        session_info = lstat_fixed(session_root)
    except FileNotFoundError:
        session_info = None
    if session_info is not None:
        try:
            read_lock()
        except FileNotFoundError:
            cleanup_new_session(plan_sha)
        else:
            raise ValueError("incomplete generation has an active ownership lock")
    try:
        read_lock()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("another host apply ownership lock exists")
    cleanup_unowned_incomplete_generations()
    generations = retained_generations()
    if len(generations) >= MAX_RETAINED_SESSIONS:
        raise ValueError("rollback retention limit reached")
    if challenge_was_used(private["challenge"]):
        raise ValueError("private challenge replay is forbidden")
    if shutil.disk_usage(ROLLBACK_ROOT).free < MIN_FREE_BYTES:
        raise ValueError("rollback free-space gate failed")
    ownership = {"activatorSha256": self_sha256(), "bundleContentSha256": bindings["bundleContentSha256"],
                 "gitCommit": bindings["gitCommit"], "gitTree": bindings["gitTree"], "hostSessionId": envelope["hostSessionId"],
                 "operation": "proxmox-guarded-apply", "planSha256": plan_sha, "startedAt": envelope["startedAt"]}
    created_session = False
    journal_written = False
    try:
        session_root.mkdir(mode=0o700)
        created_session = True
        os.chown(session_root, 0, 0)
        info = session_root.lstat()
        if stat.S_IMODE(info.st_mode) != 0o700 or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
            raise ValueError("rollback session root mode is invalid")
        manifest = {"actionManifestSha256": action_manifest_sha, "actions": envelope["actions"], "entries": [],
                    "format": "home-lab-proxmox-rollback-v2", "planSha256": plan_sha}
        validate_manifest(manifest, plan_sha)
        manifest_bytes = canonical(manifest)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ValueError("serialized rollback manifest capacity exceeded")
        write_exclusive_fixed(manifest_path, manifest_bytes)
        journal = {"actionManifestSha256": action_manifest_sha, "challenge": private["challenge"], "completed": [],
                   "format": "home-lab-proxmox-session-journal-v2", "hostSessionId": envelope["hostSessionId"],
                   "nextSequence": 1, "ownership": ownership,
                   "pendingTransition": {"operation": "begin", "requestSha256": request_digest(envelope)},
                   "planSha256": plan_sha, "state": "initializing", "terminalResult": None}
        validate_journal(journal, plan_sha)
        write_exclusive_fixed(journal_path(plan_sha), canonical(journal))
        journal_written = True
        journal = reconcile_initializing(journal)
        retry = completed_retry(journal, envelope)
        if retry is None:
            raise ValueError("begin reconciliation did not complete")
        return retry
    except Exception:
        # Once the initialization journal is durable, it is the recovery authority.
        if created_session and not journal_written:
            cleanup_new_session(plan_sha)
        raise


def finalize_action(journal, envelope):
    action = envelope["action"]
    result = {"actionId": action["id"], "hostSessionId": envelope["hostSessionId"],
              "sequence": action["sequence"], "status": "applied"}
    journal["completed"].append({"actionId": action["id"], "operation": "action",
                                 "requestSha256": request_digest(envelope), "result": result})
    journal["nextSequence"] += 1
    journal["pendingTransition"] = None
    journal["state"] = "applying"
    save_journal(envelope["planSha256"], journal)
    return result


def resume_pending_action(journal, manifest, envelope, execute):
    pending = journal["pendingTransition"]
    action = envelope["action"]
    if pending is None or pending["operation"] != "action" or pending["requestSha256"] != request_digest(envelope) or \
            pending["actionId"] != action["id"] or pending["sequence"] != action["sequence"]:
        raise ValueError("pending action request differs")
    sequence = journal["nextSequence"]
    if sequence > len(manifest["actions"]) or action != manifest["actions"][sequence - 1]:
        raise ValueError("pending action differs from the exact retained manifest")
    validate_session_consistency(journal, manifest)
    item = catalog_item(action)
    entries = manifest["entries"]
    if len(entries) not in {sequence - 1, sequence}:
        raise ValueError("pending action capture position is invalid")
    captured = entries[-1] if len(entries) == sequence else None
    if captured is not None and captured["actionId"] != action["id"]:
        raise ValueError("pending action capture differs")
    current = observe_item(item)
    if current == action["after"]:
        if item.get("nativeOperation") is None:
            if captured is None:
                journal["state"] = "failed"
                save_journal(envelope["planSha256"], journal)
                raise ValueError("action reached postcondition without durable capture")
            return finalize_action(journal, envelope)
        pending["stage"] = "postcondition-pending"
        journal["state"] = "action-retryable"
        save_journal(envelope["planSha256"], journal)
        if not execute:
            return None
        run_post_write(item)
        if observe_item(item) != action["after"]:
            raise ValueError("action post-write condition differs")
        return finalize_action(journal, envelope)
    if current != action["before"]:
        journal["state"] = "failed"
        save_journal(envelope["planSha256"], journal)
        retain_diagnostic(envelope["planSha256"], "action-failed", action["id"])
        raise ValueError("pending action state is neither saved precondition nor postcondition")
    pending["stage"] = "prepared"
    journal["state"] = "action-retryable"
    save_journal(envelope["planSha256"], journal)
    if not execute:
        return None
    if captured is None:
        expected_identity, captured_state = capture_once(envelope["planSha256"], action, item)
        if captured_state != action["before"]:
            raise ValueError("captured action precondition differs")
    else:
        expected_identity = None if captured["capturedFingerprint"] is None else tuple(captured["capturedFingerprint"])
    journal["state"] = "action-pending"
    save_journal(envelope["planSha256"], journal)
    mutate_item(item, expected_identity)
    if observe_item(item) != action["after"]:
        raise ValueError("action postcondition differs")
    return finalize_action(journal, envelope)


def action_session(envelope):
    validate_envelope_shape(envelope)
    plan_sha = envelope["planSha256"]
    journal = read_journal(plan_sha)
    retry = completed_retry(journal, envelope)
    if retry is not None:
        return retry
    require_lock(envelope)
    manifest = read_manifest(plan_sha)
    action = envelope["action"]
    if journal["state"] in {"action-pending", "action-retryable"}:
        try:
            return resume_pending_action(journal, manifest, envelope, True)
        except Exception:
            if journal["state"] != "failed":
                journal["state"] = "failed"
                save_journal(plan_sha, journal)
            retain_diagnostic(plan_sha, "action-failed", action["id"])
            raise
    if journal["state"] not in {"begun", "applying"}:
        raise ValueError("session state does not allow an action")
    sequence = journal["nextSequence"]
    if sequence > len(manifest["actions"]) or action != manifest["actions"][sequence - 1]:
        raise ValueError("action differs from the exact retained plan manifest")
    journal["pendingTransition"] = {"actionId": action["id"], "operation": "action",
                                    "requestSha256": request_digest(envelope), "sequence": sequence, "stage": "prepared"}
    journal["state"] = "action-pending"
    save_journal(plan_sha, journal)
    try:
        return resume_pending_action(journal, manifest, envelope, True)
    except Exception:
        if journal["state"] != "failed":
            journal["state"] = "failed"
            save_journal(plan_sha, journal)
        retain_diagnostic(plan_sha, "action-failed", action["id"])
        raise


def resume_rollback(journal, manifest, envelope):
    pending = journal["pendingTransition"]
    if pending is None or pending["operation"] != "rollback" or pending["requestSha256"] != request_digest(envelope):
        raise ValueError("pending rollback request differs")
    validate_session_consistency(journal, manifest)
    entries = {entry["actionId"]: entry for entry in manifest["entries"]}
    expected_order = [entry["actionId"] for entry in reversed(manifest["entries"])]
    if pending["restoredActionIds"] + pending["remainingActionIds"] != expected_order:
        raise ValueError("pending rollback progress differs from captured actions")
    while pending["remainingActionIds"]:
        action_id = pending["remainingActionIds"][0]
        entry = entries[action_id]
        domain, name = entry["identity"].split("\0", 1)
        item = SPEC["catalog"].get(domain + "\0" + name)
        if item is None or not restore_entry(entry, item):
            raise ValueError("rollback verification failed")
        pending["remainingActionIds"].pop(0)
        pending["restoredActionIds"].append(action_id)
        save_journal(envelope["planSha256"], journal)
    result = {"hostSessionId": envelope["hostSessionId"], "planSha256": envelope["planSha256"],
              "restoredActionIds": pending["restoredActionIds"], "status": "recovered"}
    journal["completed"].append({"actionId": None, "operation": "rollback",
                                 "requestSha256": request_digest(envelope), "result": result})
    terminal_release(journal, "recovered", result)
    return result


def rollback(envelope):
    validate_envelope_shape(envelope)
    plan_sha = envelope["planSha256"]
    journal = read_journal(plan_sha)
    retry = completed_retry(journal, envelope)
    if retry is not None:
        journal = reconcile_terminal_release(journal)
        if journal["state"] != "released-recovered":
            raise ValueError("rollback retry is not release-complete")
        return retry
    if journal["state"] in {"committed-release-pending", "released-committed", "recovered-release-pending",
                            "released-recovered"}:
        raise ValueError("terminal session cannot start rollback")
    require_lock(envelope)
    manifest = read_manifest(plan_sha)
    validate_session_consistency(journal, manifest)
    if journal["state"] == "rollback-in-progress":
        try:
            return resume_rollback(journal, manifest, envelope)
        except Exception:
            journal["state"] = "rollback-failed"
            save_journal(plan_sha, journal)
            retain_diagnostic(plan_sha, "rollback-verification-failed")
            raise ValueError("rollback verification failed; ownership lock retained")
    if journal["state"] == "rollback-failed":
        raise ValueError("failed rollback requires inspected recovery")
    order = [entry["actionId"] for entry in reversed(manifest["entries"])]
    journal["pendingTransition"] = {"operation": "rollback", "remainingActionIds": order,
                                    "requestSha256": request_digest(envelope), "restoredActionIds": []}
    journal["state"] = "rollback-in-progress"
    save_journal(plan_sha, journal)
    retain_diagnostic(plan_sha, "controller-requested-rollback")
    try:
        return resume_rollback(journal, manifest, envelope)
    except Exception:
        journal["state"] = "rollback-failed"
        save_journal(plan_sha, journal)
        retain_diagnostic(plan_sha, "rollback-verification-failed")
        raise ValueError("rollback verification failed; ownership lock retained")


def commit(envelope):
    validate_envelope_shape(envelope)
    plan_sha = envelope["planSha256"]
    journal = read_journal(plan_sha)
    retry = completed_retry(journal, envelope)
    if retry is not None:
        journal = reconcile_terminal_release(journal)
        if journal["state"] != "released-committed":
            raise ValueError("commit retry is not release-complete")
        return retry
    require_lock(envelope)
    manifest = read_manifest(plan_sha)
    validate_session_consistency(journal, manifest)
    planned_ids = [action["id"] for action in manifest["actions"]]
    if journal["state"] not in {"begun", "applying"} or journal["pendingTransition"] is not None or \
            envelope["verifiedActionIds"] != planned_ids or journal["nextSequence"] != len(planned_ids) + 1:
        raise ValueError("commit differs from the complete exact action manifest")
    result = {"hostSessionId": envelope["hostSessionId"], "planSha256": plan_sha, "status": "committed"}
    journal["completed"].append({"actionId": None, "operation": "commit",
                                 "requestSha256": request_digest(envelope), "result": result})
    terminal_release(journal, "committed", result)
    return result


def status(envelope):
    validate_envelope_shape(envelope)
    plan_sha = envelope["planSha256"]
    journal = read_journal(plan_sha)
    manifest = read_manifest(plan_sha)
    if journal["hostSessionId"] != envelope["hostSessionId"]:
        raise ValueError("status session binding differs")
    validate_session_consistency(journal, manifest)
    if journal["state"] == "initializing":
        journal = reconcile_initializing(journal)
    elif journal["state"] in {"action-pending", "action-retryable"}:
        require_lock(envelope)
        action = manifest["actions"][journal["nextSequence"] - 1]
        action_envelope = {"action": action, "hostSessionId": journal["hostSessionId"], "operation": "action",
                           "planSha256": plan_sha, "protocol": PROTOCOL}
        try:
            resume_pending_action(journal, manifest, action_envelope, False)
        except Exception:
            if journal["state"] != "failed":
                journal["state"] = "failed"
                save_journal(plan_sha, journal)
    journal = reconcile_terminal_release(journal)
    journal = read_journal(plan_sha)
    manifest = read_manifest(plan_sha)
    return status_result(journal, manifest)


def session():
    envelope = read_canonical_stdin()
    if not isinstance(envelope, dict):
        raise ValueError("session envelope must be an object")
    validate_common(envelope)
    ensure_fixed_root(SESSION_ROOT, 0o700)
    ensure_fixed_root(ROLLBACK_ROOT, 0o700)
    operation_fd = acquire_operation()
    if operation_fd is None:
        os.write(1, canonical({"hostSessionId": envelope["hostSessionId"], "operation": envelope.get("operation"),
                              "planSha256": envelope["planSha256"], "status": "busy"}))
        return
    try:
        # Lock order is always the live operation flock followed by persistent
        # ownership inspection/creation.  Ansible uses the same order.
        if persistent_exists(ANSIBLE_LOCK_PATH):
            raise ValueError("Ansible host ownership is active")
        operation = envelope.get("operation")
        handler = {"begin": begin, "action": action_session, "rollback": rollback, "commit": commit, "status": status}.get(operation)
        if handler is None:
            raise ValueError("unknown session operation")
        try:
            result = handler(envelope)
        except Exception:
            result = {"hostSessionId": envelope["hostSessionId"], "operation": operation,
                      "planSha256": envelope["planSha256"], "status": "failed"}
        os.write(1, canonical(result))
    finally:
        os.close(operation_fd)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"version", "self-check", "session"}:
        os.write(2, b"usage: proxmox-activator <version|self-check|session>\n")
        return 64
    if sys.argv[1] == "version":
        os.write(1, canonical({"capabilities": ["guarded-session"], "helper": "proxmox-activator", "protocol": PROTOCOL, "version": 1}))
    elif sys.argv[1] == "self-check":
        os.write(1, b"proxmox-activator=self-check-passed protocol=4 capabilities=guarded-session\n")
    else:
        session()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        os.write(2, b"proxmox-activator: guarded session failed\n")
        raise SystemExit(1)
