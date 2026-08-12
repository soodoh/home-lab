#!/usr/bin/python3
"""Fixed root-only protected precondition preparer (template input)."""

import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROTOCOL = 4
SPEC = json.loads('@PREPARATION_SPEC@')
ROOT = Path("/var/lib/home-lab/reconciliation")
PROTECTED = ROOT / "protected-inputs.json"
PROTECTED_MAC = ROOT / "protected-inputs.mac"
KEY = ROOT / "session.key"
INSTALL = ROOT / "install-manifest.json"
OPERATION_LOCK = ROOT / "operation.lock"
APPLY_LOCK = ROOT / "apply.lock"
ANSIBLE_LOCK = Path("/var/lib/iac-ansible-production.lock")
MAX_INPUT = 2 * 1024 * 1024
MAX_OUTPUT = 256 * 1024
HEX = re.compile(r"^[0-9a-f]{64}$")
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
DOMAIN_ORDER = {name: index for index, name in enumerate(("identity", "managed-artifacts", "managed-files",
    "managed-fragments", "packages", "accounts", "services", "tailscale", "pve-access", "pve-storage",
    "storage", "pve-firewall", "health", "audit-absence", "protected-access", "opentofu", "protected-hardware"))}
OBSERVED_DOMAINS = {"accounts", "auditAbsence", "health", "managedArtifacts", "managedFiles", "managedFragments",
    "packages", "protectedAccess", "protectedHardware", "pveAccess", "pveFirewall", "pveStorage", "services",
    "storage", "tailscale", "vm"}


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def self_sha256():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def write_stdout(content):
    offset = 0
    while offset < len(content):
        written = os.write(1, content[offset:])
        if written < 1:
            raise OSError("protected output write made no progress")
        offset += written


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(label + " shape differs")
    return value


def parse_time(value):
    if not isinstance(value, str) or not TIME.fullmatch(value):
        raise ValueError("invalid timestamp")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def format_time(value):
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def open_fixed_dir(path, final_mode):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("fixed runtime path differs")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, component in enumerate(path.parts[1:]):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            final = index == len(path.parts[1:]) - 1
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or \
                    (final and stat.S_IMODE(info.st_mode) != final_mode) or (not final and stat.S_IMODE(info.st_mode) & 0o022):
                os.close(child)
                raise ValueError("fixed runtime directory metadata differs")
            os.close(fd); fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def secure_json(path, maximum):
    parent_fd = open_fixed_dir(path.parent, 0o700)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > maximum:
                raise ValueError("protected runtime file unavailable")
            chunks = []
            remaining = before.st_size
            while remaining:
                block = os.read(fd, min(65536, remaining))
                if not block:
                    raise ValueError("protected runtime read was incomplete")
                chunks.append(block); remaining -= len(block)
            after = os.fstat(fd)
            if fingerprint(before) != fingerprint(after):
                raise ValueError("protected runtime file changed while read")
            raw = b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    value = json.loads(raw)
    if raw != canonical(value):
        raise ValueError("protected runtime file noncanonical")
    return value


def persistent_exists(path):
    try:
        os.stat(path, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def acquire_operation():
    parent_fd = open_fixed_dir(ROOT, 0o700)
    try:
        fd = os.open(OPERATION_LOCK.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            os.close(fd)
            raise ValueError("shared operation lock metadata differs")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    finally:
        os.close(parent_fd)


def secure_key():
    parent_fd = open_fixed_dir(ROOT, 0o700)
    try:
        fd = os.open(KEY.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            raw = os.read(fd, 129)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 32 <= len(raw) <= 64:
        raise ValueError("session key unavailable")
    return raw


def run(args, accepted=(0,)):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=10)
        if result.returncode not in accepted or result.stderr or len(result.stdout) > 4 * 1024 * 1024:
            return None
        return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None


def read_fixed(path, required_mode=0o600, owner_name="root"):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022:
                os.close(child); return None
            os.close(fd); fd = child
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            expected = pwd.getpwnam(owner_name)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != expected.pw_uid or before.st_gid != expected.pw_gid or \
                    before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != required_mode or before.st_size > 256 * 1024:
                return None
            chunks = []
            remaining = before.st_size
            while remaining:
                block = os.read(file_fd, min(65536, remaining))
                if not block: return None
                chunks.append(block); remaining -= len(block)
            after = os.fstat(file_fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                return None
            return b"".join(chunks).decode("utf-8", "strict")
        finally:
            os.close(file_fd)
    except (OSError, KeyError, UnicodeError):
        return None
    finally:
        os.close(fd)


def absent_fixed(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                return True
            os.close(fd); fd = child
        try:
            os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            return False
        except FileNotFoundError:
            return True
    except OSError:
        return False
    finally:
        os.close(fd)


def token_valid(token):
    try:
        if not isinstance(token, str) or TOKEN.fullmatch(token) is None:
            return False
        request = urllib.request.Request("https://" + "127.0.0.1" + ":8006/api2/json/version",
                                         headers={"Authorization": "PVEAPIToken=" + token}, method="GET")
        with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=5) as response:
            return response.status == 200 and len(response.read(1024 * 1024 + 1)) <= 1024 * 1024
    except (OSError, ValueError, urllib.error.URLError):
        return False


def token_policy_valid(token, principal, acl_records, sealed_identity):
    identity = token_identity(token)
    if identity is None or identity != sealed_identity:
        return False
    binding = next((item for item in SPEC["pveAccessBindings"] if item["principal"] == principal), None)
    if binding is None:
        return False
    user, token_name = identity.split("!", 1)
    metadata_raw = run(("/usr/bin/pvesh", "get", "/access/users/" + user + "/token/" + token_name,
                        "--output-format", "json"))
    if metadata_raw is None:
        return False
    try:
        metadata = json.loads(metadata_raw)
    except Exception:
        return False
    if not isinstance(metadata, dict) or int(metadata.get("privsep", -1)) != (1 if binding["privilegeSeparation"] else 0):
        return False
    expected = {(binding["primaryAcl"], binding["role"], 1)} | \
        {(item["path"], item["role"], 1) for item in binding["additionalAcls"]}
    selected = [item for item in acl_records if isinstance(item, dict) and item.get("ugid") == identity]
    actual = []
    for item in selected:
        try:
            propagate = int(item.get("propagate"))
        except (TypeError, ValueError):
            return False
        if set(item) - {"path", "roleid", "ugid", "propagate", "type"}:
            return False
        actual.append((item.get("path"), item.get("roleid"), propagate))
    return len(actual) == len(set(actual)) and set(actual) == expected


SSH_KEY = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ([A-Za-z0-9+/]+={0,2})(?: ([^\r\n]+))?$")
TOKEN = re.compile(r"^([^\s!=]+![^\s!=]+)=([^\s]+)$")
BY_ID = re.compile(r"^/dev/disk/by-id/[^\s/]+$")
USB_PORT = re.compile(r"^[0-9]+-[0-9]+(?:\.[0-9]+)*$")


def valid_key(value):
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        return False
    match = SSH_KEY.fullmatch(value)
    if match is None:
        return False
    try:
        import base64
        decoded = base64.b64decode(match.group(2), validate=True)
    except Exception:
        return False
    return len(decoded) >= 32


def key_identity(value):
    match = SSH_KEY.fullmatch(value) if isinstance(value, str) else None
    return None if match is None else match.group(1) + " " + match.group(2)


def token_identity(value):
    match = TOKEN.fullmatch(value) if isinstance(value, str) else None
    return match.group(1) if match is not None else None


def runtime_state():
    value = secure_json(PROTECTED, 256 * 1024)
    supplied_mac = read_fixed(PROTECTED_MAC)
    expected_mac = hmac.new(secure_key(), canonical(value), hashlib.sha256).hexdigest() + "\n"
    if supplied_mac is None or not hmac.compare_digest(supplied_mac, expected_mac):
        raise ValueError("protected runtime keyed attestation differs")
    exact(value, {"access", "format", "hardware"}, "protected state")
    if value["format"] != "home-lab-proxmox-protected-inputs-v1":
        raise ValueError("protected state format differs")
    access = exact(value["access"], {"applyKeys", "applyToken", "applyTokenIdentity", "firewallKeys", "planKeys", "planToken", "planTokenIdentity"}, "protected access")
    hardware = exact(value["hardware"], {"gamesDiskIdentity", "poolGuid", "poolMembers", "usbMappings"}, "protected hardware")
    key_identities = []
    for key in ("applyKeys", "firewallKeys", "planKeys"):
        if not isinstance(access[key], list) or not access[key] or any(not valid_key(x) for x in access[key]):
            raise ValueError("protected key input differs")
        key_identities.extend(key_identity(x) for x in access[key])
    if None in key_identities or len(key_identities) != len(set(key_identities)) or token_identity(access["applyToken"]) is None or \
            token_identity(access["planToken"]) is None or token_identity(access["applyToken"]) == token_identity(access["planToken"]) or \
            token_identity(access["applyToken"]) != access["applyTokenIdentity"] or token_identity(access["planToken"]) != access["planTokenIdentity"] or \
            any(not isinstance(access[name], str) or re.fullmatch(r"[^\s!=]+![^\s!=]+", access[name]) is None
                for name in ("applyTokenIdentity", "planTokenIdentity")):
        raise ValueError("protected access identities differ")
    if not isinstance(hardware["poolGuid"], str) or not hardware["poolGuid"].isdigit() or \
            not isinstance(hardware["gamesDiskIdentity"], str) or BY_ID.fullmatch(hardware["gamesDiskIdentity"]) is None:
        raise ValueError("protected scalar input differs")
    members = hardware["poolMembers"]
    mappings = hardware["usbMappings"]
    if not isinstance(members, list) or len(members) != 12 or len(set(members)) != 12 or any(BY_ID.fullmatch(x) is None for x in members) or \
            not isinstance(mappings, list) or len(mappings) != 2:
        raise ValueError("protected hardware input differs")
    names, ports, serials = [], [], []
    for mapping in mappings:
        exact(mapping, {"mapping", "port", "serial"}, "protected USB mapping")
        if not isinstance(mapping["mapping"], str) or re.fullmatch(r"[a-z][a-z0-9_-]*", mapping["mapping"]) is None or \
                not isinstance(mapping["port"], str) or USB_PORT.fullmatch(mapping["port"]) is None or \
                not isinstance(mapping["serial"], str) or not mapping["serial"] or any(c.isspace() for c in mapping["serial"]):
            raise ValueError("protected USB mapping differs")
        names.append(mapping["mapping"]); ports.append(mapping["port"]); serials.append(mapping["serial"])
    if any(len(values) != len(set(values)) for values in (names, ports, serials)):
        raise ValueError("protected USB identities are not unique")
    return value


def summary_record(checks):
    count = sum(value is True for value in checks)
    return {"expectedCount": len(checks), "matches": count == len(checks), "observedCount": count, "status": "complete"}


def parse_qm_disk(raw):
    records = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        if not line or ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in records:
            raise ValueError("duplicate VM config key")
        records[key] = value
    return records.get("scsi1", "").split(",", 1)[0]


def parse_zfs_mirrors(raw):
    mirrors = []
    current = None
    forbidden_sections = {"logs", "cache", "spares", "special", "dedup"}
    for line in raw.decode("utf-8", "strict").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        first = stripped.split()[0]
        if first.rstrip(":") in forbidden_sections or re.match(r"^(raidz|draid|replacing|spare)-?", first):
            raise ValueError("unsupported ZFS vdev section")
        if re.match(r"^mirror-[0-9]+$", first):
            current = []
            mirrors.append(current)
            continue
        if first.startswith("/dev/"):
            if BY_ID.fullmatch(first) is None or current is None:
                raise ValueError("unrecognized ZFS leaf")
            current.append(first)
            continue
        allowed_prefixes = ("pool:", "state:", "status:", "action:", "scan:", "config:", "errors:", "NAME")
        if stripped.startswith(allowed_prefixes) or first == SPEC["pool"]:
            continue
        # Within the vdev table every state-bearing row must have been the
        # exact pool root, mirror, or by-id leaf handled above.
        if any(word in stripped.split() for word in ("ONLINE", "OFFLINE", "DEGRADED", "FAULTED", "UNAVAIL", "REMOVED")):
            raise ValueError("unrecognized ZFS vdev row")
    if len(mirrors) != 6 or any(len(pair) != 2 for pair in mirrors):
        raise ValueError("ZFS mirror topology differs")
    leaves = [item for pair in mirrors for item in pair]
    if len(leaves) != 12 or len(set(leaves)) != 12:
        raise ValueError("ZFS leaves differ")
    return mirrors


def parse_udev(raw):
    records = []
    for block in raw.decode("utf-8", "strict").split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if len(line) > 3 and line[1:3] == ": ":
                key, value = line[3:].split("=", 1) if "=" in line[3:] else (line[0], line[3:])
                fields.setdefault(key, []).append(value)
        serials = fields.get("ID_SERIAL_SHORT", [])
        device_types = fields.get("DEVTYPE", [])
        paths = fields.get("P", []) or fields.get("DEVPATH", [])
        if device_types != ["usb_device"] or len(serials) != 1 or len(paths) != 1:
            continue
        port = paths[0].rstrip("/").split("/")[-1]
        if USB_PORT.fullmatch(port) is not None:
            records.append((serials[0], port))
    return records


def pve_mapping_matches(raw, expected):
    value = json.loads(raw)
    candidates = value.get("map") if isinstance(value, dict) else None
    if candidates is None and isinstance(value, list):
        candidates = value
    if not isinstance(candidates, list) or len(candidates) != 1:
        return False
    item = candidates[0]
    if isinstance(item, str):
        parts = item.split(",")
        if len(parts) != 3 or any("=" not in part for part in parts):
            return False
        fields = dict(part.split("=", 1) for part in parts)
        return set(fields) == {"id", "node", "path"} and \
            re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{4}", fields["id"]) is not None and \
            fields["node"] == SPEC["node"] and fields["path"] == expected
    if not isinstance(item, dict) or not set(item).issubset({"id", "node", "path"}):
        return False
    return item.get("node") == SPEC["node"] and item.get("path") == expected and \
        ("id" not in item or isinstance(item["id"], str) and
         re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{4}", item["id"]) is not None)


def summaries():
    try:
        state = runtime_state()
        access = state["access"]
        home = Path("/home")
        human_ok = all(absent_fixed(home / "proxmox" / ".ssh" / name) for name in ("authorized_keys", "authorized_keys2"))
        forced = 'restrict,command="sudo -n -- /usr/local/libexec/home-lab/proxmox-observer observe" '
        plan_text = read_fixed(home / "tofu-plan" / ".ssh" / "authorized_keys", owner_name="tofu-plan")
        apply_text = read_fixed(home / "tofu-apply" / ".ssh" / "authorized_keys", owner_name="tofu-apply")
        firewall_text = read_fixed(home / "firewall-apply" / ".ssh" / "authorized_keys", owner_name="firewall-apply")
        firewall_forced = 'restrict,command="/usr/local/libexec/home-lab/proxmox-firewall-transport" '
        apply_forced = 'restrict,command="/usr/local/libexec/home-lab/proxmox-apply-transport" '
        plan_ok = plan_text == "".join(forced + key + "\n" for key in access["planKeys"])
        apply_ok = apply_text == "".join(apply_forced + key + "\n" for key in access["applyKeys"])
        firewall_ok = firewall_text == "".join(firewall_forced + key + "\n" for key in access["firewallKeys"])
        escrow = Path("/root") / ".config" / "home-lab"
        plan_escrow = read_fixed(escrow / "proxmox-plan-token.env")
        apply_escrow = read_fixed(escrow / "proxmox-apply-token.env")
        acl_raw = run(("/usr/bin/pvesh", "get", "/access/acl", "--output-format", "json"))
        acl_records = json.loads(acl_raw) if acl_raw is not None else None
        if not isinstance(acl_records, list):
            raise ValueError("protected ACL observation unavailable")
        plan_token_ok = plan_escrow == "PROXMOX_VE_API_TOKEN=" + access["planToken"] + "\n" and \
            token_valid(access["planToken"]) and token_policy_valid(access["planToken"], "plan", acl_records,
                                                                 access["planTokenIdentity"])
        apply_token_ok = apply_escrow == "PROXMOX_VE_API_TOKEN=" + access["applyToken"] + "\n" and \
            token_valid(access["applyToken"]) and token_policy_valid(access["applyToken"], "apply", acl_records,
                                                                   access["applyTokenIdentity"])
        access_summary = summary_record((human_ok, plan_ok, apply_ok, firewall_ok, plan_token_ok, apply_token_ok))

        hardware = state["hardware"]
        vm = run(("/usr/sbin/qm", "config", "100"))
        guid = run(("/usr/sbin/zpool", "get", "-H", "-o", "value", "guid", SPEC["pool"]))
        topology = run(("/usr/sbin/zpool", "status", "-P", SPEC["pool"]))
        games_ok = vm is not None and parse_qm_disk(vm) == hardware["gamesDiskIdentity"]
        mirrors = parse_zfs_mirrors(topology) if topology is not None else []
        pool_ok = guid is not None and guid.decode("ascii", "strict").strip() == hardware["poolGuid"] and \
            [item for pair in mirrors for item in pair] == hardware["poolMembers"]
        udev = run(("/usr/bin/udevadm", "info", "--export-db"))
        observed_usb = parse_udev(udev) if udev is not None else []
        usb_ok = True
        for mapping in hardware["usbMappings"]:
            resolved = [(serial, port) for serial, port in observed_usb if serial == mapping["serial"]]
            raw_mapping = run(("/usr/bin/pvesh", "get", "/cluster/mapping/usb/" + mapping["mapping"], "--output-format", "json"))
            usb_ok = usb_ok and resolved == [(mapping["serial"], mapping["port"])] and raw_mapping is not None and \
                pve_mapping_matches(raw_mapping.decode("utf-8", "strict"), mapping["port"])
        hardware_summary = summary_record((games_ok, pool_ok, usb_ok))
        return {"protectedAccess": access_summary, "protectedHardware": hardware_summary}
    except Exception:
        return {"protectedAccess": {"expectedCount": 6, "matches": None, "observedCount": None, "status": "unavailable"},
                "protectedHardware": {"expectedCount": 3, "matches": None, "observedCount": None, "status": "unavailable"}}


def valid_state(domain, value, expected_keys):
    if not isinstance(value, dict) or value.get("state") not in {"absent", "present"}:
        return False
    if value["state"] == "absent":
        return set(value) == {"state"}
    if set(value) != expected_keys:
        return False
    boolean_keys = {"contentMatches", "groupMatches", "ownerMatches", "symlinkTargetMatches", "active", "enabled"}
    if any(key in value and not isinstance(value[key], bool) for key in boolean_keys):
        return False
    if "mode" in value and (not isinstance(value["mode"], str) or re.fullmatch(r"0[0-7]{3}", value["mode"]) is None):
        return False
    if "matchCount" in value and (not isinstance(value["matchCount"], int) or isinstance(value["matchCount"], bool) or value["matchCount"] < 0):
        return False
    types = {"managed-files": {"file", "symlink", "other", "absent"},
             "managed-fragments": {"file", "symlink", "other", "absent"},
             "managed-artifacts": {"file", "symlink", "other", "absent"}}
    return "type" not in value or value["type"] in types.get(domain, set())


def catalog_action(action):
    keys = {"after", "approvalRequired", "before", "dependsOn", "domain", "id", "kind", "postconditions",
            "preconditionSha256", "rebootRequired", "safetyClass", "sequence", "target", "watchdogRequired"}
    exact(action, keys, "action")
    if not isinstance(action["domain"], str) or not isinstance(action["target"], dict):
        raise ValueError("action target differs")
    target_key = "name" if action["domain"] == "services" else "path"
    exact(action["target"], {target_key, "type"}, "action target")
    target = action["target"][target_key]
    item = SPEC["catalog"].get(action["domain"] + "\0" + target)
    fixed = {k: action[k] for k in ("after", "approvalRequired", "domain", "kind", "rebootRequired", "safetyClass", "target", "watchdogRequired")}
    if item is None or fixed != item["action"] or action["watchdogRequired"] or action["rebootRequired"] or \
            any(not isinstance(action[key], bool) for key in ("approvalRequired", "rebootRequired", "watchdogRequired")):
        raise ValueError("action is closed during protected preparation")
    after = action["after"]
    before = action["before"]
    if after != item["after"] or not valid_state(action["domain"], before, set(after)):
        raise ValueError("action state differs")
    expected_precondition = digest({"before": before, "domain": action["domain"], "target": target})
    expected_id = digest({"after": after, "before": before, "domain": action["domain"], "kind": action["kind"], "target": target})
    if not isinstance(action["sequence"], int) or isinstance(action["sequence"], bool) or action["sequence"] < 1 or \
            not isinstance(action["dependsOn"], list) or any(not isinstance(value, str) or HEX.fullmatch(value) is None for value in action["dependsOn"]) or \
            action["preconditionSha256"] != expected_precondition or action["id"] != expected_id or \
            action["postconditions"] != [{"expected": after, "type": "state-equals"}]:
        raise ValueError("action identity or postcondition differs")


def validate_issue(issue, collection):
    exact(issue, {"code", "detail", "domain", "id", "kind", "target"}, "issue")
    allowed = {"blocker"} if collection == "blockers" else {"audit", "drift", "opentofu"}
    if any(not isinstance(issue[key], str) for key in ("code", "detail", "domain", "id", "kind", "target")) or \
            re.fullmatch(r"[a-z0-9-]+", issue["code"]) is None or issue["kind"] not in allowed or \
            issue["domain"] not in DOMAIN_ORDER or HEX.fullmatch(issue["id"]) is None or \
            issue["id"] != digest({"code": issue["code"], "domain": issue["domain"], "target": issue["target"]}):
        raise ValueError("issue binding differs")


def validate_plan(plan, install):
    exact(plan, {"actions", "applyEligible", "bindings", "blockers", "findings", "format", "freshness", "mode",
                 "observedState", "planSha256", "privatePreconditionsRequired", "status"}, "plan")
    if plan["format"] != "home-lab-proxmox-plan-v1" or plan["status"] != "ready" or plan["mode"] != "steady" or \
            plan["applyEligible"] is not True or plan["blockers"] != [] or not isinstance(plan["findings"], list) or \
            not isinstance(plan["actions"], list) or plan["privatePreconditionsRequired"] != bool(plan["actions"]):
        raise ValueError("plan is not prepare-eligible")
    if not isinstance(plan["planSha256"], str) or HEX.fullmatch(plan["planSha256"]) is None or \
            digest({k: v for k, v in plan.items() if k != "planSha256"}) != plan["planSha256"]:
        raise ValueError("plan hash differs")
    freshness = exact(plan["freshness"], {"completedAt", "maxAgeSeconds", "observedAt", "validUntil"}, "plan freshness")
    observed = parse_time(freshness["observedAt"]); completed = parse_time(freshness["completedAt"])
    valid_until = parse_time(freshness["validUntil"])
    if not isinstance(freshness["maxAgeSeconds"], int) or isinstance(freshness["maxAgeSeconds"], bool) or \
            freshness["maxAgeSeconds"] != 300 or valid_until != observed + dt.timedelta(seconds=300) or \
            completed < observed or completed > valid_until or dt.datetime.now(dt.timezone.utc) > valid_until:
        raise ValueError("plan freshness differs or expired")
    observed_state = exact(plan["observedState"], {"domainStatuses", "sha256"}, "observed state")
    exact(observed_state["domainStatuses"], OBSERVED_DOMAINS, "observed domain statuses")
    if not isinstance(observed_state["sha256"], str) or HEX.fullmatch(observed_state["sha256"]) is None or \
            any(value not in {"complete", "unavailable"} for value in observed_state["domainStatuses"].values()):
        raise ValueError("observed state differs")
    previous = None
    previous_order = -1
    for index, action in enumerate(plan["actions"], 1):
        catalog_action(action)
        order = SPEC["catalogOrder"].index(action["domain"] + "\0" + str(action["target"].get("path", action["target"].get("name"))))
        if action["sequence"] != index or action["dependsOn"] != ([] if previous is None else [previous]) or order <= previous_order:
            raise ValueError("action order or dependency differs")
        previous = action["id"]; previous_order = order
    for name in ("findings", "blockers"):
        last = None
        for issue in plan[name]:
            validate_issue(issue, name)
            current = (DOMAIN_ORDER[issue["domain"]], issue["target"], issue["code"], issue["id"])
            if last is not None and current < last:
                raise ValueError("issue ordering differs")
            last = current
    bindings = plan["bindings"]
    expected = install["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != set(expected) or bindings != expected:
        raise ValueError("installed binding differs")
    for name, value in bindings.items():
        if name == "observerProtocol":
            if value != PROTOCOL: raise ValueError("protocol binding differs")
        elif name == "bundleFormat":
            if value != "home-lab-proxmox-host-bundle-v1": raise ValueError("bundle format differs")
        elif name in {"gitCommit", "gitTree"}:
            if not isinstance(value, str) or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None: raise ValueError("Git binding differs")
        elif not isinstance(value, str) or HEX.fullmatch(value) is None:
            raise ValueError("hash binding differs")
    if bindings.get("privatePreparerSha256") != self_sha256():
        raise ValueError("installed preparer differs")


def install_manifest():
    value = secure_json(INSTALL, 128 * 1024)
    exact(value, {"bindings", "bundleContentSha256", "firewallAssets", "format", "gitCommit", "gitTree", "helpers"}, "install manifest")
    firewall_assets = value["firewallAssets"]
    if not isinstance(firewall_assets, dict) or not firewall_assets:
        raise ValueError("installed firewall assets differ")
    for path, record in firewall_assets.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(record, dict) or \
                set(record) != {"mode", "sha256"} or record["mode"] not in {0o644, 0o755} or \
                not isinstance(record["sha256"], str) or HEX64.fullmatch(record["sha256"]) is None:
            raise ValueError("installed firewall asset binding differs")
    helpers = exact(value["helpers"], {"proxmox-activator", "proxmox-observer", "proxmox-private-preparer"}, "installed helpers")
    bindings = value["bindings"]
    expected_binding_keys = {"activationEnvelopeSchemaSha256", "activatorSha256", "bundleContentSha256", "bundleFormat",
        "flakeLockSha256", "gitCommit", "gitTree", "observerProtocol", "observerSha256", "packageManifestSha256",
        "planSchemaSha256", "privatePreconditionsSchemaSha256", "privatePreparationRequestSchemaSha256",
        "privatePreparerSha256", "projectionSha256"}
    exact(bindings, expected_binding_keys, "installed bindings")
    if value["format"] != "home-lab-proxmox-install-v2" or bindings["gitCommit"] != value["gitCommit"] or \
            bindings["gitTree"] != value["gitTree"] or bindings["bundleContentSha256"] != value["bundleContentSha256"] or \
            bindings["activatorSha256"] != helpers["proxmox-activator"] or bindings["observerSha256"] != helpers["proxmox-observer"] or \
            bindings["privatePreparerSha256"] != helpers["proxmox-private-preparer"] or helpers["proxmox-private-preparer"] != self_sha256():
        raise ValueError("install manifest differs")
    return value


def sidecar_projection(value):
    projection = json.loads(canonical(value))
    projection["hostSession"].pop("sidecarMac", None)
    return projection


def prepare():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("request too large")
    request = json.loads(raw)
    if raw != canonical(request):
        raise ValueError("request noncanonical")
    exact(request, {"format", "operatorGates", "plan", "protocol", "requestedAt"}, "request")
    if request["format"] != "home-lab-proxmox-private-preparation-request-v1" or request["protocol"] != PROTOCOL:
        raise ValueError("request protocol differs")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    requested = parse_time(request["requestedAt"])
    if abs((now - requested).total_seconds()) > 30:
        raise ValueError("request is stale")
    gates = exact(request["operatorGates"], {"backupsConfirmed", "consoleConfirmed", "lanRollbackConfirmed", "noConcurrentMutationConfirmed"}, "gates")
    if gates["noConcurrentMutationConfirmed"] is not True or any(not isinstance(v, bool) for v in gates.values()):
        raise ValueError("operator gate differs")
    install = install_manifest()
    plan = request["plan"]
    validate_plan(plan, install)
    if any(action["watchdogRequired"] for action in plan["actions"]) and not all(gates.values()):
        raise ValueError("watchdog gates differ")
    observed = summaries()
    if any(value["status"] != "complete" or value["matches"] is not True for value in observed.values()):
        raise ValueError("protected preconditions unavailable or mismatched")
    key = secure_key()
    challenge = secrets.token_urlsafe(32)
    session_id = secrets.token_urlsafe(32)
    expires = min(parse_time(plan["freshness"]["validUntil"]), now + dt.timedelta(seconds=300))
    attestations = {}
    for type_name in ("protectedAccess", "protectedHardware"):
        message = {"challenge": challenge, "expectedCount": observed[type_name]["expectedCount"], "hostSessionId": session_id,
                   "matches": True, "planSha256": plan["planSha256"], "type": type_name}
        attestations[type_name] = {"expectedCount": observed[type_name]["expectedCount"], "keyedAttestation": hmac.new(key, canonical(message), hashlib.sha256).hexdigest(), "matches": True}
    sidecar = {"actionManifestSha256": digest(plan["actions"]), "attestations": attestations,
               "bindings": {name: value for name, value in plan["bindings"].items()
                            if name not in {"bundleFormat", "observerProtocol"}},
               "challenge": challenge, "createdAt": format_time(now),
               "format": "home-lab-proxmox-private-preconditions-v1", "hostSession": {"id": session_id, "sidecarMac": ""},
               "operatorGates": gates, "packageSession": None, "planSha256": plan["planSha256"], "validUntil": format_time(expires)}
    sidecar["hostSession"]["sidecarMac"] = hmac.new(key, canonical(sidecar_projection(sidecar)), hashlib.sha256).hexdigest()
    output = canonical(sidecar)
    if len(output) > MAX_OUTPUT:
        raise ValueError("sidecar too large")
    write_stdout(output)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"summary", "prepare"}:
        os.write(2, b"usage: proxmox-private-preparer <summary|prepare>\n")
        return 64
    operation_fd = acquire_operation()
    try:
        # Shared ordering: live mutex, then persistent ownership inspection.
        if persistent_exists(ANSIBLE_LOCK):
            raise ValueError("Ansible host ownership is active")
        if sys.argv[1] == "summary":
            write_stdout(canonical(summaries()))
        else:
            if persistent_exists(APPLY_LOCK):
                raise ValueError("Nix apply ownership is active")
            prepare()
    finally:
        os.close(operation_fd)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        os.write(2, b"proxmox-private-preparer: protected operation failed\n")
        raise SystemExit(1)
