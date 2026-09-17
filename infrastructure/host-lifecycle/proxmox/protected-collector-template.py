#!/usr/bin/python3
"""Read-only protected summary collector. Retains sealed runtime format, not mutation authority."""

import base64

import datetime as dt

import fcntl

import hashlib

import hmac

import grp

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

SPEC = json.loads('@PROTECTED_SPEC@')

ROOT = Path("/var/lib/home-lab/reconciliation")

PROTECTED = ROOT / "protected-inputs.json"

PROTECTED_MAC = ROOT / "protected-inputs.mac"

KEY = ROOT / "session.key"

ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}

PVE_ROOT = "/" + "etc" + "/" + "pve"

SSH_DIRECTORY = "/" + "." + "ssh"

KEY_NAMES = ("authorized" + "_" + "keys", "authorized" + "_" + "keys2")

PVE_ROOT_KEY = Path(PVE_ROOT + "/priv/authorized_keys")

ROOT_KEY_LINK = Path("/root/.ssh/authorized_keys")

AUTHORIZED_KEY_ABSENCE_CATALOG = tuple(sorted({
    PVE_ROOT + "/priv/authorized_keys2",
    "/root/.ssh/authorized_keys2",
    *(f"/home/{account}" + SSH_DIRECTORY + "/" + name for account in ("proxmox", "firewall-apply", "ansible-plan", "ansible-deploy", "tofu-plan", "tofu-apply") for name in KEY_NAMES),
}))

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

def read_fixed_group(path, owner_name, group_name, required_mode=0o600):
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
            if not stat.S_ISREG(before.st_mode) or before.st_uid != pwd.getpwnam(owner_name).pw_uid or \
                    before.st_gid != grp.getgrnam(group_name).gr_gid or before.st_nlink != 1 or \
                    stat.S_IMODE(before.st_mode) != required_mode or before.st_size > 256 * 1024:
                return None
            chunks = []
            remaining = before.st_size
            while remaining:
                block = os.read(file_fd, min(65536, remaining))
                if not block: return None
                chunks.append(block); remaining -= len(block)
            after = os.fstat(file_fd)
            if fingerprint(before) != fingerprint(after):
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

def inert_root_key_ok():
    try:
        link = os.lstat(ROOT_KEY_LINK)
        if not stat.S_ISLNK(link.st_mode) or link.st_uid != 0 or link.st_gid != 0 or \
                os.readlink(ROOT_KEY_LINK) != str(PVE_ROOT_KEY):
            return False
        text = read_fixed_group(PVE_ROOT_KEY, "root", "www-data")
        active = [line.split() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")] if text is not None else []
        if len(active) != 1 or len(active[0]) < 2 or re.fullmatch(r"(?:ssh|ecdsa)-[^\s]+", active[0][0]) is None:
            return False
        decoded = base64.b64decode(active[0][1], validate=True)
        observed = "SHA256:" + base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")
        sshd = run(("/usr/sbin/sshd", "-T", "-C", "user=root,host=proxmox,addr=127.0.0.1,laddr=127.0.0.1,lport=22"))
        effective = set(sshd.decode("utf-8", "strict").splitlines()) if sshd is not None else set()
        return observed == SPEC["permittedRootKeyFingerprint"] and \
            "pubkeyauthentication no" in effective and "permitrootlogin no" in effective
    except (OSError, UnicodeError, ValueError):
        return False

def summaries():
    try:
        state = runtime_state()
        access = state["access"]
        if SPEC["conventionalKeyPolicy"] != "single-inert-pve-root-key":
            raise ValueError("protected conventional-key policy differs")
        conventional_ok = inert_root_key_ok() and all(absent_fixed(Path(path)) for path in AUTHORIZED_KEY_ABSENCE_CATALOG)
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
        access_checks = [conventional_ok, plan_token_ok, apply_token_ok]
        access_summary = summary_record(access_checks)

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
        return {"protectedAccess": {"expectedCount": SPEC["protectedAccessExpectedCount"], "matches": None, "observedCount": None, "status": "unavailable"},
                "protectedHardware": {"expectedCount": 3, "matches": None, "observedCount": None, "status": "unavailable"}}

if __name__ == "__main__":
    if os.geteuid() != 0 or sys.argv[1:] != ["summary"]:
        raise SystemExit(64)
    write_stdout(canonical(summaries()))
