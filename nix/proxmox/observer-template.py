#!/usr/bin/python3
"""Fixed, bundle-specific, redacting Proxmox observer (template input)."""

import grp
import hashlib
import json
import os
import pwd
import re
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROTOCOL = 2
SPEC = json.loads('@OBSERVATION_SPEC@')
MAX_COMMAND_BYTES = 4 * 1024 * 1024
ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def run_result(arguments, timeout=8, accepted=(0,)):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=timeout)
        if result.returncode not in accepted or result.stderr or len(result.stdout) > MAX_COMMAND_BYTES:
            return None
        return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None


def run(arguments, timeout=8):
    return run_result(arguments, timeout)


def content_matches(path, expected):
    try:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                block = handle.read(65536)
                if not block:
                    break
                hasher.update(block)
        return hasher.hexdigest() == expected
    except OSError:
        return None


def file_record(item):
    path = Path(item["target"])
    record = {"target": item["target"], "type": "absent", "ownerMatches": False, "groupMatches": False,
              "mode": "0000", "contentMatches": False}
    try:
        info = path.lstat()
        record["type"] = "file" if stat.S_ISREG(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "other"
        record["ownerMatches"] = pwd.getpwuid(info.st_uid).pw_name == item["owner"]
        record["groupMatches"] = grp.getgrgid(info.st_gid).gr_name == item["group"]
        record["mode"] = f"0{stat.S_IMODE(info.st_mode):03o}"
        if stat.S_ISREG(info.st_mode):
            matches = content_matches(path, item["expectedSha256"])
            if matches is None:
                return record, False
            record["contentMatches"] = matches
    except FileNotFoundError:
        pass
    except (OSError, KeyError):
        return record, False
    return record, True


def fragment_record(item):
    base, available = file_record(item)
    count = 0
    if base["type"] == "file":
        try:
            with Path(item["target"]).open("r", encoding="utf-8", errors="strict") as handle:
                count = sum(1 for line in handle if line.rstrip("\n") == item["content"])
        except (OSError, UnicodeError):
            available = False
    return ({"target": base["target"], "type": base["type"], "ownerMatches": base["ownerMatches"],
             "groupMatches": base["groupMatches"], "mode": base["mode"], "matchCount": count}, available)


def artifact_record(item):
    base, available = file_record(item)
    symlink = None
    try:
        candidate = Path(item["target"])
        if candidate.is_symlink():
            link = os.readlink(candidate)
            if "/" not in link and link not in {".", ".."}:
                symlink = link
                if symlink == item["symlinkTarget"]:
                    target_info = candidate.stat()
                    base["ownerMatches"] = pwd.getpwuid(target_info.st_uid).pw_name == item["owner"]
                    base["groupMatches"] = grp.getgrgid(target_info.st_gid).gr_name == item["group"]
                    base["mode"] = f"0{stat.S_IMODE(target_info.st_mode):03o}"
                    matches = content_matches(candidate, item["expectedSha256"])
                    if matches is None:
                        available = False
                    else:
                        base["contentMatches"] = matches
    except OSError:
        available = False
    return {**base, "symlinkTargetMatches": symlink == item["symlinkTarget"]}, available


def audit_record(item):
    path = Path(item["target"])
    if item["absence"] == "file":
        try:
            path.lstat()
            return {"count": 1, "target": item["target"], "type": item["absence"]}, True
        except FileNotFoundError:
            return {"count": 0, "target": item["target"], "type": item["absence"]}, True
        except OSError:
            return None, False
    try:
        expression = re.compile(item["pattern"])
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            count = sum(1 for line in handle if expression.fullmatch(line.rstrip("\n")))
        return {"count": count, "target": item["target"], "type": item["absence"]}, True
    except FileNotFoundError:
        return {"count": 0, "target": item["target"], "type": item["absence"]}, True
    except (OSError, UnicodeError, re.error):
        return None, False


def parse_dpkg_query(raw):
    records = []
    try:
        for line in raw.decode("utf-8", "strict").splitlines():
            status, name, architecture, version = line.split("\t")
            if len(status) != 3:
                raise ValueError("invalid status")
            if status[1] != "i":
                continue
            if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", name) or not architecture or len(version) > 256:
                raise ValueError("invalid package record")
            records.append({"name": name, "version": version})
    except (UnicodeError, ValueError):
        return None
    if len({item["name"] for item in records}) != len(records):
        return None
    return sorted(records, key=lambda item: item["name"])


def packages():
    raw = run(("/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${Architecture}\\t${Version}\\n"), 15)
    records = parse_dpkg_query(raw) if raw is not None else None
    return records_domain(records)


def records_domain(records, unexpected=0):
    if records is None:
        return {"records": [], "status": "unavailable", "unexpectedCount": None}
    return {"records": records, "status": "complete", "unexpectedCount": unexpected}


def services():
    records = []
    for name in SPEC["services"]:
        enabled = run_result(("/usr/bin/systemctl", "is-enabled", name), accepted=(0, 1, 3, 4))
        active = run_result(("/usr/bin/systemctl", "is-active", name), accepted=(0, 3, 4))
        if enabled is None or active is None:
            return records_domain(None)
        records.append({"active": active.strip() == b"active", "enabled": enabled.strip() == b"enabled", "name": name})
    return records_domain(records)


def accounts():
    records = []
    for item in SPEC["accounts"]:
        try:
            account = pwd.getpwnam(item["name"])
            primary = grp.getgrgid(account.pw_gid).gr_name
            groups = sorted(group.gr_name for group in grp.getgrall() if item["name"] in group.gr_mem)
            password = run(("/usr/bin/passwd", "-S", item["name"]))
            if password is None:
                return records_domain(None)
            fields = password.split()
            locked = len(fields) > 1 and fields[1] in {b"L", b"LK"}
            records.append({"commentMatches": account.pw_gecos == item["comment"], "exists": True,
                            "expectedGroupsMatch": groups == sorted(item["groups"]), "home": account.pw_dir,
                            "name": item["name"], "passwordLocked": locked,
                            "primaryGroupMatches": primary == item["primaryGroup"], "shell": account.pw_shell})
        except (KeyError, OSError):
            records.append({"commentMatches": False, "exists": False, "expectedGroupsMatch": False,
                            "home": item["home"], "name": item["name"], "passwordLocked": False,
                            "primaryGroupMatches": False, "shell": item["shell"]})
    return records_domain(records)


def summary(status="unavailable", expected=1, observed=None, matches=None):
    return {"expectedCount": expected, "matches": matches, "observedCount": observed, "status": status}


def json_command(arguments):
    raw = run(arguments)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        return None


def normalized_boolean(value, default=None):
    if value is None:
        return default
    if value in (True, 1, "1"):
        return True
    if value in (False, 0, "0"):
        return False
    return None


def normalized_firewall_rule(value):
    if not isinstance(value, dict):
        return None
    aliases = {"dest_port": "destination_port", "destination_port": "destination_port", "dport": "destination_port",
               "dest": "destination", "destination": "destination", "sport": "source_port", "source_port": "source_port",
               "iface": "interface", "interface": "interface", "source": "source", "protocol": "protocol",
               "proto": "protocol", "direction": "direction", "type": "direction", "action": "action", "log": "log"}
    normalized = {"destination": None, "destination_port": None, "enabled": normalized_boolean(value.get("enable"), True),
                  "interface": None, "source": None, "source_port": None}
    for source, target in aliases.items():
        if source in value:
            normalized[target] = value[source]
    for key in ("destination_port", "source_port"):
        if normalized[key] is not None:
            try:
                normalized[key] = int(normalized[key])
            except (TypeError, ValueError):
                return None
    for key in ("direction", "action"):
        if key in normalized and isinstance(normalized[key], str):
            normalized[key] = normalized[key].upper()
    required = {"action", "direction", "log", "protocol", "source"}
    if normalized["enabled"] is None or not required.issubset(normalized):
        return None
    return normalized


def normalized_collection(item):
    if isinstance(item, str):
        values = item.split(",")
    elif isinstance(item, list):
        values = item
    else:
        return None
    if any(not isinstance(part, str) or not part for part in values):
        return None
    return sorted(set(values))


def normalized_storage(value):
    if not isinstance(value, dict):
        return None
    content = normalized_collection(value.get("content"))
    nodes = normalized_collection(value.get("nodes"))
    disabled = normalized_boolean(value.get("disable"), False)
    if content is None or nodes is None or disabled is None:
        return None
    return {"content": content, "disabled": disabled, "mountpoint": value.get("mountpoint"),
            "nodes": nodes, "pool": value.get("pool"), "type": value.get("type")}


def normalized_privileges(value):
    if isinstance(value, str):
        privileges = value.split(",") if value else []
    elif isinstance(value, list):
        privileges = value
    else:
        return None
    if any(not isinstance(item, str) or not item.strip() for item in privileges):
        return None
    stripped = [item.strip() for item in privileges]
    if len(stripped) != len(set(stripped)):
        return None
    return sorted(stripped)


def parse_nfs_exports(raw):
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError:
        return None
    entries = []
    for line in lines:
        match = re.fullmatch(r"\s*(\S+)\s+(\S+)\(([^()]*)\)\s*", line)
        if not match:
            return None
        options = match.group(3).split(",") if match.group(3) else []
        if any(not option for option in options):
            return None
        entries.append({"client": match.group(2), "export": match.group(1), "options": sorted(options)})
    return sorted(entries, key=lambda item: (item["export"], item["client"], item["options"]))


def tailscale_summary():
    status_value = json_command(("/usr/bin/tailscale", "status", "--json"))
    prefs = json_command(("/usr/bin/tailscale", "debug", "prefs"))
    if not isinstance(status_value, dict) or not isinstance(prefs, dict):
        return summary(expected=2)
    expected = SPEC["tailscale"]
    netfilter = prefs.get("NetfilterMode")
    if isinstance(netfilter, int) and not isinstance(netfilter, bool):
        netfilter = {0: "off", 1: "nodivert", 2: "on"}.get(netfilter)
    routes, tags = prefs.get("AdvertiseRoutes"), prefs.get("AdvertiseTags")
    if not isinstance(routes, list) or not isinstance(tags, list) or \
            any(not isinstance(item, str) for item in routes + tags) or \
            not all(isinstance(prefs.get(key), bool) for key in ("CorpDNS", "RouteAll", "RunSSH")) or \
            not isinstance(prefs.get("Hostname"), str) or not isinstance(netfilter, str):
        return summary(expected=2)
    observed = {"acceptDns": prefs.get("CorpDNS"), "acceptRoutes": prefs.get("RouteAll"),
                "advertiseRoutes": sorted(routes), "advertiseTags": sorted(tags),
                "hostname": prefs.get("Hostname"), "netfilterMode": netfilter, "ssh": prefs.get("RunSSH")}
    desired = {key: expected[key] for key in observed}
    matches = status_value.get("BackendState") == expected["backendState"] and observed == desired
    return summary("complete", 2, 2, matches)


def public_summaries():
    options = json_command(("/usr/bin/pvesh", "get", "/cluster/firewall/options", "--output-format", "json"))
    rules = json_command(("/usr/bin/pvesh", "get", "/cluster/firewall/rules", "--output-format", "json"))
    firewall = summary(expected=len(SPEC["pveFirewall"]["rules"]) + 1)
    if isinstance(options, dict) and isinstance(rules, list):
        desired = SPEC["pveFirewall"]
        normalized_rules = [normalized_firewall_rule(item) for item in rules]
        expected_rules = [normalized_firewall_rule(item) for item in desired["rules"]]
        observed_options = {key: options.get(key) for key in desired["options"]}
        if isinstance(desired["options"].get("enable"), bool):
            observed_options["enable"] = observed_options.get("enable") in {True, 1, "1"}
        matches = observed_options == desired["options"] and None not in normalized_rules and \
            sorted(normalized_rules, key=canonical) == sorted(expected_rules, key=canonical)
        firewall = summary("complete", len(expected_rules) + 1, len(normalized_rules) + 1, matches)

    storage_id = SPEC["pveStorage"]["id"]
    registration = json_command(("/usr/bin/pvesh", "get", "/storage/" + storage_id, "--output-format", "json"))
    storage_registration = summary()
    if isinstance(registration, dict):
        desired = normalized_storage(SPEC["pveStorage"])
        storage_registration = summary("complete", 1, 1, normalized_storage(registration) == desired)

    roles = json_command(("/usr/bin/pvesh", "get", "/access/roles", "--output-format", "json"))
    access = summary(expected=len(SPEC["pveAccessRoles"]))
    if isinstance(roles, list):
        observed_roles = {item.get("roleid"): normalized_privileges(item.get("privs"))
                          for item in roles if isinstance(item, dict) and isinstance(item.get("roleid"), str)}
        desired_roles = {item["role"]: normalized_privileges(item["privileges"]) for item in SPEC["pveAccessRoles"]}
        observed_expected_count = sum(1 for name in desired_roles if name in observed_roles)
        access = summary("complete", len(desired_roles), observed_expected_count,
                         None not in observed_roles.values() and None not in desired_roles.values() and
                         all(observed_roles.get(name) == privileges for name, privileges in desired_roles.items()))

    storage = storage_summary()
    vm = vm_summary()
    health = health_summary(vm)
    return tailscale_summary(), access, firewall, storage_registration, storage, vm, health


def storage_summary():
    policy = SPEC["storage"]
    health = run(("/usr/sbin/zpool", "list", "-H", "-o", "health", SPEC["pveStorage"]["pool"]))
    topology = run(("/usr/sbin/zpool", "status", "-P", SPEC["pveStorage"]["pool"]))
    dataset = run(("/usr/sbin/zfs", "get", "-H", "-o", "property,value", "mountpoint,mounted,sharenfs", policy["dataset"]))
    arc = run(("/bin/cat", "/sys/module/zfs/parameters/zfs_arc_max"))
    exports = run(("/usr/sbin/exportfs", "-v"))
    if None in (health, topology, dataset, arc, exports):
        return summary(expected=6)
    try:
        properties = dict(line.split("\t", 1) for line in dataset.decode("utf-8", "strict").splitlines())
        topology_lines = topology.decode("utf-8", "strict").splitlines()
        mirror_count = sum(1 for line in topology_lines if re.match(r"^\s+mirror-\d+\s+", line))
        status_rows = sum(1 for line in topology_lines if re.match(
            r"^\s+\S+\s+(?:ONLINE|DEGRADED|FAULTED|UNAVAIL|OFFLINE)\s+", line))
        member_count = status_rows - mirror_count - 1
        export_entries = parse_nfs_exports(exports)
        expected_export = {"client": policy["nfs"]["client"], "export": policy["nfs"]["export"],
                           "options": sorted(policy["nfs"]["options"] + [policy["nfs"]["squashPolicy"]])}
        export_matches = export_entries == [expected_export]
        matches = health.strip().decode("ascii") == policy["expectedHealth"] and int(arc.strip()) == policy["arcMaxBytes"] and \
            properties == {"mounted": "yes", "mountpoint": policy["mountpoint"],
                           "sharenfs": policy["datasetProperties"]["sharenfs"]} and \
            mirror_count == policy["mirrorTopology"]["count"] and \
            member_count == policy["mirrorTopology"]["count"] * policy["mirrorTopology"]["width"] and export_matches
        return summary("complete", 6, 6, matches)
    except (UnicodeError, ValueError):
        return summary(expected=6)


def vm_summary():
    raw = run(("/usr/sbin/qm", "status", "100"))
    if raw is None:
        return summary()
    try:
        match = re.fullmatch(r"status:\s+([a-z]+)\s*", raw.decode("ascii", "strict"))
        if not match:
            return summary()
        return summary("complete", 1, 1, match.group(1) == SPEC["health"]["vmStatus"])
    except UnicodeError:
        return summary()


def health_summary(vm):
    context = ssl._create_unverified_context()
    try:
        local_api_url = "https://" + "127.0.0.1" + ":8006/api2/json/version"
        request = urllib.request.Request(local_api_url, method="GET")
        try:
            response = urllib.request.urlopen(request, context=context, timeout=5)
            code = response.status
            response.close()
        except urllib.error.HTTPError as error:
            code = error.code
        api_matches = code in SPEC["health"]["pveApiStatusCodes"]
    except (OSError, urllib.error.URLError, ValueError):
        return summary(expected=2)
    vm_matches = vm["matches"] is True if SPEC["health"]["requireVm"] else True
    return summary("complete", 2, 2, api_matches and vm_matches)


def host():
    os_name = "unknown"
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("ID="):
                os_name = line[3:].strip('"')
    except OSError:
        pass
    pve = run(("/usr/bin/pveversion",))
    pve_version = "unavailable"
    if pve:
        try:
            fields = pve.decode("utf-8", "strict").strip().split("/")
            if len(fields) >= 2 and fields[0] and fields[1]:
                pve_version = "/".join(fields[:2])[:256]
        except UnicodeError:
            pass
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine)
    return {"architecture": machine, "hostname": os.uname().nodename,
            "kernel": os.uname().release, "os": os_name, "pveVersion": pve_version}


def unexpected_regular_count(directory, expected):
    try:
        count = 0
        for entry in os.scandir(directory):
            mode = entry.stat(follow_symlinks=False).st_mode
            if not stat.S_ISREG(mode):
                if not stat.S_ISDIR(mode):
                    return None
                continue
            if entry.name not in expected:
                count += 1
        return count
    except FileNotFoundError:
        return 0 if not expected else None
    except OSError:
        return None


def observe():
    files_with_status = [file_record(item) for item in SPEC["managedFiles"]]
    files = sorted((item for item, _ in files_with_status), key=lambda item: item["target"])
    apt_unknown = unexpected_regular_count("/etc/apt/sources.list.d", set(SPEC["aptSourceNames"]))
    network_unknown = unexpected_regular_count("/etc/network/interfaces.d", set(SPEC["networkSnippetNames"]))
    managed_status = "complete" if apt_unknown is not None and network_unknown is not None and \
        all(available for _, available in files_with_status) else "unavailable"
    managed = records_domain(files, (apt_unknown or 0) + (network_unknown or 0)) if managed_status == "complete" else records_domain(None)
    fragments_with_status = [fragment_record(item) for item in SPEC["managedFragments"]]
    fragments = records_domain(sorted((item for item, _ in fragments_with_status), key=lambda item: item["target"])) \
        if all(available for _, available in fragments_with_status) else records_domain(None)
    artifacts_with_status = [artifact_record(item) for item in SPEC["managedArtifacts"]]
    artifacts = records_domain(sorted((item for item, _ in artifacts_with_status), key=lambda item: item["target"])) \
        if all(available for _, available in artifacts_with_status) else records_domain(None)
    audited = [audit_record(item) for item in SPEC["auditAbsence"]]
    audit = records_domain(sorted((item for item, _ in audited if item is not None), key=lambda item: item["target"])) \
        if all(available for _, available in audited) else records_domain(None)
    tailscale, access, firewall, registration, storage, vm, health = public_summaries()
    value = {"domains": {"accounts": accounts(), "auditAbsence": audit, "health": health,
        "managedArtifacts": artifacts, "managedFiles": managed, "managedFragments": fragments,
        "packages": packages(), "protectedAccess": summary(expected=SPEC["protectedAccessExpectedCount"]),
        "protectedHardware": summary(expected=SPEC["protectedExpectedCount"]), "pveAccess": access,
        "pveFirewall": firewall, "pveStorage": registration, "services": services(), "storage": storage,
        "tailscale": tailscale, "vm": vm}, "format": "home-lab-proxmox-observation-v1", "host": host(),
        "observerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "protocol": PROTOCOL}
    output = canonical(value)
    if len(output) > 1024 * 1024:
        raise RuntimeError("bounded observation exceeded")
    os.write(1, output)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"version", "self-check", "observe"}:
        os.write(2, b"usage: proxmox-observer <version|self-check|observe>\n")
        return 64
    if sys.argv[1] == "version":
        os.write(1, canonical({"capabilities": ["observe"], "helper": "proxmox-observer", "protocol": PROTOCOL, "version": 1}))
    elif sys.argv[1] == "self-check":
        os.write(1, b"proxmox-observer=self-check-passed protocol=2 capabilities=observe\n")
    else:
        observe()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        os.write(2, b"proxmox-observer: observation unavailable\n")
        raise SystemExit(1)
