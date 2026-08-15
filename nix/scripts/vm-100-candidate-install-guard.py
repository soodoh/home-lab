#!/usr/bin/env python3
"""Fail-closed inspection/install guard for the exact VM 100 candidate disk."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

FORMAT = "home-lab-vm-100-candidate-install-v1"
PROTECTED_FORMAT = "home-lab-vm-100-protected-disks-v1"
HANDOFF_FORMAT = "home-lab-vm-100-ephemeral-inspection-handoff-v1"
EXPECTED_SERIAL = "QUAL-NIXOS-128G"
EXPECTED_SIZE = 137438953472
MINIMUM_SIZE = 120 * 1024 * 1024 * 1024
MAXIMUM_SIZE = 136 * 1024 * 1024 * 1024
CANDIDATE_BY_ID = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2"
BY_ID = re.compile(r"^/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2$")
PROTECTED_BY_ID = re.compile(r"^/dev/disk/by-id/[A-Za-z0-9._:+-]+$")
ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}
TOOLS = {"fuser": "/usr/bin/fuser", "findmnt": "/usr/bin/findmnt", "lsblk": "/usr/bin/lsblk", "wipefs": "/usr/bin/wipefs"}


def fail(message):
    raise ValueError(message)


def read_canonical(path, expected_keys, label):
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > 16 * 1024):
            fail(f"{label} metadata differs")
        chunks = []
        remaining = 16 * 1024 + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            fail(f"{label} changed while read")
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != expected_keys or raw != (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode():
        fail(f"{label} is noncanonical or has the wrong shape")
    return value


def read_request(path):
    value = read_canonical(path, {"approvedSerial", "device", "format", "mode", "observedSizeBytes"}, "request")
    if value["format"] != FORMAT or value["mode"] not in {"inspect", "install"}:
        fail("request mode or format differs")
    if value["approvedSerial"] != EXPECTED_SERIAL or value["observedSizeBytes"] != EXPECTED_SIZE:
        fail("request disk identity differs")
    if not isinstance(value["device"], str) or BY_ID.fullmatch(value["device"]) is None:
        fail("request device path differs")
    return value


def read_protected(path):
    value = read_canonical(path, {"format", "gamesDevice"}, "protected disk input")
    if value["format"] != PROTECTED_FORMAT or not isinstance(value["gamesDevice"], str) or PROTECTED_BY_ID.fullmatch(value["gamesDevice"]) is None:
        fail("protected disk input differs")
    return value


def read_handoff(path):
    value = read_canonical(path, {"bootIdSha256", "device", "format", "mode", "resolvedDevice", "serial", "sizeBytes"}, "inspection handoff")
    if (value["format"] != HANDOFF_FORMAT or value["mode"] != "inspect" or value["device"] != CANDIDATE_BY_ID
            or value["serial"] != EXPECTED_SERIAL or value["sizeBytes"] != EXPECTED_SIZE
            or not isinstance(value["resolvedDevice"], str) or not value["resolvedDevice"].startswith("/dev/")
            or not isinstance(value["bootIdSha256"], str) or re.fullmatch(r"[0-9a-f]{64}", value["bootIdSha256"]) is None):
        fail("inspection handoff identity differs")
    return value


def require_inspection_mode(request, handoff):
    if handoff["mode"] != "inspect" or request["mode"] != handoff["mode"]:
        fail("inspection handoff cannot authorize request mode")


def run_json(tool, argv):
    result = subprocess.run([TOOLS[tool], *argv], stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=10, check=True)
    if result.stderr:
        fail(f"{tool} observation emitted diagnostics")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        fail(f"{tool} observation shape differs")
    return value


def mounted_sources():
    value = run_json("findmnt", ["--json", "--output", "SOURCE"])
    filesystems = value.get("filesystems")
    if not isinstance(filesystems, list):
        fail("mounted-source observation shape differs")
    sources = set()
    pending = list(filesystems)
    while pending:
        item = pending.pop()
        if not isinstance(item, dict) or not isinstance(item.get("children", []), list):
            fail("mounted-source observation shape differs")
        source = item.get("source")
        if isinstance(source, str) and source.startswith("/dev/"):
            source = source.split("[", 1)[0]
            try:
                sources.add(str(Path(source).resolve(strict=True)))
            except FileNotFoundError:
                fail("mounted source cannot be resolved")
        pending.extend(item.get("children", []))
    return sources


def observe(device, games_device):
    if not Path(device).is_symlink() or not Path(games_device).is_symlink():
        fail("candidate or protected games by-id path is unavailable")
    candidate_link = Path(device)
    games_link = Path(games_device)
    resolved = str(candidate_link.resolve(strict=True))
    games_resolved = str(games_link.resolve(strict=True))
    if not stat.S_ISBLK(Path(resolved).stat().st_mode) or not stat.S_ISBLK(Path(games_resolved).stat().st_mode):
        fail("candidate or protected games by-id does not resolve to a block device")
    if resolved == games_resolved or resolved in mounted_sources():
        fail("candidate aliases a protected or mounted source device")
    value = run_json("lsblk", ["--bytes", "--json", "--output", "PATH,TYPE,SIZE,SERIAL,MOUNTPOINTS,FSTYPE", resolved])
    devices = value.get("blockdevices")
    if not isinstance(devices, list) or len(devices) != 1 or not isinstance(devices[0], dict):
        fail("candidate observation shape differs")
    observed = devices[0]
    if observed.get("path") != resolved:
        fail("lsblk did not report the exact resolved candidate device")
    serial = observed.get("serial")
    if observed.get("type") != "disk" or serial != EXPECTED_SERIAL:
        fail("candidate serial or type differs")
    size = observed.get("size")
    if not isinstance(size, int) or size != EXPECTED_SIZE or not MINIMUM_SIZE <= size <= MAXIMUM_SIZE:
        fail("candidate capacity differs")
    if observed.get("fstype") not in (None, "") or any(item not in (None, "") for item in (observed.get("mountpoints") or [])):
        fail("candidate disk is mounted or formatted")
    if observed.get("children") not in (None, []):
        fail("candidate disk is not empty")
    wipe = run_json("wipefs", ["--json", "--output", "DEVICE,OFFSET,TYPE,UUID,LABEL", resolved])
    if not isinstance(wipe.get("signatures"), list) or wipe["signatures"]:
        fail("candidate has a filesystem or partition signature")
    holders = Path("/sys/class/block") / Path(resolved).name / "holders"
    if any(holders.iterdir()):
        fail("candidate has holders")
    opener = subprocess.run([TOOLS["fuser"], resolved], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, timeout=10, check=False)
    if opener.returncode != 1 or opener.stdout != b"" or opener.stderr != b"":
        fail("candidate has openers or opener observation failed")
    if str(candidate_link.resolve(strict=True)) != resolved or str(games_link.resolve(strict=True)) != games_resolved:
        fail("candidate or protected games by-id changed during exact resolved-device observation")
    return {"device": device, "resolved": resolved, "serial": serial, "sizeBytes": size}


def main():
    if (len(sys.argv) != 7 or sys.argv[1] != "--request" or sys.argv[3] != "--protected-disk-input"
            or sys.argv[5] != "--inspection-handoff"):
        print("usage: vm-100-candidate-install-guard --request REQUEST --protected-disk-input INPUT --inspection-handoff HANDOFF", file=sys.stderr)
        return 64
    if os.geteuid() != 0:
        fail("candidate guard requires root")
    if any(not Path(path).is_file() or not os.access(path, os.X_OK) for path in TOOLS.values()):
        fail("fixed inspection tool is unavailable")
    request = read_request(Path(sys.argv[2]))
    protected = read_protected(Path(sys.argv[4]))
    handoff = read_handoff(Path(sys.argv[6]))
    require_inspection_mode(request, handoff)
    observed_boot_id = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
    if hashlib.sha256(observed_boot_id).hexdigest() != handoff["bootIdSha256"]:
        fail("inspection handoff boot identity differs")
    first = observe(request["device"], protected["gamesDevice"])
    second = observe(request["device"], protected["gamesDevice"])
    if first != second or first["resolved"] != handoff["resolvedDevice"] or first["device"] != handoff["device"]:
        fail("candidate identity changed or differs from the runner handoff")
    if request["mode"] != "inspect":
        fail("only inspection is authorized by this handoff generation")
    output = {"device": request["device"], "format": FORMAT, "mode": request["mode"], "serial": EXPECTED_SERIAL, "sizeBytes": second["sizeBytes"], "status": "approved"}
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("vm-100-candidate-install-guard: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
