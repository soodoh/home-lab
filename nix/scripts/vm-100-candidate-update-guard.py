#!/usr/bin/env python3
"""Fail-closed guard for updating the installed qualification generation."""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

FORMAT = "home-lab-vm-100-candidate-update-v1"
DEVICE = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2"
SERIAL = "QUAL-NIXOS-128G"
SIZE = 137438953472
SYSTEM = re.compile(r"^/nix/store/[0-9a-z]{32}-nixos-system-[0-9A-Za-z._+-]+$")
ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def fail(message):
    raise ValueError(message)


def read_request(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 16 * 1024:
        fail("request metadata differs")
    raw = path.read_bytes()
    value = json.loads(raw)
    if raw != (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode():
        fail("request is noncanonical")
    expected = {"approvedSerial", "device", "expectedCurrentSystem", "format", "observedSizeBytes", "targetSystem"}
    if set(value) != expected or value["format"] != FORMAT:
        fail("request shape differs")
    if value["approvedSerial"] != SERIAL or value["device"] != DEVICE or value["observedSizeBytes"] != SIZE:
        fail("request disk identity differs")
    for name in ("expectedCurrentSystem", "targetSystem"):
        if not isinstance(value[name], str) or SYSTEM.fullmatch(value[name]) is None:
            fail("request system identity differs")
    if value["expectedCurrentSystem"] == value["targetSystem"]:
        fail("request systems must differ")
    return value


def observe():
    if not Path(DEVICE).is_symlink():
        fail("candidate by-id path is unavailable")
    result = subprocess.run(
        ("lsblk", "--bytes", "--json", "--output", "PATH,TYPE,SIZE,SERIAL,MOUNTPOINTS,FSTYPE,PARTLABEL", DEVICE),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        timeout=10,
        check=True,
    )
    if result.stderr:
        fail("candidate observation emitted diagnostics")
    devices = json.loads(result.stdout).get("blockdevices")
    if not isinstance(devices, list) or len(devices) not in {1, 4}:
        fail("candidate observation shape differs")
    disk = devices[0]
    if disk.get("type") != "disk" or disk.get("serial") not in {SERIAL, "drive-scsi2"} or disk.get("size") != SIZE:
        fail("candidate disk identity differs")
    if disk.get("mountpoints") not in (None, [], [None]):
        fail("candidate disk is mounted")
    children = disk.get("children") if len(devices) == 1 else devices[1:]
    if not isinstance(children, list) or len(children) != 3:
        fail("candidate partition count differs")
    expected = {
        "disk-vm100-root-bios": ("part", None),
        "disk-vm100-root-ESP": ("part", "vfat"),
        "disk-vm100-root-root": ("part", "ext4"),
    }
    observed = {}
    for child in children:
        label = child.get("partlabel")
        if label in observed or child.get("mountpoints") not in (None, [], [None]):
            fail("candidate partition state differs")
        observed[label] = (child.get("type"), child.get("fstype"))
    if observed != expected:
        fail("candidate partition layout differs")
    return value_output(disk)


def value_output(disk):
    return {"device": DEVICE, "format": FORMAT, "serial": SERIAL, "sizeBytes": disk["size"], "status": "approved"}


def main():
    if len(sys.argv) != 2:
        print("usage: vm-100-candidate-update-guard REQUEST", file=sys.stderr)
        return 64
    if os.geteuid() != 0:
        fail("candidate update guard requires root")
    request = read_request(Path(sys.argv[1]))
    observed = observe()
    if os.environ.get("VM100_CANDIDATE_UPDATE_CONFIRMED") != "update-reviewed-qualification-candidate":
        fail("explicit candidate update gate required")
    observed.update({"expectedCurrentSystem": request["expectedCurrentSystem"], "targetSystem": request["targetSystem"]})
    print(json.dumps(observed, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("vm-100-candidate-update-guard: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
