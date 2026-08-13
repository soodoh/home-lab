#!/usr/bin/env python3
"""Fail-closed guard for the VM 100 candidate-root Disko installation."""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

FORMAT = "home-lab-vm-100-candidate-install-v1"
EXPECTED_SERIAL = "QUAL-NIXOS-128G"
EXPECTED_SIZE = 137438953472
MINIMUM_SIZE = 120 * 1024 * 1024 * 1024
MAXIMUM_SIZE = 136 * 1024 * 1024 * 1024
BY_ID = re.compile(r"^/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2$")
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
    expected = {"approvedSerial", "device", "format", "mode", "observedSizeBytes"}
    if set(value) != expected or value["format"] != FORMAT or value["mode"] not in {"inspect", "install"}:
        fail("request shape differs")
    if value["approvedSerial"] != EXPECTED_SERIAL or value["observedSizeBytes"] != EXPECTED_SIZE:
        fail("request disk identity differs")
    device = value["device"]
    if not isinstance(device, str) or BY_ID.fullmatch(device) is None:
        fail("request device path differs")
    return value


def observe(device):
    if not Path(device).is_symlink():
        fail("candidate by-id path is unavailable")
    result = subprocess.run(
        ("lsblk", "--bytes", "--json", "--output", "PATH,TYPE,SIZE,SERIAL,MOUNTPOINTS,FSTYPE", device),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        timeout=10,
        check=True,
    )
    if result.stderr:
        fail("candidate observation emitted diagnostics")
    value = json.loads(result.stdout)
    devices = value.get("blockdevices")
    if not isinstance(devices, list) or len(devices) != 1:
        fail("candidate observation shape differs")
    observed = devices[0]
    serial = observed.get("serial")
    if observed.get("type") != "disk" or serial not in {EXPECTED_SERIAL, "drive-scsi2"}:
        fail("candidate serial or type differs")
    size = observed.get("size")
    if not isinstance(size, int) or size != EXPECTED_SIZE or not MINIMUM_SIZE <= size <= MAXIMUM_SIZE:
        fail("candidate capacity differs")
    mountpoints = observed.get("mountpoints")
    if observed.get("fstype") not in (None, "") or mountpoints not in (None, [], [None]):
        fail("candidate disk is mounted or formatted")
    if observed.get("children") not in (None, []):
        fail("candidate disk is not empty")
    return observed


def main():
    if len(sys.argv) != 2:
        print("usage: vm-100-candidate-install-guard REQUEST", file=sys.stderr)
        return 64
    if os.geteuid() != 0:
        fail("candidate guard requires root")
    request = read_request(Path(sys.argv[1]))
    observed = observe(request["device"])
    if request["mode"] == "install" and os.environ.get("VM100_CANDIDATE_INSTALL_CONFIRMED") != "install-reviewed-qualification-candidate":
        fail("explicit candidate installation gate required")
    output = {
        "device": request["device"],
        "format": FORMAT,
        "mode": request["mode"],
        "serial": EXPECTED_SERIAL,
        "sizeBytes": observed["size"],
        "status": "approved",
    }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("vm-100-candidate-install-guard: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
