#!/usr/bin/env python3
"""Authorize an exact destructive candidate install only in host-attested VMID 9900."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

FORMAT = "home-lab-vm-100-candidate-install-v1"
AUTH_FORMAT = "home-lab-vm-100-install-qualification-authorization-v1"
HOST_FORMAT = "home-lab-vm-100-ephemeral-host-attestation-v1"
CONFIRMATION = "install-disposable-vmid-9900-scsi2-reviewed"
DEVICE = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2"
SERIAL = "QUAL-NIXOS-128G"
SIZE = 137438953472
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def fail(message):
    raise ValueError(message)


def load_guard(path):
    if not path.is_absolute() or not path.is_file():
        fail("fixed candidate disk guard source is unavailable")
    raw = path.read_bytes()
    module_name = "vm_100_candidate_disk_guard"
    spec = importlib.util.spec_from_loader(module_name, loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    sys.modules[module_name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def read_canonical(path, keys, label):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > 64 * 1024):
            fail(f"{label} metadata differs")
        raw = b""
        while chunk := os.read(descriptor, 65536):
            raw += chunk
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        fail(f"{label} changed while read")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} shape differs")
    if raw != (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode():
        fail(f"{label} is noncanonical")
    return value, hashlib.sha256(raw).hexdigest()


def main():
    if (len(sys.argv) != 10 or sys.argv[2] != "--request" or sys.argv[4] != "--protected-disk-input"
            or sys.argv[6] != "--authorization" or sys.argv[8] != "--host-attestation"):
        return 64
    if os.geteuid() != 0:
        fail("qualified candidate install guard requires root")
    disk_guard = load_guard(Path(sys.argv[1]))
    request, _ = read_canonical(Path(sys.argv[3]), {"approvedSerial", "device", "format", "mode", "observedSizeBytes"}, "install request")
    authorization, _ = read_canonical(Path(sys.argv[7]), {"commit", "confirmation", "format", "hostAttestationSha256", "mode", "vmId"}, "install authorization")
    host, host_sha = read_canonical(Path(sys.argv[9]), {"bios", "candidateSerial", "candidateSizeBytes", "collectedAt", "commit", "format", "machine", "productUuid", "pveConfigSha256", "result", "vmId"}, "host attestation")
    protected = disk_guard.read_protected(Path(sys.argv[5]))
    if request != {"approvedSerial": SERIAL, "device": DEVICE, "format": FORMAT, "mode": "install", "observedSizeBytes": SIZE}:
        fail("install request differs")
    if (authorization["format"] != AUTH_FORMAT or authorization["confirmation"] != CONFIRMATION
            or authorization["mode"] != "install" or authorization["vmId"] != 9900
            or SHA256.fullmatch(authorization["hostAttestationSha256"] or "") is None):
        fail("install authorization differs")
    observed_uuid = Path("/sys/class/dmi/id/product_uuid").read_text(encoding="ascii").strip().lower()
    if (host["format"] != HOST_FORMAT or host["vmId"] != 9900 or host["result"] != "passed"
            or host["bios"] != "seabios" or host["machine"] != "q35" or host["candidateSerial"] != SERIAL
            or host["candidateSizeBytes"] != SIZE or UUID.fullmatch(observed_uuid) is None
            or host["productUuid"] != observed_uuid or host["commit"] != authorization["commit"]
            or host_sha != authorization["hostAttestationSha256"]):
        fail("host-attested disposable identity differs")
    first = disk_guard.observe(DEVICE, protected["gamesDevice"])
    second = disk_guard.observe(DEVICE, protected["gamesDevice"])
    if first != second:
        fail("candidate identity changed before destructive approval")
    print(json.dumps({"device": DEVICE, "format": AUTH_FORMAT, "mode": "install", "serial": SERIAL, "sizeBytes": SIZE, "status": "approved"}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("vm-100-candidate-install-qualified-guard: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
