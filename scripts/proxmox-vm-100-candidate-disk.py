#!/usr/bin/env python3
"""Attach VM 100's qualified candidate disk through a reviewed OpenTofu action."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

VMID = 100
SSH = (
    "/usr/bin/ssh",
    "-F",
    str(Path.home() / ".ssh/config"),
    "-T",
    "-o",
    "BatchMode=yes",
    "root@proxmox",
)
ATTACH_VALUE = (
    "local-lvm:128,backup=1,cache=none,discard=ignore,iothread=1,"
    "replicate=1,serial=QUAL-NIXOS-128G,ssd=0"
)
VOLUME = re.compile(r"^local-lvm:vm-100-disk-[0-9]+$")


def run(argv: list[str] | tuple[str, ...], cwd: Path | None = None) -> str:
    return subprocess.run(argv, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def remote(*argv: str) -> str:
    return run((*SSH, "--", *argv))


def parse_config(raw: str) -> dict[str, str]:
    config: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(": ")
        if separator:
            config[key] = value
    return config


def disk_value(raw: str) -> tuple[str, dict[str, str]]:
    parts = raw.split(",")
    return parts[0], dict(part.split("=", 1) for part in parts[1:] if "=" in part)


def candidate_is_exact(raw: str) -> bool:
    volume, options = disk_value(raw)
    return (
        VOLUME.fullmatch(volume) is not None
        and options.get("serial") == "QUAL-NIXOS-128G"
        and options.get("size") == "128G"
        and options.get("backup") == "1"
        and options.get("cache") == "none"
        and options.get("iothread") == "1"
        and options.get("discard", "ignore") == "ignore"
        and options.get("replicate", "1") == "1"
        and options.get("ssd", "0") == "0"
    )


def inspect(allowed_boots: set[str] | None = None) -> dict[str, object]:
    status = remote("/usr/sbin/qm", "status", str(VMID))
    pid = remote("/bin/cat", f"/var/run/qemu-server/{VMID}.pid")
    start_ticks = remote("/usr/bin/stat", "-c", "%Y", f"/proc/{pid}")
    config = parse_config(remote("/usr/sbin/qm", "config", str(VMID), "--current"))
    required = {"scsi0", "scsi1", "boot", "protection", "onboot"}
    if not required <= config.keys():
        raise SystemExit("VM 100 required configuration is incomplete")
    if status != "status: running" or config["protection"] != "1" or config["onboot"] != "1":
        raise SystemExit("VM 100 must remain running, protected, and enabled at boot")
    accepted = allowed_boots or {"order=scsi0;net0"}
    if config["boot"] not in accepted:
        raise SystemExit("VM 100 source boot order differs")
    if not config["scsi0"].startswith("local-lvm:vm-100-disk-0,"):
        raise SystemExit("VM 100 Arch root disk differs")
    if not config["scsi1"].startswith("/dev/disk/by-id/"):
        raise SystemExit("VM 100 games disk is not the protected by-id attachment")
    return {
        "config": config,
        "pid": int(pid),
        "startTicks": int(start_ticks),
        "status": "running",
    }


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"apply", "normalize-boot"}:
        raise SystemExit("usage: proxmox-vm-100-candidate-disk.py <apply|normalize-boot>")
    if os.environ.get("HOMELAB_VM100_CANDIDATE_ATTACHMENT") != "reviewed-opentofu-action":
        raise SystemExit("candidate mutation requires the reviewed OpenTofu execution gate")
    repo = Path(__file__).resolve().parents[1]
    head = run(("git", "rev-parse", "HEAD"), repo)
    upstream = run(("git", "rev-parse", "@{upstream}"), repo)
    if head != upstream or run(("git", "status", "--porcelain", "--untracked-files=all"), repo):
        raise SystemExit("candidate mutation requires a clean pushed revision")

    if sys.argv[1] == "normalize-boot":
        before = inspect({"order=scsi0;net0", "order=scsi0;net0;ide2"})
        before_config = before["config"]
        assert isinstance(before_config, dict)
        candidate = before_config.get("scsi2")
        if not isinstance(candidate, str) or not candidate_is_exact(candidate):
            raise SystemExit("VM 100 candidate disk identity differs before boot normalization")
        changed = False
        if "ide2" in before_config:
            remote("/usr/sbin/qm", "set", str(VMID), "--delete", "ide2")
            changed = True
        if before_config["boot"] != "order=scsi0;net0":
            remote("/usr/sbin/qm", "set", str(VMID), "--boot", "order=scsi0;net0")
            changed = True
        after = inspect()
        after_config = after["config"]
        assert isinstance(after_config, dict)
        if "ide2" in after_config:
            raise SystemExit("VM 100 empty CD-ROM remained after boot normalization")
        if before["pid"] != after["pid"] or before["startTicks"] != after["startTicks"]:
            raise SystemExit("VM 100 restarted during boot normalization")
        for key in ("scsi0", "scsi1", "scsi2", "protection", "onboot"):
            if before_config[key] != after_config[key]:
                raise SystemExit(f"VM 100 protected configuration changed during boot normalization: {key}")
        evidence = {
            "format": "home-lab-vm-100-boot-normalization-v1",
            "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "gitCommit": head,
            "vmid": VMID,
            "changed": changed,
            "status": "running",
            "pidStable": True,
            "bootOrder": "scsi0;net0",
            "candidateConfigSha256": sha256(after_config["scsi2"]),
            "result": "passed",
        }
        output = repo / ".reconcile/vm-100/boot-normalization.json"
    else:
        before = inspect()
        before_config = before["config"]
        assert isinstance(before_config, dict)
        existing = before_config.get("scsi2")
        changed = False
        if existing is None:
            remote("/usr/sbin/qm", "set", str(VMID), "--scsi2", ATTACH_VALUE)
            changed = True
        elif not candidate_is_exact(existing):
            raise SystemExit("VM 100 scsi2 already exists with a different identity")

        after = inspect()
        after_config = after["config"]
        assert isinstance(after_config, dict)
        candidate = after_config.get("scsi2")
        if not isinstance(candidate, str) or not candidate_is_exact(candidate):
            raise SystemExit("VM 100 candidate disk did not attach with the exact reviewed identity")
        if before["pid"] != after["pid"] or before["startTicks"] != after["startTicks"]:
            raise SystemExit("VM 100 restarted during candidate disk attachment")
        for key in ("scsi0", "scsi1", "boot", "protection", "onboot"):
            if before_config[key] != after_config[key]:
                raise SystemExit(f"VM 100 protected configuration changed during candidate attachment: {key}")

        evidence = {
            "format": "home-lab-vm-100-candidate-attachment-v1",
            "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "gitCommit": head,
            "vmid": VMID,
            "changed": changed,
            "status": "running",
            "pidStable": True,
            "bootOrder": "scsi0;net0",
            "candidate": {
                "interface": "scsi2",
                "serial": "QUAL-NIXOS-128G",
                "sizeGiB": 128,
                "configSha256": sha256(candidate),
            },
            "preserved": {
                key: sha256(after_config[key]) for key in ("scsi0", "scsi1", "boot", "protection", "onboot")
            },
            "result": "passed",
        }
        output = repo / ".reconcile/vm-100/candidate-disk-attachment.json"

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    output.chmod(0o600)
    print(f"vm_100_candidate_{sys.argv[1]}=passed changed={str(changed).lower()} commit={head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
