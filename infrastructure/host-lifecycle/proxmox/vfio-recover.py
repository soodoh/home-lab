#!/usr/bin/env python3
"""Guarded VM 100 VFIO group unbind/rebind recovery."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Callable, Protocol

POLICY_PATH = Path("/etc/home-lab/vfio-recovery.json")


class RecoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class DevicePolicy:
    bdf: str
    vendor: str
    device: str


@dataclass(frozen=True)
class Policy:
    vmid: int
    iommu_group: int
    confirmation: str
    lock_path: Path
    devices: tuple[DevicePolicy, ...]


class Backend(Protocol):
    def group_members(self, group: int) -> tuple[str, ...]: ...
    def identity(self, bdf: str) -> tuple[str | None, str | None]: ...
    def driver(self, bdf: str) -> str | None: ...
    def device_node_exists(self, group: int) -> bool: ...
    def unbind(self, bdf: str) -> None: ...
    def bind(self, bdf: str) -> None: ...


class RealBackend:
    def __init__(self, sys_root: Path = Path("/sys"), dev_root: Path = Path("/dev")) -> None:
        self.sys_root = sys_root
        self.dev_root = dev_root

    def group_members(self, group: int) -> tuple[str, ...]:
        directory = self.sys_root / "kernel/iommu_groups" / str(group) / "devices"
        if not directory.is_dir():
            return ()
        return tuple(sorted(entry.name for entry in directory.iterdir()))

    def identity(self, bdf: str) -> tuple[str | None, str | None]:
        directory = self.sys_root / "bus/pci/devices" / bdf
        try:
            vendor = (directory / "vendor").read_text(encoding="utf-8").strip().removeprefix("0x").lower()
            device = (directory / "device").read_text(encoding="utf-8").strip().removeprefix("0x").lower()
            return vendor, device
        except (FileNotFoundError, PermissionError, OSError):
            return None, None

    def driver(self, bdf: str) -> str | None:
        link = self.sys_root / "bus/pci/devices" / bdf / "driver"
        try:
            return link.resolve(strict=True).name
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def device_node_exists(self, group: int) -> bool:
        return (self.dev_root / "vfio" / str(group)).is_char_device()

    def unbind(self, bdf: str) -> None:
        (self.sys_root / "bus/pci/drivers/vfio-pci/unbind").write_text(f"{bdf}\n", encoding="utf-8")

    def bind(self, bdf: str) -> None:
        (self.sys_root / "bus/pci/drivers/vfio-pci/bind").write_text(f"{bdf}\n", encoding="utf-8")


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RecoveryError(f"{label} must be a nonempty string")
    return value


def require_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RecoveryError(f"{label} must be a positive integer")
    return value


def load_policy(path: Path = POLICY_PATH) -> Policy:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RecoveryError(f"cannot load VFIO recovery policy: {error}") from error
    if not isinstance(document, dict) or set(document) != {"confirmation", "devices", "iommuGroup", "lockPath", "vmid"}:
        raise RecoveryError("VFIO recovery policy has unexpected fields")
    raw_devices = document["devices"]
    if not isinstance(raw_devices, list) or len(raw_devices) != 1:
        raise RecoveryError("VFIO recovery policy requires exactly one GPU device")
    devices: list[DevicePolicy] = []
    for index, raw_device in enumerate(raw_devices):
        if not isinstance(raw_device, dict) or set(raw_device) != {"bdf", "device", "vendor"}:
            raise RecoveryError(f"device {index} has unexpected fields")
        bdf = require_string(raw_device["bdf"], f"device {index} BDF")
        vendor = require_string(raw_device["vendor"], f"device {index} vendor").lower()
        device = require_string(raw_device["device"], f"device {index} device").lower()
        if len(vendor) != 4 or len(device) != 4 or any(character not in "0123456789abcdef" for character in vendor + device):
            raise RecoveryError(f"device {index} PCI identity is invalid")
        devices.append(DevicePolicy(bdf=bdf, vendor=vendor, device=device))
    if len({device.bdf for device in devices}) != len(devices):
        raise RecoveryError("VFIO recovery policy device BDFs must be unique")
    confirmation = require_string(document["confirmation"], "confirmation")
    lock_path = Path(require_string(document["lockPath"], "lock path"))
    if not lock_path.is_absolute() or lock_path.parent != Path("/run/lock"):
        raise RecoveryError("VFIO recovery lock must be directly below /run/lock")
    return Policy(
        vmid=require_integer(document["vmid"], "VMID"),
        iommu_group=require_integer(document["iommuGroup"], "IOMMU group"),
        confirmation=confirmation,
        lock_path=lock_path,
        devices=tuple(devices),
    )


def qm_status(vmid: int) -> str:
    result = subprocess.run(
        ["/usr/sbin/qm", "status", str(vmid)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RecoveryError(f"qm status failed for VM {vmid}")
    prefix = "status: "
    status = result.stdout.strip()
    if not status.startswith(prefix):
        raise RecoveryError(f"qm returned an unexpected status for VM {vmid}")
    return status.removeprefix(prefix)


def device_users(group: int, proc_root: Path = Path("/proc"), dev_root: Path = Path("/dev")) -> tuple[str, ...]:
    target = str(dev_root / "vfio" / str(group))
    users: set[str] = set()
    try:
        processes = tuple(proc_root.iterdir())
    except OSError as error:
        raise RecoveryError(f"cannot inspect process file descriptors: {error}") from error
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            descriptors = tuple((process / "fd").iterdir())
        except (FileNotFoundError, PermissionError, OSError):
            continue
        for descriptor in descriptors:
            try:
                linked = os.readlink(descriptor)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if linked == target or linked == f"{target} (deleted)":
                users.add(process.name)
                break
    return tuple(sorted(users))


def inspect(
    policy: Policy,
    backend: Backend,
    status_reader: Callable[[int], str] = qm_status,
    users_reader: Callable[[int], tuple[str, ...]] = device_users,
) -> dict[str, object]:
    reasons: list[str] = []
    try:
        vm_status = status_reader(policy.vmid)
    except RecoveryError as error:
        vm_status = "unknown"
        reasons.append(str(error))
    if vm_status != "stopped":
        reasons.append(f"VM {policy.vmid} must be stopped, observed {vm_status}")

    expected_members = tuple(sorted(device.bdf for device in policy.devices))
    observed_members = backend.group_members(policy.iommu_group)
    if observed_members != expected_members:
        reasons.append("IOMMU group membership differs from the exact recovery policy")

    device_facts: list[dict[str, object]] = []
    for device in policy.devices:
        vendor, device_id = backend.identity(device.bdf)
        driver = backend.driver(device.bdf)
        if (vendor, device_id) != (device.vendor, device.device):
            reasons.append(f"PCI identity mismatch for {device.bdf}")
        if driver != "vfio-pci":
            reasons.append(f"{device.bdf} must be bound to vfio-pci, observed {driver or 'unbound'}")
        device_facts.append({
            "bdf": device.bdf,
            "device": device_id,
            "driver": driver,
            "vendor": vendor,
        })

    node_exists = backend.device_node_exists(policy.iommu_group)
    if not node_exists:
        reasons.append(f"/dev/vfio/{policy.iommu_group} is absent")
    try:
        users = users_reader(policy.iommu_group)
    except RecoveryError as error:
        users = ()
        reasons.append(str(error))
    if users:
        reasons.append(f"/dev/vfio/{policy.iommu_group} is open by a process")

    return {
        "deviceNode": f"/dev/vfio/{policy.iommu_group}",
        "deviceNodeExists": node_exists,
        "deviceUsers": list(users),
        "devices": device_facts,
        "iommuGroup": policy.iommu_group,
        "iommuMembers": list(observed_members),
        "reasons": reasons,
        "state": "ready" if not reasons else "blocked",
        "version": 1,
        "vmStatus": vm_status,
        "vmid": policy.vmid,
    }


def perform_recovery(
    policy: Policy,
    backend: Backend,
    confirmation: str,
    status_reader: Callable[[int], str] = qm_status,
    users_reader: Callable[[int], tuple[str, ...]] = device_users,
) -> dict[str, object]:
    if confirmation != policy.confirmation:
        raise RecoveryError("VFIO recovery confirmation does not match the exact policy token")
    before = inspect(policy, backend, status_reader, users_reader)
    if before["state"] != "ready":
        raise RecoveryError("VFIO recovery prerequisites are blocked: " + "; ".join(before["reasons"]))

    try:
        for device in reversed(policy.devices):
            backend.unbind(device.bdf)
            if backend.driver(device.bdf) is not None:
                raise RecoveryError(f"{device.bdf} remained bound after VFIO unbind")
        for device in policy.devices:
            backend.bind(device.bdf)
            if backend.driver(device.bdf) != "vfio-pci":
                raise RecoveryError(f"{device.bdf} did not bind back to vfio-pci")
    except (OSError, RecoveryError) as error:
        rollback_errors: list[str] = []
        for device in policy.devices:
            if backend.driver(device.bdf) is None:
                try:
                    backend.bind(device.bdf)
                except OSError as rollback_error:
                    rollback_errors.append(f"{device.bdf}: {rollback_error}")
        suffix = "" if not rollback_errors else "; rollback failures: " + ", ".join(rollback_errors)
        raise RecoveryError(f"VFIO recovery failed: {error}{suffix}") from error

    after = inspect(policy, backend, status_reader, users_reader)
    if after["state"] != "ready":
        raise RecoveryError("VFIO recovery postconditions failed: " + "; ".join(after["reasons"]))
    after["recovered"] = True
    return after


def locked_recovery(policy: Policy, confirmation: str) -> dict[str, object]:
    policy.lock_path.parent.mkdir(parents=True, exist_ok=True)
    vm_lock_path = Path("/run/lock/qemu-server") / f"lock-{policy.vmid}.conf"
    if not vm_lock_path.parent.is_dir():
        raise RecoveryError("the Proxmox QEMU lock directory is absent")
    with policy.lock_path.open("a+", encoding="utf-8") as recovery_lock:
        try:
            fcntl.flock(recovery_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RecoveryError("another VFIO recovery operation holds the host lock") from error
        with vm_lock_path.open("a+", encoding="utf-8") as vm_lock:
            try:
                fcntl.flock(vm_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RecoveryError(f"another Proxmox operation holds the VM {policy.vmid} lock") from error
            return perform_recovery(policy, RealBackend(), confirmation)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("observe", help="inspect exact recovery prerequisites without mutation")
    recover_parser = subparsers.add_parser("recover", help="perform one guarded VFIO unbind/rebind cycle")
    recover_parser.add_argument("--confirm", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise RecoveryError("VFIO observation and recovery require root for complete process inspection")
    policy = load_policy()
    if args.command == "observe":
        result = inspect(policy, RealBackend())
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["state"] == "ready" else 2
    result = locked_recovery(policy, args.confirm)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
