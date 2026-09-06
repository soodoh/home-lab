#!/usr/bin/python3 -I
"""Guarded VM 100 VFIO group unbind/rebind recovery."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Callable, Protocol

POLICY_PATH = Path("/etc/home-lab/vfio-recovery.json")
OPERATION_LOCK = Path("/var/lib/home-lab/reconciliation/operation.lock")
VFIO_LOCK = Path("/run/lock/home-lab-vfio-recovery.lock")
RETAINED_OWNERS = (
    Path("/var/lib/iac-ansible-production.lock"),
    Path("/var/lib/home-lab/reconciliation/apply.lock"),
    Path("/var/lib/home-lab/reconciliation/owner.lock"),
    Path("/var/lib/home-lab/reconciliation/nix.lock"),
    Path("/var/lib/home-lab/firewall-transaction/active.json"),
)
QM_PATH = Path("/usr/sbin/qm")
NATIVE_ENV = {"LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


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


def fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def parent_fd(path: Path) -> int:
    """Walk canonical root-owned ancestry without following directory links."""
    if not path.is_absolute() or ".." in path.parts:
        raise RecoveryError("noncanonical fixed path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root = os.fstat(fd)
        if root.st_uid != 0 or root.st_gid != 0 or root.st_mode & 0o022:
            raise RecoveryError("unsafe root ancestor")
        walked = Path("/")
        for part in path.parts[1:-1]:
            walked /= part
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                info = os.fstat(child)
                sticky_lock = walked == Path("/run/lock") and stat.S_IMODE(info.st_mode) == 0o1777
                if info.st_uid != 0 or info.st_gid != 0 or (info.st_mode & 0o022 and not sticky_lock):
                    raise RecoveryError("unsafe fixed-path ancestor")
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def recheck_named(path: Path, parent: int, info: os.stat_result) -> None:
    current_parent = parent_fd(path)
    try:
        original, current = os.fstat(parent), os.fstat(current_parent)
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            raise RecoveryError("fixed-path ancestor changed")
        if fingerprint(info) != fingerprint(os.stat(path.name, dir_fd=current_parent, follow_symlinks=False)):
            raise RecoveryError("fixed pathname changed")
    finally:
        os.close(current_parent)


def open_fixed(path: Path, mode: int, writable: bool = False) -> int:
    parent = parent_fd(path)
    fd = None
    try:
        fd = os.open(path.name, (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode:
            raise RecoveryError("fixed file metadata differs")
        if writable:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recheck_named(path, parent, info)
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        os.close(parent)


def reject_retained_owners() -> None:
    # Presence only: never read, adopt, repair or release any owner's contents.
    for path in RETAINED_OWNERS:
        parent = parent_fd(path)
        try:
            try:
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                current_parent = parent_fd(path)
                try:
                    before, after = os.fstat(parent), os.fstat(current_parent)
                    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                        raise RecoveryError("retained-owner ancestor changed")
                finally:
                    os.close(current_parent)
            else:
                raise RecoveryError("conflicting lifecycle ownership is retained")
        finally:
            os.close(parent)


def load_policy() -> Policy:
    try:
        fd = open_fixed(POLICY_PATH, 0o440)
        try:
            before = os.fstat(fd)
            if before.st_size > 65536:
                raise RecoveryError("VFIO recovery policy exceeds bound")
            raw = b""
            while len(raw) <= 65536:
                chunk = os.read(fd, 65537 - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) != before.st_size or fingerprint(before) != fingerprint(os.fstat(fd)):
                raise RecoveryError("VFIO recovery policy changed")
            parent = parent_fd(POLICY_PATH)
            try:
                recheck_named(POLICY_PATH, parent, before)
            finally:
                os.close(parent)
        finally:
            os.close(fd)
        document = json.loads(raw)
    except (OSError, ValueError) as error:
        raise RecoveryError(f"cannot load VFIO recovery policy: {error}") from error
    return parse_policy(document)


def parse_policy(document: object) -> Policy:
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
    if document["lockPath"] != str(VFIO_LOCK):
        raise RecoveryError("VFIO recovery lock must match the exact contract path")
    return Policy(
        vmid=require_integer(document["vmid"], "VMID"),
        iommu_group=require_integer(document["iommuGroup"], "IOMMU group"),
        confirmation=confirmation,
        lock_path=lock_path,
        devices=tuple(devices),
    )


def qm_status(vmid: int) -> str:
    try:
        fd = open_fixed(QM_PATH, 0o755)
        try:
            before = os.fstat(fd)
            result = subprocess.run(
                [str(QM_PATH), "status", str(vmid)],
                check=False, capture_output=True, text=True, timeout=15,
                env=NATIVE_ENV, cwd="/", close_fds=True,
            )
            parent = parent_fd(QM_PATH)
            try:
                recheck_named(QM_PATH, parent, before)
            finally:
                os.close(parent)
        finally:
            os.close(fd)
    except (OSError, subprocess.SubprocessError) as error:
        raise RecoveryError(f"cannot execute fixed qm status: {error}") from error
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


def locked_recovery(confirmation: str) -> dict[str, object]:
    descriptors: list[int] = []
    try:
        descriptors.append(open_fixed(OPERATION_LOCK, 0o600, writable=True))
        reject_retained_owners()
        # Read only under operation serialization: a pre-lock policy/token must
        # never authorize a replacement published by a cooperating writer.
        policy = load_policy()
        if confirmation != policy.confirmation:
            raise RecoveryError("VFIO recovery confirmation does not match the exact policy token")
        descriptors.append(open_fixed(VFIO_LOCK, 0o600, writable=True))
        vm_lock = Path("/run/lock/qemu-server") / f"lock-{policy.vmid}.conf"
        descriptors.append(open_fixed(vm_lock, 0o600, writable=True))
        return perform_recovery(policy, RealBackend(), confirmation)
    except OSError as error:
        raise RecoveryError(f"VFIO coordination refused: {error}") from error
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("observe", help="advisory read-only snapshot, not transaction readiness")
    recover_parser = subparsers.add_parser("recover", help="perform one guarded VFIO unbind/rebind cycle")
    recover_parser.add_argument("--confirm", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise RecoveryError("VFIO observation and recovery require root for complete process inspection")
    if not sys.flags.isolated or sys.executable != "/usr/bin/python3":
        raise RecoveryError("fixed /usr/bin/python3 -I invocation required")
    if args.command == "observe":
        result = inspect(load_policy(), RealBackend())
        result["advisory"] = True
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["state"] == "ready" else 2
    result = locked_recovery(args.confirm)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
