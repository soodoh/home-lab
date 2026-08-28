#!/usr/bin/env python3
"""Reject any disposable disk-adoption plan that is not a bounded scsi3 update."""

from __future__ import annotations

import json
import re
import sys
from typing import Any


HEX64 = re.compile(r"^[0-9a-f]{64}$")
QUAL_SERIAL = re.compile(r"^QUAL-DISK-[A-Z0-9-]+$")
QUAL_DATASTORE = re.compile(r"^qual-[a-z0-9-]+$")
QUAL_VOLUME = re.compile(r"^vm-[0-9]+-disk-[0-9]+$")


def fail(reason: str) -> None:
    raise SystemExit(f"disk_adoption_plan_rejected={reason}")


def unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(unknown(item) for item in value)
    return False


def exact_disk(value: Any, interface: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{interface}_schema")
    if value.get("interface") != interface:
        fail(f"{interface}_identity")
    serial = value.get("serial")
    if not isinstance(serial, str) or QUAL_SERIAL.fullmatch(serial) is None:
        fail(f"{interface}_serial")
    if value.get("size") not in (1, 2):
        fail(f"{interface}_size")
    if value.get("backup") is not False or value.get("iothread") is not False or value.get("ssd") is not False:
        fail(f"{interface}_options")
    if value.get("discard") != "ignore" or value.get("replicate") is not False:
        fail(f"{interface}_options")
    if value.get("file_id") not in (None, "") or value.get("import_from") not in (None, ""):
        fail(f"{interface}_copy_or_import")
    return value


def inspect(plan: Any) -> None:
    if not isinstance(plan, dict) or plan.get("format_version") not in {"1.2", "1.3"}:
        fail("format")
    changes = plan.get("resource_changes")
    if not isinstance(changes, list) or len(changes) != 1:
        fail("resource_count")
    resource = changes[0]
    if resource.get("address") != "proxmox_virtual_environment_vm.disk_adoption[0]" or \
            resource.get("type") != "proxmox_virtual_environment_vm":
        fail("resource_identity")
    change = resource.get("change")
    if not isinstance(change, dict) or change.get("actions") != ["update"]:
        fail("actions")
    if unknown(change.get("after_unknown", {})):
        fail("unknown_values")
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        fail("state_schema")
    vmid = after.get("vm_id")
    if not isinstance(vmid, int) or isinstance(vmid, bool) or not 9901 <= vmid <= 9999 or before.get("vm_id") != vmid:
        fail("vmid")
    if after.get("name") != f"home-lab-disk-adoption-qualification-{vmid}" or before.get("name") != after.get("name"):
        fail("name")
    for key, expected in {
        "started": False,
        "on_boot": False,
        "protection": False,
        "delete_unreferenced_disks_on_destroy": False,
        "purge_on_destroy": False,
        "reboot_after_update": False,
    }.items():
        if before.get(key) is not expected or after.get(key) is not expected:
            fail(f"{key}_change")
    if before.get("boot_order") != ["scsi0"] or after.get("boot_order") != before.get("boot_order"):
        fail("boot_order")
    before_disks = before.get("disk")
    after_disks = after.get("disk")
    if not isinstance(before_disks, list) or not isinstance(after_disks, list) or len(before_disks) != 3 or len(after_disks) != 4:
        fail("disk_count")
    if before_disks != after_disks[:3]:
        fail("disk_index_or_identity_change")
    for index, disk in enumerate(after_disks):
        exact_disk(disk, f"scsi{index}")
    candidate = after_disks[3]
    datastore = candidate.get("datastore_id")
    volume = candidate.get("path_in_datastore")
    if not isinstance(datastore, str) or QUAL_DATASTORE.fullmatch(datastore) is None:
        fail("candidate_datastore")
    if not isinstance(volume, str) or QUAL_VOLUME.fullmatch(volume) is None or not volume.startswith(f"vm-{vmid}-"):
        fail("candidate_volume")
    raw = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    for prohibited in (
        "vm-100", "vm-100-disk-2", "HOME-LAB-DEBIAN-64G",
        "31602ce7-0054-498a-9f24-f51ca491e7b3", "d4a19647-7879-4079-9fc9-b3e79711b449",
    ):
        if prohibited in raw:
            fail("production_identifier")
    print("disk_adoption_plan=accepted")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: inspect-proxmox-disk-adoption-plan.py <tofu-show-json>")
    with open(sys.argv[1], encoding="utf-8") as handle:
        inspect(json.load(handle))


if __name__ == "__main__":
    main()
