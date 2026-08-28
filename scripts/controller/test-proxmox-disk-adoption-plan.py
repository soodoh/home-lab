#!/usr/bin/env python3
"""Offline positive and negative fixtures for disposable scsi3 adoption policy."""

from __future__ import annotations

import copy
import contextlib
import io
import runpy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSPECTOR = ROOT / "infrastructure/policy/inspect-proxmox-disk-adoption-plan.py"
QUALIFICATION = ROOT / "infrastructure/tofu/proxmox-disk-adoption-qualification"


def disk(interface: str, serial: str, datastore: str = "qual-disks", path: str | None = None) -> dict:
    value = {
        "interface": interface,
        "serial": serial,
        "size": 1,
        "backup": False,
        "iothread": False,
        "ssd": False,
        "discard": "ignore",
        "replicate": False,
        "file_id": None,
        "import_from": None,
        "datastore_id": datastore,
        "path_in_datastore": path,
    }
    return value


def valid_plan() -> dict:
    before_disks = [
        disk("scsi0", "QUAL-DISK-BASE-0", path="9951/vm-9951-disk-0.raw"),
        disk("scsi1", "QUAL-DISK-BASE-1", path="9951/vm-9951-disk-1.raw"),
        disk("scsi2", "QUAL-DISK-BASE-2", path="9951/vm-9951-disk-2.raw"),
    ]
    fixed = {
        "vm_id": 9951,
        "name": "home-lab-disk-adoption-qualification-9951",
        "started": False,
        "on_boot": False,
        "protection": False,
        "delete_unreferenced_disks_on_destroy": False,
        "purge_on_destroy": False,
        "reboot_after_update": False,
        "boot_order": ["scsi0"],
    }
    before = {**fixed, "disk": before_disks}
    after = {**copy.deepcopy(fixed), "disk": [*copy.deepcopy(before_disks), disk("scsi3", "QUAL-DISK-CAND-3", path="9951/vm-9951-disk-3.raw")]}
    return {
        "format_version": "1.2",
        "resource_changes": [{
            "address": "proxmox_virtual_environment_vm.disk_adoption[0]",
            "type": "proxmox_virtual_environment_vm",
            "change": {"actions": ["update"], "before": before, "after": after, "after_unknown": {}},
        }],
    }


def rejected(inspect, plan: dict, reason: str) -> None:
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            inspect(plan)
    except SystemExit as error:
        assert reason in str(error), (reason, error)
    else:
        raise AssertionError(f"unsafe disk adoption fixture accepted: {reason}")


def main() -> None:
    module = runpy.run_path(str(INSPECTOR), run_name="disk_adoption_policy_test")
    inspect = module["inspect"]
    with contextlib.redirect_stdout(io.StringIO()) as output:
        inspect(valid_plan())
    assert output.getvalue() == "disk_adoption_plan=accepted\n"

    lvmthin_plan = valid_plan()
    change = lvmthin_plan["resource_changes"][0]["change"]
    for state in (change["before"], change["after"]):
        for index, disk_value in enumerate(state["disk"]):
            disk_value["datastore_id"] = "qual-lvmthin"
            disk_value["path_in_datastore"] = f"vm-9951-disk-{index}"
    with contextlib.redirect_stdout(io.StringIO()) as lvmthin_output:
        inspect(lvmthin_plan)
    assert lvmthin_output.getvalue() == "disk_adoption_plan=accepted\n"

    mutations = []
    plan = valid_plan(); plan["resource_changes"][0]["change"]["actions"] = ["delete", "create"]; mutations.append((plan, "actions"))
    plan = valid_plan(); plan["resource_changes"][0]["change"]["after_unknown"] = {"disk": [False, False, False, True]}; mutations.append((plan, "unknown_values"))
    plan = valid_plan(); plan["resource_changes"][0]["change"]["after"]["disk"][0:2] = reversed(plan["resource_changes"][0]["change"]["after"]["disk"][0:2]); mutations.append((plan, "disk_index_or_identity_change"))
    plan = valid_plan(); plan["resource_changes"][0]["change"]["after"]["disk"][3]["datastore_id"] = "local-lvm"; mutations.append((plan, "candidate_datastore"))
    plan = valid_plan(); plan["resource_changes"][0]["change"]["after"]["disk"][3]["import_from"] = "qual:import/image.qcow2"; mutations.append((plan, "copy_or_import"))
    plan = valid_plan(); plan["resource_changes"][0]["change"]["after"]["disk"][3]["path_in_datastore"] = "100/vm-100-disk-2.raw"; mutations.append((plan, "candidate_volume"))
    plan = valid_plan(); plan["resource_changes"][0]["change"]["after"]["boot_order"] = ["scsi3"]; mutations.append((plan, "boot_order"))
    plan = valid_plan(); plan["resource_changes"].append(copy.deepcopy(plan["resource_changes"][0])); mutations.append((plan, "resource_count"))
    for plan, reason in mutations:
        rejected(inspect, plan, reason)

    main_tf = (QUALIFICATION / "main.tf").read_text()
    versions = (QUALIFICATION / "versions.tf").read_text()
    lock = (QUALIFICATION / ".terraform.lock.hcl").read_text()
    assert 'default = false' in main_tf
    assert 'var.qualification_vmid >= 9901 && var.qualification_vmid <= 9999' in main_tf
    assert 'startswith(var.qualification_datastore, "qual-")' in main_tf
    for required in (
        "started       = false", "on_boot       = false", "protection    = false",
        "delete_unreferenced_disks_on_destroy = false", 'serial       = "QUAL-DISK-BASE-0"',
        'serial       = "QUAL-DISK-BASE-1"', 'serial       = "QUAL-DISK-BASE-2"',
        'var.qualification_adopt_scsi3 ? [var.qualification_candidate_volume] : []',
        'path_in_datastore = disk.value', 'serial            = "QUAL-DISK-CAND-3"',
    ):
        assert required in main_tf, required
    combined = main_tf + versions
    for prohibited in (
        'backend "s3"', "vm-100-disk-2", "HOME-LAB-DEBIAN-64G",
        "31602ce7-0054-498a-9f24-f51ca491e7b3", "d4a19647-7879-4079-9fc9-b3e79711b449",
        "192.168.0.123:/storage/docker", "BC:24:11:89:19:5A",
    ):
        assert prohibited not in combined, prohibited
    assert 'version = "= 0.111.1"' in versions
    assert 'version     = "0.111.1"' in lock
    print("proxmox_disk_adoption_plan=verified")


if __name__ == "__main__":
    main()
