#!/usr/bin/env python3
"""Verify the bounded post-provider VM9900 host-capability retirement."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAY = ROOT / "ansible/playbooks/retire-vm9900-capabilities.yml"
RECOVERY_PLAY = ROOT / "ansible/playbooks/recover-vm9900-capability-retirement.yml"
TASKS = ROOT / "ansible/roles/vm9900_capability_retire/tasks/main.yml"
play = PLAY.read_text()
recovery_play = RECOVERY_PLAY.read_text()
tasks = TASKS.read_text()

for required in (
    "proxmox_observe",
    "apply_lock_action: acquire",
    "apply_lock_action: release",
    "apply_lock_operation: vm9900-capability-retirement",
    "vm9900_capability_retire",
):
    assert required in play, required

for required in (
    "apply_lock_action: adopt",
    "apply_lock_action: release",
    "vm9900_capability_retirement_owner_sha256",
    "apply_lock_expected_owner_sha256",
    "vm9900_capability_retire",
):
    assert required in recovery_play, required

for required in (
    "RETIRE_REVIEWED_VM9900_HOST_CAPABILITIES",
    "VM9900 provider cleanup or protected VM100 identity is incomplete",
    "/etc/pve/firewall/9900.fw",
    "/var/lib/vz/import/debian-20260810-2566-qualification.qcow2",
    "/var/lib/vz/import/home-lab-restic-recovery-debian-20260810-2566.qcow2",
    "/var/lib/vz/snippets/home-lab-debian-lifecycle-qualification.yaml",
    "/usr/local/libexec/home-lab/debian-qualification-snippet-transaction",
    "/usr/local/libexec/home-lab/debian-qualification-snippet-transport",
    "/etc/sudoers.d/qualification-apply",
    "/usr/local/libexec/home-lab/proxmox-restic-recovery-transport",
    "/usr/local/libexec/home-lab/proxmox-ansible-deploy-transport",
    "/etc/sudoers.d/ansible-deploy",
    "830b8b26b011967e70f9851114ba185a1cb0de399db81446d704ca4ee7564009",
    "186d6adf91649182d063165e50a4ab961968876c8a65254be53b6258bd2e95e1",
    "root@pam!tofu-plan",
    "HomeLabTofuPlanDiskInspect",
    "/vms/9900",
    "/vms/100",
    "/usr/sbin/nologin",
    "/var/lib/home-lab/restic-recovery-capability/240db6d859e21f633e3cbe9bed93414c8ebeda58a9717d70d02566744776d4b5/state.json",
    "708af9c013eea53a8158df668d75261037f05a5f95a3718811029494ace269dc",
    "/var/lib/home-lab/reconciliation/qualification-diagnostic-attempts",
    "vm9900_retirement_diagnostics_after.matched == vm9900_retirement_diagnostics_before.matched",
):
    assert required in tasks, required

for forbidden in (
    "state: absent\n    remove: true",
    "recurse: true",
    "rm -rf",
    "tofu state rm",
    "/var/lib/home-lab/restic-recovery-capability\n    state: absent",
    "/var/lib/home-lab/reconciliation/qualification-diagnostic-attempts\n    state: absent",
):
    assert forbidden not in tasks, forbidden

assert tasks.count("not ansible_check_mode") >= 8
assert "when: ansible_check_mode" in tasks
print("vm9900_capability_retirement=verified removed_paths=7 retained_evidence=2")
