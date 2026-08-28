#!/usr/bin/env python3
"""Static and adversarial structure checks for lifecycle marker adoption."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    controller = (ROOT / "scripts/controller/lifecycle-marker-transaction.py").read_text()
    activator = (ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator").read_text()
    transport = (ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport").read_text()
    role = (ROOT / "ansible/roles/lifecycle_marker/tasks/main.yml").read_text()
    playbook = (ROOT / "ansible/playbooks/adopt-lifecycle-marker.yml").read_text()

    for required in ("LIFECYCLE_MARKER_CONFIRMED", "acquire_transfer_lock", "--tags", "lifecycle_marker", "os.O_EXCL", "os.O_NOFOLLOW"):
        assert required in controller, required
    for forbidden in ("StrictHostKeyChecking=no", "shell=True", "authorized\": True"):
        assert forbidden not in controller, forbidden
    assert "home-lab-lifecycle-marker-plan-v1" in activator
    assert 'MARKER = Path("/var/lib/home-lab/lifecycle-state.json")' in activator
    assert "stage lifecycle-marker" in transport and "apply lifecycle-marker" in transport
    assert "eval" not in transport and "sh -c" not in transport

    assert role.count("ansible.builtin.copy:") == 1
    assert role.splitlines().count("    - lifecycle_marker") == 5
    assert "force: false" in role
    assert "hosts: all" in playbook and "serial: 1" in playbook and "any_errors_fatal: true" in playbook
    assert "role: lifecycle_marker" in playbook
    print("lifecycle_marker_transaction=verified")


if __name__ == "__main__":
    main()
