#!/usr/bin/env python3
"""Adversarial tests for fixed Proxmox low-risk activation support."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import types
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
CONTROLLER = ROOT / "scripts/controller/proxmox-low-risk-activation.py"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"


def load(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def load_activator():
    source = ACTIVATOR.read_text()
    prefix, separator, _ = source.partition("\ntry:\n    main()")
    assert separator
    module = types.ModuleType("fixture")
    exec(compile(prefix, str(ACTIVATOR), "exec"), module.__dict__)
    return module


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def expect_failure(action, expected: str) -> None:
    try:
        action()
    except (SystemExit, ValueError) as error:
        assert expected in str(error), (expected, error)
    else:
        raise AssertionError(f"expected failure containing {expected!r}")


def main() -> None:
    for relative in ('ansible/playbooks/proxmox-low-risk-plan.yml',
                     'ansible/roles/proxmox_low_risk_lifecycle/tasks/main.yml',
                     'ansible/roles/proxmox_low_risk_lifecycle/defaults/main.yml'):
        assert not (ROOT / relative).exists() and not (ROOT / relative).is_symlink(), relative
    activator = load_activator()
    controller = load(CONTROLLER, "proxmox_low_risk_controller")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    contents = [
        "# Repository definitions are managed in /etc/apt/sources.list.d/*.sources.\n",
        "Types: deb\nURIs: http://security.debian.org/debian-security\nSuites: trixie-security\nComponents: main contrib non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n",
        "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main contrib non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n",
        "Types: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-no-subscription\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n",
        "Types: deb\nURIs: https://pkgs.tailscale.com/stable/debian\nSuites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/tailscale-archive-keyring.gpg\n",
    ]
    records = []
    for path, content in zip(activator.APT_SOURCE_PATHS, contents):
        digest = hashlib.sha256(content.encode()).hexdigest()
        records.append({"after_sha256": digest, "before_sha256": digest, "content": content,
                        "gid": 0, "mode": "0644", "path": path, "uid": 0})
    keyrings = [
        {"path": activator.APT_KEYRING_PATHS[0], "sha256": "1" * 64, "symlink_target": "debian-archive-keyring.pgp"},
        {"path": activator.APT_KEYRING_PATHS[1], "sha256": "2" * 64, "symlink_target": None},
        {"path": activator.APT_KEYRING_PATHS[2], "sha256": "3" * 64, "symlink_target": None},
    ]
    plan = {"authorized": False, "automatic_reboot": False, "commit": "a" * 40, "contract_sha256": "b" * 64,
            "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "domain": "apt-repositories",
            "expires_at": (now + dt.timedelta(seconds=1800)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "format": "home-lab-proxmox-low-risk-activation-v1", "host": "proxmox",
            "host_key_fingerprint": activator.FINGERPRINT, "inventory_sha256": "c" * 64, "keyrings": keyrings,
            "metadata_refresh": False, "records": records, "unknown_source_files": []}
    digest = hashlib.sha256(canonical(plan)).hexdigest()
    assert activator.validate_repository_plan(plan, digest) == records

    chrony_plan = {"authorized": False, "automatic_reboot": False, "before": {"active": True, "enabled": True},
                   "commit": "a" * 40, "config_mutation": False, "contract_sha256": "b" * 64,
                   "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "desired": {"active": True, "enabled": True},
                   "domain": "chrony-service", "expires_at": (now + dt.timedelta(seconds=1800)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "format": "home-lab-proxmox-low-risk-activation-v1", "host": "proxmox",
                   "host_key_fingerprint": activator.FINGERPRINT, "inventory_sha256": "c" * 64, "restart_if_healthy": False}
    chrony_digest = hashlib.sha256(canonical(chrony_plan)).hexdigest()
    assert activator.validate_chrony_plan(chrony_plan, chrony_digest) == {"active": True, "enabled": True}
    restarting = copy.deepcopy(chrony_plan); restarting["restart_if_healthy"] = True
    restarting_digest = hashlib.sha256(canonical(restarting)).hexdigest()
    expect_failure(lambda: activator.validate_chrony_plan(restarting, restarting_digest), "chrony activation envelope differs")

    original_repo = activator.REPO
    with tempfile.TemporaryDirectory() as temporary:
        repo = Path(temporary)
        (repo / "infrastructure/contract").mkdir(parents=True)
        (repo / "ansible/inventory/host_vars").mkdir(parents=True)
        contract_path = repo / "infrastructure/contract/home-lab.yml"
        contract_path.write_text(
            "        apt_repositories:\n          current_owner: nix\n          target_owner: ansible\n"
            "          state: pending\n          parity_required: true\n          single_writer: true\n"
        )
        activator.REPO = repo
        expect_failure(lambda: activator.verify_low_risk_authority("apt-repositories", plan), "ownership is not transferred")
        contract_path.write_text(
            "        apt_repositories:\n          current_owner: ansible\n          target_owner: ansible\n"
            "          state: transferred\n          parity_required: true\n          single_writer: true\n"
            "        chrony_service:\n          current_owner: ansible\n          target_owner: ansible\n"
            "          state: transferred\n          parity_required: true\n          single_writer: true\n"
        )
        policy = {
            "repository_files": [{"content": item["content"], "group": "root", "mode": "0644", "owner": "root", "path": item["path"]}
                                 for item in records],
            "keyrings": keyrings,
            "chrony_service": {"active": True, "enabled": True},
        }
        policy_path = repo / "ansible/inventory/host_vars/proxmox.yml"
        policy_path.write_text(json.dumps({"proxmox_maintenance_policy": policy}))
        assert not (repo / "nix").exists(), "native policy fixture must not require Nix source"
        activator.REPO = repo
        activator.verify_low_risk_authority("apt-repositories", plan)
        activator.verify_low_risk_authority("chrony-service", chrony_plan)
        malicious = copy.deepcopy(plan); malicious["records"][0]["content"] += "deb http://evil.invalid stable main\n"
        malicious["records"][0]["after_sha256"] = hashlib.sha256(malicious["records"][0]["content"].encode()).hexdigest()
        expect_failure(lambda: activator.verify_low_risk_authority("apt-repositories", malicious), "contracted content")
        policy["chrony_service"]["active"] = False
        policy_path.write_text(json.dumps({"proxmox_maintenance_policy": policy}))
        expect_failure(lambda: activator.verify_low_risk_authority("chrony-service", chrony_plan), "contracted service state")
        policy_path.write_text(json.dumps({"proxmox_maintenance_policy": {}}))
        expect_failure(lambda: activator.verify_low_risk_authority("apt-repositories", plan), "policy shape differs")
    activator.REPO = original_repo

    original_native = activator.native
    activator.native = lambda arguments: types.SimpleNamespace(stdout=(
        "ActiveState=failed\nDropInPaths=\nFragmentPath=/usr/lib/systemd/system/chrony.service\nUnitFileState=masked\n"
    ))
    expect_failure(lambda: activator.chrony_state(), "unit provenance or state differs")
    activator.native = original_native

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary); target = directory / "source"; before_content = b"before\n"; after_content = b"after\n"
        target.write_bytes(after_content); (directory / "before-0.bin").write_bytes(before_content)
        record = {"after_sha256": hashlib.sha256(after_content).hexdigest(), "before_sha256": hashlib.sha256(before_content).hexdigest(),
                  "path": str(target)}
        original_snapshot = activator.repository_snapshot; original_replace = activator.replace_repository_file; original_read_fixed = activator.read_fixed
        activator.repository_snapshot = lambda path: (path.read_bytes(), hashlib.sha256(path.read_bytes()).hexdigest())
        activator.replace_repository_file = lambda path, content: path.write_bytes(content)
        activator.read_fixed = lambda path, *_: path.read_bytes()
        activator.rollback_repository(directory, [record])
        assert target.read_bytes() == before_content
        target.write_bytes(b"unrecognized\n")
        expect_failure(lambda: activator.rollback_repository(directory, [record]), "unrecognized file state")
        activator.repository_snapshot = original_snapshot; activator.replace_repository_file = original_replace; activator.read_fixed = original_read_fixed

    source = ACTIVATOR.read_text()
    repository_body = source.split("def repository_operation", 1)[1].split("def recover_repository", 1)[0]
    chrony_body = source.split("def chrony_operation", 1)[1].split("def recover_chrony", 1)[0]
    assert repository_body.index("fsync_directory(directory)") < repository_body.index("replace_repository_file")
    assert "except Exception:\n            rollback_repository(directory, records)" in repository_body
    assert repository_body.index("flock(lock_descriptor") < repository_body.index("validate_repository_plan")
    assert chrony_body.index("flock(lock_descriptor") < chrony_body.index("validate_chrony_plan")
    for forbidden in ("apt-get\", \"update", "dist-upgrade", "systemctl\", \"reboot"):
        assert forbidden not in repository_body
    for forbidden in ("chrony.conf", '"restart", "chrony.service"', '"reload", "chrony.service"', "timedatectl"):
        assert forbidden not in chrony_body

    unknown = copy.deepcopy(plan); unknown["unknown_source_files"] = ["evil.list"]
    unknown_digest = hashlib.sha256(canonical(unknown)).hexdigest()
    expect_failure(lambda: activator.validate_repository_plan(unknown, unknown_digest), "source cardinality")
    altered = copy.deepcopy(plan); altered["records"][0]["content"] += "deb http://evil.invalid stable main\n"
    altered_digest = hashlib.sha256(canonical(altered)).hexdigest()
    expect_failure(lambda: activator.validate_repository_plan(altered, altered_digest), "repository record differs")
    wrong_keyring = copy.deepcopy(plan); wrong_keyring["keyrings"][1]["symlink_target"] = "debian-archive-keyring.pgp"
    wrong_keyring_digest = hashlib.sha256(canonical(wrong_keyring)).hexdigest()
    expect_failure(lambda: activator.validate_repository_plan(wrong_keyring, wrong_keyring_digest), "keyring record differs")

    native_policy = controller.maintenance_policy()
    assert [item["path"] for item in native_policy["repository_files"]] == list(controller.SOURCE_PATHS)
    assert [item["content"] for item in native_policy["repository_files"]] == contents
    observation = {"domains": {
        "managedFiles": {"status": "complete", "records": [
            {"contentMatches": True, "groupMatches": True, "mode": "0644", "ownerMatches": True,
             "target": item["path"], "type": "file"} for item in native_policy["repository_files"]]},
        "managedArtifacts": {"status": "complete", "records": [
            {"contentMatches": True, "groupMatches": True, "ownerMatches": True, "symlinkTargetMatches": True,
             "mode": "0644", "target": item["path"]} for item in native_policy["keyrings"]]}}}
    observed_records, observed_keyrings = controller.repository_material(observation)
    assert observed_records == records
    assert observed_keyrings == native_policy["keyrings"]
    observation["domains"]["managedFiles"]["records"][0]["contentMatches"] = False
    expect_failure(lambda: controller.repository_material(observation), "repository parity")
    assert 'nix/proxmox' not in CONTROLLER.read_text()
    assert 'nix/proxmox' not in ACTIVATOR.read_text()
    assert 'infrastructure/host-lifecycle/proxmox/package-manifest.json' in ACTIVATOR.read_text()
    assert controller.handoff_state("apt_repositories")["current_owner"] == "ansible"
    assert controller.handoff_state("chrony_service")["current_owner"] == "ansible"
    for command in ("apply apt-repositories bad", "apply apt-repositories " + "a" * 64 + ";id", "apply chrony-service bad", "recover chrony-service ../x", "shell", "stage low-risk ../x"):
        result = subprocess.run((str(TRANSPORT), "-c", command), capture_output=True, timeout=10)
        assert result.returncode == 64, (command, result.returncode, result.stdout, result.stderr)
    print("proxmox_low_risk_activation=verified")


if __name__ == "__main__":
    main()
