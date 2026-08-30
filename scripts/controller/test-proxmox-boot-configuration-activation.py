#!/usr/bin/env python3
"""Adversarial tests for protected Proxmox boot-configuration activation."""

from __future__ import annotations

import ast
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
CONTROLLER = ROOT / "scripts/controller/proxmox-boot-configuration-activation.py"
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"


def load_activator() -> dict:
    source = ACTIVATOR.read_text(encoding="utf-8")
    prefix, separator, _ = source.partition("\ntry:\n    main()")
    assert separator
    namespace = {"__name__": "fixed_boot_activator_test", "__file__": "/tmp/fixed-boot-activator"}
    exec(compile(prefix, "fixed-boot-activator", "exec"), namespace)
    return namespace


def load_controller():
    loader = importlib.machinery.SourceFileLoader("protected_boot_controller_test", str(CONTROLLER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def function_source(source: str, name: str) -> str:
    tree = ast.parse(source)
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == name)
    return ast.get_source_segment(source, node) or ""


def fake_material() -> dict:
    first = "a" * 4 + ":" + "b" * 4
    second = "c" * 4 + ":" + "d" * 4
    return {
        "device_ids": [first, second],
        "file": {"group": "root", "kind": "protected-managed-file", "mode": "0644", "owner": "root",
                 "path": "/etc/modprobe.d/home-lab-vfio.conf", "projectable": False},
        "handoff": {"current_owner": "nix", "parity_required": True, "single_writer": True,
                    "state": "pending", "target_owner": "ansible"},
        "kernels": {"current": "kernel-current", "fallback": "kernel-fallback", "retention_count": 2,
                    "require_boot_history_proof": True},
        "soft_dependencies": [
            {"module": "module-a", "pre": ["vfio-pci"]},
            {"module": "module-b", "pre": ["vfio-pci"]},
        ],
    }


def exercise_transaction(namespace: dict, fail_native: bool) -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        source = root / "home-lab-vfio.conf"
        current = root / "initrd-current"
        fallback = root / "initrd-fallback"
        source.write_bytes(b"old-source\n")
        current.write_bytes(b"old-current\n")
        fallback.write_bytes(b"old-fallback\n")
        expected = b"new-source\n"
        before = {
            "expected_source_sha256": hashlib.sha256(expected).hexdigest(),
            "initramfs": [
                {"kernel": "kernel-current", "path": str(current), "role": "current",
                 "sha256": hashlib.sha256(current.read_bytes()).hexdigest(), "size": current.stat().st_size},
                {"kernel": "kernel-fallback", "path": str(fallback), "role": "fallback",
                 "sha256": hashlib.sha256(fallback.read_bytes()).hexdigest(), "size": fallback.stat().st_size},
            ],
            "source": {"sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "size": source.stat().st_size},
        }
        old = {key: namespace[key] for key in (
            "BOOT_TRANSACTION_DIR", "BOOT_TRANSACTION_LOCK", "BOOT_VFIO_PATH", "acquire_boot_conflict_locks",
            "boot_contract_material", "native", "replace_repository_file", "validate_boot_plan",
        )}
        old_fchown = namespace["os"].fchown
        namespace["BOOT_TRANSACTION_DIR"] = root / "transactions"
        namespace["BOOT_TRANSACTION_LOCK"] = root / "transaction.lock"
        namespace["BOOT_VFIO_PATH"] = source
        namespace["acquire_boot_conflict_locks"] = lambda: []
        namespace["boot_contract_material"] = lambda: (fake_material(), expected)
        namespace["replace_repository_file"] = lambda path, content: path.write_bytes(content)
        namespace["validate_boot_plan"] = lambda value, digest: before
        namespace["os"].fchown = lambda descriptor, uid, gid: None

        calls = []
        def native(arguments, accepted=(0,), timeout=300):
            calls.append(tuple(arguments))
            if fail_native:
                raise ValueError("simulated initramfs failure")
            target = current if arguments[-1] == "kernel-current" else fallback
            target.write_bytes(("new-" + arguments[-1] + "\n").encode())
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        namespace["native"] = native
        digest = "e" * 64
        try:
            if fail_native:
                try:
                    namespace["boot_operation"]({}, digest)
                except ValueError as error:
                    assert "simulated" in str(error)
                else:
                    raise AssertionError("failed initramfs update did not fail the transaction")
                journal = json.loads((root / "transactions" / digest / "journal.json").read_bytes())
                assert source.read_bytes() == b"old-source\n", (source.read_bytes(), journal)
                assert current.read_bytes() == b"old-current\n", journal
                assert fallback.read_bytes() == b"old-fallback\n", journal
                assert journal["status"] == "rolled-back", journal
            else:
                result = namespace["boot_operation"]({}, digest)
                assert result == {"boot_configuration_transaction": "committed", "changed": True,
                                  "plan_sha256": digest, "rebooted": False}
                assert source.read_bytes() == expected
                assert [item[-1] for item in calls] == ["kernel-current", "kernel-fallback"]
                journal_path = root / "transactions" / digest / "journal.json"
                journal = json.loads(journal_path.read_bytes())
                assert journal["status"] == "committed"
                assert journal["automatic_reboot"] is False
                assert journal["protected_values_exported"] is False
                assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600
        finally:
            namespace.update(old)
            namespace["os"].fchown = old_fchown


def main() -> None:
    activator_source = ACTIVATOR.read_text(encoding="utf-8")
    transport_source = TRANSPORT.read_text(encoding="utf-8")
    controller_source = CONTROLLER.read_text(encoding="utf-8")
    compile(activator_source, str(ACTIVATOR), "exec")
    compile(controller_source, str(CONTROLLER), "exec")
    controller = load_controller()
    assert controller.canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}\n'

    parsed = subprocess.run(
        ("node", "-e", "const fs=require('node:fs');const y=require('js-yaml');process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1],'utf8'))));", str(CONTRACT)),
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    contract = json.loads(parsed.stdout)
    protected_literals = [*contract["proxmox"]["vfio"]["device_ids"]]
    for value in protected_literals:
        assert value not in activator_source
        assert value not in transport_source
        assert value not in controller_source

    namespace = load_activator()
    material = fake_material()
    old_native = namespace["native"]
    namespace["native"] = lambda arguments, timeout=30: SimpleNamespace(
        stdout=json.dumps(material), stderr="", returncode=0,
    )
    try:
        observed, expected = namespace["boot_contract_material"]()
    finally:
        namespace["native"] = old_native
    assert observed == material
    assert expected.startswith(b"options vfio-pci ids=")
    assert expected.count(b"softdep ") == 2

    operation = function_source(activator_source, "boot_operation")
    recovery = function_source(activator_source, "recover_boot")
    assert operation.index("flock") < operation.index("validate_boot_plan")
    assert operation.index("boot_copy") < operation.index("replace_repository_file")
    assert operation.count('"/usr/sbin/update-initramfs"') == 1
    assert '"-u", "-k", item["kernel"]' in operation
    assert "boot_restore" in operation
    assert "update-initramfs" not in recovery
    for forbidden in ("apt-get", "dist-upgrade", "systemctl", "/sbin/reboot", '"reboot"'):
        assert forbidden not in operation
        assert forbidden not in recovery

    exercise_transaction(namespace, fail_native=False)
    exercise_transaction(namespace, fail_native=True)

    for command in (
        "stage boot-configuration bad",
        "stage boot-configuration " + "a" * 64 + ";id",
        "apply boot-configuration bad",
        "recover boot-configuration ../x",
        "observe boot-configuration extra",
        "boot-configuration shell",
    ):
        result = subprocess.run((str(TRANSPORT), "-c", command), capture_output=True, timeout=10)
        assert result.returncode == 64, (command, result.returncode, result.stdout, result.stderr)

    assert "observe\\ boot-configuration" in transport_source
    assert '\"%s-boot-configuration\"' in transport_source
    assert "apply\\ boot-configuration" in transport_source
    assert "recover\\ boot-configuration" in transport_source
    assert "protected_values_exported" in controller_source
    assert "automatic_reboot" in controller_source
    print("proxmox_boot_configuration_activation_tests=passed")


if __name__ == "__main__":
    main()
