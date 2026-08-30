#!/usr/bin/env python3
"""Adversarial tests for no-mutation Proxmox boot ownership activation."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "scripts/controller/proxmox-boot-ownership-activation.py"
ACTIVATOR = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator"
TRANSPORT = ROOT / "infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport"
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"


def load_controller():
    loader = importlib.machinery.SourceFileLoader("boot_ownership_controller_test", str(CONTROLLER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def load_activator() -> dict:
    source = ACTIVATOR.read_text(encoding="utf-8")
    prefix, separator, _ = source.partition("\ntry:\n    main()")
    assert separator
    namespace = {"__name__": "boot_ownership_activator_test", "__file__": "/tmp/boot-ownership-activator"}
    exec(compile(prefix, "fixed-boot-ownership-activator", "exec"), namespace)
    return namespace


def main() -> None:
    controller_source = CONTROLLER.read_text(encoding="utf-8")
    activator_source = ACTIVATOR.read_text(encoding="utf-8")
    transport_source = TRANSPORT.read_text(encoding="utf-8")
    compile(controller_source, str(CONTROLLER), "exec")
    compile(activator_source, str(ACTIVATOR), "exec")
    controller = load_controller()
    assert controller.canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}\n'

    parsed = subprocess.run(("node", "-e", "const fs=require('node:fs'),y=require('js-yaml');process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1],'utf8'))));", str(CONTRACT)), cwd=ROOT, check=True, capture_output=True, text=True)
    contract = json.loads(parsed.stdout)
    for protected in contract["proxmox"]["vfio"]["device_ids"]:
        assert protected not in controller_source
        assert protected not in transport_source
        assert protected not in activator_source

    namespace = load_activator()
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        old_dir = namespace["BOOT_OWNERSHIP_DIR"]
        old_lock = namespace["BOOT_TRANSACTION_LOCK"]
        old_validate = namespace["validate_boot_ownership_plan"]
        old_save = namespace["save_package_journal"]
        old_read = namespace["read_fixed"]
        namespace["BOOT_OWNERSHIP_DIR"] = root
        namespace["BOOT_TRANSACTION_LOCK"] = root / "transaction.lock"
        namespace["validate_boot_ownership_plan"] = lambda value, digest: {"source": {"sha256": "a" * 64}}
        def save(path, value, exclusive=False):
            path.write_bytes(namespace["canonical"](value))
            path.chmod(0o600)
        namespace["save_package_journal"] = save
        namespace["read_fixed"] = lambda path, *args: path.read_bytes()
        digest = "b" * 64
        try:
            first = namespace["boot_ownership_operation"]({}, digest)
            second = namespace["boot_ownership_operation"]({}, digest)
        finally:
            namespace["BOOT_OWNERSHIP_DIR"] = old_dir
            namespace["BOOT_TRANSACTION_LOCK"] = old_lock
            namespace["validate_boot_ownership_plan"] = old_validate
            namespace["save_package_journal"] = old_save
            namespace["read_fixed"] = old_read
        assert first == {"boot_ownership_transaction": "committed", "changed": False, "plan_sha256": digest}
        assert second == {"boot_ownership_transaction": "already-committed", "changed": False, "plan_sha256": digest}
        receipt = root / f"{digest}.json"
        assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
        journal = json.loads(receipt.read_bytes())
        assert journal["status"] == "committed" and journal["automatic_reboot"] is False
        assert journal["protected_values_exported"] is False

    for command in ("stage boot-ownership", "stage boot-ownership arbitrary", "apply boot-ownership", "apply boot-ownership arbitrary", "recover boot-ownership " + "a" * 64):
        result = subprocess.run((str(TRANSPORT), "-c", command), capture_output=True, timeout=10)
        assert result.returncode == 64, (command, result.returncode, result.stdout, result.stderr)
    assert "apply-boot-ownership" in activator_source
    assert "apply\\ boot-ownership" in transport_source
    assert "automatic_reboot" in controller_source and "changed" in controller_source
    print("proxmox_boot_ownership_activation_tests=passed")


if __name__ == "__main__":
    main()
