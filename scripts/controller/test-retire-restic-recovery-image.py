#!/usr/bin/env python3
"""Verify the exact image-only VM9900 Restic retirement boundary."""
import copy
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/controller/retire-restic-recovery-image.py"
spec = importlib.util.spec_from_file_location("retire_restic_recovery_image", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

image = module.contract_image()
attributes = {
    "checksum": image["sha512"],
    "checksum_algorithm": "sha512",
    "content_type": "import",
    "datastore_id": "local",
    "decompression_algorithm": None,
    "file_name": "home-lab-restic-recovery-debian-20260810-2566.qcow2",
    "id": module.IMAGE_ID,
    "node_name": "proxmox",
    "overwrite": True,
    "overwrite_unmanaged": False,
    "size": 436404224,
    "upload_timeout": 600,
    "url": image["url"],
    "verify": True,
}
state = {
    "version": 4,
    "terraform_version": "1.10.6",
    "serial": 1,
    "lineage": "91d17ecc-787b-e540-300e-3fbc1bce89df",
    "outputs": {},
    "resources": [{
        "mode": "managed",
        "type": "proxmox_download_file",
        "name": "recovery_image",
        "provider": 'provider["registry.opentofu.org/bpg/proxmox"]',
        "instances": [{"index_key": 0, "schema_version": 0, "attributes": attributes, "sensitive_attributes": []}],
    }],
    "check_results": None,
}
raw = json.dumps(state, indent=2).encode() + b"\n"

with tempfile.TemporaryDirectory(dir=ROOT / ".local") as directory:
    root = Path(directory)
    state_path = root / "tofu.tfstate"
    state_path.write_bytes(raw)
    state_path.chmod(0o600)
    original_state = module.STATE
    original_sha = module.INITIAL_STATE_SHA256
    module.STATE = state_path
    module.INITIAL_STATE_SHA256 = hashlib.sha256(raw).hexdigest()
    try:
        expected = module.inspect_initial_state(raw)
        assert expected["id"] == module.IMAGE_ID
        assert module.ADDRESS == "proxmox_download_file.recovery_image[0]"
        plan = {"resource_changes": [{"address": module.ADDRESS, "type": "proxmox_download_file", "change": {"actions": ["delete"], "before": attributes, "after": None, "after_unknown": {}}}]}
        assert module.inspect_plan(plan) == expected

        hostile = []
        item = copy.deepcopy(plan); item["resource_changes"][0]["change"]["actions"] = ["update"]; hostile.append((item, "plan-actions"))
        item = copy.deepcopy(plan); item["resource_changes"][0]["address"] = "proxmox_virtual_environment_vm.recovery[0]"; hostile.append((item, "plan-actions"))
        item = copy.deepcopy(plan); item["resource_changes"].append({"address": "proxmox_virtual_environment_vm.production", "type": "proxmox_virtual_environment_vm", "change": {"actions": ["delete"], "before": {}, "after": None}}); hostile.append((item, "plan-actions"))
        item = copy.deepcopy(plan); item["resource_changes"][0]["change"]["before"]["file_name"] = "other.qcow2"; hostile.append((item, "plan-before"))
        item = copy.deepcopy(plan); item["resource_changes"][0]["change"]["after"] = {}; hostile.append((item, "plan-after"))
        for value, reason in hostile:
            try:
                module.inspect_plan(value)
            except SystemExit as error:
                assert reason in str(error), error
            else:
                raise AssertionError(f"hostile plan passed: {reason}")

        changed = copy.deepcopy(state)
        changed["resources"].append(copy.deepcopy(changed["resources"][0]))
        changed_raw = json.dumps(changed, indent=2).encode() + b"\n"
        module.INITIAL_STATE_SHA256 = hashlib.sha256(changed_raw).hexdigest()
        try:
            module.inspect_initial_state(changed_raw)
        except SystemExit as error:
            assert "initial-state-scope" in str(error)
        else:
            raise AssertionError("multi-resource state passed")
        wrong_index = copy.deepcopy(state)
        wrong_index["resources"][0]["instances"][0]["index_key"] = 1
        wrong_index_raw = json.dumps(wrong_index, indent=2).encode() + b"\n"
        module.INITIAL_STATE_SHA256 = hashlib.sha256(wrong_index_raw).hexdigest()
        try:
            module.inspect_initial_state(wrong_index_raw)
        except SystemExit as error:
            assert "initial-state-scope" in str(error)
        else:
            raise AssertionError("wrong resource instance index passed")
        module.INITIAL_STATE_SHA256 = hashlib.sha256(raw).hexdigest()
        preserved = module.preserve_state_before(root, raw)
        assert preserved.read_bytes() == raw and preserved.stat().st_mode & 0o777 == 0o600
        empty = {**state, "serial": 2, "resources": []}
        module.inspect_empty_state(json.dumps(empty, indent=2).encode() + b"\n")
        empty["serial"] = 1
        try:
            module.inspect_empty_state(json.dumps(empty, indent=2).encode() + b"\n")
        except SystemExit as error:
            assert "empty-state-identity" in str(error)
        else:
            raise AssertionError("pre-retirement empty state passed")
    finally:
        module.STATE = original_state
        module.INITIAL_STATE_SHA256 = original_sha

source = SOURCE.read_text()
for required in (
    module.INITIAL_STATE_SHA256,
    module.JOURNAL_SHA256,
    module.IMAGE_ID,
    module.CONFIRM,
    "verify_exact_checkout",
    "live_precondition",
    "vm9900-still-present",
    "production-vm-identity",
    "plan-actions",
    "tofu-apply-no-retry",
    "inspect_empty_state",
    "preserve_state_before",
    "receipt-identity",
):
    assert required in source, required
assert "state rm" not in source
assert "unlink()" not in source
print("restic_recovery_image_retirement=verified hostile_plans=5")
