#!/usr/bin/env python3
"""Focused tests for the isolated Proxmox LXC qualification controls."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("proxmox-lxc-qualification.py")
SPEC = importlib.util.spec_from_file_location("proxmox_lxc_qualification", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load LXC qualification helper")
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)
FIXTURES = Path(__file__).resolve().parents[2] / "infrastructure/policy/fixtures"
VMID = "9020"
TEMPLATE = "local:vztmpl/debian-test_1_amd64.tar.zst"
ENDPOINT = "https://Proxmox:8006/api2/json/"


def fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text())


def environment() -> dict[str, str]:
    return {
        "TF_VAR_qualification_vm_id": VMID,
        "TF_VAR_qualification_template_file_id": TEMPLATE,
        "TF_VAR_proxmox_endpoint": ENDPOINT,
        "TF_BACKEND_BUCKET": "protected-backend-bucket",
        "PROXMOX_CA_PEM": "-----BEGIN CERTIFICATE-----\nprotected\n-----END CERTIFICATE-----\n",
        "PROXMOX_VERIFY_STORAGE_VOLUME": "true",
    }


class QualificationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = mock.patch.dict(os.environ, environment(), clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_exact_operation_modes_use_pinned_provider_plan_shape(self) -> None:
        qualification.inspect_plan(fixture("lxc-qualification-create.json"), "create")
        qualification.inspect_plan(
            fixture("lxc-qualification-protected-delete.json"), "probe-protected-delete"
        )
        qualification.inspect_plan(fixture("lxc-qualification-unprotect.json"), "unprotect")
        qualification.inspect_plan(fixture("lxc-qualification-reprotect.json"), "reprotect")
        qualification.inspect_plan(fixture("lxc-qualification-delete.json"), "delete")
        qualification.inspect_plan(
            fixture("lxc-qualification-noop-protected.json"), "verify-protected"
        )
        qualification.inspect_plan(fixture("lxc-qualification-empty.json"), "verify-empty")

    def test_forbidden_plan_shapes_are_rejected(self) -> None:
        cases = (
            ("lxc-qualification-wrong-address.json", "create"),
            ("lxc-qualification-wrong-mode.json", "create"),
            ("lxc-qualification-wrong-provider.json", "create"),
            ("lxc-qualification-wrong-vmid-100.json", "create"),
            ("lxc-qualification-wrong-vmid-101.json", "create"),
            ("lxc-qualification-storage.json", "create"),
            ("lxc-qualification-network.json", "create"),
            ("lxc-qualification-mount-point.json", "create"),
            ("lxc-qualification-device.json", "create"),
            ("lxc-qualification-features.json", "create"),
            ("lxc-qualification-start.json", "create"),
            ("lxc-qualification-extra-action.json", "create"),
            ("lxc-qualification-replace.json", "create"),
            ("lxc-qualification-import.json", "create"),
            ("lxc-qualification-protected-delete.json", "delete"),
            ("lxc-qualification-empty.json", "create"),
            ("lxc-qualification-empty.json", "verify-protected"),
            ("lxc-qualification-noop-protected.json", "verify-empty"),
        )
        for name, mode in cases:
            with self.subTest(name=name, mode=mode), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.inspect_plan(fixture(name), mode)

    def test_every_extra_provider_capability_is_rejected(self) -> None:
        forbidden_values = {
            "clone": [{"vm_id": 200}],
            "device_passthrough": [{"path": "/dev/dri/renderD128"}],
            "environment_variables": {"CAPABILITY": "forbidden"},
            "features": [{"nesting": True}],
            "hook_script_file_id": "local:snippets/hook.pl",
            "idmap": [{"container_id": 0, "host_id": 100000, "size": 1, "type": "uid"}],
            "mount_point": [{"path": "/mnt", "volume": "/host"}],
            "network_interface": [{"name": "eth0"}],
            "pool_id": "forbidden",
            "startup": [{"order": 1}],
            "tags": ["forbidden"],
            "template": True,
            "wait_for_ip": [{"ipv4": True}],
        }
        for key, value in forbidden_values.items():
            plan = fixture("lxc-qualification-create.json")
            plan["resource_changes"][0]["change"]["after"][key] = value
            with self.subTest(key=key), self.assertRaises(qualification.QualificationError):
                qualification.inspect_plan(plan, "create")

    def test_every_operation_rejects_nonexact_unknown_capabilities(self) -> None:
        cases = (
            ("lxc-qualification-create.json", "create"),
            ("lxc-qualification-unprotect.json", "unprotect"),
            ("lxc-qualification-noop-protected.json", "verify-protected"),
            ("lxc-qualification-delete.json", "delete"),
        )
        adversarial_unknowns = {
            "network_interface": True,
            "mount_point": True,
            "device_passthrough": True,
            "features": True,
            "disk": True,
            "startup": True,
            "id": True,
            "protection": True,
            "console": True,
            "cpu": True,
            "initialization": True,
            "memory": True,
            "operating_system": True,
            "started": True,
            "vm_id": True,
        }
        for name, mode in cases:
            for key, value in adversarial_unknowns.items():
                plan = fixture(name)
                unknowns = plan["resource_changes"][0]["change"]["after_unknown"]
                unknowns[key] = False if unknowns.get(key) is value else value
                with self.subTest(name=name, mode=mode, key=key), self.assertRaises(
                    qualification.QualificationError
                ):
                    qualification.inspect_plan(plan, mode)

    def test_update_and_noop_reject_before_unknown_and_nonempty_capabilities(self) -> None:
        for name, mode in (
            ("lxc-qualification-unprotect.json", "unprotect"),
            ("lxc-qualification-noop-protected.json", "verify-protected"),
        ):
            plan = fixture(name)
            plan["resource_changes"][0]["change"]["before_unknown"] = {"protection": True}
            with self.subTest(name=name, field="before_unknown"), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.inspect_plan(plan, mode)
            plan = fixture(name)
            plan["resource_changes"][0]["change"]["after"]["network_interface"] = [
                {"name": "eth0"}
            ]
            with self.subTest(name=name, field="network_interface"), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.inspect_plan(plan, mode)

    def test_description_accepts_only_marker_or_one_newline_and_canonicalizes_updates(self) -> None:
        for description in (qualification.MARKER, f"{qualification.MARKER}\n"):
            plan = fixture("lxc-qualification-create.json")
            plan["resource_changes"][0]["change"]["after"]["description"] = description
            qualification.inspect_plan(plan, "create")
        update = fixture("lxc-qualification-unprotect.json")
        update["resource_changes"][0]["change"]["before"]["description"] = qualification.MARKER
        update["resource_changes"][0]["change"]["after"]["description"] = f"{qualification.MARKER}\n"
        qualification.inspect_plan(update, "unprotect")
        for description in (
            f"{qualification.MARKER}\n\n",
            f" {qualification.MARKER}",
            f"{qualification.MARKER} ",
            f"{qualification.MARKER}\t",
            "other",
        ):
            plan = fixture("lxc-qualification-create.json")
            plan["resource_changes"][0]["change"]["after"]["description"] = description
            with self.subTest(description=repr(description)), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.inspect_plan(plan, "create")


class QualificationEvidenceTests(unittest.TestCase):
    def env(self) -> mock._patch_dict[str, str]:
        return mock.patch.dict(os.environ, environment(), clear=True)

    def attributes(self, protected: bool = True) -> dict[str, object]:
        attributes = deepcopy(
            fixture("lxc-qualification-create.json")["resource_changes"][0]["change"]["after"]
        )
        attributes["protection"] = protected
        attributes["disk"][0]["path_in_datastore"] = (
            f"local-lvm:subvol-{VMID}-disk-0"
        )
        attributes["id"] = f"proxmox/{VMID}"
        attributes["ipv4"] = {}
        attributes["ipv6"] = {}
        return attributes

    def state(self, protected: bool = True) -> dict[str, object]:
        return {
            "resources": [
                {
                    "mode": "managed",
                    "type": "proxmox_virtual_environment_container",
                    "name": "qualification",
                    "instances": [{"index_key": 0, "attributes": self.attributes(protected)}],
                }
            ]
        }

    def live_config(self, protected: bool = True) -> dict[str, object]:
        return {
            "arch": "amd64",
            "cmode": "tty",
            "console": 0,
            "cores": 1,
            "cpulimit": 0,
            "cpuunits": 100,
            "description": f"{qualification.MARKER}\n",
            "digest": "a" * 40,
            "hostname": qualification.MARKER,
            "memory": 128,
            "onboot": 0,
            "ostype": "debian",
            "protection": int(protected),
            "rootfs": f"local-lvm:vm-{VMID}-disk-0,size=1G",
            "swap": 0,
            "template": 0,
            "tty": 0,
            "unprivileged": 1,
        }

    def inventory(self) -> list[dict[str, object]]:
        return [{"vmid": int(VMID), "type": "lxc", "node": "proxmox", "status": "stopped", "name": qualification.MARKER}]

    def volumes(self) -> list[dict[str, str]]:
        return [{"volid": f"local-lvm:vm-{VMID}-disk-0"}]

    def test_protected_inputs_reject_production_ids_and_bad_template_syntax(self) -> None:
        for vmid, template in (("100", TEMPLATE), ("101", TEMPLATE), (VMID, "local:iso/bad")):
            with self.subTest(vmid=vmid, template=template), mock.patch.dict(
                os.environ,
                environment() | {"TF_VAR_qualification_vm_id": vmid, "TF_VAR_qualification_template_file_id": template},
                clear=True,
            ), self.assertRaises(qualification.QualificationError):
                qualification.secret_inputs()

    def test_state_identity_and_empty_tombstone(self) -> None:
        with self.env():
            qualification.validate_state(self.state(), "protected")
            qualification.validate_state(self.state(False), "unprotected")
            provider_defaults = self.state()
            provider_attributes = provider_defaults["resources"][0]["instances"][0]["attributes"]
            provider_attributes["hook_script_file_id"] = ""
            provider_attributes["pool_id"] = ""
            provider_initialization = provider_attributes["initialization"][0]
            provider_initialization["dns"] = None
            provider_initialization["entrypoint"] = ""
            provider_initialization["ip_config"] = None
            provider_initialization["user_account"] = None
            qualification.validate_state(provider_defaults, "protected")
            qualification.validate_state({"resources": []}, "empty")
            with self.assertRaises(qualification.QualificationError):
                qualification.validate_state(self.state(), "empty")
            adversarial = self.state()
            adversarial["resources"][0]["instances"][0]["attributes"]["mount_point"] = [
                {"path": "/mnt", "volume": "/host"}
            ]
            with self.assertRaises(qualification.QualificationError):
                qualification.validate_state(adversarial, "protected")

    def test_state_disk_path_accepts_only_bound_datastore_prefixed_volume(self) -> None:
        with self.env():
            for kind in ("vm", "subvol"):
                state = self.state()
                state["resources"][0]["instances"][0]["attributes"]["disk"][0][
                    "path_in_datastore"
                ] = f"local-lvm:{kind}-{VMID}-disk-0"
                qualification.validate_state(state, "protected")
            for path in (
                f"subvol-{VMID}-disk-0",
                f"other:subvol-{VMID}-disk-0",
                "local-lvm:subvol-9999-disk-0",
                f"local-lvm:subvol-{VMID}-disk-1",
                f"local-lvm:subvol-{VMID}-disk-0-extra",
            ):
                state = self.state()
                state["resources"][0]["instances"][0]["attributes"]["disk"][0][
                    "path_in_datastore"
                ] = path
                with self.subTest(path=path), self.assertRaises(
                    qualification.QualificationError
                ):
                    qualification.validate_state(state, "protected")
            state = self.state()
            state["resources"][0]["instances"][0]["attributes"]["disk"][0].pop(
                "path_in_datastore"
            )
            with self.assertRaises(qualification.QualificationError):
                qualification.validate_state(state, "protected")
            state = self.state()
            state["resources"][0]["instances"][0]["attributes"]["disk"].append(
                deepcopy(state["resources"][0]["instances"][0]["attributes"]["disk"][0])
            )
            with self.assertRaises(qualification.QualificationError):
                qualification.validate_state(state, "protected")

    def test_probe_rejection_requires_protection_specific_failure(self) -> None:
        self.assertTrue(qualification.classify_probe_log("Error: can't remove CT protected-value - protection mode enabled"))
        self.assertTrue(qualification.classify_probe_log("Reason: can't\nremove CT protected-value - protection mode enabled"))
        for message in (
            "401 unauthorized",
            "x509 certificate signed by unknown authority",
            "connection timed out",
            "provider failed to start",
            "generic API error",
            "can't remove CT protected-value - protection mode enabled; 403 forbidden",
        ):
            with self.subTest(message=message):
                self.assertFalse(qualification.classify_probe_log(message))

    def test_manifest_binds_all_hashed_target_identities_and_rejects_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.env():
            plan = Path(directory, "qualification.tfplan")
            plan.write_bytes(b"saved plan")
            manifest = qualification.create_manifest("create", "a" * 40, plan)
            qualification.validate_manifest(manifest, "create", "a" * 40, plan)
            self.assertRegex(manifest["run_id"], r"^[1-9][0-9]*$")
            serialized = json.dumps(manifest)
            for secret in (VMID, TEMPLATE, ENDPOINT, "protected-backend-bucket", "BEGIN CERTIFICATE"):
                self.assertNotIn(secret, serialized)
            self.assertEqual(set(manifest["target_identities"]), qualification.IDENTITY_HASH_KEYS)
            for key in qualification.IDENTITY_HASH_KEYS:
                changed = deepcopy(manifest)
                changed["target_identities"][key] = "0" * 64
                with self.subTest(key=key), self.assertRaises(qualification.QualificationError):
                    qualification.validate_manifest(changed, "create", "a" * 40, plan)
            for key, value in (("run_id", "invalid"), ("operation", "delete"), ("commit", "b" * 40), ("plan_sha256", "0" * 64)):
                changed = deepcopy(manifest)
                changed[key] = value
                with self.subTest(key=key), self.assertRaises(qualification.QualificationError):
                    qualification.validate_manifest(changed, "create", "a" * 40, plan)
            for env_key in ("TF_BACKEND_BUCKET", "TF_VAR_proxmox_endpoint", "PROXMOX_CA_PEM"):
                with self.subTest(env_key=env_key), mock.patch.dict(os.environ, {env_key: os.environ[env_key] + "changed"}), self.assertRaises(qualification.QualificationError):
                    qualification.validate_manifest(manifest, "create", "a" * 40, plan)

    def test_endpoint_normalization_is_stable_and_strict(self) -> None:
        self.assertEqual(
            qualification.normalize_endpoint("HTTPS://Proxmox:8006//api2/json/"),
            "https://proxmox:8006/api2/json",
        )
        for endpoint in ("http://proxmox/api2/json", "https://user@proxmox/api2/json", "https://proxmox", "https://proxmox/api?secret=x"):
            with self.subTest(endpoint=endpoint), self.assertRaises(qualification.QualificationError):
                qualification.normalize_endpoint(endpoint)

    def test_proxmox_ssl_context_preserves_chain_and_hostname_verification(self) -> None:
        context = qualification.proxmox_ssl_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertFalse(context.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_live_checks_bind_exact_config_volume_absence_and_template(self) -> None:
        for kind in ("vm", "subvol"):
            config = self.live_config()
            config["rootfs"] = f"local-lvm:{kind}-{VMID}-disk-0,size=1G"
            volumes = [{"volid": f"local-lvm:{kind}-{VMID}-disk-0"}]
            with self.subTest(kind=kind), self.env(), mock.patch.object(
                qualification, "api_get", side_effect=[self.inventory(), config, volumes]
            ):
                qualification.validate_live("protected")
        with self.env(), mock.patch.object(
            qualification, "api_get", side_effect=[[], [], [{"volid": TEMPLATE}]]
        ):
            qualification.validate_live("pre-create")
        with self.env(), mock.patch.object(qualification, "api_get", side_effect=[[], []]):
            qualification.validate_live("absent")

        for key, value in (("cpulimit", 1), ("template", 1)):
            config = self.live_config()
            config[key] = value
            with self.subTest(key=key), self.env(), mock.patch.object(
                qualification, "api_get", side_effect=[self.inventory(), config, self.volumes()]
            ), self.assertRaises(qualification.QualificationError):
                qualification.validate_live("protected")

    def test_volume_inventory_uses_unfiltered_storage_query(self) -> None:
        with mock.patch.object(qualification, "api_get", return_value=[]) as api_get:
            self.assertEqual(qualification.volume_ids(int(VMID)), [])
        api_get.assert_called_once_with("nodes/proxmox/storage/local-lvm/content")
    def test_live_rejects_every_extra_capability_and_residual_volume(self) -> None:
        for key, value in (("mp0", "local-lvm:vm-9020-disk-1,mp=/mnt"), ("net0", "name=eth0"), ("features", "nesting=1"), ("hookscript", "local:snippets/x"), ("tags", "x"), ("startup", "order=1")):
            config = self.live_config()
            config[key] = value
            with self.subTest(key=key), self.env(), mock.patch.object(
                qualification, "api_get", side_effect=[self.inventory(), config]
            ), self.assertRaises(qualification.QualificationError):
                qualification.validate_live("protected")
        with self.env(), mock.patch.object(
            qualification, "api_get", side_effect=[[], self.volumes()]
        ), self.assertRaises(qualification.QualificationError):
            qualification.validate_live("absent")
        for rootfs, volumes in (
            (f"other:vm-{VMID}-disk-0,size=1G", self.volumes()),
            (f"local-lvm:vm-9999-disk-0,size=1G", self.volumes()),
            (f"local-lvm:vm-{VMID}-disk-1,size=1G", self.volumes()),
            (f"local-lvm:vm-{VMID}-disk-0-extra,size=1G", self.volumes()),
            (
                f"local-lvm:vm-{VMID}-disk-0,size=1G",
                self.volumes() + [{"volid": f"local-lvm:vm-{VMID}-disk-1"}],
            ),
        ):
            config = self.live_config()
            config["rootfs"] = rootfs
            with self.subTest(rootfs=rootfs, volumes=volumes), self.env(), mock.patch.object(
                qualification, "api_get", side_effect=[self.inventory(), config, volumes]
            ), self.assertRaises(qualification.QualificationError):
                qualification.validate_live("protected")

    def test_recovery_classifies_all_sanitized_states(self) -> None:
        cases = (
            ({"resources": []}, None, "aligned-empty"),
            (self.state(True), True, "aligned-protected"),
            (self.state(False), False, "aligned-unprotected"),
            ({"resources": []}, True, "live-only-protected"),
            ({"resources": []}, False, "live-only-unprotected"),
            (self.state(True), None, "state-only"),
            (self.state(True), False, "protection-mismatch"),
        )
        with self.env():
            for state, live, expected in cases:
                with self.subTest(expected=expected):
                    self.assertEqual(qualification.recovery_classification(state, live), expected)
            invalid = self.state()
            invalid["resources"][0]["instances"][0]["attributes"]["tags"] = ["forbidden"]
            self.assertEqual(
                qualification.recovery_classification(invalid, True),
                "state-identity-mismatch:qualification-mappings-or-tags-are-forbidden",
            )
        with mock.patch.object(qualification, "live_identity", side_effect=qualification.QualificationError("test")):
            self.assertEqual(qualification.inspect_recovery(self.state()), "live-identity-mismatch:test")

    def run_evidence(self) -> dict[str, object]:
        source, version = qualification.locked_provider()
        runs = [
            {"operation": operation, "run_id": str(index + 100)}
            for index, operation in enumerate(qualification.EVIDENCE_OPERATIONS)
        ]
        return {
            "version": 1,
            "qualification_tooling_commit": "a" * 40,
            "provider": {
                "source": source,
                "version": version,
                "lock_sha256": qualification.hashlib.sha256(
                    qualification.LOCKFILE.read_bytes()
                ).hexdigest(),
            },
            "runs": runs,
            "final_proof": {
                "operation": "verify-empty",
                "run_id": runs[-1]["run_id"],
                "state": "empty",
                "plan": "no-op",
                "api": "absent",
                "volumes": "absent",
                "backend_lock": "absent",
            },
            "protected_identifiers_included": False,
        }

    def test_run_evidence_binds_sequence_commit_provider_and_final_proof(self) -> None:
        evidence = self.run_evidence()
        qualification.validate_run_evidence(evidence, "a" * 40)
        mutations = []
        duplicate = deepcopy(evidence)
        duplicate["runs"][1]["run_id"] = duplicate["runs"][0]["run_id"]
        mutations.append(duplicate)
        missing = deepcopy(evidence)
        missing["runs"].pop()
        mutations.append(missing)
        sequence = deepcopy(evidence)
        sequence["runs"][0], sequence["runs"][1] = sequence["runs"][1], sequence["runs"][0]
        mutations.append(sequence)
        provider = deepcopy(evidence)
        provider["provider"]["version"] = "0.0.0"
        mutations.append(provider)
        lock_hash = deepcopy(evidence)
        lock_hash["provider"]["lock_sha256"] = "0" * 64
        mutations.append(lock_hash)
        final_proof = deepcopy(evidence)
        final_proof["final_proof"]["plan"] = "changed"
        mutations.append(final_proof)
        identifier = deepcopy(evidence)
        identifier["protected_identifiers_included"] = True
        mutations.append(identifier)
        for invalid in mutations:
            with self.subTest(invalid=invalid), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.validate_run_evidence(invalid, "a" * 40)
        with self.assertRaises(qualification.QualificationError):
            qualification.validate_run_evidence(evidence, "b" * 40)


if __name__ == "__main__":
    unittest.main()
