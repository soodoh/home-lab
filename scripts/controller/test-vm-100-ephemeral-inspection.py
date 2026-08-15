#!/usr/bin/env python3
"""Hostile contract fixtures for the inspection-only ephemeral Nix transport."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / "scripts/controller"))

from vm_100_ephemeral import (
    CLEANUP_EVIDENCE_FORMAT, COMPOSE_ARTIFACT_SHA256, EXPORT_MANIFEST_FORMAT,
    EXPORT_REQUEST_FORMAT, HOST_ATTESTATION_FORMAT, INSTALL_ATTRIBUTE, LIVE_MODE, NIX_VERSION, QUALIFICATION_CONFIRMATION,
    QUALIFICATION_FORMAT, QUALIFICATION_MODE, QUALIFICATION_REQUEST_FORMAT, SYSTEM,
    TOPLEVEL_ATTRIBUTE, build_qualification_evidence, canonical_bytes, descriptor_metrics, load_canonical,
    open_protected, require_absent_nix, select_bootstrap_executables, validate_cleanup, validate_disk_snapshot,
    sha256_bytes, validate_export_request, validate_host_attestation, validate_host_attested_qualification,
    validate_import_observation, validate_inspection_request,
    validate_live_qualification, validate_manifest, validate_qualification, validate_qualification_request,
    validate_resources, validate_tar,
)

RUNNER_PATH = ROOT / "scripts/controller/run-vm-100-ephemeral-inspection.py"
RUNNER_SPEC = importlib.util.spec_from_file_location("vm100_ephemeral_runner", RUNNER_PATH)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)
STORE = "/nix/store/" + "0" * 32
BOOTSTRAP = STORE + "-nix-bootstrap"
INSTALLER = STORE[:-1] + "1-vm-100-candidate-install"
TOPLEVEL = STORE[:-1] + "2-nixos-system-vm-100"
SHA = "a" * 64
SIGNER = "home-lab-closure"
PUBLIC_KEY_VALUE = SIGNER + ":QUJDRA=="
HOST_ATTESTATION_SHA = "7" * 64
HELPER_SHA = "6" * 64
PRODUCT_UUID_VALUE = "11111111-2222-3333-4444-555555555555"


def entry(path, references=()):
    return {"narHash": "sha256-" + "A" * 43 + "=",  "narSize": 10, "path": path, "references": sorted(references), "registrationSize": 10, "signatures": [SIGNER + ":signature"]}


def manifest(mode=LIVE_MODE):
    return {
        "artifacts": {"bootstrap": {"bytes": 1024, "sha256": SHA}, "export": {"bytes": 2048, "sha256": "b" * 64}},
        "bootstrapPaths": [BOOTSTRAP],
        "bootstrapStorePath": BOOTSTRAP,
        "closure": [entry(BOOTSTRAP), entry(INSTALLER, [BOOTSTRAP]), entry(TOPLEVEL, [BOOTSTRAP, INSTALLER])],
        "closureBytes": 30, "commit": "c" * 40, "composeArtifactSha256": COMPOSE_ARTIFACT_SHA256,
        "flakeLockSha256": "d" * 64, "format": EXPORT_MANIFEST_FORMAT, "helperSha256": HELPER_SHA,
        "inspectionRequestSha256": "9" * 64,
        "installerAttribute": INSTALL_ATTRIBUTE, "installerPath": INSTALLER, "mode": mode, "nixVersion": NIX_VERSION,
        "qualificationEvidenceSha256": "e" * 64 if mode == LIVE_MODE else None, "requestSha256": "f" * 64,
        "resources": {"headroomBytes": 2 * 1024 ** 3, "requiredInodes": 65536, "tmpfsBytes": 1024 ** 3},
        "qualificationHostAttestationSha256": HOST_ATTESTATION_SHA,
        "system": SYSTEM, "toplevel": TOPLEVEL, "toplevelAttribute": TOPLEVEL_ATTRIBUTE,
        "trustedKeyName": SIGNER, "trustedPublicKey": PUBLIC_KEY_VALUE,
    }


def request(mode=LIVE_MODE):
    return {
        "bootstrapStorePath": BOOTSTRAP, "candidateToplevel": TOPLEVEL, "commit": "c" * 40,
        "composeArtifactSha256": COMPOSE_ARTIFACT_SHA256, "flakeLockSha256": "d" * 64,
        "format": EXPORT_REQUEST_FORMAT, "helperSha256": HELPER_SHA, "installerAttribute": INSTALL_ATTRIBUTE, "installerPath": INSTALLER,
        "mode": mode, "nixVersion": NIX_VERSION, "qualificationEvidenceSha256": "e" * 64 if mode == LIVE_MODE else None,
        "qualificationHostAttestationSha256": HOST_ATTESTATION_SHA,
        "system": SYSTEM, "toplevelAttribute": TOPLEVEL_ATTRIBUTE, "trustedPublicKey": PUBLIC_KEY_VALUE,
    }


def qualification_request():
    return {"confirmation": QUALIFICATION_CONFIRMATION, "disposableProductUuid": PRODUCT_UUID_VALUE, "disposableVmId": 9900, "format": QUALIFICATION_REQUEST_FORMAT, "hostAttestationSha256": HOST_ATTESTATION_SHA, "mode": QUALIFICATION_MODE}


def host_attestation():
    return {"bios": "seabios", "candidateSerial": "QUAL-NIXOS-128G", "candidateSizeBytes": 137438953472, "collectedAt": "2026-08-15T11:00:00Z", "commit": "c" * 40, "format": HOST_ATTESTATION_FORMAT, "machine": "q35", "productUuid": PRODUCT_UUID_VALUE, "pveConfigSha256": "8" * 64, "result": "passed", "vmId": 9900}


def qualification():
    return {
        "architecture": SYSTEM, "bootstrapImportPassed": True, "bootstrapSha256": SHA, "cleanupPassed": True,
        "closureVerificationPassed": True, "commit": "c" * 40, "disposableProductUuidSha256": "3" * 64,
        "disposableVmId": 9900, "exportSha256": "b" * 64, "exporterSha256": "1" * 64,
        "format": QUALIFICATION_FORMAT, "helperSha256": HELPER_SHA, "hostAttestationSha256": HOST_ATTESTATION_SHA,
        "installerPath": INSTALLER, "manifestSha256": "4" * 64, "nixVersion": NIX_VERSION,
        "observedAt": "2026-08-15T12:00:00Z", "qualificationRequestSha256": "5" * 64,
        "result": "passed", "runnerSha256": "2" * 64, "toplevel": TOPLEVEL,
        "trustedPublicKeySha256": sha256_bytes(PUBLIC_KEY_VALUE.encode()),
    }


class EphemeralContractTests(unittest.TestCase):
    def test_distinct_qualification_and_live_modes_break_the_prior_evidence_cycle(self):
        validate_export_request(request(QUALIFICATION_MODE))
        validate_export_request(request(LIVE_MODE))
        validate_manifest(manifest(QUALIFICATION_MODE))
        validate_manifest(manifest(LIVE_MODE))
        with self.assertRaises(ValueError):
            validate_export_request({**request(QUALIFICATION_MODE), "qualificationEvidenceSha256": "e" * 64})
        with self.assertRaises(ValueError):
            validate_export_request({**request(LIVE_MODE), "qualificationEvidenceSha256": None})
        with self.assertRaises(ValueError):
            validate_export_request({**request(LIVE_MODE), "mode": "install"})
        with self.assertRaises(ValueError):
            validate_export_request({**request(LIVE_MODE), "helperSha256": "bad"})
        with self.assertRaises(ValueError):
            validate_manifest({**manifest(LIVE_MODE), "helperSha256": "bad"})

    def test_exact_bootstrap_root_wins_when_multiple_requisites_expose_executables(self):
        underlying = STORE[:-1] + "3-nix-unwrapped"
        bootstrap_paths = sorted([BOOTSTRAP, underlying])
        model = manifest()
        model["bootstrapPaths"] = bootstrap_paths
        model["closure"].append(entry(underlying))
        model["closure"] = sorted(model["closure"], key=lambda item: item["path"])
        model["closureBytes"] += 10
        validate_manifest(model)
        nix, nix_store = select_bootstrap_executables(BOOTSTRAP, bootstrap_paths)
        self.assertEqual(nix, BOOTSTRAP + "/bin/nix")
        self.assertEqual(nix_store, BOOTSTRAP + "/bin/nix-store")
        self.assertNotEqual(nix, underlying + "/bin/nix")
        with self.assertRaises(ValueError):
            select_bootstrap_executables(STORE[:-1] + "4-unbound", bootstrap_paths)
        runner = RUNNER_PATH.read_text()
        self.assertNotIn("nix_store_candidates", runner)
        self.assertNotIn("nix_candidates", runner)

    def test_qualification_requires_disposable_vmid_product_identity_and_confirmation(self):
        validate_qualification_request(qualification_request())
        validate_host_attestation(host_attestation())
        validate_host_attested_qualification(qualification_request(), host_attestation(), PRODUCT_UUID_VALUE, HOST_ATTESTATION_SHA, HOST_ATTESTATION_SHA, manifest(QUALIFICATION_MODE))
        with self.assertRaises(ValueError):
            validate_host_attested_qualification(qualification_request(), host_attestation(), PRODUCT_UUID_VALUE, HOST_ATTESTATION_SHA, "9" * 64, manifest(QUALIFICATION_MODE))
        with self.assertRaises(ValueError):
            validate_host_attested_qualification(qualification_request(), {**host_attestation(), "vmId": 100}, PRODUCT_UUID_VALUE, HOST_ATTESTATION_SHA, HOST_ATTESTATION_SHA, manifest(QUALIFICATION_MODE))
        for mutation in ({"disposableVmId": 100}, {"disposableProductUuid": "bad"}, {"confirmation": "yes"}, {"mode": LIVE_MODE}):
            with self.assertRaises(ValueError):
                validate_qualification_request({**qualification_request(), **mutation})
        validate_qualification(qualification())
        generated = build_qualification_evidence(
            manifest=manifest(QUALIFICATION_MODE), inspection_passed=True, cleanup_passed=True,
            bootstrap_sha256=SHA, export_sha256="b" * 64, exporter_sha256="1" * 64,
            helper_sha256=HELPER_SHA, runner_sha256="2" * 64, trusted_public_key=PUBLIC_KEY_VALUE, product_uuid=PRODUCT_UUID_VALUE,
            qualification_request_sha256="5" * 64, host_attestation_sha256=HOST_ATTESTATION_SHA,
            observed_at="2026-08-15T12:00:00Z", manifest_sha256="4" * 64,
        )
        validate_qualification(generated)
        for inspection_passed, cleanup_passed in ((False, True), (True, False), (False, False)):
            with self.assertRaises(ValueError):
                build_qualification_evidence(
                    manifest=manifest(QUALIFICATION_MODE), inspection_passed=inspection_passed, cleanup_passed=cleanup_passed,
                    bootstrap_sha256=SHA, export_sha256="b" * 64, exporter_sha256="1" * 64,
                    helper_sha256=HELPER_SHA, runner_sha256="2" * 64, trusted_public_key=PUBLIC_KEY_VALUE, product_uuid=PRODUCT_UUID_VALUE,
                    qualification_request_sha256="5" * 64, host_attestation_sha256=HOST_ATTESTATION_SHA,
                    observed_at="2026-08-15T12:00:00Z", manifest_sha256="4" * 64,
                )
        validate_live_qualification(qualification(), manifest(), "1" * 64, "2" * 64, PUBLIC_KEY_VALUE)
        for key, value in (("bootstrapSha256", "7" * 64), ("commit", "8" * 40), ("exporterSha256", "9" * 64), ("helperSha256", "0" * 64), ("runnerSha256", "a" * 64), ("trustedPublicKeySha256", "b" * 64)):
            with self.assertRaises(ValueError):
                validate_live_qualification({**qualification(), key: value}, manifest(), "1" * 64, "2" * 64, PUBLIC_KEY_VALUE)
        for mutation in ({"result": "failed"}, {"architecture": "aarch64-linux"}, {"runnerSha256": "bad"}, {"bootstrapImportPassed": False}, {"cleanupPassed": False}, {"extra": True}):
            with self.assertRaises(ValueError):
                validate_qualification({**qualification(), **mutation})

    def test_inspection_request_rejects_install(self):
        inspection = {"approvedSerial": "QUAL-NIXOS-128G", "device": "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2", "format": "home-lab-vm-100-candidate-install-v1", "mode": "inspect", "observedSizeBytes": 137438953472}
        validate_inspection_request(inspection)
        with self.assertRaises(ValueError):
            validate_inspection_request({**inspection, "mode": "install"})

    def test_manifest_rejects_wrong_signatures_hashes_extra_and_missing_closure(self):
        validate_manifest(manifest())
        hostile = []
        unsigned = manifest(); unsigned["closure"][0]["signatures"] = []; hostile.append(unsigned)
        untrusted = manifest(); untrusted["closure"][0]["signatures"] = ["other:sig"]; hostile.append(untrusted)
        bad_hash = manifest(); bad_hash["artifacts"]["export"]["sha256"] = "bad"; hostile.append(bad_hash)
        missing = manifest(); missing["closure"] = missing["closure"][:-1]; missing["closureBytes"] = 20; hostile.append(missing)
        extra_ref = manifest(); extra_ref["closure"][0]["references"] = [STORE[:-1] + "3-extra"]; hostile.append(extra_ref)
        duplicate = manifest(); duplicate["closure"].append(copy.deepcopy(duplicate["closure"][0])); duplicate["closureBytes"] += 10; hostile.append(duplicate)
        for value in hostile:
            with self.assertRaises(ValueError):
                validate_manifest(value)

    def make_tar(self, members):
        temporary = tempfile.NamedTemporaryFile(delete=False)
        temporary.close()
        path = Path(temporary.name)
        with tarfile.open(path, "w") as archive:
            for member in members:
                archive.addfile(member, io.BytesIO(b"x") if member.isfile() else None)
        path.chmod(0o600)
        self.addCleanup(path.unlink)
        return path

    def test_tar_validation_rejects_truncation_traversal_absolute_extra_symlink_and_hardlink(self):
        valid = tarfile.TarInfo(BOOTSTRAP.lstrip("/") + "/bin/nix-store"); valid.size = 1
        self.assertEqual(validate_tar(self.make_tar([valid]), {BOOTSTRAP}), 1)
        hostile = []
        for name in ("../../etc/shadow", "/etc/shadow", (STORE[:-1] + "9-extra/file").lstrip("/")):
            item = tarfile.TarInfo(name); item.size = 1; hostile.append(self.make_tar([item]))
        symlink = tarfile.TarInfo(BOOTSTRAP.lstrip("/") + "/escape"); symlink.type = tarfile.SYMTYPE; symlink.linkname = "../../../../etc"; hostile.append(self.make_tar([symlink]))
        hardlink = tarfile.TarInfo(BOOTSTRAP.lstrip("/") + "/hard"); hardlink.type = tarfile.LNKTYPE; hardlink.linkname = BOOTSTRAP.lstrip("/") + "/bin/nix-store"; hostile.append(self.make_tar([hardlink]))
        truncated = self.make_tar([valid]); truncated.write_bytes(truncated.read_bytes()[:200]); hostile.append(truncated)
        for path in hostile:
            with self.assertRaises((ValueError, tarfile.TarError, EOFError)):
                validate_tar(path, {BOOTSTRAP})

    def test_descriptor_copy_consumes_pinned_bytes_after_leaf_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.bin"
            source.write_bytes(b"trusted bytes"); source.chmod(0o600)
            descriptor = open_protected(source, "fixture")
            expected = descriptor_metrics(descriptor, "fixture")
            replacement = root / "replacement.bin"
            replacement.write_bytes(b"hostile replacement"); replacement.chmod(0o600)
            os.replace(replacement, source)
            transport = root / "transport"; transport.mkdir(mode=0o700)
            copied = RUNNER.copy_descriptor(descriptor, transport, "copy.bin", expected)
            try:
                os.lseek(copied, 0, os.SEEK_SET)
                self.assertEqual(os.read(copied, 1024), b"trusted bytes")
                self.assertEqual(descriptor_metrics(copied, "copy"), expected)
            finally:
                os.close(copied); os.close(descriptor)

    def test_protected_input_rejects_symlink_parent_symlink_mode_and_extra_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "input.json"
            path.write_bytes(canonical_bytes(request()) + b"\n"); path.chmod(0o600)
            load_canonical(path, "fixture")
            link = root / "link.json"; link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                load_canonical(link, "fixture")
            linked_parent = root / "linked-parent"; linked_parent.symlink_to(root)
            with self.assertRaises((ValueError, OSError)):
                load_canonical(linked_parent / "input.json", "fixture")
            path.chmod(0o640)
            with self.assertRaises(ValueError):
                load_canonical(path, "fixture")
            path.chmod(0o600)
            hard = root / "hard.json"; os.link(path, hard)
            with self.assertRaises(ValueError):
                load_canonical(path, "fixture")

    def test_resource_import_disk_preexisting_and_cleanup_hostile_fixtures(self):
        value = validate_manifest(manifest())
        validate_resources(value, value["resources"]["tmpfsBytes"] + value["resources"]["headroomBytes"], value["resources"]["requiredInodes"])
        with self.assertRaises(ValueError): validate_resources(value, value["resources"]["tmpfsBytes"], value["resources"]["requiredInodes"])
        with self.assertRaises(ValueError): validate_resources(value, 10 ** 12, value["resources"]["requiredInodes"] - 1)
        with patch.object(RUNNER.os, "statvfs", return_value=SimpleNamespace(f_favail=value["resources"]["requiredInodes"])):
            RUNNER.require_tmpfs_inodes(Path("/nix"), value["resources"]["requiredInodes"])
        with patch.object(RUNNER.os, "statvfs", return_value=SimpleNamespace(f_favail=value["resources"]["requiredInodes"] - 1)):
            with self.assertRaises(ValueError):
                RUNNER.require_tmpfs_inodes(Path("/nix"), value["resources"]["requiredInodes"])
        expected = {BOOTSTRAP, INSTALLER, TOPLEVEL}
        validate_import_observation(expected, expected, expected, True)
        for recursive, physical, verified in ((expected - {TOPLEVEL}, expected, True), (expected | {STORE[:-1] + "3-extra"}, expected, True), (expected, expected - {INSTALLER}, True), (expected, expected, False)):
            with self.assertRaises(ValueError): validate_import_observation(expected, recursive, physical, verified)
        disk = {"byId": "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2", "children": [], "formatted": False, "holders": [], "mounted": False, "openers": [], "resolved": "/dev/sdc", "serial": "QUAL-NIXOS-128G", "sizeBytes": 137438953472, "type": "disk"}
        validate_disk_snapshot(disk, "/dev/sdb", {"/dev/sda"})
        for mutation in ({"resolved": "/dev/sdb"}, {"mounted": True}, {"formatted": True}, {"holders": ["dm-0"]}, {"openers": ["123"]}, {"children": [{}]}, {"sizeBytes": 1}):
            with self.assertRaises(ValueError): validate_disk_snapshot({**disk, **mutation}, "/dev/sdb", {"/dev/sda"})
        with tempfile.TemporaryDirectory() as directory:
            nix = Path(directory) / "nix"
            require_absent_nix(nix); nix.mkdir()
            with self.assertRaises(ValueError): require_absent_nix(nix)
        cleanup = {"bootIdStable": True, "childProcessGroupAbsent": True, "format": CLEANUP_EVIDENCE_FORMAT, "nixAbsent": True, "result": "passed", "temporaryPathsAbsent": True, "tmpfsUnmounted": True}
        validate_cleanup(cleanup)
        for key in ("bootIdStable", "childProcessGroupAbsent", "nixAbsent", "temporaryPathsAbsent", "tmpfsUnmounted"):
            changed = {**cleanup, key: False, "result": "failed"}; validate_cleanup(changed)
            with self.assertRaises(ValueError): validate_cleanup({**changed, "result": "passed"})

    def test_nix_environment_is_tmpfs_only_and_disables_host_configuration_plugins_and_substitution(self):
        runtime = Path("/nix/.runtime")
        environment = RUNNER.nix_environment(runtime, PUBLIC_KEY_VALUE)
        self.assertEqual(environment["HOME"], "/nix/.runtime/home")
        self.assertEqual(environment["NIX_USER_CONF_FILES"], "/nix/.runtime/config/nix/empty.conf")
        self.assertEqual(environment["XDG_CONFIG_HOME"], "/nix/.runtime/config")
        self.assertEqual(environment["NIX_PATH"], "")
        for setting in ("plugin-files =\n", "substituters =\n", "builders =\n", "require-sigs = true\n", f"trusted-public-keys = {PUBLIC_KEY_VALUE}\n"):
            self.assertIn(setting, environment["NIX_CONFIG"])
        self.assertNotIn("/root", json.dumps(environment, sort_keys=True))
        self.assertNotIn("/etc/nix", json.dumps(environment, sort_keys=True))
        original = RUNNER.PERSISTENT_NIX_PATHS
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory).resolve()
            RUNNER.PERSISTENT_NIX_PATHS = (existing,)
            with self.assertRaises(ValueError):
                RUNNER.reject_persistent_nix_configuration()
            RUNNER.PERSISTENT_NIX_PATHS = (existing / "absent",)
            RUNNER.reject_persistent_nix_configuration()
        RUNNER.PERSISTENT_NIX_PATHS = original

    def test_mount_success_with_diagnostics_remains_marked_mounted_for_cleanup(self):
        diagnostic = subprocess.CompletedProcess(["mount"], 0, stdout=b"", stderr=b"warning")
        with self.assertRaises(RUNNER.MountObservationError) as raised:
            RUNNER.validate_mount_result(diagnostic)
        self.assertTrue(raised.exception.mounted)
        failed = subprocess.CompletedProcess(["mount"], 1, stdout=b"", stderr=b"failed")
        with patch.object(RUNNER, "tmpfs_mounted", return_value=False), self.assertRaises(RUNNER.MountObservationError) as raised:
            RUNNER.validate_mount_result(failed)
        self.assertFalse(raised.exception.mounted)
        with patch.object(RUNNER, "tmpfs_mounted", return_value=True), self.assertRaises(RUNNER.MountObservationError) as raised:
            RUNNER.validate_mount_result(failed)
        self.assertTrue(raised.exception.mounted)
        with patch.object(RUNNER, "tmpfs_mounted", side_effect=ValueError("ambiguous")), self.assertRaises(RUNNER.MountObservationError) as raised:
            RUNNER.validate_mount_result(failed)
        self.assertTrue(raised.exception.mounted)
        clean = subprocess.CompletedProcess(["mount"], 0, stdout=b"", stderr=b"")
        self.assertTrue(RUNNER.validate_mount_result(clean))

    def test_output_root_is_pinned_empty_and_rejects_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = parent / "output"; root.mkdir(mode=0o700)
            real_fstat = RUNNER.os.fstat
            def root_metadata(descriptor):
                value = real_fstat(descriptor)
                return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino, st_mode=value.st_mode, st_uid=0, st_gid=0, st_nlink=value.st_nlink)
            with patch.object(RUNNER.os, "fstat", side_effect=root_metadata):
                descriptor, identity = RUNNER.open_private_output(root)
                try:
                    RUNNER.verify_private_output(root, descriptor, identity, set())
                    RUNNER.write_evidence(descriptor, "inspection-evidence.json", {"fixture": True})
                    RUNNER.verify_private_output(root, descriptor, identity, {"inspection-evidence.json"})
                    moved = parent / "moved"; root.rename(moved); root.mkdir(mode=0o700)
                    with self.assertRaises(ValueError):
                        RUNNER.verify_private_output(root, descriptor, identity, {"inspection-evidence.json"})
                finally:
                    os.close(descriptor)

    def test_guard_and_runner_use_stable_no_follow_reads_and_exact_fuser_no_opener(self):
        guard = (ROOT / "nix/scripts/vm-100-candidate-install-guard.py").read_text()
        runner = RUNNER_PATH.read_text()
        for control in ("os.O_NOFOLLOW", "os.fstat(descriptor)", "st_mtime_ns", "st_ctime_ns"):
            self.assertIn(control, guard)
        self.assertNotIn("path.read_bytes()", guard)
        self.assertNotIn("path.lstat()", guard)
        self.assertIn('opener.stderr != b""', guard)
        self.assertIn('fuser.stderr != b""', runner)
        self.assertIn("/proc/self/fd/", runner)
        self.assertIn("pass_fds=(bootstrap_copy,)", runner)
        self.assertIn("args.expected_trusted_public_key", runner)
        self.assertIn("process_group_absent", runner)
        self.assertIn("tmpfs_absent", runner)
        self.assertIn("reject_persistent_nix_configuration", runner)
        self.assertIn("NIX_USER_CONF_FILES", runner)
        self.assertIn('"plugin-files ="', runner)
        self.assertIn("qualification host attestation", runner)
        self.assertIn('os.listdir(descriptor) != []', runner)
        self.assertLess(runner.index('write_evidence(output_descriptor, "inspection-evidence.json"'), runner.index('write_evidence(output_descriptor, "cleanup-evidence.json"'))
        self.assertLess(runner.index('write_evidence(output_descriptor, "cleanup-evidence.json"'), runner.index('write_evidence(output_descriptor, "qualification-evidence.json"'))

    def test_exact_captured_helper_bytes_execute_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "helper.py"
            path.write_bytes(b"VALUE = 'trusted'\n")
            captured = path.read_bytes()
            replacement = path.with_name("replacement.py")
            replacement.write_bytes(b"VALUE = 'hostile'\n")
            os.replace(replacement, path)
            module_name = "vm100_exact_helper_fixture"
            module = RUNNER._load_helper_from_bytes(module_name, path, captured)
            try:
                self.assertEqual(module.VALUE, "trusted")
                self.assertEqual(path.read_text(), "VALUE = 'hostile'\n")
            finally:
                sys.modules.pop(module_name, None)

    def test_helper_hash_preflight_runs_before_helper_import_and_rejects_mismatch(self):
        exporter_path = ROOT / "scripts/controller/export-vm-100-ephemeral-inspection.py"
        for path in (RUNNER_PATH, exporter_path):
            source = path.read_text()
            self.assertLess(source.index("_EARLY_HELPER_SHA256"), source.index("from vm_100_ephemeral import"))
            self.assertLess(source.index('_load_helper_from_bytes("vm_100_ephemeral"'), source.index("from vm_100_ephemeral import"))
            self.assertEqual(source.count("HELPER_SOURCE.read_bytes()"), 1)
            self.assertIn('exec(compile(source_bytes, str(source_path), "exec"), module.__dict__)', source)
            result = subprocess.run([sys.executable, str(path), "--expected-helper-sha256", "0" * 64], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("helper preflight failed", result.stderr)
            help_result = subprocess.run([sys.executable, str(path), "--help"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(help_result.returncode, 0)
            self.assertIn("--expected-helper-sha256", help_result.stdout)

    def test_schemas_are_strict_and_transport_has_no_destructive_command_paths(self):
        schemas = sorted((ROOT / "infrastructure/vm-100").glob("ephemeral-*.schema.json"))
        self.assertEqual(len(schemas), 8)
        for schema in schemas:
            value = json.loads(schema.read_text())
            self.assertFalse(value["additionalProperties"])
        runner = RUNNER_PATH.read_text()
        exporter = (ROOT / "scripts/controller/export-vm-100-ephemeral-inspection.py").read_text()
        for forbidden in ("docker ", "/usr/bin/docker", "pvesh", "/usr/bin/ssh", "diskoScript", "nixos-install"):
            self.assertNotIn(forbidden, runner)
            self.assertNotIn(forbidden, exporter)
        for control in ("--no-substitute", "--offline", "--sigs-needed", "validate_inspection_request", "observe_disk", QUALIFICATION_CONFIRMATION):
            self.assertIn(control, runner + exporter + (ROOT / "scripts/controller/vm_100_ephemeral.py").read_text())
        self.assertIn('[NIX, "store", "sign", "--quiet", "--recursive"', exporter)
        self.assertIn("os.fchmod(output.fileno(), 0o600)", exporter)
        self.assertNotIn("output.chmod(", exporter)
        self.assertIn('command("fuser", [resolved], check=False)', runner)
        self.assertNotIn('command("fuser", ["--", resolved]', runner)
        self.assertIn('["--bytes", "--json", "--nodeps", "--output", "PATH,PKNAME", current]', runner)
        self.assertNotIn("VM100_CANDIDATE_INSTALL_CONFIRMED", exporter)
        self.assertNotIn("--query\", \"--signatures", exporter)
        self.assertNotIn("--require-signature", runner)
        flake = (ROOT / "nix/flake.nix").read_text()
        for control in ("vm-100-ephemeral-nix-cli", 'nix (Nix) 2.34.8', 'pkgs.gnugrep pkgs.gzip', '${bootstrapNix.man}/share/man/man1/nix-store.1.gz', 'path-info --help', 'store verify --help', 'grep -F -- "--sigs"'):
            self.assertIn(control, flake)


if __name__ == "__main__":
    unittest.main()
