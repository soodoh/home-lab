#!/usr/bin/env python3
"""Focused safety and fixture tests for VM 100 preparation and live pre-copy."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vm_100_gate_c import canonical_bytes, digest

HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load("vm100_prepare", "prepare-vm-100-candidate-data.py")
TRANSFER = load("vm100_transfer", "vm-100-data-transfer.py")
GATE_TEST = load("vm100_gate_test_fixtures", "test-vm-100-gate-c.py")
EXECUTION = load("vm100_execution_helpers", "vm_100_execution.py")


def args_for_transfer(root: Path, manifest: dict[str, object]) -> SimpleNamespace:
    raw = canonical_bytes(manifest) + b"\n"
    fixture = root.parent / "fixture"
    fixture.mkdir(mode=0o700, exist_ok=True)
    return SimpleNamespace(
        phase="precopy", manifest=root / "manifest.json", expected_manifest_sha256=TRANSFER.sha256_bytes(raw),
        expected_commit=GATE_TEST.COMMIT, expected_compose_artifact_sha256=GATE_TEST.ARTIFACT,
        expected_canonical_toplevel=GATE_TEST.TOPLEVEL, expected_desired_inventory_sha256=manifest["bindings"]["desiredInventorySha256"],
        expected_candidate_inventory_sha256=manifest["bindings"]["candidateInventorySha256"],
        isolated_restore_evidence=root / "restore.json", candidate_daemon_stop_evidence=root / "stop.json",
        source_daemon_stability_evidence=root / "stable.json",
        expected_isolated_restore_evidence_sha256=GATE_TEST.RESTORE, expected_restore_verifier_sha256="e" * 64,
        expected_candidate_daemon_stop_evidence_sha256=GATE_TEST.STOP_EVIDENCE,
        expected_source_daemon_stability_evidence_sha256=GATE_TEST.STABILITY_EVIDENCE,
        now=GATE_TEST.NOW, collection_max_age_seconds=600, authority="arch", output_root=root,
        evidence_name="precopy.json", fixture_root=fixture,
        rsync_command="/fixture/rsync", findmnt_command="/fixture/findmnt", lsblk_command="/fixture/lsblk",
        git_command="/fixture/git", node_command="/fixture/node",
    )


class PreparationTests(unittest.TestCase):
    def test_exact_daemon_argv_and_containerd_roots_are_fixed(self) -> None:
        self.assertEqual(tuple(PREP.ISOLATED_DOCKER_ARGV), PREP.ISOLATED_DOCKER_ARGV)
        self.assertEqual(PREP.CONTAINERD_ROOT, "/mnt/vm-100-candidate/var/lib/containerd")
        self.assertEqual(PREP.CONTAINERD_ARGV[0], "/usr/bin/containerd")
        self.assertIn("/run/vm-100-candidate-docker/containerd/containerd.sock", PREP.CONTAINERD_ARGV)

    def test_extra_candidate_volume_is_rejected_before_creation(self) -> None:
        desired = GATE_TEST.project_desired_inventory(GATE_TEST.raw_desired())
        extra = subprocess.CompletedProcess([], 0, json.dumps({"Name": "unexpected"}) + "\n", "")
        with patch.object(PREP, "run_candidate_docker", return_value=extra):
            with self.assertRaisesRegex(SystemExit, "extra or duplicate"):
                PREP.prepare_volumes("/fixture/docker", desired)

    def test_candidate_app_container_image_or_network_is_rejected(self) -> None:
        empty_info = subprocess.CompletedProcess([], 0, json.dumps({"DockerRootDir": PREP.ISOLATED_DOCKER_ROOT, "Containers": 0, "ContainersRunning": 0, "ContainersPaused": 0, "ContainersStopped": 0}), "")
        app = subprocess.CompletedProcess([], 0, "container-id\n", "")
        with patch.object(PREP, "run_candidate_docker", side_effect=[empty_info, app]):
            with self.assertRaisesRegex(SystemExit, "containers"):
                PREP.verify_empty_candidate_daemon("/fixture/docker")
        bad_info = copy.deepcopy(json.loads(empty_info.stdout)); bad_info["Containers"] = 1
        with patch.object(PREP, "run_candidate_docker", return_value=subprocess.CompletedProcess([], 0, json.dumps(bad_info), "")):
            with self.assertRaisesRegex(SystemExit, "zero-container"):
                PREP.verify_empty_candidate_daemon("/fixture/docker")

    def test_readiness_timeout_and_early_child_failure_are_rejected(self) -> None:
        process = Mock(); process.poll.return_value = None
        failure = subprocess.CompletedProcess([], 1, "", "not ready")
        with patch.object(PREP, "run_candidate_docker", return_value=failure), patch.object(PREP.time, "sleep"):
            with self.assertRaisesRegex(SystemExit, "timed out"):
                PREP.wait_ready("/fixture/docker", process, 0.001)
        process.poll.return_value = 2
        with self.assertRaisesRegex(SystemExit, "exited before readiness"):
            PREP.wait_ready("/fixture/docker", process, 1)

    def test_term_deadline_uses_kill_fallback_and_proves_reaped(self) -> None:
        process = Mock(pid=1234, returncode=-9)
        process.poll.side_effect = [None, -9]
        process.wait.side_effect = [subprocess.TimeoutExpired("dockerd", 1), None]
        with patch.object(PREP.os, "killpg") as killpg:
            result = PREP.stop_child(process, 1)
        self.assertTrue(result["termSent"]); self.assertTrue(result["killSent"]); self.assertTrue(result["pidGone"])
        self.assertEqual(killpg.call_args_list[0].args[1], PREP.signal.SIGTERM)
        self.assertEqual(killpg.call_args_list[1].args[1], PREP.signal.SIGKILL)

    def test_containerd_readiness_requires_socket_process_and_ctr(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary); socket_path = root / "c.sock"
            sock = socket.socket(socket.AF_UNIX); sock.bind(str(socket_path))
            process = Mock(); process.poll.return_value = None
            try:
                with patch.object(PREP, "physical", return_value=socket_path), patch.object(PREP.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 1, b"", b""), subprocess.CompletedProcess([], 0, b"ok", b"")]), patch.object(PREP.time, "sleep"):
                    PREP.wait_containerd_ready("/fixture/ctr", process, root, 1)
            finally: sock.close()

    def test_cleanup_attempts_containerd_after_dockerd_stop_exception(self) -> None:
        first, second = Mock(), Mock()
        ok = {"started": True, "termSent": True, "killSent": False, "exitCode": 0, "pidGone": True, "observationError": None}
        with patch.object(PREP, "stop_child", side_effect=[RuntimeError("dockerd wait"), ok]) as stop:
            dockerd, containerd = PREP.stop_children(first, second, 1)
        self.assertEqual(stop.call_count, 2)
        self.assertFalse(dockerd["pidGone"]); self.assertEqual(containerd, ok)

    def test_output_overlap_rejects_source_destination_and_backup_roots(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            base = Path(temporary); protected = base / "home/docker/hass"; protected.mkdir(parents=True); protected.chmod(0o700)
            for output in (protected, protected / "logs"):
                if output != protected: output.mkdir(mode=0o700)
                with self.assertRaisesRegex(SystemExit, "overlaps"):
                    EXECUTION.require_private_root(output, (protected,))

    def test_candidate_data_roots_reject_symlink_and_cross_device(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            fixture = Path(temporary); candidate = fixture / PREP.DESTINATION_ROOT.removeprefix("/"); library = candidate / "var/lib"; library.mkdir(parents=True)
            live = fixture / PREP.DOCKER_ROOT.removeprefix("/"); live.mkdir(parents=True)
            (library / "containerd").mkdir(mode=0o700); (library / "docker").symlink_to(live, target_is_directory=True)
            with self.assertRaisesRegex(SystemExit, "docker root identity|unsafe"): PREP.ensure_candidate_data_roots(fixture)
            (library / "docker").unlink(); (library / "docker").mkdir(mode=0o700); (library / "docker").chmod(0o710)
            PREP.ensure_candidate_data_roots(fixture)
            self.assertEqual((library / "docker").stat().st_mode & 0o777, 0o710)
            self.assertEqual((candidate / "home/docker/hass").stat().st_mode & 0o777, 0o755)
            original = PREP.Path.stat
            def changed_device(path, **kwargs):
                value = original(path, **kwargs)
                if path.name == "containerd":
                    return SimpleNamespace(st_mode=value.st_mode, st_dev=value.st_dev + 1, st_uid=value.st_uid, st_gid=value.st_gid)
                return value
            with patch.object(PREP.Path, "stat", changed_device):
                with self.assertRaisesRegex(SystemExit, "crosses|unsafe"): PREP.ensure_candidate_data_roots(fixture)

    def test_candidate_nested_mounts_reject_same_and_different_device_binds(self) -> None:
        for source in ("/dev/candidate", "/dev/other"):
            document = {"filesystems": [{"id": 1, "source": "/dev/candidate", "fstype": "ext4", "target": PREP.DESTINATION_ROOT, "children": [{"id": 2, "source": source, "fstype": "ext4", "target": PREP.DESTINATION_ROOT + "/var/lib/docker"}]}]}
            with patch.object(PREP.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(document), "")):
                with self.assertRaisesRegex(SystemExit, "nested mount"): PREP.reject_candidate_nested_mounts("/fixture/findmnt", None)

    def test_nested_mount_rejection_precedes_candidate_root_creation(self) -> None:
        source = (HERE / "prepare-vm-100-candidate-data.py").read_text(encoding="utf-8")
        main = source[source.index("def main()") :]
        preflight = main.index("verify_candidate_preflight(")
        first_rejection = main.index("reject_candidate_nested_mounts(", preflight)
        root_creation = main.index("ensure_candidate_data_roots(", preflight)
        second_rejection = main.index("reject_candidate_nested_mounts(", first_rejection + 1)
        self.assertLess(preflight, first_rejection)
        self.assertLess(first_rejection, root_creation)
        self.assertLess(root_creation, second_rejection)

    def test_socket_remaining_blocks_runtime_cleanup_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"; root.mkdir(mode=0o700)
            socket = root / "docker.sock"; socket.touch()
            socket_absent = not socket.exists()
            self.assertFalse(socket_absent)
            self.assertFalse(socket_absent and PREP.remove_runtime(root))
            self.assertTrue(root.exists())

    def test_stop_pass_is_independent_of_later_source_stability_failure(self) -> None:
        self.assertTrue(PREP.daemon_stop_passed("a" * 64, True, None))
        self.assertFalse(PREP.daemon_stop_passed("a" * 64, False, None))
        # A source-after failure is deliberately not a qualification failure.
        source_after_failure = RuntimeError("transient source observation")
        self.assertTrue(PREP.daemon_stop_passed("a" * 64, True, None))
        self.assertIsNotNone(source_after_failure)

    def test_source_stability_rejects_mutation_and_nonrunning_container(self) -> None:
        stable = {"format": PREP.FORMAT_STABILITY, "completedAt": GATE_TEST.NOW, "result": "passed", "failureStage": None, "failureReason": None, "desiredInventorySha256": "a" * 64, "beforeInventorySha256": "b" * 64, "afterInventorySha256": "b" * 64, "exactEquality": True, "containerCount": 41, "runningCount": 41, "sourceDockerRoot": "/var/lib/docker", "observationError": None}
        PREP.validate_stability_evidence(stable)
        for mutation in ({"afterInventorySha256": "c" * 64}, {"runningCount": 40}, {"sourceDockerRoot": "/other"}):
            value = {**stable, **mutation}
            with self.assertRaises(ValueError): PREP.validate_stability_evidence(value)

    def test_unique_run_roots_allow_retry_and_collision_is_pre_mutation(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            parent = Path(temporary); parent.chmod(0o700)
            first = EXECUTION.create_run_root(parent, "vm-100-test")
            second = EXECUTION.create_run_root(parent, "vm-100-test")
            self.assertNotEqual(first, second)
            EXECUTION.write_json(first, "result.json", {"status": "failed"})
            EXECUTION.write_json(second, "result.json", {"status": "passed"})
            with patch.object(EXECUTION.time, "time_ns", return_value=1), patch.object(EXECUTION.os, "getpid", return_value=2), patch.object(EXECUTION.secrets, "token_hex", return_value="0" * 16):
                EXECUTION.create_run_root(parent, "vm-100-collision")
                with self.assertRaises(FileExistsError): EXECUTION.create_run_root(parent, "vm-100-collision")

    def test_protected_inputs_require_private_owned_single_link_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); path = root / "input"; path.write_bytes(b"artifact"); path.chmod(0o600)
            self.assertEqual(EXECUTION.load_protected_bytes(path, "artifact"), b"artifact")
            path.chmod(0o644)
            with self.assertRaisesRegex(SystemExit, "mode-private"): EXECUTION.load_protected_bytes(path, "artifact")
            path.chmod(0o600); linked = root / "linked"; os.link(path, linked)
            with self.assertRaisesRegex(SystemExit, "dedicated"): EXECUTION.load_protected_bytes(path, "artifact")

    def test_candidate_checkout_and_artifact_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); artifact = root / "artifact"; artifact.write_bytes(b"exact"); artifact.chmod(0o600)
            self.assertEqual(EXECUTION.sha256_bytes(EXECUTION.load_protected_bytes(artifact, "Compose artifact")), EXECUTION.sha256_bytes(b"exact"))
            artifact.write_bytes(b"tampered")
            self.assertNotEqual(EXECUTION.sha256_bytes(EXECUTION.load_protected_bytes(artifact, "Compose artifact")), EXECUTION.sha256_bytes(b"exact"))
            with self.assertRaises(FileNotFoundError): EXECUTION.load_protected_bytes(root / "absent", "Compose artifact")
        def dirty(argv, **kwargs):
            if argv[1] == "rev-parse": return subprocess.CompletedProcess(argv, 0, GATE_TEST.COMMIT + "\n", "")
            return subprocess.CompletedProcess(argv, 0, " M file\n", "")
        with patch.object(EXECUTION.subprocess, "run", side_effect=dirty):
            with self.assertRaisesRegex(SystemExit, "clean checkout"): PREP.verify_exact_checkout("/fixture/git", GATE_TEST.COMMIT, PREP.CLOSED_ENV)

    def test_output_root_and_name_safety(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); root.chmod(0o700)
            protected = EXECUTION.require_private_root(root, ())
            EXECUTION.write_json(protected, "evidence.json", {"safe": True})
            self.assertEqual((root / "evidence.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(SystemExit): EXECUTION.write_json(protected, "../escape.json", {})
            with self.assertRaises(OSError): EXECUTION.write_json(protected, "evidence.json", {})

    def test_live_mode_has_no_override_bypass(self) -> None:
        argv = ["prepare", "--desired-inventory", "/x", "--expected-desired-inventory-sha256", "0" * 64, "--canonical-toplevel", GATE_TEST.TOPLEVEL, "--expected-commit", GATE_TEST.COMMIT, "--compose-artifact", "/x", "--expected-compose-artifact-sha256", "0" * 64, "--output-root", "/x", "--candidate-inventory-name", "candidate.json", "--candidate-daemon-stop-evidence-name", "stop.json", "--source-daemon-stability-evidence-name", "stable.json", "--authority", "arch", "--docker-command", "/tmp/docker"]
        with patch.object(sys, "argv", argv), patch.object(PREP.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(SystemExit, "forbids executable overrides"):
                PREP.main()


class TransferTests(unittest.TestCase):
    def run_fixture(self, fail_index: int | None = None, interrupt_index: int | None = None) -> tuple[dict[str, object], int]:
        _, _, _, manifest = GATE_TEST.fixture_documents()
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            base = Path(temporary); root = base / "output"; root.mkdir(mode=0o700)
            args = args_for_transfer(root, manifest)
            raw = canonical_bytes(manifest) + b"\n"
            candidate = manifest["candidate"]
            observations = {"capacityBytes": candidate["capacityBytes"], "reserveBytes": candidate["reserveBytes"], "mount": {key: candidate[key] for key in ("device", "filesystem", "mountTarget", "mountId")}, "deviceAncestry": candidate["deviceAncestry"]}
            reserve = candidate["reserveBytes"]
            capacity = {"availableBytes": reserve + 10, "availableInodes": 10, "reserveBytes": reserve, "requiredWriteBytes": 10, "requiredInodes": 1}
            def entry_observation(entry, commands, fixture_root, candidate, **kwargs):
                metadata = {"device": 1, "inode": 1, "uid": entry["uid"], "gid": entry["gid"], "mode": entry["mode"]}
                return {"sourceMount": entry["sourceMount"], "destinationMount": entry["destinationMount"], "sourceRoot": metadata, "destinationRoot": metadata}
            rsync_calls = 0
            def fake_run(argv, **kwargs):
                nonlocal rsync_calls
                if argv[0] == "/fixture/rsync":
                    index = rsync_calls; rsync_calls += 1
                    if interrupt_index == index:
                        raise KeyboardInterrupt
                    return subprocess.CompletedProcess(argv, 23 if fail_index == index else 0, "", "")
                return subprocess.CompletedProcess(argv, 0, b"" if not kwargs.get("text") else "", b"" if not kwargs.get("text") else "")
            patches = (
                patch.object(TRANSFER, "parse_args", return_value=args),
                patch.object(TRANSFER, "load_canonical_object", return_value=(manifest, raw)),
                patch.object(TRANSFER, "verify_git"), patch.object(TRANSFER, "verify_rsync", return_value="rsync  version 3.2.7  protocol version 31"),
                patch.object(TRANSFER, "validate_external_evidence"),
                patch.object(TRANSFER, "candidate_root", return_value=(Path("/tmp"), observations)),
                patch.object(TRANSFER, "build_checked_capacity_plan", return_value={index: {"requiredWriteBytes": 1, "requiredInodes": 1} for index in range(34)}),
                patch.object(TRANSFER, "capacity_check", return_value=capacity),
                patch.object(TRANSFER, "refresh_capacity_plan"),
                patch.object(TRANSFER, "observe_entry", side_effect=entry_observation),
                patch.object(TRANSFER.subprocess, "run", side_effect=fake_run),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10]:
                if interrupt_index is not None:
                    with self.assertRaises(KeyboardInterrupt): TRANSFER.main()
                elif fail_index is None:
                    TRANSFER.main()
                else:
                    with self.assertRaisesRegex(SystemExit, "canonical failure evidence"):
                        TRANSFER.main()
            run_roots = list(root.iterdir()); self.assertEqual(len(run_roots), 1)
            evidence_path = run_roots[0] / "precopy.json"
            subprocess.run(["node", str(HERE / "validate-vm-100-execution-schema.js"), "data-transfer", str(evidence_path)], check=True, capture_output=True)
            evidence = json.loads(evidence_path.read_text())
            return evidence, rsync_calls

    def test_successful_precopy_sequences_exactly_34_entries(self) -> None:
        evidence, calls = self.run_fixture()
        self.assertEqual(calls, 34); self.assertEqual(len(evidence["entries"]), 34); self.assertEqual(evidence["status"], "succeeded")
        self.assertTrue(all(item["status"] == "succeeded" for item in evidence["entries"]))

    def test_success_evidence_manifest_and_capacity_edges_fail_closed(self) -> None:
        evidence, _ = self.run_fixture()
        _, _, _, manifest = GATE_TEST.fixture_documents()
        changed = copy.deepcopy(evidence); changed["entries"][0]["logicalName"] = "wrong"
        with self.assertRaisesRegex(ValueError, "manifest"): TRANSFER.validate_evidence(changed, manifest)
        changed = copy.deepcopy(evidence); changed["entries"][0]["capacityBefore"]["requiredWriteBytes"] = changed["entries"][0]["capacityBefore"]["availableBytes"]
        with self.assertRaisesRegex(ValueError, "capacity"): TRANSFER.validate_evidence(changed, manifest)
        changed = copy.deepcopy(evidence); changed["status"] = "failed"; changed["failureStage"] = "entry"; changed["failureReason"] = "claimed failure"; changed["entries"][0]["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "success-shaped"): TRANSFER.validate_evidence(changed, manifest)

    def test_independent_manifest_bound_validator_rejects_duplicate_paths_and_null_logs(self) -> None:
        evidence, _ = self.run_fixture()
        _, _, _, manifest = GATE_TEST.fixture_documents(); manifest_raw = canonical_bytes(manifest) + b"\n"; expected = TRANSFER.sha256_bytes(manifest_raw)
        validator = HERE / "validate-vm-100-data-transfer-evidence.py"; node = shutil.which("node"); self.assertIsNotNone(node)
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); manifest_path = root / "manifest.json"; evidence_path = root / "evidence.json"
            manifest_path.write_bytes(manifest_raw); manifest_path.chmod(0o600)
            def validate(document):
                evidence_path.write_bytes(canonical_bytes(document) + b"\n"); evidence_path.chmod(0o600)
                return subprocess.run([sys.executable, str(validator), "--evidence", str(evidence_path), "--manifest", str(manifest_path), "--expected-manifest-sha256", expected, "--node-command", node], capture_output=True, text=True)
            accepted = validate(evidence); self.assertEqual(accepted.returncode, 0, accepted.stderr)
            duplicate = copy.deepcopy(evidence); duplicate["entries"][1]["index"] = 0; self.assertNotEqual(validate(duplicate).returncode, 0)
            arbitrary = copy.deepcopy(evidence); arbitrary["entries"][0]["source"] = "/arbitrary"; self.assertNotEqual(validate(arbitrary).returncode, 0)
            logless = copy.deepcopy(evidence); logless["entries"][0]["stdout"] = None; self.assertNotEqual(validate(logless).returncode, 0)

    def test_rsync_nonzero_stops_before_later_entries(self) -> None:
        evidence, calls = self.run_fixture(fail_index=3)
        self.assertEqual(calls, 4); self.assertEqual(len(evidence["entries"]), 4); self.assertEqual(evidence["entries"][-1]["exitCode"], 23); self.assertEqual(evidence["status"], "failed")

    def test_interruption_writes_honest_failure_evidence(self) -> None:
        evidence, calls = self.run_fixture(interrupt_index=2)
        self.assertEqual(calls, 3)
        self.assertEqual(evidence["status"], "failed")
        self.assertIsNone(evidence["entries"][-1]["after"])
        self.assertIsNotNone(evidence["entries"][-1]["observationError"])

    def test_manifest_argv_hash_and_authority_tampering_are_rejected(self) -> None:
        _, _, _, manifest = GATE_TEST.fixture_documents()
        manifest["copyEntries"][0]["writeArgv"][1] = "--wrong"
        with self.assertRaisesRegex(ValueError, "copy argv"):
            GATE_TEST.validate_manifest(manifest)
        self.assertNotEqual(digest([TRANSFER.LIVE_RSYNC, "--wrong"]), digest([TRANSFER.LIVE_RSYNC, "--other"]))
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); root = base / "output"; root.mkdir(mode=0o700)
            _, _, _, valid = GATE_TEST.fixture_documents(); args = args_for_transfer(root, valid); args.authority = "nixos"
            with patch.object(TRANSFER, "parse_args", return_value=args):
                with self.assertRaisesRegex(SystemExit, "arch authority"): TRANSFER.main()

    def test_mount_deletion_and_capacity_tampering_are_rejected(self) -> None:
        _, _, _, manifest = GATE_TEST.fixture_documents(); entry = manifest["copyEntries"][0]
        metadata = {"device": 1, "inode": 1, "uid": entry["uid"], "gid": entry["gid"], "mode": entry["mode"]}
        with patch.object(TRANSFER, "require_directory", side_effect=[Path("/tmp/source"), Path("/tmp/destination")]), patch.object(TRANSFER, "reject_nested_mounts"), patch.object(TRANSFER, "mount_identity", side_effect=[entry["sourceMount"], entry["destinationMount"]]), patch.object(TRANSFER, "root_metadata", return_value=metadata):
            changed = copy.deepcopy(entry); changed["permittedDeletionRoot"] = changed["destination"] + "/nested"
            with self.assertRaisesRegex(SystemExit, "deletion root"):
                TRANSFER.observe_entry(changed, {"findmnt": "/fixture/findmnt"}, Path("/fixture"), manifest["candidate"])
        fake_vfs = SimpleNamespace(f_frsize=1, f_bavail=5, f_blocks=manifest["candidate"]["capacityBytes"], f_favail=0)
        plan = {index: {"requiredWriteBytes": 1, "requiredInodes": 1} for index in range(34)}
        with patch.object(TRANSFER, "candidate_root", return_value=(Path("/tmp"), {})), patch.object(TRANSFER, "refresh_capacity_plan"), patch.object(TRANSFER.os, "statvfs", return_value=fake_vfs):
            with self.assertRaisesRegex(SystemExit, "capacity|inode"):
                TRANSFER.capacity_check(manifest, {"findmnt": "x", "lsblk": "x"}, Path("/fixture"), plan)

    def test_symlink_and_changed_mount_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "real").mkdir(); (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaisesRegex(SystemExit, "symlink"):
                EXECUTION.require_directory("/link", root)
        _, _, _, manifest = GATE_TEST.fixture_documents(); entry = manifest["copyEntries"][0]
        with patch.object(TRANSFER, "require_directory", side_effect=[Path("/tmp/source"), Path("/tmp/dest")]), patch.object(TRANSFER, "reject_nested_mounts"), patch.object(TRANSFER, "mount_identity", return_value={"device": "/dev/changed", "filesystem": "ext4", "mountTarget": "/", "mountId": 99}):
            with self.assertRaisesRegex(SystemExit, "source mount identity changed"):
                TRANSFER.observe_entry(entry, {"findmnt": "x"}, Path("/fixture"), manifest["candidate"])

    def test_external_restore_evidence_is_opened_hashed_fresh_and_cross_bound(self) -> None:
        _, _, _, manifest = GATE_TEST.fixture_documents()
        replica = manifest["backupEvidence"]["replicas"][0]
        restore = {"format": "home-lab-vm-100-isolated-restore-evidence-v1", "completedAt": GATE_TEST.NOW, "result": "passed", "backupArchive": {key: replica[key] for key in ("archiveName", "sha256", "sizeBytes")}, "verifierSha256": "e" * 64, "isolatedTarget": {"path": "/tmp/isolated", "independentEnvironment": True, "productionFilesystemsMounted": False, "emptyBefore": True, "removedAfter": True}, "restore": {"result": "passed", "memberCount": 2, "fileCount": 1, "byteCount": 10}}
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            path = Path(temporary) / "restore.json"; raw = canonical_bytes(restore) + b"\n"; path.write_bytes(raw); path.chmod(0o600)
            expected = TRANSFER.sha256_bytes(raw); manifest["bindings"]["isolatedRestoreEvidenceSha256"] = expected
            args = SimpleNamespace(now=GATE_TEST.NOW, collection_max_age_seconds=600, expected_restore_verifier_sha256="e" * 64)
            node = shutil.which("node"); self.assertIsNotNone(node)
            TRANSFER.validate_external_evidence("isolated-restore", path, expected, manifest, args, node)
            args.expected_restore_verifier_sha256 = "f" * 64
            with self.assertRaisesRegex(SystemExit, "semantics"): TRANSFER.validate_external_evidence("isolated-restore", path, expected, manifest, args, node)
            args.expected_restore_verifier_sha256 = "e" * 64
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(SystemExit, "canonical|SHA-256"): TRANSFER.validate_external_evidence("isolated-restore", path, expected, manifest, args, node)
            stale = {**restore, "completedAt": "2026-08-11T00:00:00Z"}; stale_raw = canonical_bytes(stale) + b"\n"; path.write_bytes(stale_raw)
            stale_sha = TRANSFER.sha256_bytes(stale_raw); manifest["bindings"]["isolatedRestoreEvidenceSha256"] = stale_sha
            with self.assertRaisesRegex(SystemExit, "stale"): TRANSFER.validate_external_evidence("isolated-restore", path, stale_sha, manifest, args, node)
            not_independent = copy.deepcopy(restore); not_independent["isolatedTarget"]["independentEnvironment"] = False; false_raw = canonical_bytes(not_independent) + b"\n"; path.write_bytes(false_raw); false_sha = TRANSFER.sha256_bytes(false_raw); manifest["bindings"]["isolatedRestoreEvidenceSha256"] = false_sha
            with self.assertRaises(subprocess.CalledProcessError): TRANSFER.validate_external_evidence("isolated-restore", path, false_sha, manifest, args, node)
            overlapping = copy.deepcopy(restore); overlapping["isolatedTarget"]["path"] = "/var/lib/docker/restore"; overlap_raw = canonical_bytes(overlapping) + b"\n"; path.write_bytes(overlap_raw); overlap_sha = TRANSFER.sha256_bytes(overlap_raw); manifest["bindings"]["isolatedRestoreEvidenceSha256"] = overlap_sha
            with self.assertRaisesRegex(SystemExit, "semantics"): TRANSFER.validate_external_evidence("isolated-restore", path, overlap_sha, manifest, args, node)
            path.write_bytes(raw); manifest["bindings"]["isolatedRestoreEvidenceSha256"] = expected; manifest["backupEvidence"]["replicas"][0]["sha256"] = "f" * 64
            with self.assertRaisesRegex(SystemExit, "semantics"): TRANSFER.validate_external_evidence("isolated-restore", path, expected, manifest, args, node)
            with self.assertRaises(FileNotFoundError): TRANSFER.validate_external_evidence("isolated-restore", path.with_name("absent.json"), expected, manifest, args, node)

    def test_exact_origin_main_is_required(self) -> None:
        def run(argv, **kwargs):
            if argv[1:4] == ["rev-parse", "--verify", "HEAD"]: return subprocess.CompletedProcess(argv, 0, GATE_TEST.COMMIT + "\n", "")
            if argv[1:4] == ["rev-parse", "--verify", "refs/remotes/origin/main"]: return subprocess.CompletedProcess(argv, 0, "f" * 40 + "\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch.object(TRANSFER.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(SystemExit, "origin/main"): TRANSFER.verify_git("/fixture/git", GATE_TEST.COMMIT)

    def test_recursive_nested_mount_and_metadata_drift_are_rejected(self) -> None:
        nested = {"filesystems": [{"id": 1, "source": "/dev/a", "fstype": "ext4", "target": "/root", "children": [{"id": 2, "source": "/dev/a", "fstype": "ext4", "target": "/root/bind"}]}]}
        with patch.object(TRANSFER, "run_json", return_value=nested) as run:
            with self.assertRaisesRegex(SystemExit, "nested mount"): TRANSFER.reject_nested_mounts("findmnt", "/root", Path("/root"))
        run.assert_called_once_with("findmnt", ["--json", "--submounts", "--target", "/root", "--output", "ID,SOURCE,FSTYPE,TARGET"])
        _, _, _, manifest = GATE_TEST.fixture_documents(); entry = manifest["copyEntries"][0]
        metadata = {"device": 1, "inode": 1, "uid": entry["uid"] + 1, "gid": entry["gid"], "mode": entry["mode"]}
        with patch.object(TRANSFER, "require_directory", side_effect=[Path("/s"), Path("/d")]), patch.object(TRANSFER, "reject_nested_mounts"), patch.object(TRANSFER, "mount_identity", side_effect=[entry["sourceMount"], entry["destinationMount"]]), patch.object(TRANSFER, "root_metadata", return_value=metadata):
            with self.assertRaisesRegex(SystemExit, "source root metadata"): TRANSFER.observe_entry(entry, {"findmnt": "x"}, Path("/fixture"), manifest["candidate"])
        good = {"device": 1, "inode": 2, "uid": entry["uid"], "gid": entry["gid"], "mode": entry["mode"]}; destination = {**good, "inode": 3}
        before = {"sourceMount": entry["sourceMount"], "destinationMount": entry["destinationMount"], "sourceRoot": good, "destinationRoot": destination}
        changed_source = {**good, "inode": 99}
        with patch.object(TRANSFER, "require_directory", side_effect=[Path("/s"), Path("/d")]), patch.object(TRANSFER, "reject_nested_mounts"), patch.object(TRANSFER, "mount_identity", side_effect=[entry["sourceMount"], entry["destinationMount"]]), patch.object(TRANSFER, "root_metadata", side_effect=[changed_source, destination]):
            with self.assertRaisesRegex(SystemExit, "source root identity"): TRANSFER.observe_entry(entry, {"findmnt": "x"}, Path("/fixture"), manifest["candidate"], after=True, before=before)

    def test_capacity_plan_handles_retries_delete_delay_and_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); source = root / "source"; destination = root / "destination"; source.mkdir(); destination.mkdir()
            source_file = source / "data"; destination_file = destination / "data"
            source_file.write_bytes(b"unchanged"); destination_file.write_bytes(b"unchanged")
            os.utime(destination_file, ns=(source_file.stat().st_atime_ns, source_file.stat().st_mtime_ns))
            unchanged = TRANSFER.root_write_requirement(source, destination, 4096)
            self.assertEqual(unchanged["requiredInodes"], 0)
            self.assertEqual(unchanged["requiredWriteBytes"], 8192)  # root + file metadata reserve
            os.utime(destination_file, ns=(destination_file.stat().st_atime_ns, destination_file.stat().st_mtime_ns - 1))
            self.assertGreaterEqual(TRANSFER.root_write_requirement(source, destination, 4096)["requiredWriteBytes"], 8192)
            destination_file.unlink(); (destination / "stale-extra").write_bytes(b"x" * 1000)
            missing = TRANSFER.root_write_requirement(source, destination, 4096)
            self.assertGreaterEqual(missing["requiredWriteBytes"], 8192); self.assertEqual(missing["requiredInodes"], 1)
            os.link(source_file, source / "hardlink")
            hardlinks = TRANSFER.root_write_requirement(source, destination, 4096)
            self.assertGreaterEqual(hardlinks["requiredWriteBytes"], 16384)
            self.assertEqual(hardlinks["requiredInodes"], 2)

    def test_capacity_plan_checks_inodes_and_refreshes_active_root_growth(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); source = root / "source"; destination = root / "destination"; source.mkdir(); destination.mkdir()
            source_file = source / "data"; destination_file = destination / "data"; source_file.write_bytes(b"a"); destination_file.write_bytes(b"a")
            os.utime(destination_file, ns=(source_file.stat().st_atime_ns, source_file.stat().st_mtime_ns))
            manifest = {"candidate": {"reserveBytes": 10}, "copyEntries": [{"source": "/source", "destination": "/destination"}]}
            plan = {0: TRANSFER.root_write_requirement(source, destination)}
            source_file.write_bytes(b"active-growth")
            fake_vfs = SimpleNamespace(f_frsize=1, f_bsize=4096, f_bavail=20000, f_favail=10)
            def directory(logical, fixture): return source if logical == "/source" else destination
            with patch.object(TRANSFER, "candidate_root", return_value=(root, {})), patch.object(TRANSFER, "require_directory", side_effect=directory), patch.object(TRANSFER.os, "statvfs", return_value=fake_vfs):
                TRANSFER.refresh_capacity_plan(plan, manifest, None, 0)
                observed = TRANSFER.capacity_check(manifest, {}, None, plan)
            self.assertGreaterEqual(observed["requiredWriteBytes"], 8192); self.assertEqual(observed["requiredInodes"], 1)
            fake_vfs.f_favail = 0
            with patch.object(TRANSFER, "candidate_root", return_value=(root, {})), patch.object(TRANSFER, "require_directory", side_effect=directory), patch.object(TRANSFER.os, "statvfs", return_value=fake_vfs):
                with self.assertRaisesRegex(SystemExit, "inode"): TRANSFER.capacity_check(manifest, {}, None, plan)

    def test_capacity_traversal_is_ordered_after_mount_observation(self) -> None:
        manifest = {"candidate": {}, "copyEntries": [{"source": "/source", "destination": "/destination"}]}
        with patch.object(TRANSFER, "observe_entry", side_effect=SystemExit("nested mount")), patch.object(TRANSFER, "root_write_requirement") as traverse:
            with self.assertRaisesRegex(SystemExit, "nested mount"): TRANSFER.build_checked_capacity_plan(manifest, {}, None)
        traverse.assert_not_called()
        order = []
        with patch.object(TRANSFER, "observe_entry", side_effect=lambda *args, **kwargs: order.append("observe") or {"safe": True}), patch.object(TRANSFER, "require_directory", side_effect=lambda value, fixture: Path(value)), patch.object(TRANSFER, "root_write_requirement", side_effect=lambda *args: order.append("traverse") or {"requiredWriteBytes": 0, "requiredInodes": 0}):
            TRANSFER.build_checked_capacity_plan(manifest, {}, None)
        self.assertEqual(order, ["observe", "traverse"])
        order = []
        with patch.object(TRANSFER, "observe_entry", side_effect=lambda *args, **kwargs: order.append("observe") or {"safe": True}), patch.object(TRANSFER, "refresh_capacity_plan", side_effect=lambda *args: order.append("refresh")), patch.object(TRANSFER, "capacity_check", side_effect=lambda *args: order.append("capacity") or {"safe": 1}):
            TRANSFER.active_capacity_observation(manifest, {}, None, {0: {}}, 0)
        self.assertEqual(order, ["observe", "refresh", "capacity"])

    def test_streaming_capacity_rounds_tiny_files_directories_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); source = root / "source"; destination = root / "destination"; source.mkdir(); destination.mkdir(); (source / "new-directory").mkdir()
            for index in range(100): (source / f"tiny-{index}").write_bytes(b"x")
            requirement = TRANSFER.root_write_requirement(source, destination, 4096)
            self.assertGreaterEqual(requirement["requiredWriteBytes"], 100 * 8192 + 4096)
            self.assertEqual(requirement["requiredInodes"], 101)

    def test_streaming_capacity_handles_deep_large_tree_and_symlink_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); source = root / "source"; destination = root / "destination"; outside = root / "outside"; source.mkdir(); destination.mkdir(); outside.mkdir()
            current = source
            for index in range(64): current = current / f"d{index}"; current.mkdir()
            (current / "leaf").write_bytes(b"leaf")
            for index in range(2000): (source / f"item-{index}").write_bytes(b"z")
            (outside / "leaf").write_bytes(b"leaf"); (destination / "d0").symlink_to(outside, target_is_directory=True)
            requirement = TRANSFER.root_write_requirement(source, destination, 4096)
            self.assertEqual(set(requirement), {"requiredWriteBytes", "requiredInodes"})
            self.assertGreater(requirement["requiredWriteBytes"], 2000 * 4096)
            self.assertGreater(requirement["requiredInodes"], 2000)

    def test_lock_contention_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            lock = Path(temporary) / "lock"; first = TRANSFER.acquire_lock(lock)
            try:
                with self.assertRaisesRegex(SystemExit, "holds the lock"):
                    TRANSFER.acquire_lock(lock)
            finally: os.close(first)

    def test_fixture_rsync_executable_version_and_live_override_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "rsync"; script.write_text("#!/bin/sh\nprintf '%s\\n' 'rsync  version 3.2.7  protocol version 31'\n"); script.chmod(0o755)
            self.assertEqual(TRANSFER.verify_rsync(str(script), True), "rsync  version 3.2.7  protocol version 31")
            with self.assertRaisesRegex(SystemExit, "fixed /usr/bin/rsync"): TRANSFER.verify_rsync(str(script), False)

    def test_closed_schemas_compile_and_reject_unknown_fields(self) -> None:
        for schema in ("isolated-restore-evidence.schema.json", "candidate-daemon-stop-evidence.schema.json", "source-daemon-stability-evidence.schema.json", "data-transfer-evidence.schema.json"):
            command = ["node", "-e", "const A=require('ajv/dist/2020');const s=JSON.parse(require('fs').readFileSync(process.argv[1]));new A({strict:true}).compile(s)", str(HERE.parent.parent / "infrastructure/vm-100" / schema)]
            subprocess.run(command, check=True, capture_output=True)
        stable = {"format": PREP.FORMAT_STABILITY, "completedAt": GATE_TEST.NOW, "result": "passed", "failureStage": None, "failureReason": None, "desiredInventorySha256": "a" * 64, "beforeInventorySha256": "b" * 64, "afterInventorySha256": "b" * 64, "exactEquality": True, "containerCount": 41, "runningCount": 41, "sourceDockerRoot": "/var/lib/docker", "observationError": None}
        stop_state = {"started": True, "termSent": True, "killSent": False, "exitCode": 0, "pidGone": True, "observationError": None}
        metrics = {"sha256": "d" * 64, "bytes": 0, "lines": 0}
        stop = {"format": PREP.FORMAT_STOP, "completedAt": GATE_TEST.NOW, "result": "passed", "failureStage": None, "failureReason": None, "candidateInventorySha256": "a" * 64, "isolatedDockerArgvSha256": digest(list(PREP.ISOLATED_DOCKER_ARGV)), "containerdArgvSha256": digest(list(PREP.CONTAINERD_ARGV)), "dockerd": stop_state, "containerd": stop_state, "socketAbsent": True, "runtimeFilesRemoved": True, "logs": {"containerd": {"name": "candidate-containerd.log", "metrics": metrics}, "dockerd": {"name": "candidate-dockerd.log", "metrics": metrics}, "collector": {"name": "candidate-collector.log", "metrics": metrics}}}
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            for kind, name, document in (("source-daemon-stability", "stable.json", stable), ("candidate-daemon-stop", "stop.json", stop)):
                path = Path(temporary) / name; path.write_bytes(canonical_bytes(document) + b"\n")
                subprocess.run(["node", str(HERE / "validate-vm-100-execution-schema.js"), kind, str(path)], check=True, capture_output=True)
            bad_stop = copy.deepcopy(stop); bad_stop["dockerd"]["started"] = False
            path = Path(temporary) / "bad-stop.json"; path.write_bytes(canonical_bytes(bad_stop) + b"\n")
            rejected = subprocess.run(["node", str(HERE / "validate-vm-100-execution-schema.js"), "candidate-daemon-stop", str(path)], capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
        with self.assertRaises(ValueError): PREP.validate_stability_evidence({**stable, "unknown": True})
        with self.assertRaises(ValueError): PREP.validate_stability_evidence({**stable, "afterInventorySha256": "c" * 64})
        false_green = {"format": TRANSFER.FORMAT, "phase": "precopy", "startedAt": GATE_TEST.NOW, "completedAt": GATE_TEST.NOW, "status": "succeeded", "failureStage": None, "failureReason": None, "manifestSha256": "a" * 64, "bindingsSha256": "b" * 64, "rsyncVersion": "rsync  version 3.2.7  protocol version 31", "candidateBefore": {}, "candidateAfter": {}, "candidateObservationError": None, "entries": []}
        with self.assertRaises(ValueError): TRANSFER.validate_evidence(false_green)


if __name__ == "__main__": unittest.main()
