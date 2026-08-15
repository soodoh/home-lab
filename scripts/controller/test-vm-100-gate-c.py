#!/usr/bin/env python3
"""Synthetic fixture and rejection tests for VM 100 Gate C evidence."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vm_100_gate_c import (
    ANONYMOUS_VOLUME_ALLOWLIST, BACKUP_PATHS, CANONICAL_SERVICES, CANONICAL_VOLUMES, CANDIDATE_BY_ID,
    CANDIDATE_INVENTORY_FORMAT, CANDIDATE_PROFILE, CANDIDATE_SERIAL,
    CLASSIFICATIONS, COLLECTION_FORMAT, DESTINATION_ROOT, DISK_BYTES, DOCKER_ROOT,
    FORMAT, ISOLATED_DOCKER_ARGV, ISOLATED_DOCKER_HOST, ISOLATED_DOCKER_PIDFILE,
    ISOLATED_DOCKER_ROOT, LEGACY_VOLUMES, PROJECT,
    _contained, checksum_argv,
    digest, expected_volume_names, host_destination, project_desired_inventory,
    project_runtime_inventory, validate_collection, validate_freshness,
    validate_manifest, volume_destination, volume_source, write_argv,
)

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("collector", HERE / "collect-vm-100-gate-c.py")
assert SPEC and SPEC.loader
COLLECTOR = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(COLLECTOR)
CANDIDATE_SPEC = importlib.util.spec_from_file_location("candidate_collector", HERE / "collect-vm-100-candidate-volume-inventory.py")
assert CANDIDATE_SPEC and CANDIDATE_SPEC.loader
CANDIDATE_COLLECTOR = importlib.util.module_from_spec(CANDIDATE_SPEC); CANDIDATE_SPEC.loader.exec_module(CANDIDATE_COLLECTOR)
MODEL_SPEC = importlib.util.spec_from_file_location("compose_model_inventory", HERE.parent / "compose-model-inventory.py")
assert MODEL_SPEC and MODEL_SPEC.loader
MODEL_INVENTORY = importlib.util.module_from_spec(MODEL_SPEC); MODEL_SPEC.loader.exec_module(MODEL_INVENTORY)
COMMIT = "a" * 40; ARTIFACT = "b" * 64; RESTORE = "e" * 64
STOP_EVIDENCE = "1" * 64; STABILITY_EVIDENCE = "2" * 64
TOPLEVEL = "/nix/store/" + "c" * 32 + "-vm-100-production-migration"
EXPECTED = sorted(CANONICAL_VOLUMES | LEGACY_VOLUMES)
NOW = "2026-08-12T00:05:00Z"


def raw_desired() -> dict[str, object]:
    services = {name: {"binds": [], "volumes": []} for name in CANONICAL_SERVICES}
    return {"kind": "desired", "project_name": PROJECT, "service_count": 41, "volume_count": 30, "services": services, "volumes": sorted(CANONICAL_VOLUMES), "networks": {}}


def anonymous_mounts(projected: bool = False) -> list[dict[str, object]]:
    values = []
    for index, (service, destination, read_only) in enumerate(sorted(ANONYMOUS_VOLUME_ALLOWLIST)):
        identifier = format(10_000 + index, "064x"); source = f"{DOCKER_ROOT}/volumes/{identifier}/_data"
        if projected:
            values.append({"container": service, "service": service, "kind": "anonymous-volume", "source": source, "destination": destination, "readOnly": read_only, "logicalName": None})
        else:
            values.append({"Type": "volume", "Name": identifier, "Source": source, "Destination": destination, "RW": not read_only})
    return values


def containers_for_desired(desired: dict[str, object]) -> list[dict[str, object]]:
    result = [{"Id": format(index + 1, "064x"), "Name": f"/{item['service']}", "Config": {"Labels": {"com.docker.compose.project": PROJECT, "com.docker.compose.service": item["service"]}}, "State": {"Running": True}, "Mounts": []} for index, item in enumerate(desired["serviceMounts"])]
    for mount, identity in zip(anonymous_mounts(), sorted(ANONYMOUS_VOLUME_ALLOWLIST)):
        next(item for item in result if item["Config"]["Labels"]["com.docker.compose.service"] == identity[0])["Mounts"].append(mount)
    return result


def projected_containers(desired: dict[str, object]) -> list[dict[str, object]]:
    return [{"id": format(index + 1, "064x"), "name": item["service"], "service": item["service"], "running": True} for index, item in enumerate(desired["serviceMounts"])]


def raw_runtime() -> dict[str, object]:
    return {"kind": "runtime", "project_name": PROJECT, "container_count": 0, "running_count": 0, "project_volume_count": 33, "project_volumes": [f"{PROJECT}_{name}" for name in EXPECTED], "services": {}}


def fixture_documents() -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    desired = project_desired_inventory(raw_desired()); runtime = project_runtime_inventory(raw_runtime(), EXPECTED)
    destination_mount = {"device": "/dev/sdc2", "filesystem": "ext4", "mountTarget": DESTINATION_ROOT, "mountId": 42}
    source_mount = {"device": "/dev/sda1", "filesystem": "ext4", "mountTarget": "/", "mountId": 10}
    created = "2026-08-11T20:00:00Z"
    qualified = []
    entries = []
    for index, name in enumerate(EXPECTED):
        engine = f"{PROJECT}_{name}"; labels = {"com.docker.compose.project": PROJECT, "com.docker.compose.volume": name}
        qualified.append({"logicalName": name, "engineName": engine, "driver": "local", "options": {}, "hostMountpoint": volume_destination(engine), "guestMountpoint": volume_source(engine), "composeLabels": labels, "createdAt": created})
        destination = volume_destination(engine)
        entries.append({"kind": "docker-volume", "logicalName": name, "engineName": engine, "legacy": name in LEGACY_VOLUMES, "source": volume_source(engine), "destination": destination, "sourceMount": source_mount, "destinationMount": destination_mount, "driver": "local", "options": {}, "composeLabels": labels, "candidateCreatedAt": created, "uid": 1000, "gid": 1000, "mode": "0750", "allocatedBytes": index + 1, "apparentBytes": index + 1, "inodeCount": 1, "permittedDeletionRoot": destination, "disposition": "copy"})
    entries.append({"kind": "host-path", "logicalName": None, "engineName": None, "legacy": False, "source": "/home/docker/hass", "destination": host_destination(), "sourceMount": source_mount, "destinationMount": destination_mount, "driver": None, "options": {}, "composeLabels": {}, "candidateCreatedAt": None, "uid": 1000, "gid": 1000, "mode": "0755", "allocatedBytes": 12, "apparentBytes": 12, "inodeCount": 2, "permittedDeletionRoot": host_destination(), "disposition": "copy"})
    generation = "system-42-link"
    qualification = {"format": CANDIDATE_INVENTORY_FORMAT, "collectedAt": "2026-08-11T23:30:00Z", "candidateDisk": {"wholeDiskById": CANDIDATE_BY_ID, "serial": CANDIDATE_SERIAL, "sizeBytes": DISK_BYTES}, "candidateMount": {"device": "/dev/sdc2", "filesystem": "ext4", "target": DESTINATION_ROOT, "deviceAncestry": ["/dev/sdc", "/dev/sdc2"]}, "isolatedDockerHost": ISOLATED_DOCKER_HOST, "isolatedDockerRoot": ISOLATED_DOCKER_ROOT, "isolatedDockerDaemonArgv": list(ISOLATED_DOCKER_ARGV), "systemProfile": {"guestProfilePath": CANDIDATE_PROFILE, "hostProfilePath": f"{DESTINATION_ROOT}{CANDIDATE_PROFILE}", "profileLinkText": generation, "guestGenerationLinkPath": f"/nix/var/nix/profiles/{generation}", "hostGenerationLinkPath": f"{DESTINATION_ROOT}/nix/var/nix/profiles/{generation}", "generationLinkText": TOPLEVEL, "hostToplevelPath": f"{DESTINATION_ROOT}{TOPLEVEL}"}, "canonicalProductionMigrationToplevel": TOPLEVEL, "volumes": qualified}
    candidate = {"wholeDiskById": CANDIDATE_BY_ID, "wholeDiskDevice": "/dev/sdc", "deviceAncestry": ["/dev/sdc", "/dev/sdc2"], "serial": CANDIDATE_SERIAL, "sizeBytes": DISK_BYTES, "destinationRoot": DESTINATION_ROOT, **destination_mount, "capacityBytes": 100_000_000, "availableBytes": 90_000_000, "reserveBytes": 10_000_000}
    archive = "daily-local-backup-2026-08-12T00-00-00.tar.gz.gpg"; replicas = []
    for index, path in enumerate(BACKUP_PATHS):
        mount = {"device": f"/dev/backup{index}", "filesystem": "ext4", "filesystemUuid": f"00000000-0000-0000-0000-00000000000{index}", "mountTarget": path, "mountId": 50 + index}
        if index == 2: mount.update({"device": "192.168.0.123:/storage/docker", "filesystem": "nfs4", "filesystemUuid": None})
        replicas.append({"path": path, "archiveName": archive, "sidecarName": f"{archive}.sha256", "sha256": "d" * 64, "sizeBytes": 1234, "mtime": f"2026-08-12T00:00:0{index}Z", "mount": mount})
    anonymous = anonymous_mounts(projected=True)
    collection = {"format": COLLECTION_FORMAT, "collectedAt": NOW, "desiredInventorySha256": digest(desired), "runtimeInventorySha256": digest(runtime), "candidateInventorySha256": digest(qualification), "sourceDockerRoot": "/var/lib/docker", "candidateQualification": qualification, "candidate": candidate, "copyEntries": entries, "backupEvidence": {"maxAgeSeconds": 3600, "replicas": replicas}, "operationalMetadata": {"containers": projected_containers(desired), "writers": copy.deepcopy(anonymous), "timers": [], "mounts": anonymous}}
    projected = []
    for entry in entries:
        value = copy.deepcopy(entry); value["writeArgv"] = write_argv(entry["source"], entry["destination"]); value["checksumArgv"] = checksum_argv(entry["source"], entry["destination"]); projected.append(value)
    manifest = {"format": FORMAT, "version": 1, "bindings": {"gitCommit": COMMIT, "composeArtifactSha256": ARTIFACT, "isolatedRestoreEvidenceSha256": RESTORE, "candidateDaemonStopEvidenceSha256": STOP_EVIDENCE, "sourceDaemonStabilityEvidenceSha256": STABILITY_EVIDENCE, "canonicalProductionMigrationToplevel": TOPLEVEL, "desiredInventorySha256": digest(desired), "runtimeInventorySha256": digest(runtime), "candidateInventorySha256": digest(qualification), "collectionSha256": digest(collection), "collectedAt": NOW}, "inventories": {"desired": desired, "runtime": runtime, "collection": collection}, "candidate": candidate, "sourceDockerRoot": "/var/lib/docker", "copyEntries": projected, "classifications": [{"name": n, "path": p, "disposition": d, "reason": r} for n, p, d, r in CLASSIFICATIONS], "backupEvidence": collection["backupEvidence"], "operationalMetadata": collection["operationalMetadata"]}
    return desired, runtime, collection, manifest


def schema_result(document: dict[str, object]) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as temporary:
        json.dump(document, temporary, sort_keys=True, separators=(",", ":")); temporary.flush()
        return subprocess.run(["node", str(HERE / "validate-vm-100-gate-c-schema.js"), temporary.name], capture_output=True, text=True)


def run_candidate_fixture(**mutations: object) -> tuple[dict[str, object], list[list[str]]]:
    with tempfile.TemporaryDirectory(dir=HERE) as temporary:
        root = Path(temporary); candidate_root = root / DESTINATION_ROOT.removeprefix("/")
        profile = candidate_root / CANDIDATE_PROFILE.removeprefix("/"); profile.parent.mkdir(parents=True)
        profile_link = str(mutations.get("profile_link", "system-42-link")); profile.symlink_to(profile_link)
        if "/" not in profile_link:
            generation = profile.parent / profile_link
            generation.symlink_to(str(mutations.get("generation_link", TOPLEVEL)))
        toplevel_path = candidate_root / TOPLEVEL.removeprefix("/")
        if mutations.get("toplevel_symlink"):
            real_toplevel = candidate_root / "real-toplevel"; real_toplevel.mkdir(parents=True); toplevel_path.parent.mkdir(parents=True); toplevel_path.symlink_to(real_toplevel)
        else: toplevel_path.mkdir(parents=True)
        pidfile = root / ISOLATED_DOCKER_PIDFILE.removeprefix("/"); pidfile.parent.mkdir(parents=True); pidfile.write_text("4242\n"); pidfile.chmod(0o600)
        cmdline = root / "proc/4242/cmdline"; cmdline.parent.mkdir(parents=True)
        daemon_argv = mutations.get("daemon_argv", list(ISOLATED_DOCKER_ARGV)); cmdline.write_bytes(b"\0".join(str(item).encode() for item in daemon_argv) + b"\0")
        device = root / "dev/sdc"; device.parent.mkdir(parents=True); device.touch()
        by_id = root / CANDIDATE_BY_ID.removeprefix("/"); by_id.parent.mkdir(parents=True); by_id.symlink_to("../../sdc")
        output = root / "output"; output.mkdir(mode=0o700)
        desired = project_desired_inventory(raw_desired()); desired_path = root / "desired.json"; desired_path.write_text(json.dumps(raw_desired()))
        calls: list[list[str]] = []
        engines = [f"{PROJECT}_{name}" for name in EXPECTED]
        def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(list(argv)); command = argv[0]
            if command == "/fixture/findmnt":
                payload = {"filesystems": [{"source": mutations.get("mount_source", "/dev/sdc2"), "fstype": mutations.get("filesystem", "ext4"), "target": mutations.get("mount_target", DESTINATION_ROOT)}]}
            elif command == "/fixture/lsblk":
                payload = {"blockdevices": [{"path": "/dev/sdc", "serial": CANDIDATE_SERIAL, "size": DISK_BYTES, "type": "disk", "children": [{"path": "/dev/sdc2", "type": "part"}]}]}
            elif command == "/fixture/docker":
                if argv[1:3] != ["--host", ISOLATED_DOCKER_HOST]: raise AssertionError("Docker call omitted the exact isolated host")
                docker_argv = argv[3:]
                if docker_argv[0] == "info": payload = {"DockerRootDir": mutations.get("docker_root", ISOLATED_DOCKER_ROOT), "Containers": mutations.get("containers", 0), "ContainersRunning": mutations.get("running", 0), "ContainersPaused": 0, "ContainersStopped": mutations.get("stopped", 0)}
                elif docker_argv == ["ps", "--all", "--quiet"]:
                    return subprocess.CompletedProcess(argv, 0, str(mutations.get("ps_output", "")), "")
                elif docker_argv[:2] == ["volume", "ls"]:
                    listed = [{"Name": engine} for engine in engines]
                    if mutations.get("extra_volume"): listed.append({"Name": "anonymous-extra"})
                    return subprocess.CompletedProcess(argv, 0, "\n".join(json.dumps(item) for item in listed) + "\n", "")
                elif docker_argv[:2] == ["volume", "inspect"]:
                    engine = docker_argv[2]; logical = engine.removeprefix(f"{PROJECT}_")
                    mountpoint = "/wrong" if mutations.get("wrong_mountpoint") else volume_destination(engine)
                    payload = [{"Name": engine, "Driver": "local", "Options": {}, "Mountpoint": mountpoint, "Labels": {"com.docker.compose.project": PROJECT, "com.docker.compose.volume": logical}, "CreatedAt": "2026-08-11T20:00:00Z"}]
                else: raise AssertionError(f"unexpected Docker argv: {docker_argv}")
            else: raise AssertionError(f"unexpected command: {command}")
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        argv = ["collector", "--desired-inventory", str(desired_path), "--expected-desired-inventory-sha256", digest(desired), "--canonical-toplevel", TOPLEVEL, "--output-root", str(output), "--output-name", "candidate.json", "--collected-at", "2026-08-11T20:00:00Z", "--fixture-root", str(root), "--docker-command", "/fixture/docker", "--findmnt-command", "/fixture/findmnt", "--lsblk-command", "/fixture/lsblk"]
        with patch.object(CANDIDATE_COLLECTOR.subprocess, "run", side_effect=fake_run), patch.object(sys, "argv", argv):
            CANDIDATE_COLLECTOR.main()
        return json.loads((output / "candidate.json").read_text()), calls


class GateCTests(unittest.TestCase):
    def test_canonical_inventory_openfit_and_exact_argv_arrays(self) -> None:
        desired, runtime, collection, manifest = fixture_documents()
        self.assertIn("openfit-data", desired["volumes"]); self.assertEqual(len(validate_collection(collection, desired, runtime)), 34)
        validate_manifest(manifest, COMMIT, ARTIFACT, TOPLEVEL, digest(desired), collection["candidateInventorySha256"], NOW, 600, RESTORE, STOP_EVIDENCE, STABILITY_EVIDENCE)
        first = manifest["copyEntries"][0]
        self.assertEqual(first["writeArgv"], ["rsync", "-aHAXSx", "--numeric-ids", "--delete", "--delete-delay", "--itemize-changes", "--", first["source"] + "/", first["destination"] + "/."])
        self.assertEqual(first["checksumArgv"], ["rsync", "-aHAXSx", "--numeric-ids", "--delete", "--delete-delay", "--dry-run", "--checksum", "--itemize-changes", "--", first["source"] + "/", first["destination"] + "/."])

    def test_desired_inventory_requires_exact_unique_41_services(self) -> None:
        raw = raw_desired(); raw["services"].pop("zwave"); raw["service_count"] = 40
        with self.assertRaisesRegex(ValueError, "canonical 41-service"): project_desired_inventory(raw)
        desired = project_desired_inventory(raw_desired()); desired["serviceMounts"][1]["service"] = desired["serviceMounts"][0]["service"]
        with self.assertRaisesRegex(ValueError, "duplicate service"): expected_volume_names(desired)

    def test_arbitrary_30_and_independent_desired_digest_rejected(self) -> None:
        raw = raw_desired(); raw["volumes"] = [f"wrong-{i}" for i in range(30)]
        with self.assertRaisesRegex(ValueError, "canonical"): project_desired_inventory(raw)
        desired, runtime, collection, _ = fixture_documents()
        with self.assertRaisesRegex(ValueError, "independently"): validate_collection(collection, desired, runtime, expected_desired_sha256="0" * 64)

    def test_candidate_volume_listing_rejects_extras_and_missing(self) -> None:
        engines = [f"{PROJECT}_{name}" for name in EXPECTED]; listed = [{"Name": engine} for engine in engines]
        CANDIDATE_COLLECTOR.require_exact_daemon_volumes(listed, sorted(engines))
        with self.assertRaisesRegex(SystemExit, "extra.*missing"): CANDIDATE_COLLECTOR.require_exact_daemon_volumes(listed[:-1], sorted(engines))
        with self.assertRaisesRegex(SystemExit, "anonymous|unlabeled"): CANDIDATE_COLLECTOR.require_exact_daemon_volumes([*listed, {"Name": "anonymous-extra"}], sorted(engines))

    def test_isolated_candidate_collector_accepts_and_hosts_every_docker_call(self) -> None:
        inventory, calls = run_candidate_fixture()
        self.assertEqual(inventory["isolatedDockerHost"], ISOLATED_DOCKER_HOST)
        self.assertEqual(inventory["isolatedDockerRoot"], ISOLATED_DOCKER_ROOT)
        self.assertEqual(inventory["systemProfile"]["profileLinkText"], "system-42-link")
        self.assertEqual(inventory["systemProfile"]["generationLinkText"], TOPLEVEL)
        self.assertEqual(inventory["isolatedDockerDaemonArgv"], list(ISOLATED_DOCKER_ARGV))
        docker_calls = [call for call in calls if call[0] == "/fixture/docker"]
        self.assertEqual(len(docker_calls), 36)
        self.assertTrue(all(call[1:3] == ["--host", ISOLATED_DOCKER_HOST] for call in docker_calls))
        self.assertIn(["/fixture/findmnt", "--json", "--target", DESTINATION_ROOT, "--output", "SOURCE,FSTYPE,TARGET"], calls)

    def test_isolated_candidate_collector_rejects_wrong_daemon_and_volume_shape(self) -> None:
        for mutation, message in (({"docker_root": DOCKER_ROOT}, "Docker root"), ({"docker_root": "/other"}, "Docker root"), ({"wrong_mountpoint": True}, "volume identity"), ({"extra_volume": True}, "extra")):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(SystemExit, message): run_candidate_fixture(**mutation)
        desired, runtime, collection, _ = fixture_documents(); collection["candidateQualification"]["isolatedDockerHost"] = "unix:///var/run/docker.sock"
        with self.assertRaisesRegex(ValueError, "isolated Docker"): validate_collection(collection, desired, runtime)

    def test_isolated_candidate_collector_rejects_mount_profile_and_unrelated_device(self) -> None:
        for mutation, message in (({"mount_target": "/"}, "exact mounted"), ({"filesystem": "tmpfs"}, "exact mounted"), ({"mount_source": "/dev/sda1"}, "descendant"), ({"profile_link": TOPLEVEL}, "generation link"), ({"profile_link": "../system-42-link"}, "generation link"), ({"profile_link": "system-0-link"}, "generation link"), ({"generation_link": "/nix/store/" + "d" * 32 + "-wrong"}, "differs"), ({"toplevel_symlink": True}, "symlink path component")):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(SystemExit, message): run_candidate_fixture(**mutation)

    def test_isolated_candidate_daemon_requires_zero_containers_and_exact_argv(self) -> None:
        for mutation, message in (({"containers": 1, "running": 1}, "zero-container"), ({"ps_output": "abc\n"}, "contains containers"), ({"daemon_argv": list(ISOLATED_DOCKER_ARGV)[:-1]}, "exact safety policy"), ({"daemon_argv": [*ISOLATED_DOCKER_ARGV, "--debug"]}, "exact safety policy"), ({"daemon_argv": [ISOLATED_DOCKER_ARGV[0], ISOLATED_DOCKER_ARGV[2], ISOLATED_DOCKER_ARGV[1], *ISOLATED_DOCKER_ARGV[3:]]}, "exact safety policy")):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(SystemExit, message): run_candidate_fixture(**mutation)

    def test_candidate_live_mode_rejects_command_overrides(self) -> None:
        argv = ["collector", "--desired-inventory", "/unused", "--expected-desired-inventory-sha256", "0" * 64, "--canonical-toplevel", TOPLEVEL, "--output-root", "/unused", "--output-name", "out.json", "--docker-command", "/other/docker"]
        with patch.object(sys, "argv", argv), patch.object(CANDIDATE_COLLECTOR.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(SystemExit, "forbids command overrides"): CANDIDATE_COLLECTOR.main()

    def test_volume_source_normalization_and_anonymous_allowlist_are_exact(self) -> None:
        declared = {"openfit-data", "caddy-data"}
        self.assertEqual(MODEL_INVENTORY.normalize_desired_volume_source("docker-compose_openfit-data", declared, PROJECT), "openfit-data")
        self.assertEqual(MODEL_INVENTORY.normalize_desired_volume_source("other_openfit-data", declared, PROJECT), "other_openfit-data")
        self.assertEqual(MODEL_INVENTORY.normalize_desired_volume_source("docker-compose_unknown", declared, PROJECT), "docker-compose_unknown")
        self.assertEqual(ANONYMOUS_VOLUME_ALLOWLIST, frozenset({
            ("calibre-web-automated", "/cwa-book-ingest", False),
            ("flaresolverr", "/config", False),
            ("nextcloud-redis", "/data", False),
            ("wolf", "/run/user/wolf", False),
        }))
        classifications = {(name, path, disposition) for name, path, disposition, _ in CLASSIFICATIONS}
        self.assertIn(("home-docker-ssh", "/home/docker/.ssh", "excluded"), classifications)
        self.assertIn(("anonymous-runtime-volumes", "/var/lib/docker/volumes", "regenerate"), classifications)
        desired = project_desired_inventory(raw_desired()); fleet = containers_for_desired(desired); flaresolverr = next(item for item in fleet if item["Config"]["Labels"]["com.docker.compose.service"] == "flaresolverr")
        anonymous_name = "f" * 64; flaresolverr["Mounts"] = [{"Type": "volume", "Name": anonymous_name, "Source": f"{DOCKER_ROOT}/volumes/{anonymous_name}/_data", "Destination": "/config", "RW": True}]
        _, _, mounts = COLLECTOR.safe_container_metadata(fleet, desired); self.assertIsNone(next(item for item in mounts if item["service"] == "flaresolverr")["logicalName"])
        missing = copy.deepcopy(fleet); next(item for item in missing if item["Config"]["Labels"]["com.docker.compose.service"] == "wolf")["Mounts"] = []
        with self.assertRaisesRegex(SystemExit, "missing or extra"): COLLECTOR.safe_container_metadata(missing, desired)
        zero = copy.deepcopy(fleet)
        for item in zero: item["Mounts"] = []
        with self.assertRaisesRegex(SystemExit, "missing or extra"): COLLECTOR.safe_container_metadata(zero, desired)
        flaresolverr["Mounts"][0]["Destination"] = "/unexpected"
        with self.assertRaisesRegex(SystemExit, "unexpected"): COLLECTOR.safe_container_metadata(fleet, desired)

    def test_shared_operational_validation_requires_exact_four_anonymous_mounts_and_writers(self) -> None:
        desired, runtime, collection, _ = fixture_documents()
        self.assertEqual(sum(item["kind"] == "anonymous-volume" for item in collection["operationalMetadata"]["mounts"]), 4)
        validate_collection(collection, desired, runtime)
        for remove_all in (False, True):
            bad = copy.deepcopy(collection)
            count = 4 if remove_all else 1
            del bad["operationalMetadata"]["mounts"][:count]
            del bad["operationalMetadata"]["writers"][:count]
            with self.subTest(remove_all=remove_all), self.assertRaisesRegex(ValueError, "exact four"):
                validate_collection(bad, desired, runtime)
        bad = copy.deepcopy(collection); fifth = copy.deepcopy(bad["operationalMetadata"]["mounts"][0]); fifth["source"] = f"{DOCKER_ROOT}/volumes/{'f' * 64}/_data"
        bad["operationalMetadata"]["mounts"].append(fifth); bad["operationalMetadata"]["writers"].append(copy.deepcopy(fifth))
        with self.assertRaisesRegex(ValueError, "exact four"): validate_collection(bad, desired, runtime)
        bad = copy.deepcopy(collection); bad["operationalMetadata"]["writers"].pop()
        with self.assertRaisesRegex(ValueError, "writer evidence"): validate_collection(bad, desired, runtime)

    def test_candidate_identity_qualification_and_digest_rejected(self) -> None:
        desired, runtime, collection, _ = fixture_documents(); collection["candidate"]["serial"] = "OTHER"
        with self.assertRaisesRegex(ValueError, "exact public"): validate_collection(collection, desired, runtime)
        desired, runtime, collection, _ = fixture_documents(); collection["candidateQualification"]["volumes"][0]["hostMountpoint"] = "/wrong"
        with self.assertRaisesRegex(ValueError, "identity"): validate_collection(collection, desired, runtime)
        desired, runtime, collection, _ = fixture_documents()
        with self.assertRaisesRegex(ValueError, "candidate qualification digest"): validate_collection(collection, desired, runtime, expected_candidate_sha256="0" * 64)

    def test_candidate_mount_descendant_and_tmpfs_rejected(self) -> None:
        tree = {"blockdevices": [{"path": "/dev/sdc", "serial": CANDIDATE_SERIAL, "size": DISK_BYTES, "type": "disk", "children": [{"path": "/dev/sdc2", "type": "part", "size": DISK_BYTES - 1}]}]}
        with patch.object(COLLECTOR, "run_json", return_value=tree):
            _, ancestry = COLLECTOR.verify_candidate_device("fixture-lsblk", Path("/dev/sdc"), "/dev/sdc2")
        self.assertEqual(ancestry, ["/dev/sdc", "/dev/sdc2"])
        with patch.object(COLLECTOR, "run_json", return_value=tree):
            with self.assertRaisesRegex(SystemExit, "descendant"): COLLECTOR.verify_candidate_device("fixture-lsblk", Path("/dev/sdc"), "/dev/sda1")
        desired, runtime, collection, _ = fixture_documents(); collection["candidate"].update({"device": "tmpfs", "filesystem": "tmpfs"})
        with self.assertRaises(ValueError): validate_collection(collection, desired, runtime)

    def test_containment_equality_and_wholesale_classification(self) -> None:
        self.assertFalse(_contained(DESTINATION_ROOT, DESTINATION_ROOT, allow_equal=False))
        self.assertIn(("docker-root-wholesale", "/var/lib/docker", "excluded"), {(n, p, d) for n, p, d, _ in CLASSIFICATIONS})
        _, _, _, manifest = fixture_documents(); manifest["classifications"] = [item for item in manifest["classifications"] if item["name"] != "docker-root-wholesale"]
        with self.assertRaisesRegex(ValueError, "classification"): validate_manifest(manifest)

    def test_unknown_fields_and_unsafe_values_rejected(self) -> None:
        _, _, _, manifest = fixture_documents(); manifest["inventories"]["desired"]["unknown"] = "value"
        with self.assertRaises(ValueError): validate_manifest(manifest)
        self.assertNotEqual(schema_result(manifest).returncode, 0)
        _, _, _, manifest = fixture_documents(); manifest["operationalMetadata"]["timers"] = [{"unit": "bad\nunit", "activates": "x.service"}]; manifest["inventories"]["collection"]["operationalMetadata"] = manifest["operationalMetadata"]
        with self.assertRaises(ValueError): validate_manifest(manifest)

    def test_complete_daemon_container_inventory_rejects_nonproject_missing_and_duplicate(self) -> None:
        desired = project_desired_inventory(raw_desired()); fleet = containers_for_desired(desired)
        COLLECTOR.safe_container_metadata(fleet, desired)
        nonproject = copy.deepcopy(fleet); nonproject[0]["Config"]["Labels"]["com.docker.compose.project"] = "other"
        with self.assertRaisesRegex(SystemExit, "nonproject"): COLLECTOR.safe_container_metadata(nonproject, desired)
        with self.assertRaisesRegex(SystemExit, "exactly one container"): COLLECTOR.safe_container_metadata(fleet[:-1], desired)
        duplicate = copy.deepcopy(fleet); duplicate[1]["Config"]["Labels"]["com.docker.compose.service"] = duplicate[0]["Config"]["Labels"]["com.docker.compose.service"]
        with self.assertRaisesRegex(SystemExit, "duplicate service"): COLLECTOR.safe_container_metadata(duplicate, desired)

    def test_canonical_special_binds_are_classified_but_unprojected_mounts_fail(self) -> None:
        special = ["/dev", "/etc/localtime", "/usr/share/zoneinfo", "/run/dbus", "/run/udev", "/var/run/docker.sock"]
        raw = raw_desired(); raw["services"]["openfit"] = {"binds": [{"source": source, "target": f"/host/{index}", "read_only": True} for index, source in enumerate(special)], "volumes": []}
        desired = project_desired_inventory(raw); policy = COLLECTOR.desired_mount_policy(desired)["openfit"]
        self.assertEqual(len(policy), len(special))
        fleet = containers_for_desired(desired); app = next(item for item in fleet if item["Config"]["Labels"]["com.docker.compose.service"] == "openfit")
        app["Mounts"] = [{"Type": "bind", "Source": source, "Destination": f"/host/{index}", "RW": False} for index, source in enumerate(special)]
        COLLECTOR.safe_container_metadata(fleet, desired)
        bad = copy.deepcopy(fleet); next(item for item in bad if item["Config"]["Labels"]["com.docker.compose.service"] == "openfit")["Mounts"].append({"Type": "bind", "Source": "/run/dbus/nested", "Destination": "/unexpected", "RW": False})
        with self.assertRaisesRegex(SystemExit, "unexpected"): COLLECTOR.safe_container_metadata(bad, desired)

    def test_unexpected_anonymous_nested_and_bind_mounts_rejected(self) -> None:
        raw = raw_desired(); raw["services"]["openfit"] = {"binds": [{"source": "/mnt/storage/media", "target": "/media", "read_only": True}], "volumes": [{"source": "openfit-data", "target": "/data", "read_only": False}]}
        desired = project_desired_inventory(raw); fleet = containers_for_desired(desired); app = next(item for item in fleet if item["Config"]["Labels"]["com.docker.compose.service"] == "openfit")
        app["Mounts"] = [{"Type": "volume", "Name": f"{PROJECT}_openfit-data", "Source": volume_source(f"{PROJECT}_openfit-data"), "Destination": "/data", "RW": True}, {"Type": "bind", "Source": "/mnt/storage/media", "Destination": "/media", "RW": False}]
        containers, writers, mounts = COLLECTOR.safe_container_metadata(fleet, desired); self.assertEqual(len(containers), 41); self.assertEqual(len(mounts), 6); self.assertEqual(len(writers), 5)
        missing_mount = copy.deepcopy(fleet); next(item for item in missing_mount if item["Config"]["Labels"]["com.docker.compose.service"] == "openfit")["Mounts"].pop()
        with self.assertRaisesRegex(SystemExit, "missing desired mounts"): COLLECTOR.safe_container_metadata(missing_mount, desired)
        for mutation in (lambda m: m.update({"Name": "", "Source": "/var/lib/docker/volumes/anon/_data"}), lambda m: m.update({"Source": volume_source(f"{PROJECT}_openfit-data") + "/nested"}), lambda m: m.update({"Type": "bind", "Source": "/mnt/storage/media/nested"})):
            bad = copy.deepcopy(fleet); bad_app = next(item for item in bad if item["Config"]["Labels"]["com.docker.compose.service"] == "openfit"); mutation(bad_app["Mounts"][0])
            with self.assertRaisesRegex(SystemExit, "unexpected|anonymous"): COLLECTOR.safe_container_metadata(bad, desired)

    def test_candidate_qualification_freshness_is_bounded_against_collection(self) -> None:
        desired, runtime, collection, _ = fixture_documents()
        collection["candidateQualification"]["collectedAt"] = "2026-08-11T23:04:59Z"; collection["candidateInventorySha256"] = digest(collection["candidateQualification"])
        with self.assertRaisesRegex(ValueError, "stale or from the future"): validate_collection(collection, desired, runtime)
        desired, runtime, collection, _ = fixture_documents(); collection["candidateQualification"]["collectedAt"] = "2026-08-12T00:05:01Z"; collection["candidateInventorySha256"] = digest(collection["candidateQualification"])
        with self.assertRaisesRegex(ValueError, "stale or from the future"): validate_collection(collection, desired, runtime)

    def test_backup_freshness_equality_devices_and_collection_age(self) -> None:
        desired, runtime, collection, _ = fixture_documents(); collection["backupEvidence"]["replicas"][2]["sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "not equal"): validate_collection(collection, desired, runtime)
        desired, runtime, collection, _ = fixture_documents(); collection["backupEvidence"]["replicas"][2]["mount"].update({"device": "/dev/other", "filesystem": "ext4", "mountId": 999, "filesystemUuid": collection["backupEvidence"]["replicas"][1]["mount"]["filesystemUuid"]})
        with self.assertRaisesRegex(ValueError, "distinct underlying"): validate_collection(collection, desired, runtime)
        desired, runtime, collection, _ = fixture_documents(); collection["backupEvidence"]["replicas"][2]["mount"].update({"device": "192.168.0.123:/storage/docker", "filesystem": "ext4", "filesystemUuid": None})
        with self.assertRaises(ValueError): validate_collection(collection, desired, runtime)
        with self.assertRaisesRegex(ValueError, "stale"): validate_freshness(NOW, "2026-08-12T01:00:00Z", 60)

    def test_backup_archive_bytes_are_streamed_and_verified(self) -> None:
        archive_name = "daily-local-backup-2026-08-12T00-00-00.tar.gz.gpg"; content = b"encrypted fixture bytes"; checksum = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for logical in BACKUP_PATHS:
                directory = root / logical.removeprefix("/"); directory.mkdir(parents=True)
                archive = directory / archive_name; archive.write_bytes(content); os.utime(archive, (1786492800, 1786492800))
                (directory / f"{archive_name}.sha256").write_text(f"{checksum}  {archive_name}\n", encoding="ascii")
            def identity(_command: str, logical: str, _physical: Path, *, include_uuid: bool = False) -> dict[str, object]:
                index = BACKUP_PATHS.index(logical)
                return {"device": f"/dev/backup{index}", "filesystem": "ext4", "filesystemUuid": f"00000000-0000-0000-0000-00000000000{index}", "mountTarget": logical, "mountId": 50 + index}
            collected = __import__("datetime").datetime(2026, 8, 12, 0, 5, tzinfo=__import__("datetime").UTC)
            with patch.object(COLLECTOR, "mount_identity", side_effect=identity): COLLECTOR.backup_evidence("findmnt", root, collected, 3600)
            tampered = root / BACKUP_PATHS[0].removeprefix("/") / archive_name
            tampered.write_bytes(b"tampered"); os.utime(tampered, (1786492800, 1786492800))
            with patch.object(COLLECTOR, "mount_identity", side_effect=identity):
                with self.assertRaisesRegex(SystemExit, "bytes do not match"): COLLECTOR.backup_evidence("findmnt", root, collected, 3600)

    def test_output_is_exclusive_private_and_symlink_root_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); root.chmod(0o700)
            with patch.object(COLLECTOR.os, "fsync", wraps=os.fsync) as fsync:
                COLLECTOR.protected_output(root, "evidence.json", b"{}\n")
            self.assertGreaterEqual(fsync.call_count, 2); self.assertEqual(stat.S_IMODE((root / "evidence.json").stat().st_mode), 0o600)
            with self.assertRaises(OSError): COLLECTOR.protected_output(root, "evidence.json", b"{}\n")
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary); real = parent / "real"; real.mkdir(mode=0o700); link = parent / "link"; link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(SystemExit, "output root"): COLLECTOR.protected_output(link, "evidence.json", b"{}\n")

    def test_cross_root_hardlink_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"; second = Path(temporary) / "second"; first.mkdir(); second.mkdir(); original = first / "file"; original.write_text("fixture"); os.link(original, second / "linked")
            with self.assertRaisesRegex(SystemExit, "cross-root"): COLLECTOR.reject_cross_root_hardlinks([("/first", COLLECTOR.tree_metrics(first)[3]), ("/second", COLLECTOR.tree_metrics(second)[3])])

    def test_schema_positive_and_fixed_argv_negative(self) -> None:
        _, _, _, manifest = fixture_documents(); result = schema_result(manifest); self.assertEqual(result.returncode, 0, result.stderr)
        manifest["copyEntries"][0]["writeArgv"][6] = "wrong"; self.assertNotEqual(schema_result(manifest).returncode, 0)
        _, _, _, manifest = fixture_documents(); manifest["classifications"].pop(); self.assertNotEqual(schema_result(manifest).returncode, 0)
        _, _, _, manifest = fixture_documents(); del manifest["bindings"]["isolatedRestoreEvidenceSha256"]; self.assertNotEqual(schema_result(manifest).returncode, 0)
        _, _, _, manifest = fixture_documents(); del manifest["bindings"]["candidateDaemonStopEvidenceSha256"]; self.assertNotEqual(schema_result(manifest).returncode, 0)
        _, _, _, manifest = fixture_documents(); del manifest["bindings"]["sourceDaemonStabilityEvidenceSha256"]; self.assertNotEqual(schema_result(manifest).returncode, 0)
        _, _, _, manifest = fixture_documents(); manifest["inventories"]["collection"]["candidateQualification"]["systemProfile"]["profileLinkText"] = "../system-42-link"; self.assertNotEqual(schema_result(manifest).returncode, 0)
        _, _, _, manifest = fixture_documents(); manifest["inventories"]["collection"]["candidateQualification"]["isolatedDockerDaemonArgv"].append("--debug"); self.assertNotEqual(schema_result(manifest).returncode, 0)

    def test_restore_binding_and_freshness_pair_are_fail_closed(self) -> None:
        _, _, _, manifest = fixture_documents()
        with self.assertRaisesRegex(ValueError, "restore evidence"): validate_manifest(manifest, expected_isolated_restore_evidence_sha256="f" * 64)
        with self.assertRaisesRegex(ValueError, "daemon stop evidence"): validate_manifest(manifest, expected_candidate_daemon_stop_evidence_sha256="f" * 64)
        with self.assertRaisesRegex(ValueError, "daemon stability evidence"): validate_manifest(manifest, expected_source_daemon_stability_evidence_sha256="f" * 64)
        with self.assertRaisesRegex(ValueError, "both current time"): validate_manifest(manifest, now=NOW)
        with self.assertRaisesRegex(ValueError, "both current time"): validate_manifest(manifest, collection_max_age_seconds=600)

    def test_builder_and_external_freshness_validator(self) -> None:
        desired, _, collection, _ = fixture_documents()
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = Path(temporary); root.chmod(0o700)
            desired_path = root / "desired.json"; runtime_path = root / "runtime.json"; collection_path = root / "collection.json"
            desired_path.write_text(json.dumps(raw_desired())); runtime_path.write_text(json.dumps(raw_runtime())); collection_path.write_text(json.dumps(collection))
            builder_base = [sys.executable, str(HERE / "build-vm-100-gate-c-manifest.py"), "--desired-inventory", str(desired_path), "--runtime-inventory", str(runtime_path), "--collection", str(collection_path), "--commit", COMMIT, "--compose-artifact-sha256", ARTIFACT, "--output-root", str(root), "--output-name", "manifest.json", "--expected-desired-inventory-sha256", digest(desired), "--expected-candidate-inventory-sha256", collection["candidateInventorySha256"], "--canonical-toplevel", TOPLEVEL, "--now", NOW, "--collection-max-age-seconds", "600"]
            missing = subprocess.run(builder_base, capture_output=True, text=True); self.assertNotEqual(missing.returncode, 0); self.assertIn("isolated-restore-evidence-sha256", missing.stderr)
            evidence_args = ["--isolated-restore-evidence-sha256", RESTORE, "--candidate-daemon-stop-evidence-sha256", STOP_EVIDENCE, "--source-daemon-stability-evidence-sha256", STABILITY_EVIDENCE]
            subprocess.run([*builder_base, *evidence_args], check=True, capture_output=True, text=True)
            expected_evidence_args = ["--expected-isolated-restore-evidence-sha256", RESTORE, "--expected-candidate-daemon-stop-evidence-sha256", STOP_EVIDENCE, "--expected-source-daemon-stability-evidence-sha256", STABILITY_EVIDENCE]
            subprocess.run([sys.executable, str(HERE / "validate-vm-100-gate-c.py"), str(root / "manifest.json"), "--expected-commit", COMMIT, "--expected-compose-artifact-sha256", ARTIFACT, "--expected-canonical-toplevel", TOPLEVEL, "--expected-desired-inventory-sha256", digest(desired), "--expected-candidate-inventory-sha256", collection["candidateInventorySha256"], *expected_evidence_args, "--now", NOW, "--collection-max-age-seconds", "600"], check=True, capture_output=True, text=True)
            validator_base = [sys.executable, str(HERE / "validate-vm-100-gate-c.py"), str(root / "manifest.json"), "--expected-commit", COMMIT, "--expected-compose-artifact-sha256", ARTIFACT, "--expected-canonical-toplevel", TOPLEVEL, "--expected-desired-inventory-sha256", digest(desired), "--expected-candidate-inventory-sha256", collection["candidateInventorySha256"], "--expected-candidate-daemon-stop-evidence-sha256", STOP_EVIDENCE, "--expected-source-daemon-stability-evidence-sha256", STABILITY_EVIDENCE, "--collection-max-age-seconds", "600"]
            mismatch = subprocess.run([*validator_base, "--expected-isolated-restore-evidence-sha256", "f" * 64, "--now", NOW], capture_output=True, text=True); self.assertNotEqual(mismatch.returncode, 0); self.assertIn("restore evidence", mismatch.stderr)
            failed = subprocess.run([*validator_base, "--expected-isolated-restore-evidence-sha256", RESTORE, "--now", "2026-08-13T00:00:00Z"], capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0); self.assertIn("stale", failed.stderr)


if __name__ == "__main__": unittest.main()
