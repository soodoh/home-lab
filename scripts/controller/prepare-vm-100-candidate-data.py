#!/usr/bin/env python3
"""Prepare the mounted VM 100 candidate data root with an isolated Docker daemon."""

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

from argparse import ArgumentParser
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import time
from types import SimpleNamespace
from typing import Any

from vm_100_execution import SAFE_JSON_NAME, TRANSFER_LOCK_PATH, acquire_transfer_lock, bounded_error, create_run_root, file_metrics, load_canonical_object, load_protected_bytes, open_exclusive, require_private_root, sha256_bytes, verify_exact_checkout, write_json
from vm_100_gate_c import (
    BACKUP_PATHS, CANONICAL_SERVICES, DESTINATION_ROOT, DOCKER_ROOT, ISOLATED_DOCKER_ARGV,
    ISOLATED_DOCKER_HOST, ISOLATED_DOCKER_ROOT, PROJECT, digest,
    expected_volume_names, project_desired_inventory, project_runtime_inventory,
    volume_destination,
)

FORMAT_STOP = "home-lab-vm-100-candidate-daemon-stop-evidence-v1"
FORMAT_STABILITY = "home-lab-vm-100-source-daemon-stability-evidence-v1"
RUNTIME_ROOT = "/run/vm-100-candidate-docker"
CONTAINERD_ROOT = f"{DESTINATION_ROOT}/var/lib/containerd"
CONTAINERD_STATE = f"{RUNTIME_ROOT}/containerd"
CONTAINERD_SOCKET = f"{CONTAINERD_STATE}/containerd.sock"
CONTAINERD_ARGV = (
    "/usr/bin/containerd", "--root", CONTAINERD_ROOT, "--state", CONTAINERD_STATE,
    "--address", CONTAINERD_SOCKET,
)
CTR_ARGV = ("/usr/bin/ctr", "--address", CONTAINERD_SOCKET, "version")
LIVE = {
    "source_docker": "/usr/bin/docker", "docker": "/usr/bin/docker",
    "findmnt": "/usr/bin/findmnt", "lsblk": "/usr/bin/lsblk",
    "containerd": "/usr/bin/containerd", "dockerd": "/usr/bin/dockerd",
    "ctr": "/usr/bin/ctr", "git": "/usr/bin/git", "node": "/usr/bin/node", "python": "/usr/bin/python3",
}
CLOSED_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def import_file(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load committed helper: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_inventory(desired: dict[str, Any], docker: str) -> dict[str, object]:
    helper = import_file("vm100_compose_model_inventory", Path(__file__).resolve().parent.parent / "compose-model-inventory.py")
    helper.LIVE_DOCKER = docker
    helper.SUBPROCESS_ENV = CLOSED_ENV
    raw = helper.runtime_inventory(SimpleNamespace(project_name=PROJECT))
    expected = expected_volume_names(desired)
    projected = project_runtime_inventory(raw, expected)
    services = raw.get("services")
    if raw.get("container_count") != 41 or raw.get("running_count") != 41 or not isinstance(services, dict) or set(services) != CANONICAL_SERVICES:
        raise SystemExit("source daemon must contain exactly the 41 running canonical services")
    if any(not isinstance(value, dict) or value.get("running") is not True for value in services.values()):
        raise SystemExit("all 41 source containers must remain running")
    gate_collector = import_file("vm100_gate_c_collector", Path(__file__).resolve().with_name("collect-vm-100-gate-c.py"))
    listed_result = subprocess.run([docker, "ps", "--all", "--format", "{{json .}}"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLOSED_ENV)
    try:
        identifiers = [str(json.loads(line)["ID"]) for line in listed_result.stdout.splitlines() if line]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise SystemExit("complete source container listing is malformed") from error
    inspect_result = subprocess.run([docker, "inspect", "--", *identifiers], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLOSED_ENV) if identifiers else None
    try:
        inspected = json.loads(inspect_result.stdout) if inspect_result is not None else []
    except json.JSONDecodeError as error:
        raise SystemExit("complete source container inspection is malformed") from error
    if not isinstance(inspected, list):
        raise SystemExit("complete source container inspection is malformed")
    safe_containers, writers, mounts = gate_collector.safe_container_metadata(inspected, desired)
    if any(container["running"] is not True for container in safe_containers):
        raise SystemExit("all 41 source containers must remain running")
    info_result = subprocess.run([docker, "info", "--format", "{{json .}}"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLOSED_ENV)
    try:
        info = json.loads(info_result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("source Docker info is not JSON") from error
    if not isinstance(info, dict) or info.get("DockerRootDir") != DOCKER_ROOT:
        raise SystemExit("source Docker root differs from /var/lib/docker")
    # This projection intentionally excludes environment and command fields.
    safe_services = {
        name: {
            "containerName": value.get("container_name"),
            "running": value.get("running"),
            "health": value.get("health"),
            "image": value.get("image"),
            "imageId": value.get("image_id"),
            "ports": value.get("ports"),
            "binds": value.get("binds"),
            "volumes": value.get("volumes"),
            "devices": value.get("devices"),
            "networkMode": value.get("network_mode"),
            "networks": value.get("networks"),
            "healthcheckSha256": value.get("healthcheck_sha256"),
            "healthcheckFieldsSha256": value.get("healthcheck_fields_sha256"),
        }
        for name, value in sorted(services.items())
    }
    return {"sourceDockerRoot": DOCKER_ROOT, "runtime": projected, "containerCount": 41, "runningCount": 41, "services": safe_services, "containers": safe_containers, "writers": writers, "mounts": mounts}


def physical(logical: str, fixture_root: Path | None) -> Path:
    return Path(logical) if fixture_root is None else fixture_root / logical.removeprefix("/")


def verify_candidate_preflight(canonical_toplevel: str, commands: dict[str, str], fixture_root: Path | None) -> None:
    collector = import_file("vm100_candidate_inventory_collector", Path(__file__).resolve().with_name("collect-vm-100-candidate-volume-inventory.py"))
    candidate_root = physical(DESTINATION_ROOT, fixture_root)
    collector.verify_system_profile(candidate_root, canonical_toplevel)
    by_id = physical(collector.CANDIDATE_BY_ID, fixture_root)
    try:
        resolved = by_id.resolve(strict=True)
    except FileNotFoundError as error:
        raise SystemExit("exact candidate by-id is missing") from error
    def closed_json(command: str, argv: list[str]) -> Any:
        result = subprocess.run([command, *argv], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLOSED_ENV)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SystemExit(f"command returned invalid JSON: {command}") from error
    collector.run_json = closed_json
    mount = closed_json(commands["findmnt"], ["--json", "--target", DESTINATION_ROOT, "--output", "SOURCE,FSTYPE,TARGET"])
    filesystems = mount.get("filesystems") if isinstance(mount, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise SystemExit("candidate root mount identity is ambiguous")
    source, filesystem, target = (filesystems[0].get(key) for key in ("source", "fstype", "target"))
    if not isinstance(source, str) or not source.startswith("/dev/") or source.startswith("/dev/disk/by-id/") or not isinstance(filesystem, str) or filesystem in {"tmpfs", "devtmpfs", "overlay"} or target != DESTINATION_ROOT:
        raise SystemExit("candidate root is not the exact mounted block filesystem")
    collector.verify_candidate_device(commands["lsblk"], resolved, source)


def reject_candidate_nested_mounts(findmnt: str, fixture_root: Path | None) -> None:
    target = physical(DESTINATION_ROOT, fixture_root)
    result = subprocess.run([findmnt, "--json", "--submounts", "--target", str(target), "--output", "ID,SOURCE,FSTYPE,TARGET"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLOSED_ENV)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("candidate recursive mount listing is malformed") from error
    filesystems = value.get("filesystems") if isinstance(value, dict) else None
    if not isinstance(filesystems, list) or not filesystems:
        raise SystemExit("candidate recursive mount listing is empty")
    pending = list(filesystems)
    exact = str(target).rstrip("/")
    while pending:
        item = pending.pop()
        if not isinstance(item, dict) or not isinstance(item.get("target"), str) or not isinstance(item.get("children", []), list):
            raise SystemExit("candidate recursive mount listing is malformed")
        observed = item["target"].rstrip("/")
        if observed != exact and observed.startswith(exact + "/"):
            raise SystemExit(f"nested mount exists below {DESTINATION_ROOT}: {item['target']}")
        pending.extend(item.get("children", []))


def ensure_candidate_data_roots(fixture_root: Path | None) -> None:
    candidate = physical(DESTINATION_ROOT, fixture_root)
    candidate_value = candidate.stat(follow_symlinks=False)
    if not stat.S_ISDIR(candidate_value.st_mode) or stat.S_ISLNK(candidate_value.st_mode):
        raise SystemExit("candidate root is not a real directory")
    current = candidate
    for part in ("var", "lib"):
        current /= part
        value = current.stat(follow_symlinks=False)
        if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode) or value.st_dev != candidate_value.st_dev:
            raise SystemExit("candidate data parent is unsafe or crosses a filesystem")
    expected = (("containerd", 0o700), ("docker", 0o710))
    for name, mode in expected:
        root = current / name
        try:
            value = root.stat(follow_symlinks=False)
        except FileNotFoundError:
            root.mkdir(mode=0o700)
            descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fchmod(descriptor, mode)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            value = root.stat(follow_symlinks=False)
        if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode) or value.st_dev != candidate_value.st_dev or value.st_uid != os.geteuid() or value.st_gid != os.getegid() or stat.S_IMODE(value.st_mode) != mode:
            raise SystemExit(f"candidate {name} root identity, ownership, or mode is unsafe")
    docker = current / "docker"
    live = physical(DOCKER_ROOT, fixture_root)
    docker_resolved = docker.resolve(strict=True)
    live_resolved = live.resolve(strict=True)
    if docker_resolved == live_resolved or docker_resolved in live_resolved.parents or live_resolved in docker_resolved.parents:
        raise SystemExit("isolated Docker root overlaps the live Docker root")

    expected_uid = os.geteuid() if fixture_root is not None else 1000
    expected_gid = os.getegid() if fixture_root is not None else 1000
    data_path = candidate
    for name, mode, uid, gid in (("home", 0o755, os.geteuid(), os.getegid()), ("docker", 0o700, expected_uid, expected_gid), ("hass", 0o755, expected_uid, expected_gid)):
        data_path /= name
        try:
            value = data_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            data_path.mkdir(mode=mode)
            descriptor = os.open(data_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fchmod(descriptor, mode)
                if fixture_root is None:
                    os.fchown(descriptor, uid, gid)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            value = data_path.stat(follow_symlinks=False)
        if (stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode) or value.st_dev != candidate_value.st_dev
                or value.st_uid != uid or value.st_gid != gid or stat.S_IMODE(value.st_mode) != mode):
            raise SystemExit("candidate Home Assistant destination identity, ownership, or mode is unsafe")


def create_runtime_root(fixture_root: Path | None) -> Path:
    root = physical(RUNTIME_ROOT, fixture_root)
    if root.exists() or root.is_symlink():
        raise SystemExit("isolated runtime root must not already exist")
    root.mkdir(mode=0o700, parents=True)
    (root / "containerd").mkdir(mode=0o700)
    value = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o700 or value.st_uid != os.geteuid():
        raise SystemExit("isolated runtime root is not private")
    return root


def start_child(policy_argv: tuple[str, ...], executable: str, log: Any, fixture_root: Path | None) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(list(policy_argv), executable=executable, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=CLOSED_ENV, start_new_session=True)
    if fixture_root is not None and policy_argv == ISOLATED_DOCKER_ARGV:
        proc = fixture_root / f"proc/{process.pid}"
        proc.mkdir(parents=True, exist_ok=True)
        (proc / "cmdline").write_bytes(b"\0".join(item.encode() for item in policy_argv) + b"\0")
        pidfile = physical(f"{RUNTIME_ROOT}/docker.pid", fixture_root)
        pidfile.write_text(f"{process.pid}\n", encoding="ascii")
        pidfile.chmod(0o600)
    return process


def run_candidate_docker(command: str, argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run([command, "--host", ISOLATED_DOCKER_HOST, *argv], check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLOSED_ENV)


def wait_containerd_ready(ctr: str, process: subprocess.Popen[bytes], fixture_root: Path | None, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    socket = physical(CONTAINERD_SOCKET, fixture_root)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SystemExit("isolated containerd exited before readiness")
        try:
            socket_value = socket.stat(follow_symlinks=False)
        except FileNotFoundError:
            socket_value = None
        if socket_value is not None and stat.S_ISSOCK(socket_value.st_mode):
            result = subprocess.run(list(CTR_ARGV), executable=ctr, check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLOSED_ENV)
            if result.returncode == 0 and process.poll() is None:
                return
        time.sleep(0.05)
    raise SystemExit("isolated containerd readiness timed out")


def wait_ready(docker: str, process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SystemExit("isolated dockerd exited before readiness")
        result = run_candidate_docker(docker, ["info", "--format", "{{json .}}"], check=False)
        if result.returncode == 0:
            try:
                value = json.loads(result.stdout)
            except json.JSONDecodeError:
                value = None
            if isinstance(value, dict) and value.get("DockerRootDir") == ISOLATED_DOCKER_ROOT:
                return
        time.sleep(0.05)
    raise SystemExit("isolated dockerd readiness timed out")


def verify_empty_candidate_daemon(docker: str) -> None:
    info = run_candidate_docker(docker, ["info", "--format", "{{json .}}"])
    try:
        value = json.loads(info.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("candidate Docker info is malformed") from error
    counts = ("Containers", "ContainersRunning", "ContainersPaused", "ContainersStopped")
    if not isinstance(value, dict) or value.get("DockerRootDir") != ISOLATED_DOCKER_ROOT or any(value.get(key) != 0 for key in counts):
        raise SystemExit("candidate daemon root or zero-container state differs")
    for argv, label in ((["ps", "--all", "--quiet"], "containers"), (["image", "ls", "--quiet"], "images"), (["network", "ls", "--filter", "type=custom", "--quiet"], "custom networks")):
        if run_candidate_docker(docker, argv).stdout != "":
            raise SystemExit(f"candidate daemon contains {label}")


def prepare_volumes(docker: str, desired: dict[str, Any]) -> None:
    expected = expected_volume_names(desired)
    engines = sorted(f"{PROJECT}_{name}" for name in expected)
    listed_result = run_candidate_docker(docker, ["volume", "ls", "--format", "{{json .}}"])
    listed = []
    try:
        for line in listed_result.stdout.splitlines():
            if line:
                value = json.loads(line)
                if not isinstance(value, dict) or not isinstance(value.get("Name"), str):
                    raise ValueError
                listed.append(value["Name"])
    except (json.JSONDecodeError, ValueError) as error:
        raise SystemExit("candidate volume listing is malformed") from error
    if len(listed) != len(set(listed)) or not set(listed).issubset(engines):
        raise SystemExit("isolated candidate daemon contains an extra or duplicate volume")
    for logical in expected:
        engine = f"{PROJECT}_{logical}"
        if engine not in listed:
            result = run_candidate_docker(docker, ["volume", "create", "--driver", "local", "--label", f"com.docker.compose.project={PROJECT}", "--label", f"com.docker.compose.volume={logical}", engine])
            if result.stdout != f"{engine}\n":
                raise SystemExit("candidate volume creation returned an unexpected identity")
    final = run_candidate_docker(docker, ["volume", "ls", "--format", "{{json .}}"])
    try:
        names = sorted(json.loads(line)["Name"] for line in final.stdout.splitlines() if line)
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise SystemExit("final candidate volume listing is malformed") from error
    if names != engines:
        raise SystemExit("candidate daemon does not contain exactly 33 canonical volumes")
    for logical in expected:
        engine = f"{PROJECT}_{logical}"
        inspected = run_candidate_docker(docker, ["volume", "inspect", engine])
        try:
            values = json.loads(inspected.stdout)
        except json.JSONDecodeError as error:
            raise SystemExit("candidate volume inspection is malformed") from error
        exact_labels = {"com.docker.compose.project": PROJECT, "com.docker.compose.volume": logical}
        if not isinstance(values, list) or len(values) != 1:
            raise SystemExit(f"candidate volume inspection is ambiguous: {engine}")
        value = values[0]
        if not isinstance(value, dict) or value.get("Name") != engine or value.get("Driver") != "local" or (value.get("Options") or {}) != {} or value.get("Labels") != exact_labels or value.get("Mountpoint") != volume_destination(engine):
            raise SystemExit(f"existing candidate volume identity differs: {engine}")


def stop_child(process: subprocess.Popen[bytes] | None, timeout: float) -> dict[str, object]:
    result: dict[str, object] = {"started": process is not None, "termSent": False, "killSent": False, "exitCode": None, "pidGone": process is None, "observationError": None}
    if process is None:
        return result
    errors: list[str] = []
    try:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                result["termSent"] = True
            except OSError as error:
                errors.append(str(error))
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    result["killSent"] = True
                except OSError as error:
                    errors.append(str(error))
                try:
                    process.wait(timeout=timeout)
                except (subprocess.TimeoutExpired, OSError) as error:
                    errors.append(str(error))
    except BaseException as error:
        errors.append(str(error))
    try:
        result["exitCode"] = process.returncode
        result["pidGone"] = process.poll() is not None
    except BaseException as error:
        errors.append(str(error))
        result["pidGone"] = False
    result["observationError"] = bounded_error("; ".join(errors) if errors else None)
    return result


def stop_children(dockerd: subprocess.Popen[bytes] | None, containerd: subprocess.Popen[bytes] | None, timeout: float) -> tuple[dict[str, object], dict[str, object]]:
    results: list[dict[str, object]] = []
    for child in (dockerd, containerd):
        try:
            results.append(stop_child(child, timeout))
        except BaseException as error:
            results.append({"started": child is not None, "termSent": False, "killSent": False, "exitCode": None, "pidGone": False, "observationError": bounded_error(error)})
    return results[0], results[1]


def remove_runtime(root: Path) -> bool:
    try:
        root_value = root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(root_value.st_mode) or root_value.st_uid != os.geteuid() or stat.S_IMODE(root_value.st_mode) & 0o077:
            return False
        for current, directories, files in os.walk(root, topdown=False, followlinks=False):
            for name in [*directories, *files]:
                path = Path(current) / name
                value = path.stat(follow_symlinks=False)
                if stat.S_ISLNK(value.st_mode):
                    return False
        shutil.rmtree(root)
        return not root.exists()
    except OSError:
        return False


def daemon_stop_passed(candidate_sha: str | None, cleanup_ok: bool, qualification_failure: BaseException | None) -> bool:
    return candidate_sha is not None and cleanup_ok and qualification_failure is None


def validate_stop_evidence(value: dict[str, object]) -> None:
    keys = {"format", "completedAt", "result", "failureStage", "failureReason", "candidateInventorySha256", "isolatedDockerArgvSha256", "containerdArgvSha256", "dockerd", "containerd", "socketAbsent", "runtimeFilesRemoved", "logs"}
    if set(value) != keys or value.get("format") != FORMAT_STOP or value.get("result") not in {"passed", "failed"}:
        raise ValueError("candidate daemon stop evidence envelope differs")
    if value["result"] == "passed":
        if value.get("candidateInventorySha256") is None or value.get("failureStage") is not None or value.get("failureReason") is not None or value.get("isolatedDockerArgvSha256") != digest(list(ISOLATED_DOCKER_ARGV)) or value.get("containerdArgvSha256") != digest(list(CONTAINERD_ARGV)) or value.get("socketAbsent") is not True or value.get("runtimeFilesRemoved") is not True:
            raise ValueError("candidate daemon cleanup proof failed")
        for name in ("dockerd", "containerd"):
            item = value[name]
            if not isinstance(item, dict) or item.get("started") is not True or item.get("pidGone") is not True or item.get("observationError") is not None:
                raise ValueError("candidate daemon PID cleanup proof failed")


def validate_stability_evidence(value: dict[str, object]) -> None:
    keys = {"format", "completedAt", "result", "failureStage", "failureReason", "desiredInventorySha256", "beforeInventorySha256", "afterInventorySha256", "exactEquality", "containerCount", "runningCount", "sourceDockerRoot", "observationError"}
    if set(value) != keys or value.get("format") != FORMAT_STABILITY or value.get("result") not in {"passed", "failed"}:
        raise ValueError("source daemon stability evidence differs")
    if value["exactEquality"] and value.get("beforeInventorySha256") != value.get("afterInventorySha256"):
        raise ValueError("source daemon exact-equality evidence contradicts its hashes")
    if value["result"] == "passed" and (value.get("exactEquality") is not True or value.get("containerCount") != 41 or value.get("runningCount") != 41 or value.get("sourceDockerRoot") != DOCKER_ROOT or value.get("failureStage") is not None or value.get("failureReason") is not None or value.get("observationError") is not None):
        raise ValueError("source daemon stability pass differs")


def parse_args() -> Any:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--desired-inventory", required=True, type=Path)
    parser.add_argument("--expected-desired-inventory-sha256", required=True)
    parser.add_argument("--canonical-toplevel", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--compose-artifact", required=True, type=Path)
    parser.add_argument("--expected-compose-artifact-sha256", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--candidate-inventory-name", required=True)
    parser.add_argument("--candidate-daemon-stop-evidence-name", required=True)
    parser.add_argument("--source-daemon-stability-evidence-name", required=True)
    parser.add_argument("--collected-at")
    parser.add_argument("--authority", required=True)
    parser.add_argument("--readiness-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--stop-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--fixture-root", type=Path)
    for command in LIVE:
        parser.add_argument(f"--{command.replace('_', '-')}-command")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    os.umask(0o077)
    if args.authority != "arch":
        raise SystemExit("candidate preparation requires independently asserted arch authority")
    overrides = {name: getattr(args, f"{name}_command") for name in LIVE}
    if args.fixture_root is None:
        if os.geteuid() != 0:
            raise SystemExit("candidate preparation must run as root")
        if any(overrides.values()):
            raise SystemExit("live mode forbids executable overrides")
        commands = LIVE
        fixture_root = None
        lock_path = Path(TRANSFER_LOCK_PATH)
    else:
        if not all(overrides.values()):
            raise SystemExit("fixture mode requires every explicit executable")
        fixture_root = args.fixture_root.resolve(strict=True)
        commands = overrides
        lock_path = fixture_root / TRANSFER_LOCK_PATH.removeprefix("/")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    if args.readiness_timeout_seconds <= 0 or args.stop_timeout_seconds <= 0:
        raise SystemExit("timeouts must be positive")
    canonical_roots = (DOCKER_ROOT, "/home/docker/hass", DESTINATION_ROOT, *BACKUP_PATHS)
    forbidden_output = tuple(physical(path, fixture_root) for path in canonical_roots)
    output_parent = require_private_root(args.output_root, forbidden_output)
    output_names = (args.candidate_inventory_name, args.candidate_daemon_stop_evidence_name, args.source_daemon_stability_evidence_name)
    if any(SAFE_JSON_NAME.fullmatch(name) is None for name in output_names) or len(set(output_names)) != 3:
        raise SystemExit("candidate preparation output names must be distinct safe JSON names")
    raw_desired, _ = load_canonical_object(args.desired_inventory, "desired inventory")
    desired = project_desired_inventory(raw_desired)
    if digest(desired) != args.expected_desired_inventory_sha256:
        raise SystemExit("expected desired inventory digest differs")
    if re.fullmatch(r"[0-9a-f]{64}", args.expected_compose_artifact_sha256) is None:
        raise SystemExit("expected Compose artifact SHA-256 is invalid")
    artifact_raw = load_protected_bytes(args.compose_artifact, "Compose artifact")
    if sha256_bytes(artifact_raw) != args.expected_compose_artifact_sha256:
        raise SystemExit("Compose artifact exact file SHA-256 differs")
    verify_exact_checkout(commands["git"], args.expected_commit, CLOSED_ENV)
    lock = acquire_transfer_lock(lock_path)
    try:
        output_root = create_run_root(output_parent, "vm-100-candidate")
    except BaseException:
        os.close(lock)
        raise
    before: dict[str, object] | None = None
    after: dict[str, object] | None = None
    runtime_root: Path | None = None
    containerd: subprocess.Popen[bytes] | None = None
    dockerd: subprocess.Popen[bytes] | None = None
    candidate_sha: str | None = None
    failure: BaseException | None = None
    failure_stage: str | None = "authority-validation"
    after_error: BaseException | None = None
    dockerd_stop = stop_child(None, args.stop_timeout_seconds)
    containerd_stop = stop_child(None, args.stop_timeout_seconds)
    run_id = f"{os.getpid()}-{dt.datetime.now(dt.UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    containerd_log_name = f"candidate-containerd-{run_id}.log"
    dockerd_log_name = f"candidate-dockerd-{run_id}.log"
    collector_log_name = f"candidate-inventory-collector-{run_id}.log"
    try:
        with open_exclusive(output_root, containerd_log_name) as containerd_log, open_exclusive(output_root, dockerd_log_name) as dockerd_log, open_exclusive(output_root, collector_log_name) as collector_log:
            try:
                failure_stage = "checkout-validation"
                verify_exact_checkout(commands["git"], args.expected_commit, CLOSED_ENV)
                authority = Path(__file__).resolve().with_name("check-vm-100-authority.js")
                subprocess.run([commands["node"], str(authority), "--require-ordinary-mutation"], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLOSED_ENV)
                failure_stage = "source-before-observation"
                before = source_inventory(desired, commands["source_docker"])
                failure_stage = "candidate-preflight"
                verify_candidate_preflight(args.canonical_toplevel, commands, fixture_root)
                # Reject every submount before creating or traversing candidate
                # daemon data roots, then recheck after their validation.
                reject_candidate_nested_mounts(commands["findmnt"], fixture_root)
                ensure_candidate_data_roots(fixture_root)
                reject_candidate_nested_mounts(commands["findmnt"], fixture_root)
                failure_stage = "runtime-start"
                runtime_root = create_runtime_root(fixture_root)
                containerd = start_child(CONTAINERD_ARGV, commands["containerd"], containerd_log, fixture_root)
                failure_stage = "containerd-readiness"
                wait_containerd_ready(commands["ctr"], containerd, fixture_root, args.readiness_timeout_seconds)
                failure_stage = "dockerd-readiness"
                reject_candidate_nested_mounts(commands["findmnt"], fixture_root)
                dockerd = start_child(ISOLATED_DOCKER_ARGV, commands["dockerd"], dockerd_log, fixture_root)
                wait_ready(commands["docker"], dockerd, args.readiness_timeout_seconds)
                verify_empty_candidate_daemon(commands["docker"])
                failure_stage = "candidate-volume-preparation"
                prepare_volumes(commands["docker"], desired)
                failure_stage = "candidate-inventory"
                collector = Path(__file__).resolve().with_name("collect-vm-100-candidate-volume-inventory.py")
                collector_argv = [commands["python"], str(collector), "--desired-inventory", str(args.desired_inventory), "--expected-desired-inventory-sha256", args.expected_desired_inventory_sha256, "--canonical-toplevel", args.canonical_toplevel, "--output-root", str(output_root), "--output-name", args.candidate_inventory_name]
                if args.collected_at:
                    collector_argv.extend(["--collected-at", args.collected_at])
                if fixture_root is not None:
                    collector_argv.extend(["--fixture-root", str(fixture_root), "--docker-command", commands["docker"], "--findmnt-command", commands["findmnt"], "--lsblk-command", commands["lsblk"]])
                result = subprocess.run(collector_argv, stdin=subprocess.DEVNULL, stdout=collector_log, stderr=subprocess.STDOUT, env=CLOSED_ENV)
                if result.returncode != 0:
                    raise SystemExit("candidate inventory collector failed")
                candidate_value, _ = load_canonical_object(output_root / args.candidate_inventory_name, "candidate inventory")
                candidate_sha = digest(candidate_value)
                failure_stage = None
            except BaseException as error:
                failure = error
            finally:
                # This helper independently attempts both children and aggregates their errors.
                dockerd_stop, containerd_stop = stop_children(dockerd, containerd, args.stop_timeout_seconds)
                for log in (containerd_log, dockerd_log, collector_log):
                    log.flush(); os.fsync(log.fileno())
        socket_absent = not physical(f"{RUNTIME_ROOT}/docker.sock", fixture_root).exists() and not physical(CONTAINERD_SOCKET, fixture_root).exists()
        runtime_removed = not physical(RUNTIME_ROOT, fixture_root).exists() or (socket_absent and remove_runtime(physical(RUNTIME_ROOT, fixture_root)))
        qualification_failure = failure
        try:
            after = source_inventory(desired, commands["source_docker"])
        except BaseException as error:
            after_error = error
            if failure is None:
                failure, failure_stage = error, "source-after-observation"
        timestamp = args.collected_at or dt.datetime.now(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        exact = before is not None and after is not None and before == after
        cleanup_ok = bool(dockerd_stop["pidGone"] and containerd_stop["pidGone"] and dockerd_stop["observationError"] is None and containerd_stop["observationError"] is None and socket_absent and runtime_removed)
        stop_passed = daemon_stop_passed(candidate_sha, cleanup_ok, qualification_failure)
        logs = {
            "containerd": {"name": containerd_log_name, "metrics": file_metrics(output_root / containerd_log_name)},
            "dockerd": {"name": dockerd_log_name, "metrics": file_metrics(output_root / dockerd_log_name)},
            "collector": {"name": collector_log_name, "metrics": file_metrics(output_root / collector_log_name)},
        }
        stop = {"format": FORMAT_STOP, "completedAt": timestamp, "result": "passed" if stop_passed else "failed", "failureStage": None if stop_passed else (failure_stage or "cleanup"), "failureReason": None if stop_passed else bounded_error(failure or "isolated daemon cleanup proof failed"), "candidateInventorySha256": candidate_sha, "isolatedDockerArgvSha256": digest(list(ISOLATED_DOCKER_ARGV)), "containerdArgvSha256": digest(list(CONTAINERD_ARGV)), "dockerd": dockerd_stop, "containerd": containerd_stop, "socketAbsent": socket_absent, "runtimeFilesRemoved": runtime_removed, "logs": logs}
        stability_passed = exact and after is not None and after.get("containerCount") == 41 and after.get("runningCount") == 41 and after.get("sourceDockerRoot") == DOCKER_ROOT
        stability = {"format": FORMAT_STABILITY, "completedAt": timestamp, "result": "passed" if stability_passed else "failed", "failureStage": None if stability_passed else ("source-after-observation" if after_error else "source-stability"), "failureReason": None if stability_passed else bounded_error(after_error or "source daemon inventory changed or was unavailable"), "desiredInventorySha256": digest(desired), "beforeInventorySha256": digest(before) if before is not None else None, "afterInventorySha256": digest(after) if after is not None else None, "exactEquality": exact, "containerCount": after.get("containerCount") if after is not None else None, "runningCount": after.get("runningCount") if after is not None else None, "sourceDockerRoot": after.get("sourceDockerRoot") if after is not None else None, "observationError": bounded_error(after_error)}
        validate_stop_evidence(stop)
        validate_stability_evidence(stability)
        write_json(output_root, args.candidate_daemon_stop_evidence_name, stop)
        write_json(output_root, args.source_daemon_stability_evidence_name, stability)
    finally:
        os.close(lock)
    print(f"vm100_run_root={output_root}", file=sys.stderr if failure is not None or not stability_passed or not stop_passed else sys.stdout)
    print(f"vm100_candidate_stop_evidence={output_root / args.candidate_daemon_stop_evidence_name}", file=sys.stderr if failure is not None or not stop_passed else sys.stdout)
    print(f"vm100_source_stability_evidence={output_root / args.source_daemon_stability_evidence_name}", file=sys.stderr if failure is not None or not stability_passed else sys.stdout)
    if failure is not None:
        raise failure
    if not stability_passed:
        raise SystemExit("source daemon inventory changed during candidate preparation")
    if not stop_passed:
        raise SystemExit("isolated daemon cleanup proof failed")


if __name__ == "__main__":
    main()
