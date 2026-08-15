#!/usr/bin/env python3
"""Install the qualified VM 100 candidate through the signed ephemeral Nix transport."""

import argparse
import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
COMMON_RUNNER = ROOT / "scripts/controller/run-vm-100-ephemeral-inspection.py"

def load_common(path: Path):
    loader = importlib.machinery.SourceFileLoader("vm100_ephemeral_common_runner", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module

common = load_common(COMMON_RUNNER)
helper = sys.modules["vm_100_ephemeral"]

FORMAT = "home-lab-vm-100-production-install-authorization-v1"
HOST_FORMAT = "home-lab-vm-100-production-install-host-attestation-v1"
EVIDENCE_FORMAT = "home-lab-vm-100-production-install-evidence-v1"
CLEANUP_FORMAT = "home-lab-vm-100-production-install-cleanup-v1"
CONFIRMATION = "install-production-vm-100-scsi2-reviewed"
DEVICE = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi2"
SERIAL = "QUAL-NIXOS-128G"
SIZE = 137438953472
TARGET = Path("/mnt/vm-100-candidate")
DOCKER = "/usr/bin/docker"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STORE_PATH = re.compile(r"^/nix/store/[0-9a-df-np-sv-z]{32}-[^/\x00]+$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CLEAN_ENV = {"HOME": "/root", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inspection-request", "export-request", "protected-disks", "manifest", "bootstrap", "export", "transport-qualification-evidence", "qualified-install-evidence", "qualified-cold-boot-evidence", "production-inspection-evidence", "production-host-attestation", "authorization", "output-root"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--retry-cleanup", type=Path)
    parser.add_argument("--confirmation", required=True)
    for name in ("runner-sha256", "common-runner-sha256", "helper-sha256", "manifest-sha256", "bootstrap-sha256", "export-sha256", "authorization-sha256", "host-attestation-sha256", "qualified-install-evidence-sha256", "qualified-cold-boot-evidence-sha256", "production-inspection-evidence-sha256"):
        parser.add_argument(f"--expected-{name}", required=True)
    parser.add_argument("--expected-retry-cleanup-sha256")
    parser.add_argument("--expected-trusted-public-key", required=True)
    return parser.parse_args()


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def exact_sha(value: str, label: str) -> str:
    if SHA256.fullmatch(value or "") is None:
        raise ValueError(f"{label} SHA-256 differs")
    return value


def validate_authorization(value: dict[str, Any]) -> dict[str, Any]:
    keys = {
        "candidateToplevel", "confirmation", "device", "diskoScript", "format", "hostAttestationSha256",
        "mode", "nixosInstall", "productionInspectionEvidenceSha256", "qualifiedColdBootEvidenceSha256",
        "qualifiedCommit", "qualifiedInstallEvidenceSha256", "serial", "sizeBytes", "transportCommit",
        "transportManifestSha256", "transportQualificationEvidenceSha256", "vmId",
    }
    helper.exact_keys(value, keys, "production install authorization")
    if (value["format"] != FORMAT or value["confirmation"] != CONFIRMATION or value["mode"] != "install"
            or value["vmId"] != 100 or value["device"] != DEVICE or value["serial"] != SERIAL or value["sizeBytes"] != SIZE):
        raise ValueError("production install authorization target differs")
    for key in ("hostAttestationSha256", "productionInspectionEvidenceSha256", "qualifiedColdBootEvidenceSha256", "qualifiedInstallEvidenceSha256", "transportManifestSha256", "transportQualificationEvidenceSha256"):
        exact_sha(value[key], key)
    for key in ("candidateToplevel", "diskoScript"):
        if STORE_PATH.fullmatch(value[key] or "") is None:
            raise ValueError("production install authorization store path differs")
    if re.fullmatch(r"/nix/store/[0-9a-df-np-sv-z]{32}-nixos-install/bin/nixos-install", value["nixosInstall"] or "") is None:
        raise ValueError("production nixos-install executable path differs")
    for key in ("qualifiedCommit", "transportCommit"):
        if re.fullmatch(r"[0-9a-f]{40}", value[key] or "") is None:
            raise ValueError("production install authorization commit differs")
    return value


def validate_host(value: dict[str, Any], authorization: dict[str, Any], observed_uuid: str) -> None:
    keys = {"bios", "bootOrder", "candidateSerial", "candidateSizeBytes", "collectedAt", "format", "machine", "productUuid", "pveConfigSha256", "result", "status", "transportCommit", "vmId"}
    helper.exact_keys(value, keys, "production install host attestation")
    if (value["format"] != HOST_FORMAT or value["vmId"] != 100 or value["status"] != "running" or value["result"] != "passed"
            or value["bios"] != "seabios" or value["machine"] != "q35" or value["bootOrder"] != "scsi0;net0"
            or value["candidateSerial"] != SERIAL or value["candidateSizeBytes"] != SIZE
            or value["transportCommit"] != authorization["transportCommit"] or value["productUuid"] != observed_uuid):
        raise ValueError("production host-attested identity differs")


def docker_inventory() -> list[str]:
    result = subprocess.run([DOCKER, "ps", "--format", "{{.Names}}"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLEAN_ENV, timeout=30)
    if result.returncode != 0 or result.stderr:
        raise ValueError("production Docker inventory failed")
    names = sorted(result.stdout.decode("utf-8", "strict").splitlines())
    if len(names) != 41 or len(set(names)) != 41:
        raise ValueError("production running Docker inventory differs")
    return names


def write_output(directory_fd: int, name: str, value: dict[str, Any]) -> None:
    common.write_evidence(directory_fd, name, value)


def write_diagnostic(root: Path, name: str, data: bytes) -> None:
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(directory)


def run_child(argv: list[str], env: dict[str, str], timeout: int) -> tuple[int, bytes, bytes]:
    child = subprocess.Popen([common.TOOLS["unshare"], "--net", "--", *argv], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True)
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        raise ValueError("production install child timed out")
    if not common.process_group_absent(child):
        raise ValueError("production install child process group remains")
    return child.returncode, stdout, stderr


def installed_observation() -> dict[str, Any]:
    value = common.json_command("lsblk", ["--bytes", "--json", "--output", "PATH,TYPE,SIZE,SERIAL,FSTYPE,PARTLABEL,MOUNTPOINTS", DEVICE])
    devices = value.get("blockdevices")
    if not isinstance(devices, list) or len(devices) != 4:
        raise ValueError("installed candidate partition shape differs")
    disk, *partitions = devices
    labels = sorted(item.get("partlabel") for item in partitions)
    if (disk.get("type") != "disk" or disk.get("size") != SIZE or disk.get("serial") not in {SERIAL, "drive-scsi2"}
            or labels != ["disk-vm100-root-ESP", "disk-vm100-root-bios", "disk-vm100-root-root"]
            or any(item.get("mountpoints") not in (None, [], [None]) for item in devices)):
        raise ValueError("installed candidate identity, partitions, or mounts differ")
    return {"byId": DEVICE, "partitionLabels": labels, "serial": SERIAL, "sizeBytes": SIZE}


def main() -> None:
    args = arguments()
    os.umask(0o077)
    failure: Exception | None = None
    output_fd: int | None = None
    output_identity = None
    mounted_nix = False
    created_nix = False
    target_mounted = False
    bootstrap_copy: int | None = None
    export_copy: int | None = None
    before_boot: str | None = None
    docker_before: list[str] | None = None
    authorization: dict[str, Any] | None = None
    manifest: dict[str, Any] | None = None
    installed: dict[str, Any] | None = None
    install_stage = "preflight"
    input_state = "blank"
    try:
        if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("production install runner requires root on x86_64-linux")
        if args.confirmation != CONFIRMATION or any(name.startswith("NIX_") or name == "VM100_CANDIDATE_INSTALL_CONFIRMED" for name in os.environ):
            raise ValueError("production install confirmation or environment differs")
        for path in (Path(__file__), COMMON_RUNNER):
            if not path.is_file():
                raise ValueError("fixed runner source is unavailable")
        if (file_sha(Path(__file__)) != exact_sha(args.expected_runner_sha256, "runner")
                or file_sha(COMMON_RUNNER) != exact_sha(args.expected_common_runner_sha256, "common runner")
                or hashlib.sha256(common._HELPER_BYTES).hexdigest() != exact_sha(args.expected_helper_sha256, "helper")):
            raise ValueError("independently expected runner source identity differs")
        protected_paths = [args.inspection_request, args.export_request, args.protected_disks, args.manifest, args.bootstrap, args.export,
            args.transport_qualification_evidence, args.qualified_install_evidence, args.qualified_cold_boot_evidence,
            args.production_inspection_evidence, args.production_host_attestation, args.authorization]
        if args.retry_cleanup is not None:
            protected_paths.append(args.retry_cleanup)
        if any(not path.is_absolute() for path in protected_paths):
            raise ValueError("production install inputs must use absolute paths")
        if (args.retry_cleanup is None) != (args.expected_retry_cleanup_sha256 is None):
            raise ValueError("retry cleanup path and independent hash must be supplied together")
        request, request_raw = helper.load_canonical(args.inspection_request, "inspection request", owner=0, maximum=16 * 1024)
        request = helper.validate_inspection_request(request)
        export_request, export_request_raw = helper.load_canonical(args.export_request, "export request", owner=0, maximum=64 * 1024)
        export_request = helper.validate_export_request(export_request)
        if export_request["mode"] != helper.LIVE_MODE:
            raise ValueError("production install requires the qualified live transport")
        protected, protected_raw = helper.load_canonical(args.protected_disks, "protected disk input", owner=0, maximum=16 * 1024)
        if set(protected) != {"format", "gamesDevice"} or protected["format"] != common.PROTECTED_DISKS_FORMAT:
            raise ValueError("protected disk input differs")
        manifest_value, manifest_raw = helper.load_canonical(args.manifest, "export manifest", owner=0)
        manifest = helper.validate_manifest(manifest_value)
        if hashlib.sha256(manifest_raw).hexdigest() != exact_sha(args.expected_manifest_sha256, "manifest"):
            raise ValueError("transport manifest hash differs")
        if (manifest["mode"] != helper.LIVE_MODE or manifest["requestSha256"] != hashlib.sha256(export_request_raw).hexdigest()
                or manifest["inspectionRequestSha256"] != hashlib.sha256(request_raw).hexdigest()):
            raise ValueError("transport manifest request binding differs")
        transport_qualification, transport_qualification_raw = helper.load_canonical(args.transport_qualification_evidence, "transport qualification evidence", owner=0, maximum=64 * 1024)
        transport_qualification = helper.validate_qualification(transport_qualification)
        helper.validate_live_qualification(transport_qualification, manifest, transport_qualification["exporterSha256"], transport_qualification["runnerSha256"], args.expected_trusted_public_key)
        production_inspection, production_inspection_raw = helper.load_canonical(args.production_inspection_evidence, "production inspection evidence", owner=0, maximum=64 * 1024)
        helper.validate_inspection_evidence(production_inspection)
        qualified_install, qualified_install_raw = helper.load_canonical(args.qualified_install_evidence, "qualified install evidence", owner=0, maximum=64 * 1024)
        qualified_cold, qualified_cold_raw = helper.load_canonical(args.qualified_cold_boot_evidence, "qualified cold-boot evidence", owner=0, maximum=64 * 1024)
        authorization_value, authorization_raw = helper.load_canonical(args.authorization, "production install authorization", owner=0, maximum=64 * 1024)
        authorization = validate_authorization(authorization_value)
        host, host_raw = helper.load_canonical(args.production_host_attestation, "production install host attestation", owner=0, maximum=64 * 1024)
        expected_hashes = {
            hashlib.sha256(authorization_raw).hexdigest(): args.expected_authorization_sha256,
            hashlib.sha256(host_raw).hexdigest(): args.expected_host_attestation_sha256,
            hashlib.sha256(qualified_install_raw).hexdigest(): args.expected_qualified_install_evidence_sha256,
            hashlib.sha256(qualified_cold_raw).hexdigest(): args.expected_qualified_cold_boot_evidence_sha256,
            hashlib.sha256(production_inspection_raw).hexdigest(): args.expected_production_inspection_evidence_sha256,
        }
        if any(actual != exact_sha(expected, "independent evidence") for actual, expected in expected_hashes.items()):
            raise ValueError("independently expected authorization or evidence hash differs")
        transport_qualification_sha = hashlib.sha256(transport_qualification_raw).hexdigest()
        if (authorization["hostAttestationSha256"] != args.expected_host_attestation_sha256
                or authorization["qualifiedInstallEvidenceSha256"] != args.expected_qualified_install_evidence_sha256
                or authorization["qualifiedColdBootEvidenceSha256"] != args.expected_qualified_cold_boot_evidence_sha256
                or authorization["productionInspectionEvidenceSha256"] != args.expected_production_inspection_evidence_sha256
                or authorization["transportManifestSha256"] != args.expected_manifest_sha256
                or authorization["transportQualificationEvidenceSha256"] != transport_qualification_sha
                or authorization["candidateToplevel"] != manifest["toplevel"]
                or authorization["transportCommit"] != manifest["commit"]
                or qualified_install.get("commit") != authorization["qualifiedCommit"]
                or qualified_cold.get("commit") != authorization["qualifiedCommit"]
                or qualified_cold.get("installEvidenceSha256") != args.expected_qualified_install_evidence_sha256
                or qualified_install.get("candidateToplevel") != authorization["candidateToplevel"]
                or qualified_cold.get("candidateToplevel") != authorization["candidateToplevel"]
                or qualified_install.get("result") != "passed" or qualified_cold.get("result") != "passed"):
            raise ValueError("production authorization qualification binding differs")
        observed_uuid = common.product_uuid()
        validate_host(host, authorization, observed_uuid)
        if hashlib.sha256(host_raw).hexdigest() != authorization["hostAttestationSha256"]:
            raise ValueError("production host attestation byte binding differs")
        closure_paths = {entry["path"] for entry in manifest["closure"]}
        if authorization["diskoScript"] not in closure_paths or str(Path(authorization["nixosInstall"]).parents[1]) not in closure_paths:
            raise ValueError("authorized installation executables are absent from signed closure")
        output_fd, output_identity = common.open_private_output(args.output_root)
        before_boot = common.boot_id()
        docker_before = docker_inventory()
        common.reject_persistent_nix_configuration()
        helper.require_absent_nix(common.NIX)
        if not common.daemon_absent():
            raise ValueError("a Nix daemon or socket is present")
        try:
            first_disk = common.observe_disk(DEVICE, protected["gamesDevice"])
        except Exception:
            if args.retry_cleanup is None or args.expected_retry_cleanup_sha256 is None:
                raise
            retry_cleanup, retry_raw = helper.load_canonical(args.retry_cleanup, "prior production install cleanup", owner=0, maximum=16 * 1024)
            if (hashlib.sha256(retry_raw).hexdigest() != exact_sha(args.expected_retry_cleanup_sha256, "retry cleanup")
                    or retry_cleanup != {"bootIdStable": True, "dockerInventoryStable": True, "format": CLEANUP_FORMAT,
                        "nixAbsent": True, "result": "passed", "targetUnmounted": True, "tmpfsUnmounted": True}):
                raise ValueError("prior failed-attempt cleanup evidence differs")
            first_disk = installed_observation()
            input_state = "qualified-partitioned-retry"
        resources = manifest["resources"]
        helper.validate_resources(manifest, common.mem_available(), resources["requiredInodes"])
        common.NIX.mkdir(mode=0o755)
        created_nix = True
        mount = common.command("mount", ["-t", "tmpfs", "-o", f"rw,nosuid,nodev,exec,size={resources['tmpfsBytes']},nr_inodes={resources['requiredInodes'] + 1},mode=0755", "tmpfs", "/nix"], check=False)
        mounted_nix = common.validate_mount_result(mount)
        common.require_tmpfs_inodes(common.NIX, resources["requiredInodes"])
        transport = common.NIX / ".transport"; transport.mkdir(mode=0o700)
        runtime = common.NIX / ".runtime"
        for path in (runtime, runtime / "home", runtime / "tmp", runtime / "cache", runtime / "config", runtime / "config/nix"):
            path.mkdir(mode=0o700)
        (runtime / "config/nix/empty.conf").write_bytes(b""); (runtime / "config/nix/empty.conf").chmod(0o400)
        isolated_env = common.nix_environment(runtime, args.expected_trusted_public_key)
        bootstrap_fd = helper.open_protected(args.bootstrap, "bootstrap archive", owner=0)
        export_fd = helper.open_protected(args.export, "closure export", owner=0)
        try:
            bootstrap_metric = helper.descriptor_metrics(bootstrap_fd, "bootstrap archive")
            export_metric = helper.descriptor_metrics(export_fd, "closure export")
            if (bootstrap_metric["sha256"] != args.expected_bootstrap_sha256 or export_metric["sha256"] != args.expected_export_sha256
                    or bootstrap_metric != manifest["artifacts"]["bootstrap"] or export_metric != manifest["artifacts"]["export"]):
                raise ValueError("transport artifact identity differs")
            bootstrap_copy = common.copy_descriptor(bootstrap_fd, transport, "bootstrap.tar", manifest["artifacts"]["bootstrap"])
            export_copy = common.copy_descriptor(export_fd, transport, "closure.export", manifest["artifacts"]["export"])
        finally:
            os.close(bootstrap_fd); os.close(export_fd)
        helper.validate_tar_descriptor(bootstrap_copy, set(manifest["bootstrapPaths"]))
        os.lseek(bootstrap_copy, 0, os.SEEK_SET)
        tar = subprocess.run([common.TOOLS["tar"], "--extract", "--file", f"/proc/self/fd/{bootstrap_copy}", "--directory", "/", "--numeric-owner", "--same-owner", "--no-overwrite-dir"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLEAN_ENV, pass_fds=(bootstrap_copy,))
        if tar.returncode != 0 or tar.stdout or tar.stderr:
            raise ValueError("bootstrap extraction failed")
        nix, nix_store = helper.select_bootstrap_executables(manifest["bootstrapStorePath"], manifest["bootstrapPaths"])
        init = subprocess.run([nix_store, "--init"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=isolated_env)
        if init.returncode != 0 or init.stdout or init.stderr:
            raise ValueError("ephemeral Nix initialization failed")
        os.lseek(export_copy, 0, os.SEEK_SET)
        with os.fdopen(os.dup(export_copy), "rb") as source:
            imported = subprocess.run([nix_store, "--option", "require-sigs", "true", "--option", "trusted-public-keys", args.expected_trusted_public_key, "--import"], stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=isolated_env)
        if imported.returncode != 0 or imported.stderr:
            raise ValueError("signed closure import failed")
        common.verify_import(nix, manifest, set(imported.stdout.decode().splitlines()), isolated_env)
        os.close(bootstrap_copy); bootstrap_copy = None
        os.close(export_copy); export_copy = None
        current_disk = common.observe_disk(DEVICE, protected["gamesDevice"]) if input_state == "blank" else installed_observation()
        if common.boot_id() != before_boot or current_disk != first_disk or docker_inventory() != docker_before:
            raise ValueError("production identity changed before destructive install")
        if not TARGET.exists():
            TARGET.mkdir(mode=0o700)
        target_info = TARGET.lstat()
        if (not stat.S_ISDIR(target_info.st_mode) or target_info.st_uid != 0 or target_info.st_gid != 0
                or TARGET.is_symlink() or any(TARGET.iterdir()) or common.command("findmnt", ["--mountpoint", str(TARGET)], check=False).returncode == 0):
            raise ValueError("candidate install target differs")
        for executable in (authorization["diskoScript"], authorization["nixosInstall"]):
            if not Path(executable).is_file() or not os.access(executable, os.X_OK):
                raise ValueError("authorized install executable is unavailable")
        install_stage = "disko"
        rc, stdout, stderr = run_child([authorization["diskoScript"]], isolated_env, 900)
        write_diagnostic(args.output_root.parent, "retry-disko.stdout", stdout)
        write_diagnostic(args.output_root.parent, "retry-disko.stderr", stderr)
        if rc != 0:
            raise ValueError("authorized Disko operation failed")
        target_mounted = common.command("findmnt", ["--mountpoint", str(TARGET)], check=False).returncode == 0
        if not target_mounted:
            raise ValueError("Disko target mount is absent")
        install_stage = "nixos-install"
        rc, stdout, stderr = run_child([authorization["nixosInstall"], "--root", str(TARGET), "--system", authorization["candidateToplevel"], "--no-channel-copy", "--no-root-password"], isolated_env, 1800)
        write_diagnostic(args.output_root.parent, "retry-nixos-install.stdout", stdout)
        write_diagnostic(args.output_root.parent, "retry-nixos-install.stderr", stderr)
        if rc != 0:
            raise ValueError("authorized NixOS installation failed")
        profile = subprocess.run(["/usr/bin/readlink", "-f", str(TARGET / "nix/var/nix/profiles/system")], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=CLEAN_ENV)
        if profile.returncode != 0 or profile.stdout.decode().strip() != authorization["candidateToplevel"] or profile.stderr:
            raise ValueError("installed candidate system profile differs")
        install_stage = "unmount"
        unmount = common.command("umount", ["--recursive", "--", str(TARGET)], check=False)
        if unmount.returncode != 0 or unmount.stdout or unmount.stderr:
            raise ValueError("installed candidate filesystems did not unmount cleanly")
        target_mounted = False
        installed = installed_observation()
        if common.boot_id() != before_boot or docker_inventory() != docker_before:
            raise ValueError("production boot or Docker inventory changed during install")
        install_stage = "completed"
    except Exception as error:
        failure = error
    finally:
        for descriptor in (bootstrap_copy, export_copy):
            if descriptor is not None:
                try: os.close(descriptor)
                except OSError: pass
        if target_mounted:
            result = common.command("umount", ["--recursive", "--", str(TARGET)], check=False)
            target_mounted = result.returncode != 0
        if mounted_nix:
            for attempt in range(5):
                result = common.command("umount", ["--", "/nix"], check=False)
                if result.returncode == 0 and not result.stdout and not result.stderr:
                    mounted_nix = False; break
                if not common.tmpfs_mounted():
                    mounted_nix = False; break
                if attempt < 4:
                    time.sleep(0.1)
        if created_nix and common.tmpfs_absent():
            try: common.NIX.rmdir()
            except OSError: pass
        nix_absent = not os.path.lexists(common.NIX)
        try: boot_stable = before_boot is not None and common.boot_id() == before_boot
        except Exception: boot_stable = False
        try: docker_stable = docker_before is not None and docker_inventory() == docker_before
        except Exception: docker_stable = False
        target_unmounted = common.command("findmnt", ["--mountpoint", str(TARGET)], check=False).returncode != 0
        cleanup = {"bootIdStable": boot_stable, "dockerInventoryStable": docker_stable, "format": CLEANUP_FORMAT,
            "nixAbsent": nix_absent, "result": "passed" if boot_stable and docker_stable and nix_absent and target_unmounted else "failed",
            "targetUnmounted": target_unmounted, "tmpfsUnmounted": common.tmpfs_absent()}
        if output_fd is not None and output_identity is not None:
            try:
                common.verify_private_output(args.output_root, output_fd, output_identity, set())
                if failure is None and authorization is not None and manifest is not None and installed is not None:
                    evidence = {"authorizationSha256": args.expected_authorization_sha256, "bootIdStable": boot_stable,
                        "candidate": installed, "candidateToplevel": authorization["candidateToplevel"], "commit": authorization["transportCommit"],
                        "dockerInventoryCount": len(docker_before or []), "dockerInventoryStable": docker_stable, "format": EVIDENCE_FORMAT,
                        "hostAttestationSha256": args.expected_host_attestation_sha256, "installStage": install_stage,
                        "qualifiedColdBootEvidenceSha256": args.expected_qualified_cold_boot_evidence_sha256,
                        "qualifiedInstallEvidenceSha256": args.expected_qualified_install_evidence_sha256,
                        "result": "passed", "vmId": 100}
                    write_output(output_fd, "production-install-evidence.json", evidence)
                write_output(output_fd, "production-install-cleanup.json", cleanup)
                expected = {"production-install-cleanup.json"}
                if failure is None: expected.add("production-install-evidence.json")
                common.verify_private_output(args.output_root, output_fd, output_identity, expected)
            except Exception as evidence_error:
                if failure is None: failure = evidence_error
            os.close(output_fd)
        if cleanup["result"] != "passed" and failure is None:
            failure = ValueError("production install cleanup proof failed")
    if failure is not None:
        print("run-vm-100-ephemeral-install: fixed operation failed", file=sys.stderr)
        raise SystemExit(1)
    print(f"production_install_evidence={args.output_root / 'production-install-evidence.json'}")
    print(f"production_install_cleanup={args.output_root / 'production-install-cleanup.json'}")


if __name__ == "__main__":
    main()
