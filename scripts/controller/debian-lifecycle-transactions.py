#!/usr/bin/env python3
"""Plan and execute exact, independently locked Debian lifecycle transactions."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import signal
import subprocess
import tempfile

from protected_execution import acquire_transfer_lock, canonical_bytes, load_canonical_object, load_protected_bytes

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "infrastructure/contract/home-lab.yml"
INVENTORY = ROOT / "ansible/inventory/production.yml"
QUALIFICATION_INVENTORY = ROOT / "ansible/inventory/debian-qualification.yml"
EXECUTOR = ROOT / "ansible/roles/debian_lifecycle_transaction/files/debian-lifecycle-host-transaction"
AUTHORITY_PRODUCER = ROOT / "scripts/controller/debian-lifecycle-authority-receipts.py"
ACCESS_CLEANUP = ROOT / "scripts/controller/debian-access-cleanup.py"
LOCK = ROOT / ".local/locks/debian-lifecycle-transaction.lock"
OPERATIONS = {
    "storage-activation",
    "identity-recovery",
    "tailscale-enrollment",
    "production-activation",
    "state-disk-initialization",
    "ssh-tightening",
    "qualification-canary",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DEVICE = re.compile(r"^/dev/disk/by-id/[A-Za-z0-9._:+-]{1,180}$")
ABS_PATH = re.compile(r"^/(?:[A-Za-z0-9._-]+/?)+$")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def exact_confirmation(plan: dict, digest: str) -> str:
    operation = plan["operation"]
    if operation == "state-disk-initialization":
        serial = plan["request"]["parameters"]["serial"]
        if re.fullmatch(r"[A-Za-z0-9._:+-]{1,128}", serial) is None:
            raise SystemExit("state disk serial is unsafe for exact confirmation")
        return f"apply-debian-{operation}-{serial}-{digest}"
    return f"apply-debian-{operation}-{digest}"


def now_text(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.check_output(("git", *args), cwd=ROOT, text=True).strip()


def clean_pushed_commit() -> str:
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "origin/main") or git("status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("Debian lifecycle transaction planning requires clean pushed HEAD")
    return commit

def contract_policy() -> dict:
    script='const fs=require("fs"),yaml=require("js-yaml");const c=yaml.load(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(JSON.stringify({transaction:c.debian.transaction,hostname:c.vm_100.host_name,tag:c.tailscale.tags.docker_host,state:c.proxmox.vm.state_disk,storage:c.vm_100.storage,protected_mounts:c.debian.qualification.protected_mounts}))'
    result=subprocess.run(["node","-e",script,str(CONTRACT)],cwd=ROOT,text=True,capture_output=True)
    if result.returncode or result.stderr: raise SystemExit("direct Debian transaction contract projection failed")
    return json.loads(result.stdout)


def execution_route(operation: str, profile: str) -> tuple[Path, str]:
    if operation == "qualification-canary" and profile == "inert":
        policy = contract_policy()["transaction"]
        return QUALIFICATION_INVENTORY, policy["qualification_canary_inventory_host"]
    if operation == "ssh-tightening" and profile == "production":
        return INVENTORY, "docker-host-production"
    if operation in OPERATIONS - {"qualification-canary", "ssh-tightening"} and profile == "recovery":
        return INVENTORY, "docker-host-production"
    raise SystemExit("operation and lifecycle execution profile route differs")


def private_output(directory: Path) -> Path:
    directory = directory.resolve()
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise SystemExit("transaction output must be an owned mode-private directory")
    current = Path(directory.anchor)
    for part in directory.parts[1:]:
        current /= part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise SystemExit("transaction output has a symlink component")
    return directory


def read_input(path: Path, label: str, protected: bool = False) -> tuple[dict, bytes]:
    if protected:
        try:
            return load_canonical_object(path, label)
        except OSError as error:
            raise SystemExit(f"{label} must be an owned mode-private dedicated regular file") from error
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit(f"{label} is not JSON") from error
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        raise SystemExit(f"{label} must be canonical JSON")
    return value, raw


def exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise SystemExit(f"{label} fields differ")

def validate_evidence(operation: str, params: dict, paths: list[Path] | None) -> list[str]:
    values=[]; digests=[]
    for index,path in enumerate(paths or []):
        value,raw=read_input(path,f"transaction evidence {index}",protected=True); values.append(value); digests.append(sha(raw))
    if operation == "storage-activation":
        expected=[params["attachment_receipt_sha256"]]
        receipt=values[0] if len(values)==1 else {}; required={"authority","commit","devices","format","plan_sha256","producer_sha256","state_sha256","status","target","version","vmid"}
        if set(receipt)!=required or receipt.get("producer_sha256")!=sha(AUTHORITY_PRODUCER.read_bytes()) or receipt.get("authority")!="opentofu" or receipt.get("devices")!=params["devices"] or receipt.get("format")!="home-lab-opentofu-storage-attachment-receipt-v1" or receipt.get("status")!="applied" or receipt.get("target")!="debian" or receipt.get("version")!=1 or receipt.get("vmid")!=100 or re.fullmatch(r"[0-9a-f]{40}",receipt.get("commit","") or "") is None or HEX64.fullmatch(receipt.get("plan_sha256","") or "") is None or HEX64.fullmatch(receipt.get("state_sha256","") or "") is None: raise SystemExit("OpenTofu storage attachment receipt differs")
    elif operation == "identity-recovery":
        expected=[params["recovery_receipt_sha256"]]
        receipt=values[0] if len(values)==1 else {}; required={"bundle_plaintext_sha256","commit","format","identity_sha256","path","producer_sha256","recipient","recovery_bundle_sha256","status","target","version"}
        if set(receipt)!=required or receipt.get("producer_sha256")!=sha(AUTHORITY_PRODUCER.read_bytes()) or receipt.get("format")!="home-lab-age-recovery-receipt-v1" or receipt.get("identity_sha256")!=params["identity_sha256"] or receipt.get("path")!=params["path"] or receipt.get("recipient")!=params["recipient"] or receipt.get("status")!="verified" or receipt.get("target")!="debian" or receipt.get("version")!=1 or re.fullmatch(r"[0-9a-f]{40}",receipt.get("commit","") or "") is None or HEX64.fullmatch(receipt.get("recovery_bundle_sha256","") or "") is None or HEX64.fullmatch(receipt.get("bundle_plaintext_sha256","") or "") is None: raise SystemExit("age recovery receipt differs")
    elif operation == "state-disk-initialization":
        expected=[params["tofu_receipt_sha256"]]; disk={key:params[key] for key in ("path","serial","size_bytes")}
        receipt=values[0] if len(values)==1 else {}; required={"authority","blank_required","commit","disk","format","plan_sha256","producer_sha256","state_sha256","status","target","version","vmid"}
        if set(receipt)!=required or receipt.get("producer_sha256")!=sha(AUTHORITY_PRODUCER.read_bytes()) or receipt.get("authority")!="opentofu" or receipt.get("blank_required") is not True or receipt.get("disk")!=disk or receipt.get("format")!="home-lab-opentofu-state-disk-receipt-v1" or receipt.get("status")!="applied" or receipt.get("target")!="debian" or receipt.get("version")!=1 or receipt.get("vmid")!=100 or re.fullmatch(r"[0-9a-f]{40}",receipt.get("commit","") or "") is None or HEX64.fullmatch(receipt.get("plan_sha256","") or "") is None or HEX64.fullmatch(receipt.get("state_sha256","") or "") is None: raise SystemExit("OpenTofu state-disk receipt differs")
    elif operation == "production-activation":
        expected=[params["restic_recovery_receipt_sha256"]]; receipt=values[0] if len(values)==1 else {}; required={"commit","format","producer_sha256","repository_id","restore_manifest_sha256","snapshot_id","snapshot_manifest_sha256","status","target","tree_sha256","version"}
        if set(receipt)!=required or receipt.get("producer_sha256")!=sha(AUTHORITY_PRODUCER.read_bytes()) or receipt.get("format")!="home-lab-restic-recovery-activation-receipt-v1" or receipt.get("status")!="verified" or receipt.get("target")!="debian" or receipt.get("version")!=1 or re.fullmatch(r"[0-9a-f]{40}",receipt.get("commit","") or "") is None or any(HEX64.fullmatch(receipt.get(key,"") or "") is None for key in ("repository_id","restore_manifest_sha256","snapshot_id","snapshot_manifest_sha256","tree_sha256")): raise SystemExit("Restic recovery activation receipt differs")
    elif operation == "ssh-tightening":
        expected=sorted(item["sha256"] for item in params["access_cleanup_receipts"]); by_kind={item["kind"]:item for item in values}
        required={"commit","format","kind","manifest_sha256","plan_sha256","producer_sha256","status","target","version"}
        if len(values)!=3 or set(by_kind)!={"legacy-marker-removal","conventional-key-removal","openssh-tightening"} or any(set(value)!=required or value.get("producer_sha256")!=sha(ACCESS_CLEANUP.read_bytes()) or value.get("format")!="home-lab-debian-access-cleanup-operation-receipt-v1" or value.get("kind")!=kind or value.get("status")!="committed" or value.get("target")!="debian" or value.get("version")!=1 or re.fullmatch(r"[0-9a-f]{40}",value.get("commit","") or "") is None or HEX64.fullmatch(value.get("manifest_sha256","") or "") is None or HEX64.fullmatch(value.get("plan_sha256","") or "") is None for kind,value in by_kind.items()): raise SystemExit("access cleanup receipts differ")
    else: expected=[]
    if sorted(digests)!=sorted(expected): raise SystemExit("transaction evidence hashes differ")
    return sorted(digests)


def common_observation(value: dict) -> None:
    exact_keys(value, {"format", "target", "profile", "host", "locks", "storage", "mounts", "identity", "tailscale", "production", "ssh"}, "observation")
    if value["format"] != "home-lab-debian-lifecycle-observation-v1" or value["target"] != "debian":
        raise SystemExit("observation identity differs")
    if value["profile"] not in {"inert", "recovery", "production"} or not isinstance(value["locks"], list):
        raise SystemExit("observation lifecycle fields differ")
    host = value["host"]
    exact_keys(host, {"hostname", "machine_id_sha256", "host_key_fingerprint"}, "observation host")
    if not isinstance(host["hostname"], str) or not host["hostname"] or HEX64.fullmatch(host["machine_id_sha256"]) is None or not isinstance(host["host_key_fingerprint"], str) or not host["host_key_fingerprint"].startswith("SHA256:"):
        raise SystemExit("observation host identity differs")
    for key in ("storage", "mounts"):
        if not isinstance(value[key], list):
            raise SystemExit(f"observation {key} differs")
    for key in ("identity", "tailscale", "production", "ssh"):
        if not isinstance(value[key], dict):
            raise SystemExit(f"observation {key} differs")


def storage_map(observation: dict) -> dict[str, dict]:
    result = {}
    for item in observation["storage"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or item["path"] in result:
            raise SystemExit("observed storage identities differ")
        result[item["path"]] = item
    return result


def mount_map(observation: dict) -> dict[str, dict]:
    result = {}
    for item in observation["mounts"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or item["path"] in result:
            raise SystemExit("observed mount identities differ")
        result[item["path"]] = item
    return result


def validate_request(operation: str, request: dict, observation: dict, now: datetime) -> list[str]:
    common_observation(observation)
    exact_keys(request, {"format", "operation", "profile", "parameters"}, "request")
    if request["format"] != "home-lab-debian-lifecycle-request-v1" or request["operation"] != operation or request["profile"] != observation["profile"] or not isinstance(request["parameters"], dict):
        raise SystemExit("request identity or lifecycle profile differs")
    blockers = list(observation["locks"])
    params = request["parameters"]
    policy = contract_policy()
    expected_hostname = policy["transaction"]["qualification_canary_hostname"] if request["profile"] == "inert" else policy["hostname"]
    if observation["host"]["hostname"] != expected_hostname:
        blockers.append("contract-hostname-drift")

    if operation == "qualification-canary":
        exact_keys(params, {"receipt_root", "inactive_units"}, "qualification canary request")
        exact_keys(observation["production"], {"active_units"}, "qualification canary production observation")
        if request["profile"] != "inert" or params["receipt_root"] != policy["transaction"]["qualification_canary_receipt_root"] or params["inactive_units"] != policy["transaction"]["production_units"]:
            blockers.append("inert-qualification-canary-binding-required")
        if observation["production"]["active_units"] != []:
            blockers.append("qualification-production-units-active")

    elif operation == "storage-activation":
        exact_keys(params, {"devices", "mounts", "activation_path", "attachment_receipt_sha256"}, "storage request")
        if request["profile"] != "recovery" or params["activation_path"] != policy["transaction"]["storage_activation_path"]:
            blockers.append("recovery-profile-and-canonical-token-required")
        if HEX64.fullmatch(params["attachment_receipt_sha256"]) is None:
            blockers.append("OpenTofu-storage-attachment-receipt-required")
        observed_devices = storage_map(observation)
        observed_mounts = mount_map(observation)
        if not params["devices"] or not params["mounts"]:
            raise SystemExit("storage activation requires devices and mounts")
        device_numbers = set()
        for expected in params["devices"]:
            exact_keys(expected, {"path", "serial", "size_bytes", "uuid", "fstype", "surviving"}, "storage device")
            current = observed_devices.get(expected["path"])
            if (DEVICE.fullmatch(expected["path"]) is None or expected["surviving"] is not True or current is None or
                    current.get("stable_path") != expected["path"] or current.get("block") is not True or current.get("symlink") is not True or
                    current.get("serial") != expected["serial"] or current.get("size_bytes") != expected["size_bytes"] or
                    current.get("uuid") != expected["uuid"] or current.get("signatures") != [{"type": expected["fstype"], "uuid": expected["uuid"]}] or
                    current.get("holders") != [] or current.get("mounts") != []):
                blockers.append(f"surviving-device-drift:{expected['path']}")
            if current is not None and current.get("device_number") in device_numbers:
                blockers.append("storage-device-alias")
            elif current is not None:
                device_numbers.add(current.get("device_number"))
        for expected in params["mounts"]:
            exact_keys(expected, {"path", "source", "uuid", "fstype", "options", "owner", "group", "mode", "minimum_free_bytes"}, "storage mount")
            current = observed_mounts.get(expected["path"])
            if ABS_PATH.fullmatch(expected["path"]) is None or DEVICE.fullmatch(expected["source"]) is None or current is None or current.get("active") is True or current.get("symlink") is True:
                blockers.append(f"mount-target-drift:{expected['path']}")
            contracted={policy["state"]["mountpoint"]:(policy["state"]["filesystem_uuid"],policy["state"]["filesystem"],policy["state"]["mount_options"]),policy["storage"]["games"]["mountpoint"]:(policy["storage"]["games"]["filesystem_uuid"],policy["storage"]["games"]["filesystem"],policy["storage"]["games"]["options"])}
            if expected["path"] not in contracted or expected["uuid"]!=contracted.get(expected["path"],(None,None,[]))[0] or expected["fstype"]!=contracted.get(expected["path"],(None,None,[]))[1] or not set(contracted.get(expected["path"],(None,None,[]))[2]).issubset(set(expected["options"])):
                blockers.append(f"contract-storage-drift:{expected['path']}")
    elif operation == "identity-recovery":
        exact_keys(params, {"path", "recipient", "identity_sha256", "recovery_receipt_sha256"}, "identity request")
        if request["profile"] != "recovery" or params["path"] != policy["transaction"]["age_identity_path"] or HEX64.fullmatch(params["identity_sha256"]) is None or HEX64.fullmatch(params["recovery_receipt_sha256"]) is None:
            blockers.append("identity-request-binding")
        identity = observation["identity"]
        if identity.get("exists") is not False:
            blockers.append("identity-target-must-be-absent")
        if not isinstance(params["recipient"], str) or not params["recipient"].startswith("age1"):
            blockers.append("age-recipient-required")
    elif operation == "tailscale-enrollment":
        exact_keys(params, {"auth_key_sha256", "auth_key_expires_at", "one_use", "preauthorized", "hostname", "tags", "expected_dns_suffix"}, "tailscale request")
        if request["profile"] != "recovery" or params["one_use"] is not True or params["preauthorized"] is not True or HEX64.fullmatch(params["auth_key_sha256"]) is None:
            blockers.append("one-use-preauthorized-key-required")
        try:
            if utc(params["auth_key_expires_at"]) <= now or utc(params["auth_key_expires_at"]) > now + timedelta(hours=1):
                blockers.append("fresh-auth-key-required")
        except (TypeError, ValueError):
            blockers.append("auth-key-expiry-invalid")
        if not params["tags"] or any(not isinstance(tag, str) or not tag.startswith("tag:") for tag in params["tags"]):
            blockers.append("tailscale-tags-invalid")
        if params["hostname"]!=policy["hostname"] or params["tags"]!=[policy["tag"]]:
            blockers.append("contract-tailscale-identity-drift")
        if observation["tailscale"].get("backend_state") not in {"Absent", "NeedsLogin"}:
            blockers.append("tailscale-already-enrolled")
    elif operation == "production-activation":
        exact_keys(params, {"mounts", "storage_plan_sha256", "identity_recipient", "tailscale_hostname", "tailscale_tags", "systemd_dependencies", "lifecycle_marker_sha256", "compose_artifact_path", "compose_artifact_sha256", "compose_image_lock_path", "compose_image_lock_sha256", "compose_command", "root_environment_path", "root_environment_sha256", "restic_recovery_receipt_path", "restic_recovery_receipt_sha256"}, "production request")
        if request["profile"] != "recovery":
            blockers.append("recovery-profile-required")
        if params["compose_command"]!=policy["transaction"]["compose_command"] or params["compose_artifact_path"]!=policy["transaction"]["compose_artifact_path"] or params["compose_image_lock_path"]!=policy["transaction"]["compose_image_lock_path"] or params["root_environment_path"]!=policy["transaction"]["root_environment_path"] or set(params["systemd_dependencies"])!=set(policy["transaction"]["production_units"]):
            blockers.append("contract-production-activation-drift")
        if params["tailscale_hostname"]!=policy["hostname"] or params["tailscale_tags"]!=[policy["tag"]] or {item["path"] for item in params["mounts"]}!=set(policy["protected_mounts"]):
            blockers.append("contract-production-identity-drift")
        current_mounts = mount_map(observation)
        for expected in params["mounts"]:
            exact_keys(expected, {"path", "source", "uuid", "fstype", "options", "owner", "group", "mode", "minimum_free_bytes"}, "production mount")
            if expected["path"]==policy["state"]["mountpoint"]:
                if expected["uuid"]!=policy["state"]["filesystem_uuid"] or expected["fstype"]!=policy["state"]["filesystem"] or not set(policy["state"]["mount_options"]).issubset(set(expected["options"])) or DEVICE.fullmatch(expected["source"]) is None: blockers.append(f"contract-production-mount-drift:{expected['path']}")
            elif expected["path"]==policy["storage"]["games"]["mountpoint"]:
                if expected["uuid"]!=policy["storage"]["games"]["filesystem_uuid"] or expected["fstype"]!=policy["storage"]["games"]["filesystem"] or not set(policy["storage"]["games"]["options"]).issubset(set(expected["options"])) or DEVICE.fullmatch(expected["source"]) is None: blockers.append(f"contract-production-mount-drift:{expected['path']}")
            elif expected["path"]==policy["storage"]["shared"]["mountpoint"]:
                if expected["source"]!=policy["storage"]["shared"]["source"] or expected["fstype"]!=policy["storage"]["shared"]["filesystem"] or not set(policy["storage"]["shared"]["options"]).issubset(set(expected["options"])): blockers.append(f"contract-production-mount-drift:{expected['path']}")
            else: blockers.append(f"contract-production-mount-drift:{expected['path']}")
            current = current_mounts.get(expected["path"])
            required_options = set(expected["options"])
            if current is None or current.get("active") is not True or current.get("source") != expected["source"] or current.get("uuid") != expected["uuid"] or current.get("fstype") != expected["fstype"] or not required_options.issubset(set(current.get("options", []))) or current.get("owner") != expected["owner"] or current.get("group") != expected["group"] or current.get("mode") != expected["mode"] or current.get("free_bytes", -1) < expected["minimum_free_bytes"] or current.get("same_device") is not True:
                blockers.append(f"production-mount-drift:{expected['path']}")
        identity = observation["identity"]
        if identity.get("exists") is not True or identity.get("path")!=policy["transaction"]["age_identity_path"] or identity.get("recipient") != params["identity_recipient"] or identity.get("uid") != 0 or identity.get("gid") != 0 or identity.get("mode") != "0600" or identity.get("regular") is not True or identity.get("symlink") is True or identity.get("nlink") != 1:
            blockers.append("production-identity-drift")
        tailscale = observation["tailscale"]
        if tailscale.get("backend_state") != "Running" or tailscale.get("hostname") != params["tailscale_hostname"] or sorted(tailscale.get("tags", [])) != sorted(params["tailscale_tags"]) or not tailscale.get("node_id") or tailscale.get("addresses") == []:
            blockers.append("tailscale-post-proof-required")
        production = observation["production"]
        if production.get("storage_plan_sha256") != params["storage_plan_sha256"] or production.get("lifecycle_marker_sha256") != params["lifecycle_marker_sha256"] or production.get("compose_artifact_path") != params["compose_artifact_path"] or production.get("compose_artifact_sha256") != params["compose_artifact_sha256"] or production.get("compose_image_lock_path") != params["compose_image_lock_path"] or production.get("compose_image_lock_sha256") != params["compose_image_lock_sha256"] or production.get("compose_command") != params["compose_command"] or production.get("compose_config_valid") is not True or production.get("restic_recovery_receipt_path") != params["restic_recovery_receipt_path"] or production.get("restic_recovery_receipt_sha256") != params["restic_recovery_receipt_sha256"] or production.get("root_environment_path") != params["root_environment_path"] or production.get("root_environment_sha256")!=params["root_environment_sha256"] or production.get("root_environment_protected") is not True:
            blockers.append("compose-restic-prerequisites-differ")
        if production.get("systemd_dependencies") != params["systemd_dependencies"]:
            blockers.append("systemd-dependencies-differ")
        if production.get("systemd_unit_states") != {unit:"inactive" for unit in params["systemd_dependencies"]}:
            blockers.append("production-unit-prestate-differ")
        for digest in (params["storage_plan_sha256"], params["lifecycle_marker_sha256"], params["compose_artifact_sha256"], params["compose_image_lock_sha256"], params["root_environment_sha256"], params["restic_recovery_receipt_sha256"]):
            if HEX64.fullmatch(digest) is None:
                raise SystemExit("production digest binding differs")
    elif operation == "state-disk-initialization":
        exact_keys(params, {"tofu_receipt_sha256", "path", "serial", "size_bytes", "filesystem", "filesystem_uuid", "force"}, "state disk request")
        current = storage_map(observation).get(params["path"])
        if request["profile"] != "recovery" or params["force"] is not False or params["filesystem"] != "ext4" or HEX64.fullmatch(params["tofu_receipt_sha256"]) is None or DEVICE.fullmatch(params["path"]) is None:
            blockers.append("tofu-approved-force-false-disk-required")
        if current is None or current.get("stable_path") != params["path"] or current.get("block") is not True or current.get("symlink") is not True or current.get("serial") != params["serial"] or current.get("size_bytes") != params["size_bytes"] or current.get("signatures") != [] or current.get("holders") != [] or current.get("mounts") != []:
            blockers.append("replacement-disk-not-exactly-blank")
        state=policy["state"]
        if params["serial"]!=state["serial"] or params["size_bytes"]!=state["size_gb"]*1073741824 or params["filesystem"]!=state["filesystem"] or params["filesystem_uuid"]!=state["filesystem_uuid"]:
            blockers.append("contract-state-disk-drift")
    elif operation == "ssh-tightening":
        exact_keys(params, {"access_cleanup_receipts", "required_tailscale_tag", "host_key_fingerprint"}, "SSH request")
        expected_receipts = {"legacy-marker-removal", "conventional-key-removal", "openssh-tightening"}
        receipts = params["access_cleanup_receipts"]
        if request["profile"] != "production" or not isinstance(receipts, list) or len(receipts) != 3 or any(not isinstance(item, dict) or set(item) != {"kind", "sha256"} or item.get("kind") not in expected_receipts or HEX64.fullmatch(item.get("sha256", "")) is None for item in receipts) or {item["kind"] for item in receipts} != expected_receipts:
            blockers.append("separate-access-cleanup-receipts-required")
        if params["required_tailscale_tag"]!=policy["tag"]:
            blockers.append("contract-SSH-tag-drift")
        tailscale = observation["tailscale"]
        ssh = observation["ssh"]
        if tailscale.get("backend_state") != "Running" or tailscale.get("run_ssh") is not True or params["required_tailscale_tag"] not in tailscale.get("tags", []):
            blockers.append("tailscale-ssh-proof-required")
        if ssh.get("conventional_key_paths_present") != [] or ssh.get("pubkey_authentication") != "no" or ssh.get("permit_root_login") != "no" or ssh.get("host_key_fingerprint") != params["host_key_fingerprint"]:
            blockers.append("openssh-tightening-postcondition-differs")
    return sorted(set(blockers + ["saved-reviewed-plan-required", "separate-exact-authorization-required"]))


def make_plan(operation: str, request_path: Path, observation_path: Path, output_dir: Path, now: datetime | None = None, commit: str | None = None, evidence_paths: list[Path] | None = None) -> tuple[Path, str, dict]:
    moment = now or datetime.now(timezone.utc)
    request, request_raw = read_input(request_path, "transaction request", protected=True)
    observation, observation_raw = read_input(observation_path, "transaction observation", protected=True)
    blockers = validate_request(operation, request, observation, moment)
    evidence_sha256 = validate_evidence(operation, request["parameters"], evidence_paths)
    inventory, _ = execution_route(operation, request["profile"])
    base_commit = commit or clean_pushed_commit()
    plan = {
        "format": "home-lab-debian-lifecycle-transaction-plan-v1",
        "operation": operation,
        "target": "debian",
        "profile": request["profile"],
        "base_commit": base_commit,
        "created_at": now_text(moment),
        "expires_at": now_text(moment + timedelta(minutes=30)),
        "bindings": {
            "contract_sha256": sha(CONTRACT.read_bytes()),
            "inventory_sha256": sha(inventory.read_bytes()),
            "executor_sha256": sha(EXECUTOR.read_bytes()),
            "authority_producer_sha256": sha(AUTHORITY_PRODUCER.read_bytes()),
            "access_cleanup_producer_sha256": sha(ACCESS_CLEANUP.read_bytes()),
            "request_sha256": sha(request_raw),
            "observation_sha256": sha(observation_raw),
            "evidence_sha256": evidence_sha256,
        },
        "request": request,
        "precondition": observation,
        "blockers": blockers,
        "authorized": False,
        "automatic_apply": False,
    }
    raw = canonical_bytes(plan) + b"\n"; digest = sha(raw); directory = private_output(output_dir)
    name = f"{operation}-{digest}.json"; directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return directory / name, digest, plan


def load_plan(path: Path, operation: str, now: datetime | None = None, commit: str | None = None) -> tuple[dict, bytes, str]:
    plan, raw = read_input(path, "transaction plan", protected=True); digest = sha(raw)
    if path.name != f"{operation}-{digest}.json" or plan.get("format") != "home-lab-debian-lifecycle-transaction-plan-v1" or plan.get("operation") != operation or plan.get("target") != "debian" or plan.get("authorized") is not False or plan.get("automatic_apply") is not False:
        raise SystemExit("transaction plan identity or authority differs")
    if plan.get("profile") != plan.get("request", {}).get("profile"):
        raise SystemExit("transaction plan and request lifecycle profiles differ")
    bindings = plan.get("bindings", {})
    expected_commit = commit or clean_pushed_commit()
    inventory, _ = execution_route(operation, plan.get("profile"))
    if plan.get("base_commit") != expected_commit or bindings.get("contract_sha256") != sha(CONTRACT.read_bytes()) or bindings.get("inventory_sha256") != sha(inventory.read_bytes()) or bindings.get("executor_sha256") != sha(EXECUTOR.read_bytes()) or bindings.get("authority_producer_sha256")!=sha(AUTHORITY_PRODUCER.read_bytes()) or bindings.get("access_cleanup_producer_sha256")!=sha(ACCESS_CLEANUP.read_bytes()) or bindings.get("request_sha256") != sha(canonical_bytes(plan.get("request")) + b"\n") or bindings.get("observation_sha256") != sha(canonical_bytes(plan.get("precondition")) + b"\n"):
        raise SystemExit("transaction plan current bindings differ")
    moment = now or datetime.now(timezone.utc)
    if moment < utc(plan["created_at"]) or moment > utc(plan["expires_at"]):
        raise SystemExit("transaction plan is stale")
    return plan, raw, digest


def verify(operation: str, plan_path: Path, current_path: Path, secret_path: Path | None = None, now: datetime | None = None, commit: str | None = None, evidence_paths: list[Path] | None = None) -> tuple[dict, bytes, str]:
    plan, raw, digest = load_plan(plan_path, operation, now, commit)
    current, current_raw = read_input(current_path, "current observation", protected=True)
    blockers = validate_request(operation, plan["request"], current, now or datetime.now(timezone.utc))
    expected_only = {"saved-reviewed-plan-required", "separate-exact-authorization-required"}
    if set(plan["blockers"]) != expected_only or set(blockers) != expected_only or current_raw != canonical_bytes(plan["precondition"]) + b"\n":
        raise SystemExit("transaction precondition or blockers changed after planning")
    params = plan["request"]["parameters"]
    if plan["bindings"].get("evidence_sha256") != validate_evidence(operation, params, evidence_paths):
        raise SystemExit("transaction evidence changed after planning")
    if operation in {"identity-recovery", "tailscale-enrollment"}:
        if secret_path is None:
            raise SystemExit("protected transaction secret is required")
        try:
            secret_raw = load_protected_bytes(secret_path, "transaction secret")
        except OSError as error:
            raise SystemExit("transaction secret must be an owned mode-private dedicated regular file") from error
        expected = params["identity_sha256"] if operation == "identity-recovery" else params["auth_key_sha256"]
        if sha(secret_raw) != expected:
            raise SystemExit("transaction secret hash differs")
    elif secret_path is not None:
        raise SystemExit("this transaction must not receive a secret")
    return plan, raw, digest


def run_controlled(command: tuple[str, ...]) -> int:
    process = subprocess.Popen(command, cwd=ROOT / "ansible", start_new_session=True)
    previous = {}
    def interrupted(signum, frame):
        raise InterruptedError(f"signal:{signum}")
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.signal(signum, interrupted)
    try:
        return process.wait(timeout=3600)
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        raise
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def apply(operation: str, plan_path: Path, current_path: Path, secret_path: Path | None, now: datetime | None = None, commit: str | None = None, evidence_paths: list[Path] | None = None) -> None:
    plan, _, digest = verify(operation, plan_path, current_path, secret_path, now, commit, evidence_paths)
    expected = exact_confirmation(plan, digest)
    if os.environ.get("DEBIAN_LIFECYCLE_TRANSACTION_CONFIRMED") != expected:
        raise SystemExit(f"exact confirmation required: {expected}")
    LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(LOCK.parent, 0o700)
    descriptor = acquire_transfer_lock(LOCK)
    extra = {"debian_lifecycle_transaction_plan": plan, "debian_lifecycle_transaction_plan_sha256": digest,
             "debian_lifecycle_transaction_confirmation": expected, "lifecycle_profile": plan["profile"]}
    staged_secret = None
    if secret_path is not None:
        secret_raw = load_protected_bytes(secret_path, "transaction secret")
        expected_secret = plan["request"]["parameters"]["identity_sha256" if operation == "identity-recovery" else "auth_key_sha256"]
        if sha(secret_raw) != expected_secret:
            raise SystemExit("transaction secret changed after verification")
        with tempfile.NamedTemporaryFile(mode="wb", dir=LOCK.parent, prefix="debian-lifecycle-secret-", delete=False) as secret_handle:
            staged_secret = Path(secret_handle.name); os.chmod(staged_secret, 0o600); secret_handle.write(secret_raw); secret_handle.flush(); os.fsync(secret_handle.fileno())
        extra["debian_lifecycle_transaction_secret_path"] = str(staged_secret)
    result_code = None
    inventory, inventory_host = execution_route(operation, plan["profile"])
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=LOCK.parent, prefix="debian-lifecycle-", suffix=".json", delete=False) as handle:
            extra_path = Path(handle.name); os.chmod(extra_path, 0o600); handle.write(canonical_bytes(extra) + b"\n"); handle.flush(); os.fsync(handle.fileno())
        try:
            command = ("ansible-playbook", "-i", str(inventory), str(ROOT / "ansible/playbooks/apply-debian-lifecycle-transaction.yml"), "--limit", inventory_host, "--tags", operation, "--extra-vars", f"@{extra_path}")
            result_code = run_controlled(command)
        finally:
            extra_path.unlink(missing_ok=True)
    finally:
        if staged_secret is not None:
            staged_secret.unlink(missing_ok=True)
        os.close(descriptor)
    if result_code:
        raise SystemExit("Debian lifecycle transaction failed; host lock is intentionally retained for recovery")
    print(json.dumps({"operation": operation, "plan_sha256": digest, "status": "applied", "automatic_apply": False}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True)
    planner = commands.add_parser("plan"); planner.add_argument("operation", choices=sorted(OPERATIONS)); planner.add_argument("request", type=Path); planner.add_argument("observation", type=Path); planner.add_argument("output", type=Path); planner.add_argument("--evidence",type=Path,action="append",default=[])
    checker = commands.add_parser("verify"); checker.add_argument("operation", choices=sorted(OPERATIONS)); checker.add_argument("plan", type=Path); checker.add_argument("current", type=Path); checker.add_argument("--secret", type=Path); checker.add_argument("--evidence",type=Path,action="append",default=[])
    runner = commands.add_parser("apply"); runner.add_argument("operation", choices=sorted(OPERATIONS)); runner.add_argument("plan", type=Path); runner.add_argument("current", type=Path); runner.add_argument("--secret", type=Path); runner.add_argument("--evidence",type=Path,action="append",default=[])
    args = parser.parse_args()
    if args.command == "plan":
        path, digest, plan = make_plan(args.operation, args.request, args.observation, args.output, evidence_paths=args.evidence)
        print(json.dumps({"path": str(path), "plan_sha256": digest, "blockers": plan["blockers"], "authorized": False}, sort_keys=True))
    elif args.command == "verify":
        _, _, digest = verify(args.operation, args.plan, args.current, args.secret, evidence_paths=args.evidence)
        print(json.dumps({"operation": args.operation, "plan_sha256": digest, "ready_for_exact_authorization": True}, sort_keys=True))
    else:
        apply(args.operation, args.plan, args.current, args.secret, evidence_paths=args.evidence)


if __name__ == "__main__":
    main()
