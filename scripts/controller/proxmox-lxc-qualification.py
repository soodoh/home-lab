#!/usr/bin/env python3
"""Fail-closed controls for the disposable Proxmox LXC qualification root."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
from typing import Any
from urllib import parse, request

MARKER = "home-lab-lxc-provider-qualification-v1"
ADDRESS = "proxmox_virtual_environment_container.qualification[0]"
BACKEND_KEY = "home-lab/proxmox-lxc-qualification/tofu.tfstate"
LOCKFILE = Path("infrastructure/tofu/proxmox-lxc-qualification/.terraform.lock.hcl")
PROVIDER_SOURCE = "registry.opentofu.org/bpg/proxmox"
EVIDENCE_OPERATIONS = [
    "create",
    "probe-protected-delete",
    "verify-protected",
    "unprotect",
    "delete",
    "verify-empty",
]
OPERATIONS = {
    "create",
    "probe-protected-delete",
    "verify-protected",
    "unprotect",
    "reprotect",
    "delete",
    "verify-empty",
}
RECOVERY_RESULTS = {
    "aligned-empty",
    "aligned-protected",
    "aligned-unprotected",
    "live-only-protected",
    "live-only-unprotected",
    "state-only",
    "protection-mismatch",
    "identity-mismatch",
    "lock-present",
}
IDENTITY_HASH_KEYS = {
    "backend_bucket_sha256",
    "proxmox_endpoint_sha256",
    "backend_key_sha256",
    "provider_lock_sha256",
    "ca_certificate_sha256",
}
TEMPLATE_PATTERN = re.compile(
    r"^local:vztmpl/[A-Za-z0-9][A-Za-z0-9._+-]*\.tar\.(?:gz|xz|zst)$"
)
PROTECTION_REJECTIONS = (
    re.compile(r"can't remove CT .* protection mode enabled", re.IGNORECASE),
    re.compile(r"cannot (?:delete|remove).* protection (?:is )?enabled", re.IGNORECASE),
    re.compile(r"(?:delete|remove).*(?:denied|refused).*protected", re.IGNORECASE),
)
INCONCLUSIVE_ERRORS = re.compile(
    r"(?:401|403|unauthori[sz]ed|forbidden|permission denied|certificate|tls|x509|"
    r"connection (?:refused|reset)|could not resolve|no route to host|timed? out|timeout|"
    r"transport error|provider.*(?:unavailable|failed to start|crash))",
    re.IGNORECASE,
)
PROVIDER_KEYS = {
    "clone",
    "console",
    "cpu",
    "description",
    "device_passthrough",
    "disk",
    "environment_variables",
    "features",
    "hook_script_file_id",
    "id",
    "idmap",
    "initialization",
    "ipv4",
    "ipv6",
    "memory",
    "mount_point",
    "network_interface",
    "node_name",
    "operating_system",
    "pool_id",
    "protection",
    "start_on_boot",
    "started",
    "startup",
    "tags",
    "template",
    "timeout_clone",
    "timeout_create",
    "timeout_delete",
    "timeout_start",
    "timeout_update",
    "unprivileged",
    "vm_id",
    "wait_for_ip",
}
PLAN_REQUIRED_KEYS = PROVIDER_KEYS - {"id", "ipv4", "ipv6"}
EMPTY_BLOCKS = {
    "clone",
    "device_passthrough",
    "features",
    "idmap",
    "mount_point",
    "network_interface",
    "startup",
    "wait_for_ip",
}
KNOWN_AFTER_UNKNOWN = {
    "clone": [],
    "console": [{}],
    "cpu": [{}],
    "device_passthrough": [],
    "disk": [{}],
    "features": [],
    "idmap": [],
    "initialization": [{"dns": [], "ip_config": [], "user_account": []}],
    "memory": [{}],
    "mount_point": [],
    "network_interface": [],
    "operating_system": [{}],
    "startup": [],
    "wait_for_ip": [],
}
CREATE_AFTER_UNKNOWN = deepcopy(KNOWN_AFTER_UNKNOWN)
CREATE_AFTER_UNKNOWN["disk"] = [{"path_in_datastore": True}]
CREATE_AFTER_UNKNOWN.update({"id": True, "ipv4": True, "ipv6": True})


class QualificationError(ValueError):
    """Raised when qualification evidence violates an invariant."""


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize_endpoint(value: str) -> str:
    parsed = parse.urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise QualificationError("the Proxmox endpoint identity is invalid")
    try:
        port = parsed.port
    except ValueError as error:
        raise QualificationError("the Proxmox endpoint identity is invalid") from error
    hostname = parsed.hostname.lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    authority = hostname if port is None else f"{hostname}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path).rstrip("/")
    if not path:
        raise QualificationError("the Proxmox endpoint path is missing")
    return f"https://{authority}{path}"


def target_identities(lockfile: Path = LOCKFILE) -> dict[str, str]:
    bucket = os.environ.get("TF_BACKEND_BUCKET", "")
    endpoint = os.environ.get("TF_VAR_proxmox_endpoint", "")
    ca_certificate = os.environ.get("PROXMOX_CA_PEM", "")
    if not bucket or not ca_certificate:
        raise QualificationError("a target identity input is missing")
    try:
        lock_digest = hashlib.sha256(lockfile.read_bytes()).hexdigest()
    except OSError as error:
        raise QualificationError("the provider lock identity is unavailable") from error
    return {
        "backend_bucket_sha256": sha256_text(bucket),
        "proxmox_endpoint_sha256": sha256_text(normalize_endpoint(endpoint)),
        "backend_key_sha256": sha256_text(BACKEND_KEY),
        "provider_lock_sha256": lock_digest,
        "ca_certificate_sha256": sha256_text(ca_certificate),
    }


def secret_inputs() -> tuple[int, str]:
    raw_vmid = os.environ.get("TF_VAR_qualification_vm_id", "")
    template = os.environ.get("TF_VAR_qualification_template_file_id", "")
    if not raw_vmid.isdigit():
        raise QualificationError("the protected qualification VMID is missing or invalid")
    vmid = int(raw_vmid)
    if vmid in {100, 101} or not 102 <= vmid <= 999999999:
        raise QualificationError("the protected qualification VMID is outside the permitted range")
    if not TEMPLATE_PATTERN.fullmatch(template):
        raise QualificationError("the protected template file ID has invalid syntax")
    return vmid, template


def canonical_description(value: Any) -> str:
    if value not in (MARKER, f"{MARKER}\n"):
        raise QualificationError("qualification marker is not exact")
    return MARKER


def changed_keys(before: Any, after: Any, prefix: tuple[str, ...] = ()) -> set[tuple[str, ...]]:
    if isinstance(before, dict) and isinstance(after, dict):
        result: set[tuple[str, ...]] = set()
        for key in before.keys() | after.keys():
            result |= changed_keys(before.get(key), after.get(key), prefix + (str(key),))
        return result
    if before != after:
        return {prefix}
    return set()


def singleton_block(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise QualificationError(f"qualification {name} block is not singular")
    return value[0]


def exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise QualificationError(f"qualification {name} exposes unexpected capabilities")


def validate_identity(
    value: Any, protected: bool, *, require_disk_path: bool = False
) -> dict[str, Any]:
    expected_vmid, expected_template = secret_inputs()
    if not isinstance(value, dict):
        raise QualificationError("qualification identity is missing")
    normalized = deepcopy(value)
    if not PLAN_REQUIRED_KEYS <= set(normalized) or not set(normalized) <= PROVIDER_KEYS:
        raise QualificationError("qualification identity exposes unexpected provider capabilities")
    normalized["description"] = canonical_description(normalized.get("description"))
    if normalized.get("vm_id") != expected_vmid or normalized.get("node_name") != "proxmox":
        raise QualificationError("qualification VMID or node does not match the protected identity")
    if normalized.get("protection") is not protected:
        raise QualificationError("qualification protection is not exact")
    if normalized.get("started") is not False or normalized.get("start_on_boot") is not False:
        raise QualificationError("qualification must remain stopped and off at boot")
    if normalized.get("unprivileged") is not True or normalized.get("template") is not False:
        raise QualificationError("qualification privilege or template mode is not minimal")
    for name in EMPTY_BLOCKS:
        if normalized.get(name) != []:
            raise QualificationError(f"qualification {name} capability is forbidden")
    if normalized.get("environment_variables") not in (None, {}) or normalized.get("tags") not in (None, []):
        raise QualificationError("qualification mappings or tags are forbidden")
    if normalized.get("hook_script_file_id") not in (None, "") or normalized.get("pool_id") not in (None, ""):
        raise QualificationError("qualification hooks or pool mappings are forbidden")
    normalized["hook_script_file_id"] = None
    normalized["pool_id"] = None
    expected_timeouts = {
        "timeout_clone": 1800,
        "timeout_create": 1800,
        "timeout_delete": 60,
        "timeout_start": 300,
        "timeout_update": 1800,
    }
    if any(normalized.get(key) != expected for key, expected in expected_timeouts.items()):
        raise QualificationError("qualification provider timeouts are not defaults")
    console = singleton_block(normalized.get("console"), "console")
    exact_keys(console, {"enabled", "tty_count", "type"}, "console")
    if console != {"enabled": False, "tty_count": 0, "type": "tty"}:
        raise QualificationError("qualification console is not disabled")
    cpu = singleton_block(normalized.get("cpu"), "CPU")
    exact_keys(cpu, {"architecture", "cores", "limit", "units"}, "CPU")
    if cpu != {"architecture": "amd64", "cores": 1, "limit": 0, "units": 100}:
        raise QualificationError("qualification CPU is not minimal")
    memory = singleton_block(normalized.get("memory"), "memory")
    exact_keys(memory, {"dedicated", "swap"}, "memory")
    if memory != {"dedicated": 128, "swap": 0}:
        raise QualificationError("qualification memory is not minimal")
    disk = singleton_block(normalized.get("disk"), "root disk")
    if not {"acl", "datastore_id", "mount_options", "quota", "replicate", "size"} <= set(disk) or not set(disk) <= {
        "acl", "datastore_id", "mount_options", "path_in_datastore", "quota", "replicate", "size"
    }:
        raise QualificationError("qualification root disk exposes unexpected capabilities")
    if (
        disk.get("acl") is not False
        or disk.get("datastore_id") != "local-lvm"
        or disk.get("mount_options") not in (None, [])
        or disk.get("quota") is not False
        or disk.get("replicate") is not False
        or disk.get("size") != 1
    ):
        raise QualificationError("qualification root disk is not exact")
    if require_disk_path and "path_in_datastore" not in disk:
        raise QualificationError("qualification root disk provider identity is missing")
    if "path_in_datastore" in disk and not re.fullmatch(
        rf"local-lvm:(?:vm|subvol)-{expected_vmid}-disk-0",
        str(disk["path_in_datastore"]),
    ):
        raise QualificationError("qualification root disk identity is invalid")
    initialization = singleton_block(normalized.get("initialization"), "initialization")
    exact_keys(initialization, {"dns", "entrypoint", "hostname", "ip_config", "user_account"}, "initialization")
    for empty_block in ("dns", "ip_config", "user_account"):
        if initialization.get(empty_block) is None:
            initialization[empty_block] = []
    if initialization.get("entrypoint") == "":
        initialization["entrypoint"] = None
    if initialization != {
        "dns": [], "entrypoint": None, "hostname": MARKER, "ip_config": [], "user_account": []
    }:
        raise QualificationError("qualification initialization is not exact")
    operating_system = singleton_block(normalized.get("operating_system"), "operating system")
    exact_keys(operating_system, {"template_file_id", "type"}, "operating system")
    if operating_system != {"template_file_id": expected_template, "type": "unmanaged"}:
        raise QualificationError("qualification operating system is not exact")
    if "id" in normalized and normalized["id"] not in (str(expected_vmid), f"proxmox/{expected_vmid}"):
        raise QualificationError("qualification provider ID is not exact")
    for address_family in ("ipv4", "ipv6"):
        if address_family in normalized and normalized[address_family] not in (None, {}):
            raise QualificationError("qualification has a computed network address")
    return normalized


def validate_change_unknowns(change: dict[str, Any], actions: list[str]) -> None:
    if "before_unknown" in change and change["before_unknown"] != {}:
        raise QualificationError("qualification before_unknown capabilities are forbidden")
    if actions == ["create"]:
        expected_after_unknown: Any = CREATE_AFTER_UNKNOWN
    else:
        expected_after_unknown = {}
    if change.get("after_unknown", {}) != expected_after_unknown:
        raise QualificationError("qualification after_unknown capabilities are not exact")


def inspect_plan(plan: Any, mode: str) -> None:
    if mode not in OPERATIONS or not isinstance(plan, dict):
        raise QualificationError("qualification policy mode or plan is invalid")
    resources = plan.get("resource_changes", [])
    if not isinstance(resources, list):
        raise QualificationError("qualification resource changes are malformed")
    actionable: list[dict[str, Any]] = []
    for resource in resources:
        if (
            not isinstance(resource, dict)
            or resource.get("address") != ADDRESS
            or resource.get("mode") != "managed"
            or resource.get("type") != "proxmox_virtual_environment_container"
            or resource.get("provider_name") != PROVIDER_SOURCE
        ):
            raise QualificationError("qualification plan contains a forbidden resource identity")
        change = resource.get("change", {})
        if not isinstance(change, dict):
            raise QualificationError("qualification resource change is malformed")
        actions = change.get("actions", [])
        validate_change_unknowns(change, actions)
        if change.get("importing") is not None:
            raise QualificationError("qualification imports are forbidden")
        if actions not in ([], ["no-op"], ["read"]):
            actionable.append(resource)
    if mode == "verify-empty":
        if actionable or resources:
            raise QualificationError("empty qualification verification requires no resource changes")
        return
    if mode == "verify-protected":
        if actionable or len(resources) != 1:
            raise QualificationError("protected qualification verification requires one exact no-op")
        change = resources[0].get("change", {})
        if change.get("actions") != ["no-op"]:
            raise QualificationError("protected qualification verification is not an exact no-op")
        validate_identity(change.get("before"), True)
        validate_identity(change.get("after"), True)
        return
    if len(actionable) != 1:
        raise QualificationError("qualification mutation requires exactly one resource action")
    change = actionable[0].get("change", {})
    before = change.get("before")
    after = change.get("after")
    expected_actions = {
        "create": ["create"],
        "probe-protected-delete": ["delete"],
        "unprotect": ["update"],
        "reprotect": ["update"],
        "delete": ["delete"],
    }[mode]
    if change.get("actions") != expected_actions:
        raise QualificationError("qualification action is not exact")
    if mode == "create":
        if before is not None:
            raise QualificationError("qualification create is not fresh")
        validate_identity(after, True)
    elif mode == "probe-protected-delete":
        validate_identity(before, True)
        if after is not None:
            raise QualificationError("protected-delete probe is not a deletion")
    elif mode in {"unprotect", "reprotect"}:
        normalized_before = validate_identity(before, mode == "unprotect")
        normalized_after = validate_identity(after, mode == "reprotect")
        if changed_keys(normalized_before, normalized_after) != {("protection",)}:
            raise QualificationError(f"{mode} changes more than protection")
    else:
        validate_identity(before, False)
        if after is not None:
            raise QualificationError("qualification delete is not exact")


def classify_probe_log(text: str) -> bool:
    return any(pattern.search(text) for pattern in PROTECTION_REJECTIONS) and not INCONCLUSIVE_ERRORS.search(text)


def create_manifest(operation: str, commit: str, plan: Path) -> dict[str, Any]:
    if operation not in OPERATIONS:
        raise QualificationError("saved-plan manifest operation is invalid")
    return {
        "version": 3,
        "run_id": str(time.time_ns()),
        "operation": operation,
        "commit": commit,
        "marker": MARKER,
        "plan_file": "qualification.tfplan",
        "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "target_identities": target_identities(),
    }


def validate_manifest(manifest: Any, operation: str, commit: str, plan: Path) -> None:
    expected_keys = {"version", "run_id", "operation", "commit", "marker", "plan_file", "plan_sha256", "target_identities"}
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise QualificationError("saved-plan manifest fields are invalid")
    if manifest.get("version") != 3 or manifest.get("operation") != operation:
        raise QualificationError("saved-plan manifest operation is invalid")
    if not isinstance(manifest.get("run_id"), str) or not re.fullmatch(r"[1-9][0-9]*", manifest["run_id"]):
        raise QualificationError("saved-plan manifest run ID is invalid")
    if operation not in OPERATIONS or manifest.get("commit") != commit:
        raise QualificationError("saved-plan manifest source is invalid")
    if manifest.get("marker") != MARKER or manifest.get("plan_file") != "qualification.tfplan":
        raise QualificationError("saved-plan manifest identity is invalid")
    if manifest.get("plan_sha256") != hashlib.sha256(plan.read_bytes()).hexdigest():
        raise QualificationError("saved-plan hash does not match")
    identities = manifest.get("target_identities")
    if not isinstance(identities, dict) or set(identities) != IDENTITY_HASH_KEYS or identities != target_identities():
        raise QualificationError("saved-plan target identity does not match")


def state_instance(state: Any) -> dict[str, Any] | None:
    if not isinstance(state, dict):
        raise QualificationError("qualification state is malformed")
    if state.get("outputs") not in (None, {}):
        raise QualificationError("qualification state contains unexpected outputs")
    resources = state.get("resources", [])
    if not isinstance(resources, list):
        raise QualificationError("qualification state resources are malformed")
    if not resources:
        return None
    if len(resources) != 1:
        raise QualificationError("qualification state contains an extra resource")
    resource = resources[0]
    if resource.get("mode") != "managed" or resource.get("type") != "proxmox_virtual_environment_container" or resource.get("name") != "qualification":
        raise QualificationError("qualification state address is invalid")
    instances = resource.get("instances")
    if not isinstance(instances, list) or len(instances) != 1 or instances[0].get("index_key") not in (None, 0):
        raise QualificationError("qualification state instance is not singular")
    attributes = instances[0].get("attributes")
    if not isinstance(attributes, dict):
        raise QualificationError("qualification state attributes are missing")
    return attributes


def validate_state(state: Any, mode: str) -> None:
    attributes = state_instance(state)
    if mode == "empty":
        if attributes is not None or state.get("outputs") not in (None, {}):
            raise QualificationError("qualification root state is not empty")
        return
    if mode not in {"protected", "unprotected"} or attributes is None:
        raise QualificationError("qualification state mode is invalid")
    validate_identity(
        attributes,
        mode == "protected",
        require_disk_path=True,
    )


def proxmox_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    # Proxmox's generated CA predates the CA key-usage requirement enabled by
    # Python/OpenSSL strict verification. Keep chain and hostname verification.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context

def api_get(path: str, query: dict[str, str] | None = None) -> Any:
    endpoint = normalize_endpoint(os.environ.get("TF_VAR_proxmox_endpoint", ""))
    token = os.environ.get("PROXMOX_VE_API_TOKEN", "")
    if not token:
        raise QualificationError("strict-TLS read-only credential is missing")
    url = f"{endpoint}/{path.lstrip('/')}"
    if query:
        url = f"{url}?{parse.urlencode(query)}"
    api_request = request.Request(url, headers={"Authorization": f"PVEAPIToken={token}", "Accept": "application/json"})
    try:
        with request.urlopen(api_request, timeout=20, context=proxmox_ssl_context()) as response:
            document = json.load(response)
    except Exception as error:
        raise QualificationError("protected read-only Proxmox API validation failed") from error
    if not isinstance(document, dict) or "data" not in document:
        raise QualificationError("protected read-only Proxmox API response is malformed")
    return document["data"]


def truthy(value: Any) -> bool:
    return value in (1, "1", True, "true", "on")


def falsey(value: Any) -> bool:
    return value in (0, "0", False, "false", "off", None)


def storage_volume_verification_enabled() -> bool:
    return os.environ.get("PROXMOX_VERIFY_STORAGE_VOLUME") == "true"


def volume_ids(vmid: int) -> list[str]:
    volumes = api_get("nodes/proxmox/storage/local-lvm/content")
    if not isinstance(volumes, list):
        raise QualificationError("live volume inventory is malformed")
    pattern = re.compile(rf"^local-lvm:(?:vm|subvol)-{vmid}-disk-")
    return [str(entry.get("volid")) for entry in volumes if isinstance(entry, dict) and pattern.match(str(entry.get("volid", "")))]


def live_identity() -> bool | None:
    vmid, _ = secret_inputs()
    resources = api_get("cluster/resources", {"type": "vm"})
    if not isinstance(resources, list):
        raise QualificationError("live resource inventory is malformed")
    matches = [entry for entry in resources if isinstance(entry, dict) and entry.get("vmid") == vmid]
    if not matches:
        if storage_volume_verification_enabled() and volume_ids(vmid):
            raise QualificationError("qualification volume exists without the container")
        return None
    if len(matches) != 1:
        raise QualificationError("exact qualification LXC is not present once")
    live = matches[0]
    if live.get("type") != "lxc" or live.get("node") != "proxmox" or live.get("status") != "stopped" or live.get("name") != MARKER:
        raise QualificationError("live qualification inventory identity is invalid")
    config = api_get(f"nodes/proxmox/lxc/{vmid}/config")
    if not isinstance(config, dict):
        raise QualificationError("live qualification configuration is malformed")
    allowed = {"arch", "cmode", "console", "cores", "cpulimit", "cpuunits", "description", "digest", "hostname", "memory", "onboot", "ostype", "protection", "rootfs", "swap", "template", "tty", "unprivileged"}
    if not set(config) <= allowed:
        raise QualificationError("live qualification configuration exposes an extra capability")
    required = {"cores", "description", "hostname", "memory", "protection", "rootfs", "unprivileged"}
    if not required <= set(config):
        raise QualificationError("live qualification configuration is incomplete")
    description = canonical_description(config.get("description"))
    rootfs = str(config.get("rootfs", ""))
    root_parts = rootfs.split(",")
    volume_pattern = re.compile(rf"^local-lvm:(?:vm|subvol)-{vmid}-disk-0$")
    volume_id = root_parts[0] if root_parts and volume_pattern.fullmatch(root_parts[0]) else ""
    matching_volumes = volume_ids(vmid) if storage_volume_verification_enabled() else [volume_id]
    digest = config.get("digest")
    if digest is not None and not re.fullmatch(r"[0-9a-f]{40}", str(digest)):
        raise QualificationError("live qualification configuration digest is malformed")
    if (
        config.get("hostname") != MARKER
        or description != MARKER
        or not truthy(config.get("unprivileged"))
        or not falsey(config.get("onboot"))
        or not falsey(config.get("console"))
        or config.get("tty") not in (None, 0, "0")
        or config.get("cmode") not in (None, "tty")
        or config.get("arch") not in (None, "amd64")
        or config.get("cores") not in (1, "1")
        or config.get("cpulimit") not in (None, 0, "0")
        or config.get("cpuunits") not in (None, 100, "100")
        or config.get("memory") not in (128, "128")
        or config.get("swap") not in (0, "0", None)
        or not falsey(config.get("template"))
        or root_parts != [volume_id, "size=1G"]
        or matching_volumes != [volume_id]
    ):
        raise QualificationError("live qualification configuration identity is invalid")
    return truthy(config.get("protection"))


def validate_live(mode: str) -> None:
    vmid, template = secret_inputs()
    if mode == "pre-create":
        resources = api_get("cluster/resources", {"type": "vm"})
        if not isinstance(resources, list) or any(isinstance(entry, dict) and entry.get("vmid") == vmid for entry in resources):
            raise QualificationError("qualification VMID is not absent before create")
        if storage_volume_verification_enabled() and volume_ids(vmid):
            raise QualificationError("qualification VMID has a residual volume before create")
        templates = api_get("nodes/proxmox/storage/local/content", {"content": "vztmpl"})
        if not isinstance(templates, list) or sum(isinstance(entry, dict) and entry.get("volid") == template for entry in templates) != 1:
            raise QualificationError("the exact protected template does not exist once")
        return
    protection = live_identity()
    if mode == "absent":
        if protection is not None:
            raise QualificationError("qualification LXC is still present")
        return
    if mode not in {"protected", "unprotected"} or protection is None or protection is not (mode == "protected"):
        raise QualificationError("live qualification protection is not exact")


def recovery_diagnostic(error: QualificationError) -> str:
    # QualificationError messages are fixed, value-free control labels.
    return re.sub(r"[^a-z0-9]+", "-", str(error).lower()).strip("-")[:96]


def recovery_classification(state: Any, live_protection: bool | None) -> str:
    try:
        attributes = state_instance(state)
        if attributes is None:
            state_protection = None
        else:
            protection = attributes.get("protection")
            if not isinstance(protection, bool):
                return "state-identity-mismatch:protection-not-boolean"
            validate_identity(attributes, protection, require_disk_path=True)
            state_protection = protection
    except QualificationError as error:
        return f"state-identity-mismatch:{recovery_diagnostic(error)}"
    if state_protection is None and live_protection is None:
        return "aligned-empty"
    if state_protection is None:
        return "live-only-protected" if live_protection else "live-only-unprotected"
    if live_protection is None:
        return "state-only"
    if state_protection != live_protection:
        return "protection-mismatch"
    return "aligned-protected" if state_protection else "aligned-unprotected"


def inspect_recovery(state: Any) -> str:
    try:
        live_protection = live_identity()
    except QualificationError as error:
        return f"live-identity-mismatch:{recovery_diagnostic(error)}"
    return recovery_classification(state, live_protection)


def locked_provider(lockfile: Path = LOCKFILE) -> tuple[str, str]:
    try:
        text = lockfile.read_text()
    except OSError as error:
        raise QualificationError("the provider lock evidence is unavailable") from error
    provider = re.search(
        r'^provider "([^"]+)" \{.*?^  version     = "([^"]+)"$',
        text,
        re.MULTILINE | re.DOTALL,
    )
    if provider is None or provider.group(1) != PROVIDER_SOURCE:
        raise QualificationError("the pinned provider evidence is invalid")
    return provider.group(1), provider.group(2)


def validate_run_evidence(
    evidence: Any,
    expected_tooling_commit: str | None = None,
    lockfile: Path = LOCKFILE,
) -> None:
    expected_keys = {
        "version",
        "qualification_tooling_commit",
        "provider",
        "runs",
        "final_proof",
        "protected_identifiers_included",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_keys:
        raise QualificationError("qualification evidence fields are invalid")
    commit = evidence.get("qualification_tooling_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise QualificationError("qualification tooling commit evidence is invalid")
    if expected_tooling_commit is not None and commit != expected_tooling_commit:
        raise QualificationError("qualification tooling commit does not match the PR base")
    if evidence.get("version") != 1 or evidence.get("protected_identifiers_included") is not False:
        raise QualificationError("qualification evidence version or identifier declaration is invalid")

    provider_source, provider_version = locked_provider(lockfile)
    provider = evidence.get("provider")
    expected_provider = {
        "source": provider_source,
        "version": provider_version,
        "lock_sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest(),
    }
    if provider != expected_provider:
        raise QualificationError("qualification provider evidence does not match the pinned lock")

    runs = evidence.get("runs")
    if not isinstance(runs, list) or len(runs) != len(EVIDENCE_OPERATIONS):
        raise QualificationError("qualification evidence does not record exactly six runs")
    run_ids: list[str] = []
    for run, operation in zip(runs, EVIDENCE_OPERATIONS, strict=True):
        if not isinstance(run, dict) or set(run) != {"operation", "run_id"}:
            raise QualificationError("qualification run evidence fields are invalid")
        run_id = run.get("run_id")
        if run.get("operation") != operation or not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]*", run_id):
            raise QualificationError("qualification evidence operation sequence is invalid")
        run_ids.append(run_id)
    if len(set(run_ids)) != len(run_ids):
        raise QualificationError("qualification evidence reuses a run ID")

    expected_final = {
        "operation": "verify-empty",
        "run_id": run_ids[-1],
        "state": "empty",
        "plan": "no-op",
        "api": "absent",
        "volumes": "absent",
        "backend_lock": "absent",
    }
    if evidence.get("final_proof") != expected_final:
        raise QualificationError("qualification final empty/no-op proof is invalid")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    policy = commands.add_parser("inspect-plan")
    policy.add_argument("--plan-json", type=Path, required=True)
    policy.add_argument("--mode", choices=sorted(OPERATIONS), required=True)
    classify = commands.add_parser("classify-probe-log")
    classify.add_argument("--log", type=Path, required=True)
    manifest = commands.add_parser("verify-manifest")
    manifest.add_argument("--manifest", type=Path, required=True)
    manifest.add_argument("--operation", choices=sorted(OPERATIONS), required=True)
    manifest.add_argument("--commit", required=True)
    manifest.add_argument("--plan", type=Path, required=True)
    create = commands.add_parser("create-manifest")
    create.add_argument("--manifest", type=Path, required=True)
    create.add_argument("--operation", choices=sorted(OPERATIONS), required=True)
    create.add_argument("--commit", required=True)
    create.add_argument("--plan", type=Path, required=True)
    state = commands.add_parser("validate-state")
    state.add_argument("--state-json", type=Path, required=True)
    state.add_argument("--mode", choices=("protected", "unprotected", "empty"), required=True)
    live = commands.add_parser("api-check")
    live.add_argument("--mode", choices=("pre-create", "protected", "unprotected", "absent"), required=True)
    recovery = commands.add_parser("inspect-recovery")
    recovery.add_argument("--state-json", type=Path, required=True)
    evidence = commands.add_parser("validate-run-evidence")
    evidence.add_argument("--evidence-json", type=Path, required=True)
    evidence.add_argument("--expected-tooling-commit")
    evidence.add_argument("--provider-lockfile", type=Path, default=LOCKFILE)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "inspect-plan":
            inspect_plan(json.loads(args.plan_json.read_text()), args.mode)
            print(f"qualification plan policy passed: mode={args.mode}")
        elif args.command == "classify-probe-log":
            if not classify_probe_log(args.log.read_text(errors="replace")):
                raise QualificationError("probe failure was not a recognized protection rejection")
            print("recognized protection-specific delete rejection")
        elif args.command == "verify-manifest":
            validate_manifest(json.loads(args.manifest.read_text()), args.operation, args.commit, args.plan)
            print("saved qualification plan manifest and target identities verified")
        elif args.command == "create-manifest":
            args.manifest.write_text(json.dumps(create_manifest(args.operation, args.commit, args.plan), separators=(",", ":")) + "\n")
            print("saved qualification plan manifest created")
        elif args.command == "validate-state":
            validate_state(json.loads(args.state_json.read_text()), args.mode)
            print(f"qualification state identity verified: mode={args.mode}")
        elif args.command == "api-check":
            validate_live(args.mode)
            print(f"qualification API identity verified: mode={args.mode}")
        elif args.command == "validate-run-evidence":
            validate_run_evidence(
                json.loads(args.evidence_json.read_text()),
                args.expected_tooling_commit,
                args.provider_lockfile,
            )
            print("qualification run evidence and final proof are exact")
        else:
            result = inspect_recovery(json.loads(args.state_json.read_text()))
            print(result)
            return 0 if result in RECOVERY_RESULTS else 1
        return 0
    except (OSError, json.JSONDecodeError, QualificationError) as error:
        if args.command == "inspect-recovery":
            print("identity-mismatch")
        else:
            print(f"LXC qualification validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
