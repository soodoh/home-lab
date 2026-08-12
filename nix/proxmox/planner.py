#!/usr/bin/env python3
"""Deterministic Proxmox host plan and exact guarded-apply controller."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PLAN_FORMAT = "home-lab-proxmox-plan-v1"
OBSERVATION_FORMAT = "home-lab-proxmox-observation-v1"
BUNDLE_FORMAT = "home-lab-proxmox-host-bundle-v1"
PROTOCOL = 4
MAX_OBSERVATION_BYTES = 1024 * 1024
_OBSERVER_REMOTE = "/" + "usr" + "/" + "local" + "/libexec/home-lab/proxmox-observer"
SSH_COMMAND = (
    "ssh", "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
    "-o", "RequestTTY=no", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
    "tofu-plan@proxmox", "sudo -n -- " + _OBSERVER_REMOTE + " observe",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DOMAIN_ORDER = {
    name: index for index, name in enumerate((
        "identity", "managed-artifacts", "managed-files", "managed-fragments", "packages", "accounts",
        "services", "tailscale", "pve-access", "pve-storage", "storage", "pve-firewall", "health",
        "audit-absence", "protected-access", "opentofu", "protected-hardware",
    ))
}
ACTION_KINDS = {
    "managed-files": "replace-file", "managed-fragments": "ensure-fragment", "managed-artifacts": "install-artifact",
    "packages": "reconcile-package-set", "services": "reconcile-service",
}
TARGET_TYPES = {
    "managed-files": "file", "managed-fragments": "file-fragment", "managed-artifacts": "artifact",
    "packages": "package-set", "services": "service",
}
FORBIDDEN_KEYS = {"argv", "command", "executable", "payload", "script"}
APPROVED_SOURCE_FILES = {
    "flake.lock", "flake.nix", "proxmox/activation-envelope.schema.json", "proxmox/activator-template.py",
    "proxmox/apply.py", "proxmox/bundle.py", "proxmox/controller_lock.py", "proxmox/fixture-observation.json",
    "proxmox/observation.schema.json", "proxmox/observer-template.py", "proxmox/package-manifest.json",
    "proxmox/package-manifest.schema.json",
    "proxmox/plan.schema.json", "proxmox/planner.py", "proxmox/prepare.py", "proxmox/private-preconditions.schema.json",
    "proxmox/private-preparation-request.schema.json", "proxmox/private-preparer-template.py",
    "proxmox/projection.json", "proxmox/projection.schema.json",
}
_PVE_ROOT = "/" + "etc" + "/" + "pve"
_PROTECTED_KEY_NAME = "authorized" + "_keys"
PROTECTED_VALUE = re.compile(
    r"(?:" + re.escape(_PVE_ROOT) + r"(?:/|$)|" + _PROTECTED_KEY_NAME + r"|ssh_" + r"host_|"
    r"/dev/(?:disk|serial)|/root/\.config/home-lab|"
    r"\b[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\b|\b[0-9a-f]{4}:[0-9a-f]{4}\b|"
    r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b)", re.IGNORECASE,
)
_OBSERVATION_SECRET_REFERENCE = re.compile(
    r"(?:" + "HOME" + r"LAB_[A-Z0-9_]*|PROXMOX_[A-Z0-9_]*_SSH_PUBLIC_KEYS|" +
    "TAIL" + r"SCALE_AUTH_KEY)", re.IGNORECASE,
)
_OBSERVATION_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE,
)
_OBSERVATION_HEX64 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.IGNORECASE)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def digest(value: Any) -> str:
    content = value if isinstance(value, bytes) else canonical_json(value)
    return hashlib.sha256(content).hexdigest()


def fail(message: str, code: int = 1) -> "NoReturn":
    print(f"proxmox-host: {message}", file=sys.stderr)
    raise SystemExit(code)


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must contain exactly {sorted(keys)}")
    return value


def valid_count(value: Any, nullable: bool = False) -> bool:
    return (nullable and value is None) or (isinstance(value, int) and not isinstance(value, bool) and value >= 0)


def validate_summary(value: Any, label: str) -> None:
    exact_object(value, {"expectedCount", "matches", "observedCount", "status"}, label)
    if value["status"] not in {"complete", "unavailable"} or not valid_count(value["expectedCount"]):
        raise ValueError(f"{label} has invalid status or expected count")
    if value["status"] == "unavailable":
        if value["matches"] is not None or value["observedCount"] is not None:
            raise ValueError(f"{label} unavailable summary must be redacted nulls")
    elif not isinstance(value["matches"], bool) or not valid_count(value["observedCount"]):
        raise ValueError(f"{label} complete summary is invalid")


def valid_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def valid_safe_path(value: Any) -> bool:
    return valid_nonempty_string(value) and value.startswith("/") and not PROTECTED_VALUE.search(value)


def validate_records_domain(value: Any, record_keys: set[str], label: str, identity_key: str,
                            validator: "Callable[[dict[str, Any]], bool]") -> None:
    exact_object(value, {"records", "status", "unexpectedCount"}, label)
    if value["status"] not in {"complete", "unavailable"} or not isinstance(value["records"], list):
        raise ValueError(f"{label} is invalid")
    if value["status"] == "unavailable":
        if value["records"] or value["unexpectedCount"] is not None:
            raise ValueError(f"{label} unavailable domain must have no records and a null count")
    elif not valid_count(value["unexpectedCount"]):
        raise ValueError(f"{label} complete domain has an invalid unexpected count")
    identities = []
    for index, record in enumerate(value["records"]):
        exact_object(record, record_keys, f"{label}.records[{index}]")
        if not validator(record):
            raise ValueError(f"{label}.records[{index}] has invalid field types or values")
        identities.append(record[identity_key])
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise ValueError(f"{label} records must have unique, canonical identities")


def validate_observation_no_sensitive_literals(value: Any, key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            validate_observation_no_sensitive_literals(child, child_key)
    elif isinstance(value, list):
        for child in value:
            validate_observation_no_sensitive_literals(child, key)
    elif isinstance(value, str):
        if _OBSERVATION_SECRET_REFERENCE.search(value) or _OBSERVATION_UUID.search(value) or \
                (key != "observerSha256" and _OBSERVATION_HEX64.search(value)):
            raise ValueError(f"observation contains a forbidden sensitive literal in {key or 'value'}")


def validate_observation(value: Any) -> None:
    # Scan the entire untrusted object before any digest or normalization can be computed from it.
    validate_no_forbidden(value)
    validate_observation_no_sensitive_literals(value)
    exact_object(value, {"domains", "format", "host", "observerSha256", "protocol"}, "observation")
    if value["format"] != OBSERVATION_FORMAT or value["protocol"] != PROTOCOL or \
            not isinstance(value["protocol"], int) or isinstance(value["protocol"], bool) or \
            not isinstance(value["observerSha256"], str) or not HEX64.fullmatch(value["observerSha256"]):
        raise ValueError("observation format, protocol, or observer binding is invalid")
    host = exact_object(value["host"], {"architecture", "hostname", "kernel", "os", "pveVersion"}, "host")
    if any(not valid_nonempty_string(item) or PROTECTED_VALUE.search(item) for item in host.values()):
        raise ValueError("host contains invalid or protected data")
    domains = exact_object(value["domains"], {
        "accounts", "auditAbsence", "health", "managedArtifacts", "managedFiles", "managedFragments", "packages",
        "protectedAccess", "protectedHardware", "pveAccess", "pveFirewall", "pveStorage", "services", "storage", "tailscale", "vm",
    }, "domains")
    file_types = {"file", "symlink", "other", "absent"}
    mode = lambda item: isinstance(item, str) and re.fullmatch(r"0[0-7]{3}", item) is not None
    boolean = lambda item: isinstance(item, bool)
    validate_records_domain(domains["managedFiles"], {"contentMatches", "groupMatches", "mode", "ownerMatches", "target", "type"}, "managedFiles", "target",
        lambda r: valid_safe_path(r["target"]) and r["type"] in file_types and mode(r["mode"]) and all(boolean(r[k]) for k in ("contentMatches", "groupMatches", "ownerMatches")))
    validate_records_domain(domains["managedFragments"], {"groupMatches", "matchCount", "mode", "ownerMatches", "target", "type"}, "managedFragments", "target",
        lambda r: valid_safe_path(r["target"]) and r["type"] in file_types and mode(r["mode"]) and valid_count(r["matchCount"]) and all(boolean(r[k]) for k in ("groupMatches", "ownerMatches")))
    validate_records_domain(domains["managedArtifacts"], {"contentMatches", "groupMatches", "mode", "ownerMatches", "symlinkTargetMatches", "target", "type"}, "managedArtifacts", "target",
        lambda r: valid_safe_path(r["target"]) and r["type"] in file_types and mode(r["mode"]) and all(boolean(r[k]) for k in ("contentMatches", "groupMatches", "ownerMatches", "symlinkTargetMatches")))
    validate_records_domain(domains["auditAbsence"], {"count", "target", "type"}, "auditAbsence", "target",
        lambda r: valid_safe_path(r["target"]) and r["type"] in {"file", "matching-lines"} and valid_count(r["count"]))
    validate_records_domain(domains["packages"], {"name", "version"}, "packages", "name",
        lambda r: valid_nonempty_string(r["name"]) and valid_nonempty_string(r["version"]))
    validate_records_domain(domains["services"], {"active", "enabled", "name"}, "services", "name",
        lambda r: valid_nonempty_string(r["name"]) and boolean(r["active"]) and boolean(r["enabled"]))
    validate_records_domain(domains["accounts"], {"commentMatches", "exists", "expectedGroupsMatch", "home", "name", "passwordLocked", "primaryGroupMatches", "shell"}, "accounts", "name",
        lambda r: valid_nonempty_string(r["name"]) and valid_safe_path(r["home"]) and valid_safe_path(r["shell"]) and all(boolean(r[k]) for k in ("commentMatches", "exists", "expectedGroupsMatch", "passwordLocked", "primaryGroupMatches")))
    for name in ("tailscale", "pveAccess", "pveFirewall", "pveStorage", "storage", "health", "vm", "protectedAccess", "protectedHardware"):
        validate_summary(domains[name], name)


def validate_no_forbidden(value: Any, key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key.lower() in FORBIDDEN_KEYS:
                raise ValueError(f"forbidden field: {child_key}")
            validate_no_forbidden(child, child_key)
    elif isinstance(value, list):
        for child in value:
            validate_no_forbidden(child, key)
    elif isinstance(value, str) and PROTECTED_VALUE.search(value):
        raise ValueError(f"protected value in {key or 'value'}")


def parse_time(value: str) -> dt.datetime:
    if not isinstance(value, str) or not TIME.fullmatch(value):
        raise ValueError("timestamps must be UTC seconds in YYYY-MM-DDTHH:MM:SSZ form")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def format_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_canonical(path: Path, limit: int = MAX_OBSERVATION_BYTES) -> Any:
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError("JSON input exceeds the fixed size limit")
    value = json.loads(raw)
    if raw != canonical_json(value):
        raise ValueError("JSON input is not canonical")
    return value


def record_target(record: dict[str, Any]) -> str:
    return str(record.get("target", record.get("name", "singleton")))


def target(domain: str, name: str) -> dict[str, Any]:
    key = "path" if domain in {"managed-files", "managed-fragments", "managed-artifacts"} else "name"
    return {key: name, "type": TARGET_TYPES[domain]}


def safe_state(record: dict[str, Any] | None) -> dict[str, Any]:
    if record is None:
        return {"state": "absent"}
    allowed = {("loginShell" if key == "shell" else key): value for key, value in record.items()
               if key not in {"target", "name"}}
    return {"state": "present", **allowed}


def desired_records(projection: dict[str, Any], manifest: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        "managed-files": [{"target": item["path"], "type": "file", "ownerMatches": True, "groupMatches": True,
                           "mode": item["mode"], "contentMatches": True} for item in projection["managedFiles"]],
        "managed-fragments": [{"target": item["path"], "type": "file", "ownerMatches": True, "groupMatches": True,
                               "mode": item["mode"], "matchCount": 1} for item in projection["managedFileFragments"]],
        "managed-artifacts": [{"target": item["path"], "type": "symlink" if item["symlinkTarget"] else "file",
                               "ownerMatches": True, "groupMatches": True, "mode": item["mode"],
                               "contentMatches": True, "symlinkTargetMatches": True}
                              for item in projection["managedArtifacts"]],
        "packages": [{"name": item["name"], "version": item["version"]} for item in manifest["packages"]],
        "services": [{"name": item["name"], "enabled": item["enabled"], "active": item["state"] == "started"}
                     for item in projection["nativeServices"]],
        "accounts": [{"name": item["name"], "commentMatches": True, "exists": True, "home": item["home"],
                      "shell": item["shell"], "passwordLocked": item["passwordLock"],
                      "primaryGroupMatches": True, "expectedGroupsMatch": True}
                     for group in (projection["accounts"]["service"], projection["accounts"]["human"]) for item in group],
    }


def make_issue(kind: str, domain: str, code: str, target_name: str, detail: str) -> dict[str, Any]:
    identifier = digest({"code": code, "domain": domain, "target": target_name})
    return {"code": code, "detail": detail, "domain": domain, "id": identifier, "kind": kind,
            "target": target_name}


def plan_action(domain: str, observed: dict[str, Any] | None, desired: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    name = record_target(desired)
    before, after = safe_state(observed), safe_state(desired)
    action_id = digest({"after": after, "before": before, "domain": domain, "kind": ACTION_KINDS[domain], "target": name})
    precondition = digest({"before": before, "domain": domain, "target": name})
    return {
        "after": after, "approvalRequired": policy["requiresApproval"], "before": before, "dependsOn": [],
        "domain": domain, "id": action_id, "kind": ACTION_KINDS[domain],
        "postconditions": [{"expected": after, "type": "state-equals"}],
        "preconditionSha256": precondition, "rebootRequired": policy["requiresReboot"], "safetyClass": policy["safetyClass"],
        "sequence": 0, "target": target(domain, name), "watchdogRequired": policy["requiresWatchdog"],
    }


def build_plan(bindings: dict[str, Any], projection: dict[str, Any], manifest: dict[str, Any], observation: dict[str, Any],
               observed_at: str, completed_at: str, fixture: bool) -> dict[str, Any]:
    validate_observation(observation)
    start, end = parse_time(observed_at), parse_time(completed_at)
    if end < start:
        raise ValueError("completedAt precedes observedAt")
    max_age = projection["planningPolicy"]["maxAgeSeconds"]
    if (end - start).total_seconds() > max_age:
        raise ValueError("observation expired before planning completed")
    policy = {item["domain"]: item for item in projection["planningPolicy"]["domains"]}
    file_policy = {item["path"]: item for item in projection["planningPolicy"]["managedFilePolicies"]}
    service_policy = {item["name"]: item for item in projection["planningPolicy"]["servicePolicies"]}
    expected_file_targets = {item["path"] for item in projection["managedFiles"]}
    if set(file_policy) != expected_file_targets:
        raise ValueError("every managed-file target must have exactly one safety policy")
    facts = {"domains": observation["domains"], "host": observation["host"]}
    findings: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    pve_manager = next((item for item in projection["packagePolicy"]["critical"]
                        if item["role"] == "pve-manager"), None)
    if pve_manager is None:
        raise ValueError("projection lacks the required PVE manager identity policy")
    expected_identity = {
        "architecture": projection["architecture"],
        "hostname": projection["hostNetworking"]["hostname"], "os": "debian",
        "pveVersion": "pve-manager/" + pve_manager["version"],
    }
    identity_matches = all(observation["host"][key] == expected for key, expected in expected_identity.items())
    if not identity_matches:
        findings.append(make_issue("drift", "identity", "target-identity-mismatch", "host",
                                   "hostname, architecture, operating system, or PVE version differs"))
        blockers.append(make_issue("blocker", "identity", "wrong-target", "host",
                                   "refusing actions for a host that does not match the bound target identity"))
    desired = desired_records(projection, manifest)
    observed_names = {
        "managed-files": "managedFiles", "managed-fragments": "managedFragments", "managed-artifacts": "managedArtifacts",
        "packages": "packages", "services": "services", "accounts": "accounts",
    }
    for domain, domain_desired in desired.items():
        observed_domain = observation["domains"][observed_names[domain]]
        if observed_domain["status"] != "complete":
            blockers.append(make_issue("blocker", domain, "observation-unavailable", domain, "required safe domain is unavailable"))
            continue
        if domain == "packages":
            observed_map = {item["name"]: item["version"] for item in observed_domain["records"]}
            desired_map = {item["name"]: item["version"] for item in domain_desired}
            if observed_map != desired_map or observed_domain["unexpectedCount"]:
                findings.append(make_issue("drift", domain, "complete-package-set-drift", "complete-installed-map",
                                           "complete installed package map differs from the reviewed manifest"))
                blockers.append(make_issue("blocker", domain, "sealed-package-session-required", "complete-installed-map",
                                           "one joint package transaction remains closed until protected bootstrap"))
            continue
        by_target = {record_target(item): item for item in observed_domain["records"]}
        for expected in domain_desired:
            name = record_target(expected)
            current = by_target.get(name)
            if current != expected:
                findings.append(make_issue("drift", domain, "desired-state-drift", name, "observed safe state differs"))
                action_policy = file_policy[name] if domain == "managed-files" else service_policy[name] if domain == "services" else policy[domain]
                if action_policy["automatic"] and domain in ACTION_KINDS:
                    actions.append(plan_action(domain, current, expected, action_policy))
                else:
                    blockers.append(make_issue("blocker", domain, "review-required", name, "policy forbids automatic mutation"))
        unexpected = sorted(set(by_target) - {record_target(item) for item in domain_desired})
        if unexpected or observed_domain["unexpectedCount"]:
            blockers.append(make_issue("blocker", domain, "unknown-drift", domain,
                                       "one or more unexpected records require review"))
    summary_domains = {
        "tailscale": "tailscale", "pve-access": "pveAccess", "pve-firewall": "pveFirewall",
        "pve-storage": "pveStorage", "storage": "storage", "health": "health",
    }
    for domain, observed_name in summary_domains.items():
        summary = observation["domains"][observed_name]
        if summary["status"] != "complete":
            blockers.append(make_issue("blocker", domain, "observation-unavailable", domain, "required safe domain is unavailable"))
        elif not summary["matches"]:
            findings.append(make_issue("drift", domain, "desired-state-drift", domain, "observed summary differs"))
            blockers.append(make_issue("blocker", domain, "review-required", domain, "summary drift requires reviewed activation"))
    for domain, observed_name in (("audit-absence", "auditAbsence"),):
        records = observation["domains"][observed_name]
        if records["status"] != "complete":
            blockers.append(make_issue("blocker", domain, "observation-unavailable", domain, "audit domain unavailable"))
        for record in records["records"]:
            if record["count"]:
                findings.append(make_issue("audit", domain, "unexpected-presence", record["target"], "audit-absence drift found"))
                blockers.append(make_issue("blocker", domain, "manual-remediation-required", record["target"], "audit drift is never automatically removed"))
    vm = observation["domains"]["vm"]
    if vm["status"] != "complete" or not vm["matches"]:
        findings.append(make_issue("opentofu", "opentofu", "opentofu-drift", "vm-100", "OpenTofu-owned state is incomplete or differs"))
        blockers.append(make_issue("blocker", "opentofu", "opentofu-owner-required", "vm-100", "OpenTofu drift is never mutated here"))
    access = observation["domains"]["protectedAccess"]
    if access["status"] != "complete":
        blockers.append(make_issue("blocker", "protected-access", "observation-unavailable", "protected-access",
                                   "protected access attestation is unavailable"))
    elif not access["matches"]:
        blockers.append(make_issue("blocker", "protected-access", "private-observation-mismatch", "protected-access",
                                   "protected access attestation reports a mismatch"))
    protected = observation["domains"]["protectedHardware"]
    if protected["status"] != "complete":
        blockers.append(make_issue("blocker", "protected-hardware", "observation-unavailable", "protected-hardware",
                                   "protected hardware attestation is unavailable"))
    elif not protected["matches"]:
        blockers.append(make_issue("blocker", "protected-hardware", "private-observation-mismatch", "protected-hardware",
                                   "protected hardware attestation reports a mismatch"))
    if not identity_matches:
        actions = []
    actions.sort(key=lambda item: (DOMAIN_ORDER[item["domain"]], json.dumps(item["target"], sort_keys=True), item["kind"], item["id"]))
    previous_id = None
    for sequence, action in enumerate(actions, 1):
        action["sequence"] = sequence
        action["dependsOn"] = [] if previous_id is None else [previous_id]
        previous_id = action["id"]
    issue_sort = lambda item: (DOMAIN_ORDER[item["domain"]], item["target"], item["code"], item["id"])
    findings.sort(key=issue_sort)
    blockers.sort(key=issue_sort)
    status = "fixture" if fixture else ("blocked" if blockers else "ready")
    plan = {
        "actions": actions, "applyEligible": status == "ready", "bindings": bindings, "blockers": blockers,
        "findings": findings, "format": PLAN_FORMAT,
        "freshness": {"completedAt": completed_at, "maxAgeSeconds": max_age, "observedAt": observed_at,
                      "validUntil": format_time(start + dt.timedelta(seconds=max_age))},
        "mode": "fixture" if fixture else "steady", "observedState": {"domainStatuses": {
            name: value["status"] for name, value in sorted(observation["domains"].items())
        }, "sha256": digest(facts)}, "planSha256": "", "privatePreconditionsRequired": bool(blockers) or bool(actions),
        "status": status,
    }
    plan["planSha256"] = digest({key: value for key, value in plan.items() if key != "planSha256"})
    validate_plan(plan, projection, manifest)
    return plan


def validate_plan(plan: Any, projection: dict[str, Any], manifest: dict[str, Any]) -> None:
    validate_no_forbidden(plan)
    exact_object(plan, {"actions", "applyEligible", "bindings", "blockers", "findings", "format", "freshness", "mode",
                        "observedState", "planSha256", "privatePreconditionsRequired", "status"}, "plan")
    if not isinstance(plan["blockers"], list) or plan["mode"] not in {"steady", "fixture"}:
        raise ValueError("plan mode or blockers are invalid")
    expected_status = "fixture" if plan["mode"] == "fixture" else ("blocked" if plan["blockers"] else "ready")
    if plan["format"] != PLAN_FORMAT or plan["status"] != expected_status or \
            plan["applyEligible"] != (expected_status == "ready") or not isinstance(plan["applyEligible"], bool) or \
            not isinstance(plan["planSha256"], str) or not HEX64.fullmatch(plan["planSha256"]):
        raise ValueError("plan status or format is invalid")
    if plan["privatePreconditionsRequired"] != bool(plan["blockers"] or plan["actions"]):
        raise ValueError("private-precondition flag is invalid")
    expected_hash = digest({key: value for key, value in plan.items() if key != "planSha256"})
    if plan["planSha256"] != expected_hash:
        raise ValueError("plan hash binding is invalid")
    exact_object(plan["bindings"], {"activationEnvelopeSchemaSha256", "activatorSha256", "bundleContentSha256", "bundleFormat",
                                    "flakeLockSha256", "gitCommit", "gitTree", "observerProtocol", "observerSha256",
                                    "packageManifestSha256", "planSchemaSha256", "privatePreconditionsSchemaSha256",
                                    "privatePreparationRequestSchemaSha256", "privatePreparerSha256",
                                    "projectionSha256"}, "bindings")
    if plan["bindings"]["bundleFormat"] != BUNDLE_FORMAT or plan["bindings"]["observerProtocol"] != PROTOCOL:
        raise ValueError("plan bundle binding is invalid")
    for key, value in plan["bindings"].items():
        if key.endswith("Sha256") or key in {"gitCommit", "gitTree"}:
            if not isinstance(value, str) or (not HEX64.fullmatch(value) and
                    not (key in {"gitCommit", "gitTree"} and re.fullmatch(r"[0-9a-f]{40}", value))):
                raise ValueError(f"invalid binding {key}")
    freshness = exact_object(plan["freshness"], {"completedAt", "maxAgeSeconds", "observedAt", "validUntil"}, "freshness")
    start, end = parse_time(freshness["observedAt"]), parse_time(freshness["completedAt"])
    valid_until = parse_time(freshness["validUntil"])
    if freshness["maxAgeSeconds"] != projection["planningPolicy"]["maxAgeSeconds"] or \
            not valid_count(freshness["maxAgeSeconds"]) or end < start or end > valid_until or \
            freshness["validUntil"] != format_time(start + dt.timedelta(seconds=freshness["maxAgeSeconds"])):
        raise ValueError("plan freshness binding is invalid")
    observed_state = exact_object(plan["observedState"], {"domainStatuses", "sha256"}, "observedState")
    expected_status_names = {"accounts", "auditAbsence", "health", "managedArtifacts", "managedFiles",
                             "managedFragments", "packages", "protectedAccess", "protectedHardware", "pveAccess",
                             "pveFirewall", "pveStorage", "services", "storage", "tailscale", "vm"}
    exact_object(observed_state["domainStatuses"], expected_status_names, "observedState.domainStatuses")
    if not HEX64.fullmatch(observed_state["sha256"]) or \
            any(value not in {"complete", "unavailable"} for value in observed_state["domainStatuses"].values()):
        raise ValueError("observed-state summary is invalid")
    policies = {item["domain"]: item for item in projection["planningPolicy"]["domains"]}
    file_policies = {item["path"]: item for item in projection["planningPolicy"]["managedFilePolicies"]}
    service_policies = {item["name"]: item for item in projection["planningPolicy"]["servicePolicies"]}
    expected_by_domain = {domain: {record_target(item): item for item in records}
                          for domain, records in desired_records(projection, manifest).items()}
    previous = None
    previous_order = -1
    for index, action in enumerate(plan["actions"], 1):
        exact_object(action, {"after", "approvalRequired", "before", "dependsOn", "domain", "id", "kind", "postconditions",
                              "preconditionSha256", "rebootRequired", "safetyClass", "sequence", "target", "watchdogRequired"}, "action")
        domain = action["domain"]
        if domain == "packages":
            raise ValueError("aggregate package actions remain closed until protected bootstrap")
        if action["sequence"] != index or domain not in ACTION_KINDS or action["kind"] != ACTION_KINDS[domain]:
            raise ValueError("action domain-kind or sequence is invalid")
        expected_type = TARGET_TYPES[domain]
        target_key = "path" if domain in {"managed-files", "managed-fragments", "managed-artifacts"} else "name"
        exact_object(action["target"], {target_key, "type"}, "action target")
        if action["target"]["type"] != expected_type or not isinstance(action["target"][target_key], str):
            raise ValueError("action target does not pair with its domain")
        target_name = action["target"][target_key]
        selected_policy = file_policies.get(target_name) if domain == "managed-files" else service_policies.get(target_name) if domain == "services" else policies.get(domain)
        if selected_policy is None:
            raise ValueError("action target lacks a policy")
        if not selected_policy["automatic"]:
            raise ValueError("action policy forbids automatic mutation")
        flags = (selected_policy["requiresApproval"], selected_policy["requiresReboot"],
                 selected_policy["requiresWatchdog"], selected_policy["safetyClass"])
        if flags != (action["approvalRequired"], action["rebootRequired"],
                     action["watchdogRequired"], action["safetyClass"]):
            raise ValueError("action safety flags differ from contract policy")
        before, after = action["before"], action["after"]
        expected_desired = expected_by_domain.get(domain, {}).get(target_name)
        if expected_desired is None or after != safe_state(expected_desired):
            raise ValueError("action after-state is not the exact projected desired state")
        allowed_state_keys = set(after)
        if not isinstance(before, dict) or before.get("state") not in {"absent", "present"} or \
                (before["state"] == "absent" and set(before) != {"state"}) or \
                (before["state"] == "present" and set(before) != allowed_state_keys):
            raise ValueError("action before-state is invalid")
        expected_precondition = digest({"before": before, "domain": domain, "target": target_name})
        expected_id = digest({"after": after, "before": before, "domain": domain,
                              "kind": action["kind"], "target": target_name})
        if action["preconditionSha256"] != expected_precondition or action["id"] != expected_id or \
                action["postconditions"] != [{"expected": after, "type": "state-equals"}]:
            raise ValueError("action identifiers, preconditions, or postconditions are invalid")
        expected_dependencies = [] if previous is None else [previous]
        if action["dependsOn"] != expected_dependencies or DOMAIN_ORDER[domain] < previous_order:
            raise ValueError("action dependency or domain ordering is invalid")
        previous, previous_order = action["id"], DOMAIN_ORDER[domain]
    for collection_name in ("findings", "blockers"):
        collection = plan[collection_name]
        if not isinstance(collection, list):
            raise ValueError(f"{collection_name} must be an array")
        last_sort = None
        for issue in collection:
            exact_object(issue, {"code", "detail", "domain", "id", "kind", "target"}, "issue")
            allowed_kinds = {"blocker"} if collection_name == "blockers" else {"audit", "drift", "opentofu"}
            string_fields = ("code", "detail", "domain", "id", "kind", "target")
            if any(not isinstance(issue[name], str) for name in string_fields) or \
                    re.fullmatch(r"[a-z0-9-]+", issue["code"]) is None or \
                    issue["kind"] not in allowed_kinds or issue["domain"] not in DOMAIN_ORDER or \
                    HEX64.fullmatch(issue["id"]) is None or issue["id"] != digest({
                        "code": issue["code"], "domain": issue["domain"], "target": issue["target"]}):
                raise ValueError("issue binding is invalid")
            current_sort = (DOMAIN_ORDER[issue["domain"]], issue["target"], issue["code"], issue["id"])
            if last_sort is not None and current_sort < last_sort:
                raise ValueError("issues are not canonically ordered")
            last_sort = current_sort

def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(("git", "-C", str(repo), *args), capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError("Git binding check failed")
    return result.stdout.strip()


def git_bindings(repo: Path) -> tuple[str, str]:
    if not repo.is_absolute() or not (repo / ".git").exists():
        raise ValueError("repo root must be an absolute Git worktree")
    if run_git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Git worktree must be clean")
    head = run_git(repo, "rev-parse", "HEAD")
    origin = run_git(repo, "rev-parse", "refs/remotes/origin/main")
    if head != origin:
        raise ValueError("HEAD must equal refs/remotes/origin/main")
    return head, run_git(repo, "rev-parse", "HEAD^{tree}")


def sanitized_source_binding(source: Path, repository_source: Path) -> None:
    def files(root: Path) -> dict[str, Path]:
        result = {}
        for candidate in root.rglob("*"):
            relative = candidate.relative_to(root).as_posix()
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode) or (not stat.S_ISDIR(mode) and not stat.S_ISREG(mode)):
                raise ValueError("sanitized source contains an unsupported entry")
            if stat.S_ISREG(mode):
                result[relative] = candidate
        return result
    source_files, repository_files = files(source), files(repository_source)
    if set(source_files) != APPROVED_SOURCE_FILES or set(repository_files) != APPROVED_SOURCE_FILES:
        raise ValueError("sanitized source differs from the exact allowlist")
    for relative in sorted(APPROVED_SOURCE_FILES):
        if source_files[relative].read_bytes() != repository_files[relative].read_bytes():
            raise ValueError(f"repository source binding failed: nix/{relative}")


def bundle_inputs(bundle: Path, bundle_hash_file: Path, repo: Path, source_root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    sanitized_source_binding(source_root, repo / "nix")
    verification = subprocess.run(
        (sys.executable, str(source_root / "proxmox/bundle.py"), "verify", "--bundle", str(bundle),
         "--hash-file", str(bundle_hash_file)), capture_output=True, timeout=45,
    )
    if verification.returncode or verification.stdout or verification.stderr:
        raise ValueError("bundle failed canonical content and semantic verification")
    metadata = load_canonical(bundle / "metadata.json")
    projection = load_canonical(bundle / "policy/projection.json")
    manifest_raw = (bundle / "packages/proxmox-package-manifest.json").read_bytes()
    if len(manifest_raw) > 16 * MAX_OBSERVATION_BYTES:
        raise ValueError("package manifest exceeds the fixed size limit")
    manifest = json.loads(manifest_raw)
    if digest(manifest_raw) != metadata.get("packageManifestSha256") or \
            manifest_raw != (source_root / "proxmox/package-manifest.json").read_bytes():
        raise ValueError("bundle package manifest bytes differ from metadata or fixed source")
    for schema_name, metadata_key in (("observation.schema.json", "observationSchemaSha256"),
                                      ("plan.schema.json", "planSchemaSha256"),
                                      ("private-preconditions.schema.json", "privatePreconditionsSchemaSha256"),
                                      ("private-preparation-request.schema.json", "privatePreparationRequestSchemaSha256"),
                                      ("activation-envelope.schema.json", "activationEnvelopeSchemaSha256")):
        schema_raw = (bundle / "policy" / schema_name).read_bytes()
        if schema_raw != (source_root / "proxmox" / schema_name).read_bytes() or \
                digest(schema_raw) != metadata.get(metadata_key):
            raise ValueError("bundle schema bytes differ from metadata or fixed source")
    content_hash = bundle_hash_file.read_text(encoding="ascii").strip()
    if not HEX64.fullmatch(content_hash):
        raise ValueError("bundle content hash is malformed")
    for relative, expected in (("nix/flake.lock", metadata["flakeLockSha256"]),
                               ("nix/proxmox/projection.json", metadata["projectionSha256"])):
        path = repo / relative
        if not path.is_file() or digest(path.read_bytes()) != expected:
            raise ValueError(f"repository projection binding failed: {relative}")
    observer = bundle / "helpers/proxmox-observer"
    activator = bundle / "helpers/proxmox-activator"
    preparer = bundle / "helpers/proxmox-private-preparer"
    observer_hash = digest(observer.read_bytes())
    activator_hash = digest(activator.read_bytes())
    preparer_hash = digest(preparer.read_bytes())
    if metadata["helperSha256"]["proxmox-observer"] != observer_hash or \
            metadata["helperSha256"]["proxmox-activator"] != activator_hash or \
            metadata["helperSha256"]["proxmox-private-preparer"] != preparer_hash:
        raise ValueError("bundle helper binding failed")
    commit, tree = git_bindings(repo)
    bindings = {"activationEnvelopeSchemaSha256": metadata["activationEnvelopeSchemaSha256"],
                "activatorSha256": activator_hash, "bundleContentSha256": content_hash, "bundleFormat": metadata["bundleFormat"],
                "flakeLockSha256": metadata["flakeLockSha256"], "gitCommit": commit, "gitTree": tree,
                "observerProtocol": PROTOCOL, "observerSha256": observer_hash,
                "packageManifestSha256": metadata["packageManifestSha256"], "planSchemaSha256": metadata["planSchemaSha256"],
                "privatePreconditionsSchemaSha256": metadata["privatePreconditionsSchemaSha256"],
                "privatePreparationRequestSchemaSha256": metadata["privatePreparationRequestSchemaSha256"],
                "privatePreparerSha256": preparer_hash, "projectionSha256": metadata["projectionSha256"]}
    return bindings, projection, manifest, metadata


def live_observation(expected_observer: str) -> dict[str, Any]:
    result = subprocess.run(SSH_COMMAND, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    if result.returncode or result.stderr or len(result.stdout) > MAX_OBSERVATION_BYTES:
        raise ValueError("bootstrap-required: fixed observer transport failed")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("fixed observer returned malformed JSON") from error
    if result.stdout != canonical_json(value):
        raise ValueError("fixed observer returned non-canonical JSON")
    validate_observation(value)
    if value["observerSha256"] != expected_observer:
        raise ValueError("installed observer differs from the reviewed bundle")
    return value


def open_live_output_directory(repo: Path) -> int:
    if not repo.is_absolute():
        raise ValueError("live output requires an absolute repository root")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("live output requires no-follow directory descriptor support")
    nofollow = os.O_NOFOLLOW
    directory_flag = os.O_DIRECTORY
    repo_fd = os.open(repo, os.O_RDONLY | directory_flag | nofollow)
    current_fd = repo_fd
    try:
        for component in (".reconcile", "plans"):
            try:
                os.mkdir(component, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            child_fd = os.open(component, os.O_RDONLY | directory_flag | nofollow, dir_fd=current_fd)
            info = os.fstat(child_fd)
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
                os.close(child_fd)
                raise ValueError("live plan output components must be real mode-0700 directories")
            if current_fd != repo_fd:
                os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except Exception:
        if current_fd != repo_fd:
            os.close(current_fd)
        raise
    finally:
        os.close(repo_fd)


def secure_live_output_directory(repo: Path) -> Path:
    directory_fd = open_live_output_directory(repo)
    os.close(directory_fd)
    return repo / ".reconcile" / "plans"


def secure_live_output(plan: dict[str, Any], repo: Path) -> Path:
    directory_fd = open_live_output_directory(repo)
    destination_name = f"{plan['planSha256']}.json"
    temporary_name = None
    try:
        try:
            os.stat(destination_name, dir_fd=directory_fd, follow_symlinks=False)
            raise ValueError("refusing to overwrite an existing plan")
        except FileNotFoundError:
            pass
        for attempt in range(100):
            candidate = f".plan-{os.getpid()}-{attempt}"
            try:
                file_fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        else:
            raise ValueError("unable to allocate a temporary plan file")
        with os.fdopen(file_fd, "wb") as handle:
            handle.write(canonical_json(plan))
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_name, destination_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False)
        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_name = None
        os.fsync(directory_fd)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)
    return repo / ".reconcile" / "plans" / destination_name


def secure_output(plan: dict[str, Any], directory: Path) -> Path:
    try:
        mode = directory.lstat().st_mode
    except FileNotFoundError:
        directory.mkdir(parents=True, mode=0o700)
        directory.chmod(0o700)
        mode = directory.lstat().st_mode
    if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o700:
        raise ValueError("plan output directory must be a real mode-0700 directory")
    destination = directory / f"{plan['planSha256']}.json"
    if destination.exists() or destination.is_symlink():
        raise ValueError("refusing to overwrite an existing plan")
    fd, temporary_name = tempfile.mkstemp(prefix=".plan-", dir=directory)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json(plan))
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="proxmox-host", add_help=False, allow_abbrev=False)
    parser.add_argument("command", nargs="?")
    parser.add_argument("--repo-root")
    parser.add_argument("--fixture-only", action="store_true")
    parser.add_argument("--observation-file")
    parser.add_argument("--observed-at")
    parser.add_argument("--completed-at")
    parser.add_argument("--output-dir")
    parser.add_argument("--plan-sha")
    parser.add_argument("--approve-plan-sha")
    parser.add_argument("--confirm-no-concurrent-mutation", action="store_true")
    parser.add_argument("--confirm-console", action="store_true")
    parser.add_argument("--confirm-lan-rollback", action="store_true")
    parser.add_argument("--confirm-backups", action="store_true")
    args, unknown = parser.parse_known_args()
    plan_usage = "proxmox-host plan --repo-root ABSOLUTE_PATH [--fixture-only --observation-file FILE --observed-at TIME --completed-at TIME --output-dir DIR]"
    apply_usage = "proxmox-host apply --repo-root ABSOLUTE_PATH --plan-sha SHA256 --approve-plan-sha SAME_SHA256"
    prepare_usage = "proxmox-host prepare --repo-root ABSOLUTE_PATH --plan-sha SHA256 --approve-plan-sha SAME_SHA256 --confirm-no-concurrent-mutation [conditional watchdog confirmations]"
    if unknown or args.command not in {"plan", "prepare", "apply"} or not args.repo_root:
        fail(f"usage: {plan_usage}\n       {prepare_usage}\n       {apply_usage}", 64)
    fixture_fields = (args.observation_file, args.observed_at, args.completed_at, args.output_dir)
    confirmations = (args.confirm_no_concurrent_mutation, args.confirm_console, args.confirm_lan_rollback, args.confirm_backups)
    if args.command == "plan":
        if args.plan_sha or args.approve_plan_sha or any(confirmations) or args.fixture_only != all(fixture_fields) or (not args.fixture_only and any(fixture_fields)):
            fail(f"usage: {plan_usage}", 64)
    elif args.fixture_only or any(fixture_fields) or not args.plan_sha or not args.approve_plan_sha:
        fail(f"usage: {prepare_usage if args.command == 'prepare' else apply_usage}", 64)
    elif args.command == "apply" and any(confirmations):
        fail(f"usage: {apply_usage}", 64)
    elif args.command == "prepare" and not args.confirm_no_concurrent_mutation:
        fail(f"usage: {prepare_usage}", 64)
    return args


def main() -> int:
    args = parse_args()
    try:
        repo = Path(args.repo_root)
        trusted = {name: os.environ.get(name) for name in (
            "PROXMOX_HOST_FIXED_BUNDLE", "PROXMOX_HOST_FIXED_BUNDLE_HASH", "PROXMOX_HOST_FIXED_SOURCE_ROOT")}
        if any(not value for value in trusted.values()):
            raise ValueError("fixed application bundle environment is unavailable")
        bundle_path = Path(trusted["PROXMOX_HOST_FIXED_BUNDLE"])
        bundle_hash_path = Path(trusted["PROXMOX_HOST_FIXED_BUNDLE_HASH"])
        source_root = Path(trusted["PROXMOX_HOST_FIXED_SOURCE_ROOT"])
        if args.command == "apply":
            import apply as guarded_apply
            print(guarded_apply.apply(args, bundle_path, bundle_hash_path, source_root))
            return 0
        if args.command == "prepare":
            import prepare as private_prepare
            print(private_prepare.prepare(args, bundle_path, bundle_hash_path, source_root))
            return 0
        bindings, projection, manifest, _ = bundle_inputs(bundle_path, bundle_hash_path, repo, source_root)
        if args.fixture_only:
            observation = load_canonical(Path(args.observation_file))
            observed_at, completed_at = args.observed_at, args.completed_at
            output_dir = Path(args.output_dir)
        else:
            observed_at = format_time(dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
            observation = live_observation(bindings["observerSha256"])
            completed_at = format_time(dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
            output_dir = None
        if observation.get("observerSha256") != bindings["observerSha256"]:
            raise ValueError("observation observer binding differs from the reviewed bundle")
        plan = build_plan(bindings, projection, manifest, observation, observed_at, completed_at, args.fixture_only)
        destination = secure_output(plan, output_dir) if output_dir is not None else secure_live_output(plan, repo)
        print(f"status={plan['status']} actions={len(plan['actions'])} blockers={len(plan['blockers'])} planSha256={plan['planSha256']} path={destination}")
        return 0 if plan["status"] in {"ready", "fixture"} else 2
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        fail(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
