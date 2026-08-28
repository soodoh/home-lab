#!/usr/bin/env python3
"""Guarded protocol-v4 application of one exact reviewed Proxmox plan."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import controller_lock as controller_lock_protocol
import planner

PROTOCOL = 4
MAX_PRIVATE_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_ACTIVATOR_REMOTE = "/" + "usr" + "/" + "local" + "/libexec/home-lab/proxmox-activator"
SSH_APPLY_COMMAND = planner.fixed_ssh_command("apply", "sudo -n -- " + _ACTIVATOR_REMOTE + " session")


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must contain exactly {sorted(keys)}")
    return value


def secure_regular(path: Path, label: str, maximum: int) -> bytes:
    """Open the derived file without following it and require canonical private-file semantics."""
    parent_fd = planner.open_live_output_directory(path.parents[2]) if path.parent.name == "plans" and path.parent.parent.name == ".reconcile" else None
    if parent_fd is None:
        raise ValueError(f"{label} is outside the fixed plan directory")
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise ValueError(f"{label} must be a real single-link mode-0600 regular file")
            raw = b""
            while len(raw) <= maximum:
                block = os.read(fd, min(65536, maximum + 1 - len(raw)))
                if not block:
                    break
                raw += block
            if len(raw) > maximum:
                raise ValueError(f"{label} exceeds the fixed size limit")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def load_secure_canonical(path: Path, label: str, maximum: int) -> Any:
    raw = secure_regular(path, label, maximum)
    value = json.loads(raw)
    if raw != planner.canonical_json(value):
        raise ValueError(f"{label} is not canonical JSON")
    return value


def validate_private(sidecar: Any, plan: dict[str, Any], metadata: dict[str, Any], now: dt.datetime,
                     require_fresh: bool = True) -> bool:
    exact(sidecar, {"actionManifestSha256", "attestations", "bindings", "challenge", "createdAt", "format", "hostSession",
                    "operatorGates", "packageSession", "planSha256", "validUntil"}, "private preconditions")
    action_manifest_sha = planner.digest(plan["actions"])
    if sidecar["format"] != "home-lab-proxmox-private-preconditions-v1" or sidecar["planSha256"] != plan["planSha256"] or \
            sidecar["actionManifestSha256"] != action_manifest_sha:
        raise ValueError("private precondition plan or action-manifest binding failed")
    bindings = exact(sidecar["bindings"], {"activationEnvelopeSchemaSha256", "activatorSha256", "bundleContentSha256", "flakeLockSha256",
                                                    "gitCommit", "gitTree", "observerSha256", "packageManifestSha256", "planSchemaSha256",
                                                    "privatePreconditionsSchemaSha256", "privatePreparationRequestSchemaSha256",
                                                    "privatePreparerSha256", "projectionSha256"}, "private bindings")
    expected = {
        "activationEnvelopeSchemaSha256": metadata["activationEnvelopeSchemaSha256"],
        "activatorSha256": metadata["helperSha256"]["proxmox-activator"],
        "bundleContentSha256": plan["bindings"]["bundleContentSha256"],
        "flakeLockSha256": plan["bindings"]["flakeLockSha256"],
        "gitCommit": plan["bindings"]["gitCommit"],
        "gitTree": plan["bindings"]["gitTree"],
        "observerSha256": plan["bindings"]["observerSha256"],
        "packageManifestSha256": plan["bindings"]["packageManifestSha256"],
        "planSchemaSha256": plan["bindings"]["planSchemaSha256"],
        "privatePreconditionsSchemaSha256": metadata["privatePreconditionsSchemaSha256"],
        "privatePreparationRequestSchemaSha256": metadata["privatePreparationRequestSchemaSha256"],
        "privatePreparerSha256": metadata["helperSha256"]["proxmox-private-preparer"],
        "projectionSha256": plan["bindings"]["projectionSha256"],
    }
    if bindings != expected:
        raise ValueError("private bundle, schema, Git, or helper binding failed")
    created = planner.parse_time(sidecar["createdAt"])
    expires = planner.parse_time(sidecar["validUntil"])
    if expires < created or (expires - created).total_seconds() > 300 or expires > planner.parse_time(plan["freshness"]["validUntil"]):
        raise ValueError("private preconditions exceed plan freshness")
    fresh = created <= now <= expires
    if require_fresh and not fresh:
        raise ValueError("private preconditions are stale")
    if not isinstance(sidecar["challenge"], str) or not TOKEN.fullmatch(sidecar["challenge"]):
        raise ValueError("private challenge is invalid")
    host = exact(sidecar["hostSession"], {"id", "sidecarMac"}, "host session")
    if not isinstance(host["id"], str) or not TOKEN.fullmatch(host["id"]) or not isinstance(host["sidecarMac"], str) or not HEX64.fullmatch(host["sidecarMac"]):
        raise ValueError("private host session is invalid")
    attestations = exact(sidecar["attestations"], {"protectedAccess", "protectedHardware"}, "private attestations")
    for name in ("protectedAccess", "protectedHardware"):
        record = exact(attestations[name], {"expectedCount", "keyedAttestation", "matches"}, name)
        if not isinstance(record["expectedCount"], int) or isinstance(record["expectedCount"], bool) or record["expectedCount"] < 0 or record["matches"] is not True or not isinstance(record["keyedAttestation"], str) or not HEX64.fullmatch(record["keyedAttestation"]):
            raise ValueError("private keyed attestation is invalid")
    gates = exact(sidecar["operatorGates"], {"backupsConfirmed", "consoleConfirmed", "lanRollbackConfirmed", "noConcurrentMutationConfirmed"}, "operator gates")
    if any(not isinstance(value, bool) for value in gates.values()) or not gates["noConcurrentMutationConfirmed"]:
        raise ValueError("no-concurrent-mutation gate is required")
    if any(action["watchdogRequired"] for action in plan["actions"]) and not all(gates.values()):
        raise ValueError("watchdog actions require console, LAN rollback, backup, and concurrency gates")
    package = sidecar["packageSession"]
    if any(action["domain"] == "packages" for action in plan["actions"]):
        if package is None:
            raise ValueError("package action requires a sealed aggregate package session")
        raise ValueError("bootstrap-required: aggregate package activation remains closed")
    if package is not None:
        exact(package, {"completeInstalledMapSha256", "handle", "keyedSimulationAttestation", "validUntil"}, "package session")
        if not isinstance(package["handle"], str) or not TOKEN.fullmatch(package["handle"]) or \
                not isinstance(package["completeInstalledMapSha256"], str) or not HEX64.fullmatch(package["completeInstalledMapSha256"]) or \
                not isinstance(package["keyedSimulationAttestation"], str) or not HEX64.fullmatch(package["keyedSimulationAttestation"]) or \
                (require_fresh and planner.parse_time(package["validUntil"]) < now):
            raise ValueError("aggregate package session is invalid")
    return fresh


class AmbiguousTransportError(ValueError):
    pass


class AmbiguousSessionError(ValueError):
    pass


class ConfirmedTransitionError(ValueError):
    pass


def send_session(envelope: dict[str, Any]) -> dict[str, Any]:
    content = planner.canonical_json(envelope)
    try:
        result = subprocess.run(SSH_APPLY_COMMAND, input=content, capture_output=True, timeout=45)
    except subprocess.TimeoutExpired as error:
        raise AmbiguousTransportError("fixed activator response timed out") from error
    if result.returncode or result.stderr or len(result.stdout) > MAX_RESPONSE_BYTES:
        raise AmbiguousTransportError("fixed activator response was lost or invalid")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AmbiguousTransportError("fixed activator returned malformed JSON") from error
    if result.stdout != planner.canonical_json(value):
        raise AmbiguousTransportError("fixed activator returned noncanonical output")
    return value


def status_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    return {"hostSessionId": envelope["hostSessionId"], "operation": "status",
            "planSha256": envelope["planSha256"], "protocol": PROTOCOL}


def status_proves(status: dict[str, Any], envelope: dict[str, Any], action_manifest_sha: str) -> bool:
    if status.get("status") != "session-status" or status.get("hostSessionId") != envelope["hostSessionId"] or \
            status.get("planSha256") != envelope["planSha256"] or status.get("actionManifestSha256") != action_manifest_sha:
        return False
    operation = envelope["operation"]
    if operation == "begin":
        return status.get("state") == "begun" and \
            status.get("beginRequestSha256") == planner.digest(envelope)
    if operation == "action":
        completed = status.get("completedActionIds")
        return status.get("state") == "applying" and isinstance(completed, list) and \
            len(completed) >= envelope["action"]["sequence"] and \
            completed[envelope["action"]["sequence"] - 1] == envelope["action"]["id"] and \
            status.get("nextSequence") == len(completed) + 1
    if operation == "commit":
        verified = envelope.get("verifiedActionIds")
        return status.get("state") == "released-committed" and isinstance(verified, list) and \
            status.get("capturedActionIds") == verified and status.get("completedActionIds") == verified and \
            status.get("nextSequence") == len(verified) + 1 and status.get("pendingTransition") is None
    if operation == "rollback":
        return status.get("state") == "released-recovered" and status.get("pendingTransition") is None
    return False


def pending_allows_exact_retry(status: dict[str, Any], envelope: dict[str, Any]) -> bool:
    pending = status.get("pendingTransition")
    if not isinstance(pending, dict) or pending.get("requestSha256") != planner.digest(envelope):
        return False
    if envelope["operation"] == "action":
        return status.get("state") == "action-retryable" and set(pending) == {
            "actionId", "operation", "requestSha256", "sequence", "stage"} and \
            pending["operation"] == "action" and pending["actionId"] == envelope["action"]["id"] and \
            pending["sequence"] == envelope["action"]["sequence"] and \
            pending["stage"] in {"prepared", "postcondition-pending"}
    if envelope["operation"] == "rollback":
        return status.get("state") == "rollback-in-progress" and set(pending) == {
            "operation", "remainingActionIds", "requestSha256", "restoredActionIds"} and \
            pending["operation"] == "rollback" and isinstance(pending["remainingActionIds"], list) and \
            isinstance(pending["restoredActionIds"], list)
    return False


def observe_transition_status(envelope: dict[str, Any], bootstrap: bool, primary: Exception | None) -> dict[str, Any]:
    try:
        return send_session(status_envelope(envelope))
    except AmbiguousTransportError as status_error:
        if bootstrap:
            raise ValueError("bootstrap-required: fixed activator and status transport failed") from status_error
        raise AmbiguousSessionError("ambiguous host session; ownership retained and rollback not started") from (primary or status_error)


def send_transition(envelope: dict[str, Any], expected: dict[str, Any], action_manifest_sha: str,
                    bootstrap: bool = False) -> dict[str, Any]:
    primary: Exception | None = None
    try:
        response = send_session(envelope)
    except AmbiguousTransportError as error:
        primary = error
        response = None
    if response == expected:
        return expected
    observed_status = observe_transition_status(envelope, bootstrap, primary)
    if status_proves(observed_status, envelope, action_manifest_sha):
        return expected
    if pending_allows_exact_retry(observed_status, envelope):
        # The successful status call acquired the live host flock after the lost operation exited.
        try:
            retry_response = send_session(envelope)
        except AmbiguousTransportError as retry_error:
            retry_response = None
            primary = retry_error
        if retry_response == expected:
            return expected
        observed_status = observe_transition_status(envelope, False, primary)
        if status_proves(observed_status, envelope, action_manifest_sha):
            return expected
    state = observed_status.get("state") if observed_status.get("status") == "session-status" else None
    if state in {"failed", "rollback-failed"}:
        raise ConfirmedTransitionError(f"host status confirms {envelope['operation']} failure") from primary
    if bootstrap and isinstance(response, dict) and response.get("status") == "failed":
        raise ValueError("bootstrap-required: fixed activator begin failed")
    raise AmbiguousSessionError("host session is busy or transition completion is unknown; rollback not started") from primary


def affected_state(observation: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    domain_name = {"managed-files": "managedFiles", "managed-fragments": "managedFragments",
                   "managed-artifacts": "managedArtifacts", "services": "services", "timezone": "timezone"}.get(action["domain"])
    if domain_name is None:
        raise ValueError("action domain is not representable by guarded apply")
    domain = observation["domains"][domain_name]
    if domain["status"] != "complete":
        raise ValueError("affected observation domain is unavailable")
    target = action["target"].get("path", action["target"].get("name"))
    current = next((record for record in domain["records"] if planner.record_target(record) == target), None)
    return planner.safe_state(current)


def verify_preconditions(observation: dict[str, Any], actions: list[dict[str, Any]], after: bool = False) -> None:
    for action in actions:
        actual = affected_state(observation, action)
        expected = action["after"] if after else action["before"]
        if actual != expected:
            phase = "postcondition" if after else "precondition"
            raise ValueError(f"saved affected {phase} differs; refusing to replan")
        if not after:
            target = action["target"].get("path", action["target"].get("name"))
            observed_hash = planner.digest({"before": actual, "domain": action["domain"], "target": target})
            if observed_hash != action["preconditionSha256"]:
                raise ValueError("saved affected precondition hash differs; refusing to replan")


def verify_final_observation(observation: dict[str, Any], projection: dict[str, Any], manifest: dict[str, Any],
                             actions: list[dict[str, Any]]) -> None:
    verify_preconditions(observation, actions, after=True)
    pve_manager = next((item for item in projection["packagePolicy"]["critical"] if item["role"] == "pve-manager"), None)
    if pve_manager is None:
        raise ValueError("projection lacks PVE manager identity")
    expected_host = {"architecture": projection["architecture"], "hostname": projection["hostNetworking"]["hostname"],
                     "os": "debian", "pveVersion": "pve-manager/" + pve_manager["version"]}
    if any(observation["host"][key] != value for key, value in expected_host.items()):
        raise ValueError("final host identity differs")
    desired = planner.desired_records(projection, manifest)
    observed_names = {"managed-files": "managedFiles", "managed-fragments": "managedFragments",
                      "managed-artifacts": "managedArtifacts", "packages": "packages", "services": "services",
                      "timezone": "timezone", "accounts": "accounts"}
    for domain, records in desired.items():
        observed = observation["domains"][observed_names[domain]]
        if observed["status"] != "complete" or observed["unexpectedCount"] != 0 or observed["records"] != sorted(records, key=planner.record_target):
            raise ValueError(f"final full observation differs in {domain}")
    for name in ("tailscale", "pveAccess", "pveFirewall", "pveStorage", "storage", "health", "vm"):
        summary = observation["domains"][name]
        if summary["status"] != "complete" or summary["matches"] is not True:
            raise ValueError(f"final full observation differs in {name}")
    audit = observation["domains"]["auditAbsence"]
    if audit["status"] != "complete" or audit["unexpectedCount"] != 0 or any(record["count"] for record in audit["records"]):
        raise ValueError("final full audit observation differs")


def controller_lock(repo: Path, owner: dict[str, Any]) -> controller_lock_protocol.LockHandle:
    """Acquire the mutex directly or validate the reconciler's inherited ownership."""
    return controller_lock_protocol.acquire_or_borrow(repo, owner)


def release_controller_lock(handle: controller_lock_protocol.LockHandle) -> None:
    controller_lock_protocol.release(handle)


def validate_host_status(response: Any, plan: dict[str, Any], session_id: str) -> dict[str, Any] | None:
    failed = {"hostSessionId": session_id, "operation": "status", "planSha256": plan["planSha256"], "status": "failed"}
    if response == failed:
        return None
    status_value = exact(response, {"actionManifestSha256", "beginRequestSha256", "capturedActionIds", "completedActionIds",
                                    "hostSessionId", "nextSequence", "pendingTransition", "planSha256", "state", "status"},
                         "host status")
    actions = plan["actions"]
    action_ids = [action["id"] for action in actions]
    if status_value["status"] != "session-status" or status_value["hostSessionId"] != session_id or \
            status_value["planSha256"] != plan["planSha256"] or \
            not isinstance(status_value["beginRequestSha256"], str) or not HEX64.fullmatch(status_value["beginRequestSha256"]) or \
            status_value["actionManifestSha256"] != planner.digest(actions) or \
            status_value["state"] not in {"begun", "applying", "action-pending", "action-retryable", "failed",
                                          "rollback-in-progress", "rollback-failed", "committed-release-pending",
                                          "recovered-release-pending", "released-committed", "released-recovered"} or \
            not isinstance(status_value["capturedActionIds"], list) or \
            not isinstance(status_value["completedActionIds"], list) or \
            status_value["capturedActionIds"] != action_ids[:len(status_value["capturedActionIds"])] or \
            status_value["completedActionIds"] != action_ids[:len(status_value["completedActionIds"])] or \
            not isinstance(status_value["nextSequence"], int):
        raise AmbiguousSessionError("fixed host status does not match the exact retained plan")
    if status_value["state"] == "released-committed" and \
            (status_value["capturedActionIds"] != action_ids or status_value["completedActionIds"] != action_ids or \
             status_value["nextSequence"] != len(action_ids) + 1 or status_value["pendingTransition"] is not None):
        raise AmbiguousSessionError("released commit does not cover every exact plan action")
    if status_value["state"] == "released-recovered" and status_value["pendingTransition"] is not None:
        raise AmbiguousSessionError("released recovery retains a pending transition")
    return status_value


def rollback_retained(status_value: dict[str, Any], plan: dict[str, Any], session_id: str) -> str:
    restored = list(reversed(status_value["capturedActionIds"]))
    envelope = {"hostSessionId": session_id, "operation": "rollback",
                "planSha256": plan["planSha256"], "protocol": PROTOCOL}
    expected = {"hostSessionId": session_id, "planSha256": plan["planSha256"],
                "restoredActionIds": restored, "status": "recovered"}
    send_transition(envelope, expected, planner.digest(plan["actions"]))
    return f"status=recovered actions={len(restored)} planSha256={plan['planSha256']} rebootRequired=false"


def apply(args: Any, bundle_path: Path, hash_path: Path, source_root: Path) -> str:
    repo = Path(args.repo_root)
    if not repo.is_absolute() or not HEX64.fullmatch(args.plan_sha or "") or not HEX64.fullmatch(args.approve_plan_sha or ""):
        raise ValueError("apply requires an absolute repo root and exact SHA-256 arguments")
    if args.plan_sha != args.approve_plan_sha:
        raise ValueError("explicit plan approval hash differs")
    bindings, projection, manifest, metadata = planner.bundle_inputs(bundle_path, hash_path, repo, source_root)
    plan_path = repo / ".reconcile" / "plans" / f"{args.plan_sha}.json"
    sidecar_path = repo / ".reconcile" / "plans" / f"{args.plan_sha}.private.json"
    plan = load_secure_canonical(plan_path, "plan", planner.MAX_OBSERVATION_BYTES)
    planner.validate_plan(plan, projection, manifest)
    if plan["planSha256"] != args.plan_sha or plan["status"] != "ready" or plan["mode"] != "steady" or not plan["applyEligible"] or plan["blockers"]:
        raise ValueError("apply requires the exact ready steady eligible unblocked plan")
    if plan["bindings"] != bindings:
        raise ValueError("plan bundle, Git, schema, or helper bindings differ")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    plan_fresh = now <= planner.parse_time(plan["freshness"]["validUntil"])
    sidecar = load_secure_canonical(sidecar_path, "private preconditions", MAX_PRIVATE_BYTES)
    sidecar_fresh = validate_private(sidecar, plan, metadata, now, require_fresh=False)
    session_id = sidecar["hostSession"]["id"]
    started_at = sidecar["createdAt"]
    owner = {"gitCommit": bindings["gitCommit"], "hostSessionId": session_id,
             "operation": "proxmox-guarded-apply", "planSha256": args.plan_sha, "startedAt": started_at}
    lock_handle = controller_lock(repo, owner)
    begun = False
    action_manifest_sha = planner.digest(plan["actions"])
    try:
        status_request = {"hostSessionId": session_id, "operation": "status",
                          "planSha256": args.plan_sha, "protocol": PROTOCOL}
        try:
            retained = validate_host_status(send_session(status_request), plan, session_id)
        except AmbiguousTransportError as error:
            raise AmbiguousSessionError("cannot establish exact retained host session status") from error

        if retained is not None:
            state = retained["state"]
            if state == "released-committed":
                final_observation = planner.live_observation(bindings["observerSha256"])
                verify_final_observation(final_observation, projection, manifest, plan["actions"])
                return f"status=already-applied actions={len(plan['actions'])} planSha256={args.plan_sha} rebootRequired={'true' if any(action['rebootRequired'] for action in plan['actions']) else 'false'}"
            if state == "released-recovered":
                return f"status=already-recovered actions={len(retained['capturedActionIds'])} planSha256={args.plan_sha} rebootRequired=false"
            clean_begun = state == "begun" and retained["capturedActionIds"] == [] and \
                retained["completedActionIds"] == [] and retained["nextSequence"] == 1 and \
                retained["pendingTransition"] is None
            if not (clean_begun and plan_fresh and sidecar_fresh):
                return rollback_retained(retained, plan, session_id)
            begun = True
        elif not plan_fresh or not sidecar_fresh:
            raise ValueError("reviewed plan or private preconditions expired; no retained session exists to recover")

        # New mutation is allowed only after the recovery-only preflight has found
        # no session (or an exact clean begun session) and both freshness gates pass.
        mutation_now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        if mutation_now > planner.parse_time(plan["freshness"]["validUntil"]):
            raise ValueError("reviewed plan expired before begin")
        validate_private(sidecar, plan, metadata, mutation_now)
        begin_envelope = {"actions": plan["actions"], "bindings": {"activatorSha256": bindings["activatorSha256"],
                                        "bundleContentSha256": bindings["bundleContentSha256"],
                                        "gitCommit": bindings["gitCommit"], "gitTree": bindings["gitTree"]},
                          "hostSessionId": session_id, "operation": "begin", "planSha256": args.plan_sha,
                          "privatePreconditions": sidecar, "protocol": PROTOCOL, "startedAt": started_at}
        expected_begin = {"actionManifestSha256": action_manifest_sha, "hostSessionId": session_id,
                          "planSha256": args.plan_sha, "status": "begun"}
        send_transition(begin_envelope, expected_begin, action_manifest_sha, bootstrap=True)
        begun = True
        observed = planner.live_observation(bindings["observerSha256"])
        validate_private(sidecar, plan, metadata, dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        verify_preconditions(observed, plan["actions"])
        applied: list[str] = []
        reboot_required = False
        for action in plan["actions"]:
            envelope = {"action": action, "hostSessionId": session_id, "operation": "action",
                        "planSha256": args.plan_sha, "protocol": PROTOCOL}
            expected = {"actionId": action["id"], "hostSessionId": session_id,
                        "sequence": action["sequence"], "status": "applied"}
            send_transition(envelope, expected, action_manifest_sha)
            applied.append(action["id"])
            reboot_required = reboot_required or action["rebootRequired"]
            observed = planner.live_observation(bindings["observerSha256"])
            verify_preconditions(observed, [action], after=True)
        final_observation = planner.live_observation(bindings["observerSha256"])
        verify_final_observation(final_observation, projection, manifest, plan["actions"])
        commit_envelope = {"hostSessionId": session_id, "operation": "commit", "planSha256": args.plan_sha,
                           "protocol": PROTOCOL, "verifiedActionIds": applied}
        expected_commit = {"hostSessionId": session_id, "planSha256": args.plan_sha, "status": "committed"}
        send_transition(commit_envelope, expected_commit, action_manifest_sha)
        return f"status=applied actions={len(applied)} planSha256={args.plan_sha} rebootRequired={'true' if reboot_required else 'false'}"
    except Exception as primary_error:
        if begun and not isinstance(primary_error, AmbiguousSessionError):
            try:
                session_status = validate_host_status(send_session({"hostSessionId": session_id, "operation": "status",
                                                                    "planSha256": args.plan_sha, "protocol": PROTOCOL}),
                                                      plan, session_id)
                if session_status is None:
                    raise AmbiguousSessionError("retained session disappeared; rollback not started")
                rollback_retained(session_status, plan, session_id)
            except Exception as rollback_error:
                raise ValueError(f"apply failed ({primary_error}); rollback failed or remained ambiguous ({rollback_error})") from rollback_error
        raise
    finally:
        release_controller_lock(lock_handle)
