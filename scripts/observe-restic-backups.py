#!/usr/bin/env python3
"""Observe one complete Restic chain while holding the host backup lock."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HEX = re.compile(r"^[0-9a-f]{64}$")
POLICY_PATH = Path("/etc/home-lab/restic-policy.json")
LOCK_PATH = Path("/run/lock/home-lab-backup.lock")
LOCAL_PASSWORD = Path("/etc/home-lab/restic/credentials/local-password")
PROTON_PASSWORD = Path("/etc/home-lab/restic/credentials/proton-password")
PROTON_CONFIG = Path("/var/lib/restic-proton/rclone.conf")
PROTON_CACHE = Path("/var/lib/restic-proton/cache")
OWNERS = (
    Path("/var/lib/iac-ansible-production.lock"),
    Path("/var/lib/home-lab/reconciliation/apply.lock"),
    Path("/var/lib/home-lab/reconciliation/operation.lock"),
)
UNITS = (
    "home-lab-restic-daily.timer",
    "home-lab-restic-daily.target",
    "home-lab-restic-daily-local.service",
    "home-lab-restic-daily-proton.service",
    "home-lab-restic-maintenance.timer",
    "home-lab-restic-maintenance.target",
    "home-lab-restic-maintenance-local.service",
    "home-lab-restic-maintenance-proton.service",
)


class ObservationError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_regular(path: Path, mode: int, expected_sha256: str | None = None) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ObservationError("protected_file_missing") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ObservationError("protected_file_type")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise ObservationError("protected_file_metadata")
    if expected_sha256 is not None and digest(path) != expected_sha256:
        raise ObservationError("reviewed_source_drift")


def run(arguments: list[str], environment: dict[str, str] | None = None) -> str:
    if not arguments or any(not isinstance(value, str) or not value for value in arguments):
        raise ObservationError("command_shape")
    merged = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/var/empty", "LC_ALL": "C", "TZ": "UTC"}
    if environment:
        merged.update(environment)
    try:
        result = subprocess.run(
            arguments,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=1800,
            env=merged,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ObservationError("command_execution") from error
    if result.returncode != 0:
        raise ObservationError("command_failed")
    return result.stdout


def parse_object(raw: str, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ObservationError(reason) from error
    if not isinstance(value, dict):
        raise ObservationError(reason)
    return value


def parse_snapshots(raw: str, reason: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ObservationError(reason) from error
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ObservationError(reason)
    return value


def parse_properties(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise ObservationError("unit_properties")
        result[key] = value
    return result


def snapshot_tags(snapshot: dict[str, Any]) -> set[str]:
    tags = snapshot.get("tags")
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ObservationError("snapshot_tags")
    return set(tags)


def snapshot_time(snapshot: dict[str, Any]) -> datetime:
    value = snapshot.get("time")
    if not isinstance(value, str):
        raise ObservationError("snapshot_time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ObservationError("snapshot_time") from error
    if parsed.tzinfo is None:
        raise ObservationError("snapshot_time")
    return parsed.astimezone(timezone.utc)


def snapshot_id(snapshot: dict[str, Any]) -> str:
    value = snapshot.get("id")
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        raise ObservationError("snapshot_id")
    return value


def select_chain(
    games: list[dict[str, Any]],
    nfs: list[dict[str, Any]],
    proton: list[dict[str, Any]],
    policy_sha256: str,
    artifact_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    required = {"cadence=daily", f"policy={policy_sha256}", f"artifact={artifact_sha256}"}
    nfs_by_original: dict[str, list[dict[str, Any]]] = {}
    proton_by_original: dict[str, list[dict[str, Any]]] = {}
    for destination, index in ((nfs, nfs_by_original), (proton, proton_by_original)):
        for snapshot in destination:
            original = snapshot.get("original")
            if isinstance(original, str) and HEX.fullmatch(original):
                index.setdefault(original, []).append(snapshot)
    for source in sorted(games, key=snapshot_time, reverse=True):
        source_id = snapshot_id(source)
        source_tags = snapshot_tags(source)
        if not required <= source_tags:
            continue
        nfs_matches = [item for item in nfs_by_original.get(source_id, []) if snapshot_tags(item) == source_tags]
        proton_matches = [item for item in proton_by_original.get(source_id, []) if snapshot_tags(item) == source_tags]
        if len(nfs_matches) > 1 or len(proton_matches) > 1:
            raise ObservationError("snapshot_mapping_ambiguous")
        if len(nfs_matches) == 1 and len(proton_matches) == 1:
            return source, nfs_matches[0], proton_matches[0]
    raise ObservationError("complete_chain_missing")


def local_restic(policy: dict[str, Any], repository: str, arguments: list[str]) -> str:
    restic = policy["tools"]["restic"]["installed_path"]
    return run(
        [restic, "--repo", policy["repositories"][repository]["path"], *arguments],
        {"RESTIC_PASSWORD_FILE": str(LOCAL_PASSWORD), "RESTIC_CACHE_DIR": policy["runner"]["local_cache_path"]},
    )


def proton_restic(policy: dict[str, Any], arguments: list[str]) -> str:
    restic = policy["tools"]["restic"]["installed_path"]
    repository = policy["repositories"]["proton"]["path"]
    return run(
        [
            "/usr/sbin/runuser", "--user", "restic-proton", "--", "/usr/bin/env",
            f"RESTIC_PASSWORD_FILE={PROTON_PASSWORD}", f"RESTIC_CACHE_DIR={PROTON_CACHE}",
            f"RCLONE_CONFIG={PROTON_CONFIG}", "HOME=/var/lib/restic-proton",
            restic, "--repo", repository, *arguments,
        ]
    )


def validate_units(policy: dict[str, Any]) -> dict[str, list[str]]:
    properties = [
        "LoadState", "ActiveState", "SubState", "Result", "NextElapseUSecRealtime",
        "LastTriggerUSec", "ExecMainStartTimestamp", "ExecMainExitTimestamp",
    ]
    observed: dict[str, list[str]] = {}
    parsed: dict[str, dict[str, str]] = {}
    for unit in UNITS:
        raw = run(["/usr/bin/systemctl", "show", *[f"--property={name}" for name in properties], unit])
        values = parse_properties(raw)
        observed[unit] = raw.splitlines()
        parsed[unit] = values
        if values.get("LoadState") != "loaded":
            raise ObservationError("unit_load_state")
    for timer in ("home-lab-restic-daily.timer", "home-lab-restic-maintenance.timer"):
        if parsed[timer].get("ActiveState") != "active" or parsed[timer].get("SubState") != "waiting":
            raise ObservationError("timer_state")
        if not parsed[timer].get("NextElapseUSecRealtime"):
            raise ObservationError("timer_schedule")
    if not parsed["home-lab-restic-daily.timer"].get("LastTriggerUSec"):
        raise ObservationError("daily_cadence_history")
    for unit in UNITS:
        if unit.endswith(".timer"):
            continue
        values = parsed[unit]
        if values.get("ActiveState") != "inactive" or values.get("SubState") != "dead":
            raise ObservationError("backup_writer_state")
        if unit.endswith(".service") and values.get("Result") != "success":
            raise ObservationError("backup_service_result")
    schedules = {
        Path("/etc/systemd/system/home-lab-restic-daily.timer"): policy["schedule"]["daily_calendar"],
        Path("/etc/systemd/system/home-lab-restic-maintenance.timer"): policy["schedule"]["maintenance_calendar"],
    }
    for path, calendar in schedules.items():
        require_regular(path, 0o644)
        lines = path.read_text(encoding="utf-8").splitlines()
        if lines.count(f"OnCalendar={calendar}") != 1:
            raise ObservationError("timer_cadence")
    return observed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-sha256", required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--files-from-sha256", required=True)
    parser.add_argument("--excludes-sha256", required=True)
    parser.add_argument("--restic-sha256", required=True)
    parser.add_argument("--rclone-sha256", required=True)
    parser.add_argument("--games-id", required=True)
    parser.add_argument("--nfs-id", required=True)
    parser.add_argument("--proton-id", required=True)
    arguments = parser.parse_args()
    expected_hex = vars(arguments)
    if any(HEX.fullmatch(value) is None for value in expected_hex.values()):
        raise ObservationError("expected_identity")

    require_regular(LOCK_PATH, 0o660)
    with LOCK_PATH.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ObservationError("backup_owner_active") from error

        require_regular(POLICY_PATH, 0o440, arguments.policy_sha256)
        raw_policy = POLICY_PATH.read_bytes()
        policy = parse_object(raw_policy.decode("utf-8"), "policy_json")
        if policy["runner"]["lock_path"] != str(LOCK_PATH):
            raise ObservationError("lock_policy_identity")
        journal = Path(policy["runner"]["journal_path"])
        if journal.exists() or any(path.exists() for path in OWNERS):
            raise ObservationError("operation_owner_active")
        runtime = (
            (Path(policy["runner"]["path"]), 0o755, arguments.runner_sha256),
            (Path(policy["runner"]["files_from_path"]), 0o440, arguments.files_from_sha256),
            (Path(policy["runner"]["exclude_file_path"]), 0o440, arguments.excludes_sha256),
            (Path(policy["tools"]["restic"]["installed_path"]), 0o755, arguments.restic_sha256),
            (Path(policy["tools"]["rclone"]["installed_path"]), 0o755, arguments.rclone_sha256),
        )
        for path, mode, expected in runtime:
            require_regular(path, mode, expected)
        if policy["runner"]["sha256"] != arguments.runner_sha256:
            raise ObservationError("runner_policy_identity")

        artifact_path = Path(policy["runner"]["artifact_hash_path"])
        require_regular(artifact_path, 0o444)
        artifact_sha256 = artifact_path.read_text(encoding="utf-8").strip()
        if HEX.fullmatch(artifact_sha256) is None:
            raise ObservationError("artifact_identity")
        policy_sha256 = hashlib.sha256(raw_policy).hexdigest()

        expected_ids = {"games": arguments.games_id, "nfs": arguments.nfs_id, "proton": arguments.proton_id}
        configs = {
            "games": parse_object(local_restic(policy, "games", ["cat", "config"]), "repository_config"),
            "nfs": parse_object(local_restic(policy, "nfs", ["cat", "config"]), "repository_config"),
            "proton": parse_object(proton_restic(policy, ["cat", "config"]), "repository_config"),
        }
        for name, config in configs.items():
            if config.get("id") != expected_ids[name] or policy["repositories"][name].get("id") != expected_ids[name]:
                raise ObservationError("repository_identity")

        games = parse_snapshots(local_restic(policy, "games", ["snapshots", "--json"]), "snapshot_inventory")
        nfs = parse_snapshots(local_restic(policy, "nfs", ["snapshots", "--json"]), "snapshot_inventory")
        proton = parse_snapshots(proton_restic(policy, ["snapshots", "--json"]), "snapshot_inventory")
        selected_games, selected_nfs, selected_proton = select_chain(
            games, nfs, proton, policy_sha256, artifact_sha256,
        )
        selected_time = snapshot_time(selected_games)
        age_seconds = int((datetime.now(timezone.utc) - selected_time).total_seconds())
        if age_seconds < 0 or age_seconds >= 172800:
            raise ObservationError("snapshot_freshness")
        units = validate_units(policy)

        result = {
            "artifact_sha256": artifact_sha256,
            "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policy_sha256": policy_sha256,
            "repositories": {
                "games": {"id": configs["games"]["id"], "snapshot_id": snapshot_id(selected_games), "snapshot_time": selected_games["time"], "tags": selected_games["tags"]},
                "nfs": {"id": configs["nfs"]["id"], "snapshot_id": snapshot_id(selected_nfs), "original_snapshot_id": selected_nfs["original"], "snapshot_time": selected_nfs["time"], "tags": selected_nfs["tags"]},
                "proton": {"id": configs["proton"]["id"], "snapshot_id": snapshot_id(selected_proton), "original_snapshot_id": selected_proton["original"], "snapshot_time": selected_proton["time"], "tags": selected_proton["tags"]},
            },
            "units": units,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ObservationError, KeyError, TypeError, ValueError, OSError, UnicodeDecodeError) as error:
        reason = str(error) if isinstance(error, ObservationError) else "internal_validation"
        print(f"backup_observation=failed reason={reason}", file=sys.stderr)
        raise SystemExit(1)
