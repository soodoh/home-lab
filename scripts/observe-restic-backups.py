#!/usr/bin/env python3
"""Observe strict recovery or routine local-backup admission under the backup lock."""

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


def require_repository_identity(config: dict[str, Any], expected: str) -> None:
    if config.get("id") != expected:
        raise ObservationError("repository_identity")


def require_fresh(snapshot: dict[str, Any], now: datetime) -> None:
    age = (now - snapshot_time(snapshot)).total_seconds()
    if age < 0 or age >= 172800:
        raise ObservationError("snapshot_freshness")


def select_local(snapshots: list[dict[str, Any]], policy_sha256: str, paths: list[str]) -> dict[str, Any]:
    """Require current backup scope, but allow an earlier deployment artifact."""
    required = {"cadence=daily", f"policy={policy_sha256}"}
    for source in sorted(snapshots, key=snapshot_time, reverse=True):
        snapshot_id(source)
        tags = snapshot_tags(source)
        covered = source.get("paths", [])
        if not isinstance(covered, list) or any(not isinstance(root, str) for root in covered):
            raise ObservationError("snapshot_paths")
        if not required <= tags or not any(re.fullmatch(r"artifact=[0-9a-f]{64}", tag) for tag in tags):
            continue
        if all(any(path == root or path.startswith(root.rstrip("/") + "/") for root in covered)
               for path in paths):
            return source
    raise ObservationError("local_snapshot_missing")


def match_copy(source: dict[str, Any], destination: list[dict[str, Any]]) -> dict[str, Any] | None:
    mapped = [item for item in destination if item.get("original") == snapshot_id(source)
              and snapshot_tags(item) == snapshot_tags(source)]
    if len(mapped) > 1:
        raise ObservationError("snapshot_mapping_ambiguous")
    return mapped[0] if mapped else None


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


def daily_history_present(parsed: dict[str, dict[str, str]]) -> bool:
    if parsed["home-lab-restic-daily.timer"].get("LastTriggerUSec"):
        return True
    return all(
        parsed[unit].get("ExecMainStartTimestamp") and parsed[unit].get("ExecMainExitTimestamp")
        for unit in ("home-lab-restic-daily-local.service", "home-lab-restic-daily-proton.service")
    )


def validate_unit_state(unit: str, values: dict[str, str], *, routine: bool = False) -> None:
    if values.get("ActiveState") == "inactive" and values.get("SubState") == "dead":
        pass
    elif routine and "-proton." in unit and values.get("ActiveState") == "failed" and values.get("SubState") == "failed":
        pass
    else:
        raise ObservationError("backup_writer_state")
    if unit.endswith(".service") and values.get("Result") != "success" and not (routine and "-proton." in unit):
        raise ObservationError("backup_service_result")


def validate_owners(journal: Path, apply_owner_sha256: str | None) -> None:
    if journal.exists() or journal.is_symlink():
        raise ObservationError("operation_owner_active")
    for path in OWNERS:
        if not path.exists() and not path.is_symlink():
            if path == OWNERS[0] and apply_owner_sha256 is not None:
                raise ObservationError("apply_owner_missing")
            continue
        if path != OWNERS[0] or apply_owner_sha256 is None:
            raise ObservationError("operation_owner_active")
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ObservationError("apply_owner_metadata")
        if sorted(child.name for child in path.iterdir()) != ["owner"]:
            raise ObservationError("apply_owner_metadata")
        require_regular(path / "owner", 0o600, apply_owner_sha256)


def validate_units(policy: dict[str, Any], *, routine: bool = False) -> dict[str, list[str]]:
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
    if not routine and not daily_history_present(parsed):
        raise ObservationError("daily_cadence_history")
    for unit in UNITS:
        if unit.endswith(".timer"):
            continue
        values = parsed[unit]
        validate_unit_state(unit, values, routine=routine)
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
    parser.add_argument("--admission", choices=("strict", "routine"), default="strict")
    parser.add_argument("--apply-owner-sha256")
    arguments = parser.parse_args()
    expected_hex = {key: value for key, value in vars(arguments).items() if key != "admission" and value is not None}
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
        validate_owners(journal, arguments.apply_owner_sha256)
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
        units = validate_units(policy, routine=arguments.admission == "routine")
        warnings = []
        inventories = {}
        for name in ("games", "nfs", "proton"):
            if policy["repositories"][name].get("id") != expected_ids[name]:
                raise ObservationError("repository_identity")
            try:
                config_raw = proton_restic(policy, ["cat", "config"]) if name == "proton" else local_restic(policy, name, ["cat", "config"])
                require_repository_identity(parse_object(config_raw, "repository_config"), expected_ids[name])
                raw = proton_restic(policy, ["snapshots", "--json"]) if name == "proton" else local_restic(policy, name, ["snapshots", "--json"])
                inventories[name] = parse_snapshots(raw, "snapshot_inventory")
            except ObservationError as error:
                if arguments.admission != "routine" or name == "games" or str(error) not in ("command_failed", "command_execution"):
                    raise
                inventories[name] = []
                warnings.append(f"{name}_unavailable")
        if arguments.admission == "strict":
            selected_games, selected_nfs, selected_proton = select_chain(
                inventories["games"], inventories["nfs"], inventories["proton"], policy_sha256, artifact_sha256,
            )
        else:
            paths = [line.strip() for line in Path(policy["runner"]["files_from_path"]).read_text().splitlines()
                     if line.strip() and not line.lstrip().startswith("#")]
            if not paths or any(not path.startswith("/") for path in paths):
                raise ObservationError("backup_scope")
            selected_games = select_local(inventories["games"], policy_sha256, paths)
            selected_nfs, selected_proton = (match_copy(selected_games, inventories[name]) for name in ("nfs", "proton"))
            for name, copy in (("nfs", selected_nfs), ("proton", selected_proton)):
                if copy is None:
                    warnings.append(f"{name}_replication_lag")
            for unit, properties in units.items():
                if unit.endswith(".service") and parse_properties("\n".join(properties)).get("Result") != "success":
                    warnings.append(f"{unit}_last_run_failed")
        require_fresh(selected_games, datetime.now(timezone.utc))

        result = {
            "admission": arguments.admission,
            "warnings": warnings,
            "artifact_sha256": artifact_sha256,
            "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policy_sha256": policy_sha256,
            "repositories": {
                "games": {"id": expected_ids["games"], "snapshot_id": snapshot_id(selected_games), "snapshot_time": selected_games["time"], "tags": selected_games["tags"]},
                "nfs": {"id": expected_ids["nfs"], "snapshot_id": snapshot_id(selected_nfs), "original_snapshot_id": selected_nfs["original"], "snapshot_time": selected_nfs["time"], "tags": selected_nfs["tags"]} if selected_nfs else None,
                "proton": {"id": expected_ids["proton"], "snapshot_id": snapshot_id(selected_proton), "original_snapshot_id": selected_proton["original"], "snapshot_time": selected_proton["time"], "tags": selected_proton["tags"]} if selected_proton else None,
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
