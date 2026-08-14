#!/usr/bin/env python3
"""Behavioral tests for the VM 100 migration write guard."""

from __future__ import annotations

import datetime as dt
import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, call, patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "nix/scripts/vm-100-migration-guard.py"
SPEC = importlib.util.spec_from_file_location("vm100_migration_guard", SCRIPT)
assert SPEC and SPEC.loader
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)
ARTIFACT = "a" * 64
SYSTEM = "/nix/store/" + "b" * 32 + "-nixos-system"


def request(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "bootedSystem": SYSTEM,
        "composeArtifactSha256": ARTIFACT,
        "confirmation": GUARD.CONFIRMATION,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "currentSystem": SYSTEM,
        "deploymentAuthority": GUARD.AUTHORITY,
        "version": 1,
    }
    value.update(changes)
    return value


class MigrationGuardTests(unittest.TestCase):
    def test_json_rejects_malformed_and_noncanonical_input(self) -> None:
        for raw in (b"not-json", b'{"version": 1}\n'):
            with self.assertRaises(ValueError):
                GUARD.parse_canonical_json(raw, "test")

    def validate_request(self, value: dict[str, object]) -> None:
        raw = GUARD.canonical_json(value)
        with (
            patch.object(GUARD, "read_protected_file", return_value=raw),
            patch.object(GUARD, "current_system_identity", return_value=SYSTEM),
        ):
            GUARD.validate_request(3, ARTIFACT)

    def test_request_rejects_stale_authority_artifact_and_generation(self) -> None:
        stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        for value in (
            request(createdAt=stale),
            request(deploymentAuthority="arch"),
            request(composeArtifactSha256="c" * 64),
        ):
            with self.assertRaises(ValueError):
                self.validate_request(value)
        raw = GUARD.canonical_json(request(bootedSystem="/nix/store/wrong"))
        with (
            patch.object(GUARD, "read_protected_file", return_value=raw),
            patch.object(GUARD, "current_system_identity", return_value=SYSTEM),
            self.assertRaises(ValueError),
        ):
            GUARD.validate_request(3, ARTIFACT)

    def test_protected_file_rejects_symlink_and_wrong_metadata(self) -> None:
        with patch.object(GUARD.os, "open", side_effect=OSError(errno.ELOOP, "symlink")), self.assertRaises(OSError):
            GUARD.read_protected_file(3, GUARD.REQUEST_NAME, 0o600)
        descriptor = 9
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=2,
        )
        with (
            patch.object(GUARD.os, "open", return_value=descriptor),
            patch.object(GUARD.os, "fstat", return_value=metadata),
            patch.object(GUARD.os, "close"),
            self.assertRaises(ValueError),
        ):
            GUARD.read_protected_file(3, GUARD.REQUEST_NAME, 0o600)

    def test_commit_removes_request_before_marker_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            request_path = state / GUARD.REQUEST_NAME
            request_path.write_bytes(GUARD.canonical_json(request()))
            request_path.chmod(0o600)
            directory_fd = os.open(state, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            original_open = GUARD.open_state_directory
            original_read = GUARD.read_protected_file

            def open_directory() -> int:
                return os.dup(directory_fd)

            def read_file(fd: int, name: str, mode: int) -> bytes:
                return (state / name).read_bytes()

            with (
                patch.object(GUARD, "open_state_directory", side_effect=open_directory),
                patch.object(GUARD, "read_protected_file", side_effect=read_file),
                patch.object(GUARD, "current_system_identity", return_value=SYSTEM),
                patch.object(GUARD.os, "replace", side_effect=OSError("publish failed")),
                self.assertRaises(OSError),
            ):
                GUARD.commit(ARTIFACT)
            os.close(directory_fd)
            self.assertFalse(request_path.exists())
            self.assertFalse((state / GUARD.MARKER_NAME).exists())

    def test_commit_publishes_canonical_marker_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / GUARD.REQUEST_NAME).write_bytes(GUARD.canonical_json(request()))
            directory_fd = os.open(state, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))

            def open_directory() -> int:
                return os.dup(directory_fd)

            def read_file(fd: int, name: str, mode: int) -> bytes:
                return (state / name).read_bytes()

            with (
                patch.object(GUARD, "open_state_directory", side_effect=open_directory),
                patch.object(GUARD, "read_protected_file", side_effect=read_file),
                patch.object(GUARD, "current_system_identity", return_value=SYSTEM),
            ):
                GUARD.commit(ARTIFACT)
                marker_raw = (state / GUARD.MARKER_NAME).read_bytes()
                self.assertEqual(marker_raw, GUARD.canonical_json(json.loads(marker_raw)))
                GUARD.commit(ARTIFACT)
            os.close(directory_fd)

    def test_find_mount_rejects_wrong_identity(self) -> None:
        expectation = GUARD.MountExpectation("/mnt/games", "/dev/disk/by-uuid/id", "ext4", "id")
        payload = {"filesystems": [{"target": "/mnt/games", "source": "/dev/sdb1", "fstype": "ext4", "options": "ro", "uuid": "wrong"}]}
        result = SimpleNamespace(stdout=json.dumps(payload))
        with patch.object(GUARD.subprocess, "run", return_value=result), self.assertRaises(ValueError):
            GUARD.find_mount(expectation)
        nfs = GUARD.MountExpectation("/mnt/storage", "server:/expected", "nfs4")
        wrong_nfs = {"filesystems": [{"target": "/mnt/storage", "source": "server:/other", "fstype": "nfs4", "options": "ro", "uuid": None}]}
        with (
            patch.object(GUARD.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(wrong_nfs))),
            self.assertRaises(ValueError),
        ):
            GUARD.find_mount(nfs)

    def test_verify_requires_pre_and_post_commit_states(self) -> None:
        expectations = (MagicMock(), MagicMock())
        with (
            patch.object(GUARD, "open_state_directory", return_value=3),
            patch.object(GUARD.os, "close"),
            patch.object(GUARD, "validate_marker", side_effect=FileNotFoundError),
            patch.object(GUARD, "verify_mounts") as verify,
            patch.object(GUARD, "unit_active", return_value=False),
        ):
            GUARD.verify_only(ARTIFACT, expectations)
            verify.assert_called_once_with(expectations, "ro")
        active = {"vm-100-migration-write-enable.service", "docker.service", "docker.socket"}
        with (
            patch.object(GUARD, "open_state_directory", return_value=3),
            patch.object(GUARD.os, "close"),
            patch.object(GUARD, "validate_marker"),
            patch.object(GUARD, "verify_mounts") as verify,
            patch.object(GUARD, "unit_active", side_effect=lambda unit: unit in active),
        ):
            GUARD.verify_only(ARTIFACT, expectations)
            verify.assert_called_once_with(expectations, "rw")

    def test_enable_writes_rolls_back_transitioned_mounts(self) -> None:
        games = GUARD.MountExpectation("/mnt/games", "games", "ext4", "id")
        shared = GUARD.MountExpectation("/mnt/storage", "nfs", "nfs4")
        options = iter([
            {"options": {"ro"}},
            {"options": {"ro"}},
            {"options": {"rw"}},
        ])
        run = MagicMock()
        run.side_effect = [SimpleNamespace(returncode=0), OSError("second remount failed"), SimpleNamespace(returncode=0)]
        with (
            patch.object(GUARD, "open_state_directory", return_value=3),
            patch.object(GUARD.os, "close"),
            patch.object(GUARD, "validate_marker"),
            patch.object(GUARD, "find_mount", side_effect=lambda expectation: next(options)),
            patch.object(GUARD, "verify_mounts"),
            patch.object(GUARD.subprocess, "run", run),
            self.assertRaises(OSError),
        ):
            GUARD.enable_writes(ARTIFACT, (games, shared))
        self.assertIn(call(["mount", "--options", "remount,ro", "/mnt/games"], check=False), run.mock_calls)


if __name__ == "__main__":
    unittest.main()
