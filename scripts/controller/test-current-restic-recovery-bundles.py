#!/usr/bin/env python3
"""Public CLI tests for current Restic recovery-bundle planning and building."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLANNER = ROOT / "scripts/prepare-restic-recovery-bundle-metadata"
PAIR_BUILDER = ROOT / "scripts/build-current-restic-recovery-bundles"
GENERIC_BUILDER = ROOT / "scripts/build-restic-recovery-bundle"
RESTORE_RUNNER = ROOT / "scripts/restore-critical-backup"
SCOPE_RESOLVER = ROOT / "scripts/recovery-scope.py"
SCOPE_CONFIG = ROOT / "recovery/groups.json"
PYTHON = [sys.executable, "-B", "-E", "-s", "-S"]
RECIPIENT = "age1ddk0qtwjclc2za5afrz5pl4j5kley02rqv2vh0s07c27a8t5u58sph58qm"
BUILD_CONFIRMATION = "build-two-current-encrypted-restic-recovery-bundles"
HEX = {
    "artifact": "1" * 64,
    "policy": "2" * 64,
    "games": "3" * 64,
    "nfs": "4" * 64,
    "proton": "5" * 64,
    "games_repo": "6" * 64,
    "nfs_repo": "7" * 64,
    "proton_repo": "8" * 64,
    "restic": "9" * 64,
    "rclone": "a" * 64,
}


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def executable(path: Path, source: str) -> None:
    path.write_text(source)
    path.chmod(0o700)


class BundleMetadataPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        for directory in (
            "scripts", "infrastructure/contract", "infrastructure/evidence",
        ):
            (self.repo / directory).mkdir(parents=True, exist_ok=True)
        self.planner = self.repo / "scripts/prepare-restic-recovery-bundle-metadata"
        if PLANNER.exists():
            shutil.copy2(PLANNER, self.planner)
        else:
            self.planner = PLANNER
        (self.repo / "infrastructure/contract/home-lab.yml").write_text("fixture: true\n")
        self.first_run = self.repo / "infrastructure/evidence/restic-first-run.json"
        self.qualification = self.repo / "infrastructure/evidence/proton-qualification.json"
        self.first_run.write_bytes(b'{"fixture":"first-run"}\n')
        self.qualification.write_bytes(b'{"fixture":"qualification"}\n')
        self.runner = self.repo / "scripts/restore-critical-backup"
        self.runner.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.runner.chmod(0o755)
        self.observation = self.base / "observation.json"
        self.observation.write_text(json.dumps({
            "age_seconds": 100,
            "artifact_sha256": HEX["artifact"],
            "event": "natural-systemd-timer",
            "interruption": False,
            "latest_chain": {
                "games": HEX["games"], "nfs": HEX["nfs"], "proton": HEX["proton"],
                "snapshot_time": "2026-09-18T12:06:33Z",
            },
            "observed_at": "2026-09-19T03:19:43Z",
            "pending": 0,
            "policy_sha256": HEX["policy"],
            "repositories": {
                "games": HEX["games_repo"], "nfs": HEX["nfs_repo"], "proton": HEX["proton_repo"],
            },
            "state": "observed-current-chain",
            "units": {},
            "version": 1,
        }) + "\n")
        self.observation.chmod(0o600)
        self.output_parent = self.base / "output"
        self.output_parent.mkdir(mode=0o700)
        self.output = self.output_parent / "metadata.json"
        self.bin = self.base / "bin"
        self.bin.mkdir(mode=0o700)
        executable(
            self.bin / "node",
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import json
                print(json.dumps({{
                    "restic_sha256": {HEX['restic']!r},
                    "rclone_sha256": {HEX['rclone']!r},
                    "repository_id": {HEX['proton_repo']!r},
                }}))
                """
            ),
        )
        self.env = {
            "HOME": str(self.base),
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "HOME_LAB_NODE_BINARY": str(self.bin / "node"),
        }

    def run_planner(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*PYTHON, str(self.planner), "--observation", str(self.observation),
             "--output", str(self.output), *extra],
            env=self.env, text=True, capture_output=True, timeout=10,
        )

    def test_current_observation_produces_exact_private_bundle_metadata(self) -> None:
        result = self.run_planner()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = {
            "artifact_sha256": HEX["artifact"],
            "first_run_evidence_sha256": sha(self.first_run.read_bytes()),
            "original_snapshot_id": HEX["games"],
            "policy_sha256": HEX["policy"],
            "qualification_evidence_sha256": sha(self.qualification.read_bytes()),
            "rclone_sha256": HEX["rclone"],
            "repository": "rclone:proton_backup:Backups/home-lab-restic",
            "repository_id": HEX["proton_repo"],
            "restic_sha256": HEX["restic"],
            "restore_runner_sha256": sha(self.runner.read_bytes()),
            "snapshot_id": HEX["proton"],
            "version": 1,
        }
        self.assertEqual(json.loads(self.output.read_text()), expected)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        result_value = json.loads(result.stdout)
        self.assertEqual(result_value, {
            "metadata_sha256": sha(self.output.read_bytes()),
            "observation_sha256": sha(self.observation.read_bytes()),
            "state": "metadata-prepared",
            "version": 1,
        })
        self.assertEqual(result.stderr, "")


class CurrentBundlePairBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.scripts = self.base / "scripts"
        self.scripts.mkdir(mode=0o700)
        self.builder = self.scripts / "build-current-restic-recovery-bundles"
        if PAIR_BUILDER.exists():
            shutil.copy2(PAIR_BUILDER, self.builder)
        else:
            self.builder = PAIR_BUILDER
        shutil.copy2(GENERIC_BUILDER, self.scripts / GENERIC_BUILDER.name)
        shutil.copy2(RESTORE_RUNNER, self.scripts / RESTORE_RUNNER.name)
        shutil.copy2(SCOPE_RESOLVER, self.scripts / SCOPE_RESOLVER.name)
        (self.base / "recovery").mkdir(mode=0o700)
        shutil.copy2(SCOPE_CONFIG, self.base / "recovery/groups.json")
        for path in (
            self.scripts / GENERIC_BUILDER.name,
            self.scripts / RESTORE_RUNNER.name,
            self.scripts / SCOPE_RESOLVER.name,
        ):
            path.chmod(0o755)
        self.bin = self.base / "bin"
        self.bin.mkdir(mode=0o700)
        self.restic = self.bin / "restic"
        self.rclone = self.bin / "rclone"
        self.age = self.bin / "age"
        executable(self.restic, "#!/bin/sh\nexit 0\n")
        executable(self.rclone, "#!/bin/sh\nexit 0\n")
        executable(
            self.age,
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import os, sys
                sys.stdout.buffer.write(os.urandom(16) + sys.stdin.buffer.read())
                """
            ),
        )
        for path in (self.restic, self.rclone, self.age):
            path.chmod(0o755)
        self.metadata = self.base / "metadata.json"
        self.metadata.write_text(json.dumps({
            "artifact_sha256": "1" * 64,
            "first_run_evidence_sha256": "2" * 64,
            "original_snapshot_id": "3" * 64,
            "policy_sha256": "4" * 64,
            "qualification_evidence_sha256": "5" * 64,
            "rclone_sha256": sha(self.rclone.read_bytes()),
            "repository": "rclone:proton_backup:Backups/home-lab-restic",
            "repository_id": "6" * 64,
            "restic_sha256": sha(self.restic.read_bytes()),
            "restore_runner_sha256": sha((self.scripts / RESTORE_RUNNER.name).read_bytes()),
            "snapshot_id": "7" * 64,
            "version": 1,
        }) + "\n")
        self.metadata.chmod(0o600)
        self.output_parent = self.base / "output"
        self.output_parent.mkdir(mode=0o700)
        self.output_root = self.output_parent / "current-bundles"
        self.env = {
            "HOME": str(self.base),
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "RECOVERY_BUNDLE_BUILD_CONFIRMED": BUILD_CONFIRMATION,
            "HOME_LAB_RESTIC_BINARY": str(self.restic),
            "HOME_LAB_RCLONE_BINARY": str(self.rclone),
            "HOME_LAB_AGE_BINARY": str(self.age),
            "RESTIC_PROTON_PASSWORD": "r" * 40,
            "PROTON_BACKUP_USERNAME": "fixture-user",
            "PROTON_BACKUP_PASSWORD": "P" * 48,
            "PROTON_BACKUP_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
        }

    def run_builder(self, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*PYTHON, str(self.builder), "--metadata", str(self.metadata),
             "--output-root", str(self.output_root)],
            env=env or self.env, text=True, capture_output=True, timeout=20,
        )

    def test_forged_builder_hashes_fail_and_remove_output_root(self) -> None:
        generic = self.scripts / GENERIC_BUILDER.name
        executable(
            generic,
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import json, pathlib, sys
                output = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
                output.write_bytes(b"not-the-reported-ciphertext")
                label = "a" if "bundle-a" in output.name else "b"
                print(json.dumps({{
                    "ciphertext_sha256": ("a" if label == "a" else "b") * 64,
                    "plaintext_sha256": "c" * 64,
                    "recipient_sha256": {sha(RECIPIENT.encode())!r},
                    "state": "encrypted",
                    "version": 1,
                }}))
                """
            ),
        )
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reason=bundle_identity", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.output_root.exists())

    def test_builds_two_distinct_ciphertexts_for_the_independent_recipient(self) -> None:
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        expected_files = {"bundle-a.age", "bundle-a-result.json", "bundle-b.age", "bundle-b-result.json"}
        self.assertEqual({path.name for path in self.output_root.iterdir()}, expected_files)
        a = json.loads((self.output_root / "bundle-a-result.json").read_text())
        b = json.loads((self.output_root / "bundle-b-result.json").read_text())
        self.assertEqual(a["plaintext_sha256"], b["plaintext_sha256"])
        self.assertNotEqual(a["ciphertext_sha256"], b["ciphertext_sha256"])
        recipient_sha = sha(RECIPIENT.encode())
        self.assertEqual((a["recipient_sha256"], b["recipient_sha256"]), (recipient_sha, recipient_sha))
        self.assertEqual(value, {
            "bundle_a_ciphertext_sha256": a["ciphertext_sha256"],
            "bundle_b_ciphertext_sha256": b["ciphertext_sha256"],
            "metadata_sha256": sha(self.metadata.read_bytes()),
            "plaintext_sha256": a["plaintext_sha256"],
            "recipient_sha256": recipient_sha,
            "state": "built-encrypted-distinct",
            "version": 1,
        })
        self.assertTrue(all((path.stat().st_mode & 0o777) == 0o600 for path in self.output_root.iterdir()))
        protected = tuple(self.env[key] for key in (
            "RESTIC_PROTON_PASSWORD", "PROTON_BACKUP_USERNAME", "PROTON_BACKUP_PASSWORD", "PROTON_BACKUP_TOTP_SECRET",
        ))
        self.assertFalse(any(secret in result.stdout + result.stderr for secret in protected))


if __name__ == "__main__":
    unittest.main()
