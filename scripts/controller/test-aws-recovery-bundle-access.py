#!/usr/bin/env python3
"""CLI contract tests; every SOPS and AWS interaction is synthetic."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/verify-aws-recovery-bundle-access"
PYTHON = [sys.executable, "-B", "-E", "-s", "-S"]
RECIPIENT = "age1ddk0qtwjclc2za5afrz5pl4j5kley02rqv2vh0s07c27a8t5u58sph58qm"
CONFIRMATION = "retrieve-exact-historical-bundle-read-only"
PAYLOAD = b"synthetic encrypted recovery bundle\n"
KEY = "protected/recovery-bundle.age"
VERSION_ID = "synthetic-version-id"
PRINCIPAL_ARN = "arn:aws:iam::658271954302:user/home-lab-recovery"


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def executable(path: Path, source: str) -> None:
    path.write_text(source)
    path.chmod(0o700)


class RecoveryBundleAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "infrastructure/evidence").mkdir(parents=True)
        (self.repo / "secrets").mkdir()
        self.fixture_helper = self.repo / "scripts/verify-aws-recovery-bundle-access"
        if HELPER.exists():
            shutil.copy2(HELPER, self.fixture_helper)
        else:
            self.fixture_helper = HELPER

        canonical = {
            "version": 1,
            "bundle_b_bytes": len(PAYLOAD),
            "bundle_b_ciphertext_sha256": sha(PAYLOAD),
            "bundle_b_object_key_sha256": sha(KEY.encode()),
            "bundle_b_version_id_sha256": sha(VERSION_ID.encode()),
        }
        rotation = {"version": 1, "principal_arn_sha256": sha(PRINCIPAL_ARN.encode())}
        (self.repo / "infrastructure/evidence/proton-canonical-recovery-bundles.json").write_text(
            json.dumps(canonical) + "\n"
        )
        (self.repo / "infrastructure/evidence/aws-recovery-publication-credential-rotation.json").write_text(
            json.dumps(rotation) + "\n"
        )
        self.credential = self.repo / "secrets/recovery-publication.sops.json"
        self.credential.write_text(json.dumps({
            "AWS_ACCESS_KEY_ID": "ENC[fixture]",
            "AWS_SECRET_ACCESS_KEY": "ENC[fixture]",
            "AWS_S3_BUCKET_NAME": "ENC[fixture]",
            "sops": {"age": [{"recipient": RECIPIENT}]},
        }) + "\n")

        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        self.workspace_parent = self.base / "workspace"
        self.workspace_parent.mkdir(mode=0o700)
        self.age_key = self.base / "independent-recovery.agekey"
        self.age_key.write_text("synthetic protected identity\n")
        self.age_key.chmod(0o600)
        self.bin = self.base / "bin"
        self.bin.mkdir(mode=0o700)
        self.log = self.base / "aws-calls.jsonl"
        self._write_adapters()
        self.env = {
            "HOME": str(self.home),
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "SOPS_AGE_KEY_FILE": str(self.age_key),
            "RECOVERY_RETRIEVAL_WORKSPACE_PARENT": str(self.workspace_parent),
            "RECOVERY_READ_ONLY_CONFIRMED": CONFIRMATION,
            "HOME_LAB_SOPS_BINARY": str(self.bin / "sops"),
            "HOME_LAB_AWS_BINARY": str(self.bin / "aws"),
            "HOME_LAB_AGE_KEYGEN_BINARY": str(self.bin / "age-keygen"),
        }

    def _write_adapters(self) -> None:
        executable(
            self.bin / "age-keygen",
            "#!/bin/sh\n"
            "if [ \"$1\" = -y ] && [ \"$#\" = 2 ]; then\n"
            f"  printf '%s\\n' '{RECIPIENT}'\n"
            "else\n"
            "  exit 64\n"
            "fi\n",
        )
        executable(
            self.bin / "sops",
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import os, subprocess, sys
                if len(sys.argv) < 4 or sys.argv[1] != "exec-env":
                    raise SystemExit(64)
                env = dict(os.environ)
                env.update({{
                    "AWS_ACCESS_KEY_ID": "synthetic-access-key",
                    "AWS_SECRET_ACCESS_KEY": "synthetic-secret-key",
                    "AWS_S3_BUCKET_NAME": "synthetic-recovery-bucket",
                }})
                result = subprocess.run(["/bin/sh", "-c", sys.argv[-1]], env=env)
                raise SystemExit(result.returncode)
                """
            ),
        )
        executable(
            self.bin / "aws",
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import json, pathlib, sys
                args = sys.argv[1:]
                log = pathlib.Path({str(self.log)!r})
                with log.open("a") as stream:
                    stream.write(json.dumps(args, separators=(",", ":")) + "\\n")
                if args[:2] == ["sts", "get-caller-identity"]:
                    print(json.dumps({{"Account":"658271954302","Arn":{PRINCIPAL_ARN!r},"UserId":"fixture"}}))
                elif args[:2] == ["s3api", "list-object-versions"]:
                    print(json.dumps({{"Versions":[{{"Key":{KEY!r},"VersionId":{VERSION_ID!r},"Size":{len(PAYLOAD)},"IsLatest":True}}],"DeleteMarkers":[]}}))
                elif args[:2] == ["s3api", "get-object"]:
                    output = pathlib.Path(args[-1])
                    output.write_bytes({PAYLOAD!r})
                    print(json.dumps({{"ContentLength":{len(PAYLOAD)},"ServerSideEncryption":"aws:kms","VersionId":{VERSION_ID!r}}}))
                else:
                    raise SystemExit(64)
                """
            ),
        )

    def run_helper(self, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*PYTHON, str(self.fixture_helper)],
            env=env or self.env,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def test_exact_version_is_retrieved_verified_removed_with_bounded_output(self) -> None:
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(
            value,
            {
                "aws_identity": "matched",
                "bundle_bytes": len(PAYLOAD),
                "bundle_ciphertext_sha256": sha(PAYLOAD),
                "exact_version": "matched",
                "kms_encryption": "matched",
                "selected_version_current": True,
                "state": "retrieved-verified-removed",
                "verified_at": value["verified_at"],
                "version": 1,
            },
        )
        self.assertRegex(value["verified_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(result.stderr, "")
        self.assertEqual(list(self.workspace_parent.iterdir()), [])
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([call[:2] for call in calls], [
            ["sts", "get-caller-identity"],
            ["s3api", "list-object-versions"],
            ["s3api", "get-object"],
        ])
        forbidden = {"put-object", "copy-object", "delete-object", "delete-objects"}
        self.assertFalse(any(forbidden.intersection(call) for call in calls))
        protected = ("synthetic-access-key", "synthetic-secret-key", "synthetic-recovery-bucket", KEY, VERSION_ID, PRINCIPAL_ARN)
        self.assertFalse(any(item in result.stdout + result.stderr for item in protected))

    def test_unexpected_encrypted_credential_field_fails_before_provider_access(self) -> None:
        value = json.loads(self.credential.read_text())
        value["UNEXPECTED_SECRET"] = "ENC[fixture]"
        self.credential.write_text(json.dumps(value) + "\n")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reason=credential_document", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.workspace_parent.iterdir()), [])

    def test_invalid_recipient_output_is_a_bounded_failure_before_sops(self) -> None:
        executable(
            self.bin / "age-keygen",
            f"#!{sys.executable}\nimport os\nos.write(1, b'\\xff\\xfe')\n",
        )
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reason=age_recipient", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.workspace_parent.iterdir()), [])

    def test_confirmation_and_ambient_credentials_fail_before_provider_access(self) -> None:
        cases = [
            {**self.env, "RECOVERY_READ_ONLY_CONFIRMED": "wrong"},
            {key: value for key, value in self.env.items() if key != "RECOVERY_READ_ONLY_CONFIRMED"},
            {**self.env, "AWS_PROFILE": "forbidden"},
            {**self.env, "SOPS_AGE_KEY": "forbidden"},
        ]
        for env in cases:
            with self.subTest(keys=sorted(env)):
                result = self.run_helper(env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertFalse(self.log.exists())
                self.assertEqual(list(self.workspace_parent.iterdir()), [])

    def test_ciphertext_mismatch_fails_and_removes_download(self) -> None:
        path = self.repo / "infrastructure/evidence/proton-canonical-recovery-bundles.json"
        value = json.loads(path.read_text())
        value["bundle_b_ciphertext_sha256"] = "f" * 64
        path.write_text(json.dumps(value) + "\n")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stderr_sha256=", result.stderr)
        self.assertNotIn(KEY, result.stderr)
        self.assertNotIn(VERSION_ID, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(list(self.workspace_parent.iterdir()), [])

    def test_sops_failure_is_hashed_and_workspace_is_removed(self) -> None:
        executable(
            self.bin / "sops",
            "#!/bin/sh\nprintf 'protected failure detail' >&2\nexit 9\n",
        )
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reason=provider_request", result.stderr)
        self.assertIn("stderr_sha256=", result.stderr)
        self.assertNotIn("protected failure detail", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.workspace_parent.iterdir()), [])

    def test_parent_rejects_forged_child_success_and_cleans_workspace(self) -> None:
        forged = {
            "aws_identity": "matched",
            "bundle_bytes": len(PAYLOAD),
            "bundle_ciphertext_sha256": "f" * 64,
            "exact_version": "matched",
            "kms_encryption": "matched",
            "selected_version_current": True,
            "state": "retrieved-verified",
            "verified_at": "2026-09-19T00:00:00Z",
            "version": 1,
        }
        executable(
            self.bin / "sops",
            f"#!{sys.executable}\nimport json\nprint(json.dumps({forged!r}))\n",
        )
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reason=child_output", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.workspace_parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
