#!/usr/bin/env python3
"""Orchestration tests for the qualification shell driver."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
DRIVER = REPOSITORY / "scripts/qualify-proxmox-lxc"
FAKE_LOCK_DOCUMENT = '{"ID":"11111111-1111-4111-8111-111111111111","Operation":"OperationTypeApply","Info":"","Who":"runner@test","Version":"1.12.5","Created":"2026-08-06T12:51:00Z","Path":"test-bucket/home-lab/proxmox-lxc-qualification/tofu.tfstate"}\n'


class QualificationOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/controller").mkdir(parents=True)
        (self.repo / "infrastructure/tofu/proxmox-lxc-qualification").mkdir(parents=True)
        (self.repo / "infrastructure/contract").mkdir(parents=True)
        (self.repo / ".reconcile/lxc-qualification").mkdir(parents=True)
        shutil.copy2(DRIVER, self.repo / "scripts/qualify-proxmox-lxc")
        (self.repo / ".reconcile/lxc-qualification/qualification.tfplan").write_bytes(b"plan")
        (self.repo / ".reconcile/lxc-qualification/manifest.json").write_text("{}\n")
        self.bin = self.repo / "bin"
        self.bin.mkdir()
        self.log = self.repo / "commands.log"
        self._write_fake_commands()
        self.env = os.environ | {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "TF_BACKEND_BUCKET": "test-bucket",
            "AWS_REGION": "test-region",
            "TF_VAR_proxmox_endpoint": "https://proxmox:8006/api2/json",
            "TF_VAR_qualification_vm_id": "9020",
            "TF_VAR_qualification_template_file_id": "local:vztmpl/test.tar.zst",
            "PROXMOX_PLAN_API_TOKEN": "plan-token",
            "PROXMOX_APPLY_API_TOKEN": "apply-token",
            "PROXMOX_CA_PEM": "test-ca",
            "FAKE_LOG": str(self.log),
            "FAKE_COUNTER": str(self.repo / "api-counter"),
            "FAKE_APPLY_RESULT": "success",
            "FAKE_LOCK_COUNT": "0",
            "FAKE_LOCK_PATH": "test-bucket/home-lab/proxmox-lxc-qualification/tofu.tfstate",
            "FAKE_LOCK_CREATED": "2026-08-06T12:51:00Z",
            "FAKE_LOCK_VERSION": "1.12.5",
            "FAKE_LOCK_ID": "11111111-1111-4111-8111-111111111111",
            "FAKE_LOCK_OPERATION": "OperationTypeApply",
            "FAKE_LOCK_INFO": "",
            "FAKE_LOCK_WHO": "runner@test",
        }

    def _executable(self, name: str, content: str) -> None:
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def _write_fake_commands(self) -> None:
        helper = self.repo / "scripts/controller/proxmox-lxc-qualification.py"
        helper.write_text(
            textwrap.dedent(
                """\
                import os
                from pathlib import Path
                import sys

                command = sys.argv[1]
                with Path(os.environ["FAKE_LOG"]).open("a") as log:
                    log.write("helper " + " ".join(sys.argv[1:]) + "\\n")
                if command == "classify-probe-log" and os.environ.get("FAKE_APPLY_RESULT") != "protected":
                    raise SystemExit(1)
                if command == "api-check":
                    counter = Path(os.environ["FAKE_COUNTER"])
                    count = int(counter.read_text()) + 1 if counter.exists() else 1
                    counter.write_text(str(count))
                    if os.environ.get("FAKE_POST_FAILURE") == "1" and count >= 2:
                        raise SystemExit(1)
                    mode = sys.argv[sys.argv.index("--mode") + 1]
                    if os.environ.get("FAKE_RESIDUAL") == "1" and mode == "absent":
                        raise SystemExit(1)
                if command == "inspect-recovery":
                    if os.environ.get("FAKE_STORAGE_FAILURE") == "1" and os.environ.get("PROXMOX_VERIFY_STORAGE_VOLUME") == "true":
                        raise SystemExit(1)
                    print(os.environ.get("FAKE_INSPECT_CLASS", "aligned-empty"))
                """
            )
        )
        self._executable(
            "tofu",
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                echo "tofu $*" >>"$FAKE_LOG"
                case " $* " in
                  *" init "*) [[ ${FAKE_INIT_FAILURE:-0} != 1 ]] || exit 1 ;;
                  *" state pull "*) printf '{"resources":[]}\\n' ;;
                  *" show -json "*) printf '{"resource_changes":[]}\\n' ;;
                  *" apply "*)
                    case "$FAKE_APPLY_RESULT" in
                      protected) echo "can't remove CT 9020 - protection mode enabled" >&2; exit 1 ;;
                      generic) echo "generic provider failure" >&2; exit 1 ;;
                    esac
                    ;;
                  *" plan "*)
                    for argument in "$@"; do
                      case "$argument" in -out=*) : >"${argument#-out=}" ;; esac
                    done
                    ;;
                esac
                """
            ),
        )
        self._executable(
            "aws",
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                echo "aws $*" >>"$FAKE_LOG"
                if [[ " $* " == *" s3api list-objects-v2 "* ]]; then
                  case "$FAKE_LOCK_COUNT" in
                    0) echo '{"Contents":[]}' ;;
                    1) echo '{"Contents":[{"Key":"home-lab/proxmox-lxc-qualification/tofu.tfstate.tflock"}]}' ;;
                    *) echo '{"Contents":[{"Key":"home-lab/proxmox-lxc-qualification/tofu.tfstate.tflock"},{"Key":"home-lab/proxmox-lxc-qualification/tofu.tfstate.tflock.old"}]}' ;;
                  esac
                elif [[ " $* " == *" s3api get-object "* ]]; then
                  destination=${!#}
                  printf '{"ID":"%s","Operation":"%s","Info":"%s","Who":"%s","Version":"%s","Created":"%s","Path":"%s"}\n' "$FAKE_LOCK_ID" "$FAKE_LOCK_OPERATION" "$FAKE_LOCK_INFO" "$FAKE_LOCK_WHO" "$FAKE_LOCK_VERSION" "$FAKE_LOCK_CREATED" "$FAKE_LOCK_PATH" >"$destination"
                fi
                """
            ),
        )
        self._executable(
            "git",
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                case "$*" in
                  "rev-parse HEAD"|"rev-parse origin/main") printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n' ;;
                  "branch --show-current") echo main ;;
                  "status --porcelain --untracked-files=all") ;;
                  *) exit 1 ;;
                esac
                """
            ),
        )

    def run_driver(self, *arguments: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        env = self.env | (extra_env or {})
        return subprocess.run(
            [str(self.repo / "scripts/qualify-proxmox-lxc"), *arguments],
            cwd=self.repo,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def commands(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def assert_no_dynamodb(self) -> None:
        self.assertNotIn("dynamodb", self.commands())

    def test_expected_protected_delete_rejection_completes_proof(self) -> None:
        result = self.run_driver("apply", "probe-protected-delete", extra_env={"FAKE_APPLY_RESULT": "protected"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("classify-probe-log", self.commands())
        self.assertIn("api-check --mode protected", self.commands())
        self.assert_no_dynamodb()

    def test_generic_apply_failure_fails_without_dynamodb(self) -> None:
        result = self.run_driver("apply", "probe-protected-delete", extra_env={"FAKE_APPLY_RESULT": "generic"})
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_dynamodb()

    def test_post_proof_failure_fails_without_dynamodb(self) -> None:
        result = self.run_driver("apply", "create", extra_env={"FAKE_POST_FAILURE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_dynamodb()

    def test_residual_volume_rejection_after_delete_fails_without_dynamodb(self) -> None:
        result = self.run_driver("apply", "delete", extra_env={"FAKE_RESIDUAL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("api-check --mode absent", self.commands())
        self.assert_no_dynamodb()

    def test_complete_delete_and_verify_empty_paths_apply_and_prove(self) -> None:
        for operation in ("delete", "verify-empty"):
            with self.subTest(operation=operation):
                self.log.unlink(missing_ok=True)
                Path(self.env["FAKE_COUNTER"]).unlink(missing_ok=True)
                result = self.run_driver("apply", operation)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("tofu -chdir=infrastructure/tofu/proxmox-lxc-qualification apply", self.commands())
                self.assertIn("inspect-plan", self.commands())
                self.assert_no_dynamodb()

    def test_inspect_recovery_reports_sanitized_classes_without_plan_or_apply(self) -> None:
        for classification in (
            "aligned-empty",
            "aligned-protected",
            "aligned-unprotected",
            "live-only-protected",
            "live-only-unprotected",
            "state-only",
            "protection-mismatch",
            "identity-mismatch",
        ):
            with self.subTest(classification=classification):
                self.log.unlink(missing_ok=True)
                result = self.run_driver("inspect-recovery", extra_env={"FAKE_INSPECT_CLASS": classification})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), classification)
                commands = self.commands()
                self.assertNotIn("dynamodb", commands)
                self.assertNotIn(" plan ", commands)
                self.assertNotIn(" apply ", commands)
        self.log.unlink(missing_ok=True)
        result = self.run_driver("inspect-recovery", extra_env={"FAKE_LOCK_COUNT": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            f"lock-present sha256={hashlib.sha256(FAKE_LOCK_DOCUMENT.encode()).hexdigest()}",
        )
        self.assertNotIn("helper inspect-recovery", self.commands())

        self.log.unlink(missing_ok=True)
        result = self.run_driver("inspect-recovery", extra_env={"FAKE_INIT_FAILURE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "backend-init-failed")
        self.assertEqual(result.stderr, "")



if __name__ == "__main__":
    unittest.main()
