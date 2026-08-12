#!/usr/bin/env python3
"""Regression test for saved-plan verification with an empty provider cache."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
RECONCILER = REPOSITORY / "scripts/reconcile-infrastructure"
ROOTS = ("aws-foundation", "proxmox-legacy", "proxmox", "tailscale")
POLICY = '{"grants":[]}\n'


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def write_proxmox_host_plan(plan_dir: Path, manifest: dict) -> None:
    record = manifest["proxmox_host_plan"]
    source = {"actions": [], "applyEligible": True, "blockers": [], "findings": [],
              "format": "home-lab-proxmox-plan-v1", "mode": "steady", "planSha256": record["plan_sha256"],
              "privatePreconditionsRequired": False, "status": "ready"}
    destination = REPOSITORY / record["file"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(source))
    record["file_sha256"] = hashlib.sha256(destination.read_bytes()).hexdigest()


class ManifestVerificationTests(unittest.TestCase):
    def test_recovery_expectations_hash_tampering_is_rejected_before_plan_decode(self) -> None:
        reconcile_root = REPOSITORY / ".reconcile"
        reconcile_root.mkdir(exist_ok=True)
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        commit = subprocess.run(
            [real_git, "rev-parse", "HEAD"], cwd=REPOSITORY, check=True, text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        compose_hash = subprocess.run(
            [sys.executable, "scripts/compose-artifact.py", "hash"], cwd=REPOSITORY,
            check=True, text=True, stdout=subprocess.PIPE,
        ).stdout.strip()
        with tempfile.TemporaryDirectory(dir=reconcile_root) as directory:
            temporary = Path(directory)
            plan_dir = temporary / "plans"
            binaries = temporary / "bin"
            plan_dir.mkdir()
            binaries.mkdir()
            expectations = plan_dir / "recovery-expectations.json"
            environment = {
                **os.environ,
                "TF_VAR_games_disk_by_id": "/dev/disk/by-id/test-games",
                "TF_VAR_serial_usb_paths": '{"zigbee":"2-4.1","zwave":"2-4.2"}',
            }
            subprocess.run(
                ["node", "scripts/controller/build-recovery-expectations.js", "--output", str(expectations)],
                cwd=REPOSITORY, env=environment, check=True,
            )
            expectation_hash = hashlib.sha256(expectations.read_bytes()).hexdigest()
            plans = []
            for root in ("aws-foundation", "proxmox", "tailscale"):
                plan = plan_dir / f"{root}.tfplan"
                plan.write_text(f"saved recovery plan for {root}\n")
                plans.append({
                    "root": root,
                    "file": plan.name,
                    "sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
                    "changed": False,
                    "tailscale_policy_before_sha256": "" if root != "tailscale" else "0" * 64,
                    "tailscale_policy_after_sha256": "" if root != "tailscale" else "0" * 64,
                    "tailscale_policy_etag": "" if root != "tailscale" else '"test-etag"',
                })
            extra_vars = temporary / "recovery.yml"
            extra_vars_content = f'recovery_expected_backup_identity_sha256: "{"a" * 64}"\n'
            extra_vars.write_text(extra_vars_content)
            extra_vars.chmod(0o600)
            manifest = {
                "version": 5,
                "commit": commit,
                "phase": "recovery",
                "stage": "converge",
                "backend_bucket": "test-state-bucket",
                "ansible_extra_vars_file_sha256": hashlib.sha256(extra_vars.read_bytes()).hexdigest(),
                "recovery_backup_identity_sha256": "a" * 64,
                "recovery_expectations_sha256": expectation_hash,
                "compose_artifact_sha256": compose_hash,
                "proxmox_host_plan": {"actions": 0, "external_owner_only": False, "status": "ready", "file": ".reconcile/plans/" + "f" * 64 + ".json", "file_sha256": "e" * 64, "plan_sha256": "f" * 64},
                "plans": plans,
            }
            write_proxmox_host_plan(plan_dir, manifest)
            (plan_dir / "manifest.json").write_text(json.dumps(manifest))
            log = temporary / "tofu.log"
            write_executable(
                binaries / "tofu",
                "#!/usr/bin/env bash\nprintf 'unexpected tofu decode\\n' >>\"$TOFU_TEST_LOG\"\nexit 90\n",
            )
            write_executable(
                binaries / "git",
                f"""#!/usr/bin/env bash
set -euo pipefail
if [[ ${{1:-}} == rev-parse && ${{2:-}} == HEAD ]]; then
  printf '%s\\n' "$MOCK_GIT_COMMIT"
elif [[ ${{1:-}} == status ]]; then
  exit 0
else
  exec {real_git} "$@"
fi
""",
            )
            for command in ("ansible", "ansible-playbook", "curl"):
                write_executable(binaries / command, "#!/usr/bin/env bash\nexit 0\n")
            extra_vars.write_text(extra_vars_content + "# tampered\n")
            extra_vars.chmod(0o600)
            extra_vars_result = subprocess.run(
                [str(RECONCILER), "apply", "--phase", "recovery", "--plan-dir", str(plan_dir)],
                cwd=REPOSITORY,
                env={
                    **environment,
                    "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
                    "TF_BACKEND_BUCKET": "test-state-bucket",
                    "AWS_REGION": "us-east-1",
                    "TF_VAR_tailscale_enable_management": "true",
                    "TF_VAR_omada_enable_management": "false",
                    "RECONCILE_ANSIBLE_EXTRA_VARS_FILE": str(extra_vars),
                    "TOFU_TEST_LOG": str(log),
                    "MOCK_GIT_COMMIT": commit,
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(extra_vars_result.returncode, 66, extra_vars_result.stderr)
            self.assertIn("Ansible extra-vars file", extra_vars_result.stderr)
            self.assertFalse(log.exists(), "tampered extra-vars reached provider plan decoding")

            extra_vars.write_text(extra_vars_content)
            extra_vars.chmod(0o600)
            expectations.write_text(expectations.read_text() + "\n")
            result = subprocess.run(
                [str(RECONCILER), "apply", "--phase", "recovery", "--plan-dir", str(plan_dir)],
                cwd=REPOSITORY,
                env={
                    **environment,
                    "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
                    "TF_BACKEND_BUCKET": "test-state-bucket",
                    "AWS_REGION": "us-east-1",
                    "TF_VAR_tailscale_enable_management": "true",
                    "TF_VAR_omada_enable_management": "false",
                    "RECONCILE_ANSIBLE_EXTRA_VARS_FILE": str(extra_vars),
                    "TOFU_TEST_LOG": str(log),
                    "MOCK_GIT_COMMIT": commit,
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 66, result.stderr)
            self.assertIn("saved recovery expectations", result.stderr)
            self.assertFalse(log.exists(), "tampered expectations reached provider plan decoding")

    def test_tailscale_plan_is_decoded_only_after_backend_init(self) -> None:
        reconcile_root = REPOSITORY / ".reconcile"
        reconcile_root.mkdir(exist_ok=True)
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        commit = subprocess.run(
            [real_git, "rev-parse", "HEAD"],
            cwd=REPOSITORY,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        compose_hash = subprocess.run(
            [sys.executable, "scripts/compose-artifact.py", "hash"],
            cwd=REPOSITORY,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        policy_hash = hashlib.sha256(POLICY.encode()).hexdigest()
        with tempfile.TemporaryDirectory(dir=reconcile_root) as directory:
            temporary = Path(directory)
            plan_dir = temporary / "plans"
            provider_cache = temporary / "provider-cache"
            binaries = temporary / "bin"
            plan_dir.mkdir()
            provider_cache.mkdir()
            binaries.mkdir()
            self.assertEqual(list(provider_cache.iterdir()), [])

            plans = []
            for root in ROOTS:
                plan = plan_dir / f"{root}.tfplan"
                plan.write_text(f"saved plan for {root}\n")
                record = {
                    "root": root,
                    "file": plan.name,
                    "sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
                    "changed": False,
                    "tailscale_policy_before_sha256": "",
                    "tailscale_policy_after_sha256": "",
                    "tailscale_policy_etag": "",
                }
                if root == "tailscale":
                    record.update(
                        tailscale_policy_before_sha256=policy_hash,
                        tailscale_policy_after_sha256=policy_hash,
                        tailscale_policy_etag='"test-etag"',
                    )
                plans.append(record)

            manifest = {
                "version": 5,
                "commit": commit,
                "phase": "steady",
                "stage": "converge",
                "backend_bucket": "test-state-bucket",
                "ansible_extra_vars_file_sha256": "",
                "recovery_backup_identity_sha256": "",
                "recovery_expectations_sha256": "",
                "compose_artifact_sha256": compose_hash,
                "proxmox_host_plan": {"actions": 0, "external_owner_only": False, "status": "ready", "file": ".reconcile/plans/" + "f" * 64 + ".json", "file_sha256": "e" * 64, "plan_sha256": "f" * 64},
                "plans": plans,
            }
            write_proxmox_host_plan(plan_dir, manifest)
            (plan_dir / "manifest.json").write_text(json.dumps(manifest))

            log = temporary / "tofu.log"
            write_executable(
                binaries / "tofu",
                """#!/usr/bin/env bash
set -euo pipefail
root=
operation=
for argument in "$@"; do
  case "$argument" in
    -chdir=*) root=${argument#-chdir=} ;;
    init|show) operation=$argument ;;
  esac
done
root=${root##*/}
case "$operation" in
  init)
    printf 'init:%s\\n' "$root" >>"$TOFU_TEST_LOG"
    : >"$TF_PLUGIN_CACHE_DIR/$root.ready"
    ;;
  show)
    if [[ ! -f $TF_PLUGIN_CACHE_DIR/$root.ready ]]; then
      echo "provider unavailable before init for $root" >&2
      exit 72
    fi
    printf 'show:%s\\n' "$root" >>"$TOFU_TEST_LOG"
    if [[ $root == tailscale ]]; then
      cat <<'JSON'
{"resource_changes":[{"address":"terraform_data.tailscale_policy[0]","type":"terraform_data","change":{"actions":["no-op"],"before":{"input":{"policy_json":"{\\"grants\\":[]}"}},"after":{"input":{"policy_json":"{\\"grants\\":[]}"}}}}]}
JSON
    else
      printf '{"resource_changes":[]}\\n'
    fi
    ;;
  *) echo "unexpected tofu command: $*" >&2; exit 73 ;;
esac
""",
            )
            write_executable(
                binaries / "git",
                f"""#!/usr/bin/env bash
set -euo pipefail
if [[ ${{1:-}} == rev-parse && ${{2:-}} == HEAD ]]; then
  printf '%s\\n' "$MOCK_GIT_COMMIT"
elif [[ ${{1:-}} == status ]]; then
  exit 0
else
  exec {real_git} "$@"
fi
""",
            )
            write_executable(
                binaries / "aws",
                """#!/usr/bin/env bash
echo 'unexpected AWS call after DynamoDB lease removal' >&2
exit 86
""",
            )
            for command in ("ansible", "ansible-playbook", "curl"):
                write_executable(binaries / command, "#!/usr/bin/env bash\nexit 0\n")

            environment = {
                **os.environ,
                "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
                "TF_BACKEND_BUCKET": "test-state-bucket",
                "AWS_REGION": "us-east-1",
                "TF_VAR_tailscale_enable_management": "true",
                "TF_VAR_omada_enable_management": "false",
                "TF_PLUGIN_CACHE_DIR": str(provider_cache),
                "TOFU_TEST_LOG": str(log),
                "MOCK_GIT_COMMIT": commit,
            }
            command = [
                str(RECONCILER),
                "apply",
                "--phase",
                "steady",
                "--plan-dir",
                str(plan_dir),
            ]

            invalid_manifest = manifest.copy()
            invalid_manifest["recovery_expectations_sha256"] = "0" * 64
            (plan_dir / "manifest.json").write_text(json.dumps(invalid_manifest))
            rejected = subprocess.run(
                command,
                cwd=REPOSITORY,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(rejected.returncode, 66, rejected.stderr)
            self.assertIn("manifest metadata is invalid", rejected.stderr)

            (plan_dir / "manifest.json").write_text(json.dumps(manifest))
            result = subprocess.run(
                command,
                cwd=REPOSITORY,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(result.returncode, 73, result.stderr)
            self.assertIn("inspect the protected local apply log", result.stderr)
            self.assertNotIn("unexpected AWS call", result.stderr)
            events = log.read_text().splitlines()
            tailscale_init = events.index("init:tailscale")
            tailscale_shows = [
                index for index, event in enumerate(events) if event == "show:tailscale"
            ]
            self.assertGreaterEqual(len(tailscale_shows), 3)
            self.assertTrue(all(tailscale_init < index for index in tailscale_shows))
            self.assertFalse((reconcile_root / "controller-apply.lock").exists())


if __name__ == "__main__":
    unittest.main()
