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
ROOTS = ("aws-foundation", "proxmox", "tailscale")
POLICY = '{"grants":[]}\n'


def offen_retirement_operation() -> str:
    script = """
import fs from 'node:fs';
import { load } from 'js-yaml';
const state = load(fs.readFileSync('infrastructure/contract/home-lab.yml', 'utf8')).backups.legacy_offen.retirement.state;
console.log(state === 'retirement-planned' ? 'grant' : state === 'retirement-finalizing' ? 'finalize' : '');
"""
    return subprocess.check_output(["node", "--input-type=module", "-e", script], cwd=REPOSITORY, text=True).strip()


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def write_arch_authority_node(path: Path) -> None:
    real_node = shutil.which("node")
    if real_node is None:
        raise RuntimeError("node executable is unavailable")
    write_executable(
        path,
        f"""#!/usr/bin/env bash
set -euo pipefail
if [[ ${{1:-}} == scripts/controller/check-vm-100-authority.js ]]; then
  printf 'vm_100_mutation_authority=arch\\n'
  exit 0
fi
if [[ ${{1:-}} == scripts/controller/proxmox-check-evidence.js ]]; then
  if [[ ${{2:-}} == recheck && ${{NEUTRAL_TEST_RECHECK_FAIL:-}} == true ]]; then exit 66; fi
  printf '{{"verified":true}}\n'
  exit 0
fi
exec {real_node} "$@"
""",
    )




class ManifestVerificationTests(unittest.TestCase):
    def test_retired_recovery_phase_is_rejected(self) -> None:
        result = subprocess.run(
            [str(RECONCILER), "verify", "--phase", "recovery"],
            cwd=REPOSITORY,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 64)
        self.assertIn("--phase steady", result.stderr)

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

            boundary_document = {
                "version": 1, "account_id": "658271954302", "partition": "aws",
                "plan_policy_arn": "arn:aws:iam::658271954302:policy/fixture/plan",
                "apply_policy_arn": "arn:aws:iam::658271954302:policy/fixture/apply",
                "provenance": {"review_reference": "synthetic-only", "plan_policy_sha256": "a" * 64,
                               "apply_policy_sha256": "b" * 64},
            }
            boundary_file = temporary / "controller-boundaries.json"
            boundary_file.write_text(json.dumps(boundary_document))
            boundary_file.chmod(0o600)
            manifest = {
                "controller_boundary_manifest": {"path": str(boundary_file.resolve()),
                    "sha256": hashlib.sha256(boundary_file.read_bytes()).hexdigest(), "document": boundary_document},
                "version": 6,
                "commit": commit,
                "phase": "steady",
                "stage": "converge",
                "backend_bucket": "test-state-bucket",
                "ansible_extra_vars_file_sha256": "",
                "recovery_backup_identity_sha256": "",
                "recovery_expectations_sha256": "",
                "offen_retirement_operation": offen_retirement_operation(),
                "compose_artifact_sha256": compose_hash,
                "proxmox_host_check": {"file": ".reconcile/plans/" + "f" * 64 + ".check.json", "sha256": "f" * 64},
                "plans": plans,
            }
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
            write_arch_authority_node(binaries / "node")
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
                # Ordinary validation's admitted pair is not this fixture's pair.
                "TF_VAR_controller_plan_permissions_boundary_arn": boundary_document["plan_policy_arn"],
                "TF_VAR_controller_apply_permissions_boundary_arn": boundary_document["apply_policy_arn"],
                "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
                "TF_BACKEND_BUCKET": "test-state-bucket",
                "AWS_REGION": "us-east-1",
                "TF_VAR_tailscale_enable_management": "true",
                "TF_VAR_omada_enable_management": "false",
                "TF_VAR_authentik_enable_management": "false",
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
                "--boundary-manifest", str(boundary_file),
            ]

            invalid_manifest = manifest.copy()
            invalid_manifest["recovery_expectations_sha256"] = "0" * 64
            (plan_dir / "manifest.json").write_text(json.dumps(invalid_manifest))
            environment["RECONCILE_REVIEWED_MANIFEST_SHA256"] = hashlib.sha256((plan_dir / "manifest.json").read_bytes()).hexdigest()
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
            environment["RECONCILE_REVIEWED_MANIFEST_SHA256"] = hashlib.sha256((plan_dir / "manifest.json").read_bytes()).hexdigest()
            blocked = subprocess.run(command, cwd=REPOSITORY, env={**environment, "NEUTRAL_TEST_RECHECK_FAIL": "true"}, text=True, capture_output=True)
            self.assertEqual(blocked.returncode, 66, blocked.stderr)
            self.assertNotIn("Applying exact saved", blocked.stdout)
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
            self.assertTrue((reconcile_root / "controller-apply.lock").is_file())


if __name__ == "__main__":
    unittest.main()
