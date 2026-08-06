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


class ManifestVerificationTests(unittest.TestCase):
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
        gateway_stage = next(
            line.split(":", 1)[1].strip()
            for line in (REPOSITORY / "infrastructure/contract/home-lab.yml").read_text().splitlines()
            if line.strip().startswith("gateway_policy_stage:")
        )
        self.assertIn(gateway_stage, {"active", "detached", "retired"})

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
                "version": 2,
                "commit": commit,
                "phase": "steady",
                "ct_retirement_operation": "none",
                "retirement_stage": "protected",
                "tailscale_gateway_operation": "none",
                "tailscale_gateway_policy_stage": gateway_stage,
                "network_migration": False,
                "disk_growth": False,
                "controller_bootstrap": False,
                "tailscale_controller_retirement": False,
                "backend_bucket": "test-state-bucket",
                "recovery_backup_identity_sha256": "",
                "compose_artifact_sha256": compose_hash,
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
            result = subprocess.run(
                [
                    str(RECONCILER),
                    "apply",
                    "--phase",
                    "steady",
                    "--plan-dir",
                    str(plan_dir),
                ],
                cwd=REPOSITORY,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(result.returncode, 73, result.stderr)
            self.assertIn("unexpected tofu command", result.stderr)
            self.assertNotIn("unexpected AWS call", result.stderr)
            events = log.read_text().splitlines()
            tailscale_init = events.index("init:tailscale")
            tailscale_shows = [
                index for index, event in enumerate(events) if event == "show:tailscale"
            ]
            self.assertGreaterEqual(len(tailscale_shows), 3)
            self.assertTrue(all(tailscale_init < index for index in tailscale_shows))


if __name__ == "__main__":
    unittest.main()
