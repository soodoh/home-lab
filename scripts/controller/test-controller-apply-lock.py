#!/usr/bin/env python3
"""Subprocess tests for the controller lock supervisor and re-exec boundary."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/controller/controller-apply-lock.py"
MODULE_DIR = ROOT / "nix/proxmox"
COMMIT = "a" * 40


class ControllerApplyLockTests(unittest.TestCase):
    def run_owner(self, repo: Path, source: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "run",
                "--repo-root",
                str(repo),
                "--commit",
                COMMIT,
                "--phase",
                "steady",
                "--",
                sys.executable,
                "-c",
                source,
                str(HELPER),
                str(repo),
                COMMIT,
                str(MODULE_DIR),
            ],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @staticmethod
    def verify_command() -> str:
        return """import os,subprocess,sys
helper,repo,commit,_=sys.argv[1:]
fd=int(os.environ['RECONCILE_CONTROLLER_LOCK_FD'])
command=[sys.executable,helper,'verify','--repo-root',repo,'--commit',commit,'--phase','steady']
result=subprocess.run(command,env=os.environ,pass_fds=(fd,))
raise SystemExit(result.returncode)
"""

    def test_runner_reexec_and_direct_child_verification_succeed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            result = self.run_owner(Path(name), self.verify_command())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verification_rejects_wrong_parent_pid(self) -> None:
        source = """import os,subprocess,sys
helper,repo,commit,_=sys.argv[1:]
fd=int(os.environ['RECONCILE_CONTROLLER_LOCK_FD'])
intermediate='''import os,subprocess,sys
helper,repo,commit=sys.argv[1:]
fd=int(os.environ["RECONCILE_CONTROLLER_LOCK_FD"])
command=[sys.executable,helper,"verify","--repo-root",repo,"--commit",commit,"--phase","steady"]
result=subprocess.run(command,env=os.environ,pass_fds=(fd,))
raise SystemExit(result.returncode)
'''
result=subprocess.run([sys.executable,'-c',intermediate,helper,repo,commit],env=os.environ,pass_fds=(fd,))
raise SystemExit(result.returncode)
"""
        with tempfile.TemporaryDirectory() as name:
            result = self.run_owner(Path(name), source)
        self.assertEqual(result.returncode, 66, result.stderr)
        self.assertIn("inheritance validation failed", result.stderr)

    def test_verification_rejects_incomplete_or_forged_inheritance(self) -> None:
        incomplete = """import os,subprocess,sys
helper,repo,commit,_=sys.argv[1:]
environment=dict(os.environ); environment.pop('RECONCILE_CONTROLLER_LOCK_FD')
command=[sys.executable,helper,'verify','--repo-root',repo,'--commit',commit,'--phase','steady']
result=subprocess.run(command,env=environment)
raise SystemExit(result.returncode)
"""
        forged = """import os,subprocess,sys
helper,repo,commit,_=sys.argv[1:]
fd=int(os.environ['RECONCILE_CONTROLLER_LOCK_FD'])
environment=dict(os.environ); environment['RECONCILE_CONTROLLER_LOCK_TOKEN']='f'*64
command=[sys.executable,helper,'verify','--repo-root',repo,'--commit',commit,'--phase','steady']
result=subprocess.run(command,env=environment,pass_fds=(fd,))
raise SystemExit(result.returncode)
"""
        for label, source in (("incomplete", incomplete), ("forged", forged)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as name:
                result = self.run_owner(Path(name), source)
            self.assertEqual(result.returncode, 66, result.stderr)
            self.assertIn("inheritance validation failed", result.stderr)

    def test_closed_child_fd_uses_token_and_live_parent_contention(self) -> None:
        source = """import os,subprocess,sys
_,repo,commit,module_dir=sys.argv[1:]
child='''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[3])
import controller_lock
handle=controller_lock.acquire_or_borrow(Path(sys.argv[1]),{"gitCommit":sys.argv[2],"operation":"closed-fd-child"})
assert handle.owned is False
controller_lock.release(handle)
'''
result=subprocess.run([sys.executable,'-c',child,repo,commit,module_dir],env=os.environ,close_fds=True)
raise SystemExit(result.returncode)
"""
        with tempfile.TemporaryDirectory() as name:
            result = self.run_owner(Path(name), source)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runner_rejects_caller_supplied_inheritance(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            result = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "run",
                    "--repo-root",
                    name,
                    "--commit",
                    COMMIT,
                    "--phase",
                    "steady",
                    "--",
                    "/usr/bin/true",
                ],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "RECONCILE_CONTROLLER_LOCK_TOKEN": "f" * 64,
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 66, result.stderr)


if __name__ == "__main__":
    unittest.main()
