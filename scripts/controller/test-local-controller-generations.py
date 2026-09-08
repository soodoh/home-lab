#!/usr/bin/env python3
"""Exercise the real public argument/selection boundary without credentials or hosts."""

from pathlib import Path
import json
import shutil
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PlanGenerationTests(unittest.TestCase):
    def test_generations_preserve_prior_evidence_at_same_revision(self):
        source = (ROOT / "scripts/local-controller").read_text()
        boundary = "\nload_credentials() {"
        self.assertIn(boundary, source)
        # Execute the unmodified public parser through plan selection only. No
        # credential loader, validation, TLS setup or provider command is run.
        # Boundary admission reads only the synthetic non-secret manifest.
        prefix = source.split(boundary, 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            scripts = repo / "scripts"; scripts.mkdir()
            selector = scripts / "local-controller"
            selector.write_text(prefix + '\nprintf "%s\\n" "$plan_dir"\n')
            selector.chmod(0o755)
            commit = "0" * 40
            binaries = repo / "bin"; binaries.mkdir()
            home = repo / "home"; home.mkdir(mode=0o700)
            (scripts / "controller").mkdir()
            for name in ("controller-boundaries.sh", "controller-boundary-manifest.py"):
                shutil.copyfile(ROOT / "scripts/controller" / name, scripts / "controller" / name)
            git = binaries / "git"
            git.write_text('#!/bin/sh\ncase "$1" in rev-parse) printf "%040d\\n" 0;; status) exit 0;; *) exit 98;; esac\n')
            git.chmod(0o700)
            python = binaries / "python3"
            python.write_text(f'#!/bin/sh\nexec {sys.executable} -B -E -s -S "$@"\n')
            python.chmod(0o700)
            boundary = repo / "boundaries.json"
            boundary.write_text(json.dumps({"version": 1, "account_id": "658271954302", "partition": "aws",
                "plan_policy_arn": "arn:aws:iam::658271954302:policy/fixture/plan",
                "apply_policy_arn": "arn:aws:iam::658271954302:policy/fixture/apply",
                "provenance": {"review_reference": "synthetic-only", "plan_policy_sha256": "a" * 64,
                               "apply_policy_sha256": "b" * 64}}))
            boundary.chmod(0o600)
            environment = {"HOME": str(home), "PATH": f"{binaries}:/usr/bin:/bin"}

            def select(action, *args):
                return subprocess.run([str(selector), action, "steady", *args,
                                       "--boundary-manifest", str(boundary)], cwd=repo, env=environment,
                                      capture_output=True, text=True, timeout=5, check=False)

            first = select("plan", "--generation", "first")
            self.assertEqual(first.returncode, 0, first.stderr)
            first_dir = Path(first.stdout.strip())
            self.assertEqual(first_dir, repo / ".reconcile/plans" / commit / "steady/first")
            first_dir.mkdir(parents=True, mode=0o700)
            evidence = first_dir / "failed-or-expired.json"
            evidence.write_bytes(b"retained exact prior attempt\n")
            for action in ("plan", "apply", "apply-tailnet"):
                result = select(action, "--generation", "second")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(Path(result.stdout.strip()), first_dir.parent / "second")
            self.assertEqual(evidence.read_bytes(), b"retained exact prior attempt\n")
            self.assertFalse((first_dir.parent / "second").exists())
            for arguments in ((), ("--generation", ""), ("--generation", "../first"),
                              ("--generation", "FIRST"), ("--generation", "a" * 65),
                              ("--generation", "first/second"), ("--generation", "first\n"),
                              ("--generation", "first", "--generation", "second")):
                result = select("plan", *arguments)
                self.assertEqual(result.returncode, 64, (arguments, result.stderr))
            self.assertEqual(evidence.read_bytes(), b"retained exact prior attempt\n")


if __name__ == "__main__":
    unittest.main()
