#!/usr/bin/env python3
"""Exercise the real public argument/selection boundary without credentials or hosts."""

from pathlib import Path
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
        prefix = source.split(boundary, 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            scripts = repo / "scripts"; scripts.mkdir()
            selector = scripts / "local-controller"
            selector.write_text(prefix + '\nprintf "%s\\n" "$plan_dir"\n')
            selector.chmod(0o755)
            (repo / ".gitignore").write_text(".reconcile/\n")
            for command in (["git", "init", "-q"], ["git", "add", "."],
                            ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                             "commit", "-qm", "fixture"]):
                subprocess.run(command, cwd=repo, capture_output=True, check=True)
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

            def select(action, *args):
                return subprocess.run([str(selector), action, "steady", *args], cwd=repo,
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
