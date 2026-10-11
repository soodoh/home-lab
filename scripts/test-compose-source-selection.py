#!/usr/bin/env python3
"""Exercise native Ansible Git/URI selection with a real repository and HTTP fixture."""
from __future__ import annotations

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlparse

import yaml

ROOT = Path(__file__).resolve().parent.parent
POLICY = json.loads((ROOT / "controller/compose-updates.json").read_text())


def git(directory: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(directory), *arguments], text=True).strip()


class SourceSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="compose-selection-")
        cls.base = Path(cls.temporary.name)
        cls.remote = cls.base / "remote"
        cls.remote.mkdir()
        git(cls.remote, "init", "--initial-branch=main")
        git(cls.remote, "config", "user.name", "Synthetic fixture")
        git(cls.remote, "config", "user.email", "fixture@example.invalid")
        (cls.remote / "docker-compose.yml").write_text("services: {}\n")
        # Candidate controller code is deliberately not runnable. Selection must not execute it.
        (cls.remote / "candidate-controller.py").write_text("raise RuntimeError('candidate code ran')\n")
        git(cls.remote, "add", ".")
        git(cls.remote, "commit", "-m", "initial synthetic source")
        cls.initial = git(cls.remote, "rev-parse", "HEAD")
        cls.playbook = cls.base / "select.yml"
        cls.playbook.write_text("""---
- name: Exercise the installed native selection interface
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Select source
      ansible.builtin.include_role:
        name: compose_schedule
        tasks_from: select
""")
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.http.fixture = cls
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.thread.join()
        cls.temporary.cleanup()

    def setUp(self):
        git(self.remote, "reset", "--hard", self.initial)
        self.fixture_repository = {
            "id": POLICY["repository"]["id"],
            "owner": {"id": POLICY["repository"]["owner_id"]},
            "full_name": POLICY["repository"]["full_name"],
            "default_branch": "main", "private": False, "archived": False,
        }
        self.fixture_overrides = {}
        self.fixture_runs = True
        self.fixture_status = 200
        self.fixture_advance = False
        self.fixture_requests = []
        type(self).current = self
        self.work = self.base / self.id().split(".")[-1]
        self.work.mkdir(exist_ok=True)

    def select(self, *, whole_job=False):
        variables = {
            "compose_schedule_api_base": f"http://127.0.0.1:{self.http.server_port}",
            "compose_schedule_git_url": str(self.remote),
            "compose_schedule_policy": POLICY,
            "compose_schedule_source_root": str(ROOT),
            "ansible_user": "root", "ansible_connection": "local",
            "ansible_become": False,
        }
        if not whole_job:
            variables["compose_schedule_workspace"] = {"path": str(self.work)}
        variable_file = self.work / "variables.json"
        variable_file.write_text(json.dumps(variables))
        environment = os.environ.copy()
        environment.update({
            "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
            "ANSIBLE_ROLES_PATH": str(ROOT / "ansible/roles"),
            "ANSIBLE_LOCAL_TEMP": str(self.work / "ansible"),
            "TMPDIR": str(self.work), "PYTHONDONTWRITEBYTECODE": "1",
        })
        inventory = "docker-host," if whole_job else "localhost,"
        playbook = ROOT / "ansible/playbooks/deploy-compose-automatic.yml" if whole_job else self.playbook
        return subprocess.run(
            ["ansible-playbook", "-i", inventory, "-c", "local", str(playbook), "-e", f"@{variable_file}"],
            env=environment, text=True, capture_output=True, timeout=60, check=False,
        )

    def test_success_selects_exact_commit_without_authentication_or_candidate_code(self):
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(git(self.work / "source", "rev-parse", "HEAD"), self.initial)
        self.assertIn(self.initial, result.stdout)
        self.assertTrue(self.fixture_requests)
        self.assertTrue(all(auth is None for _, auth in self.fixture_requests))
        self.assertNotIn("candidate code ran", result.stdout + result.stderr)

    def test_source_remains_frozen_if_main_advances_during_ci_read(self):
        self.fixture_advance = True
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotEqual(git(self.remote, "rev-parse", "HEAD"), self.initial)
        self.assertEqual(git(self.work / "source", "rev-parse", "HEAD"), self.initial)

    def test_repository_identity_or_visibility_changes_refuse_before_clone(self):
        variants = [
            {"id": 1}, {"owner": {"id": 1}}, {"full_name": "other/repository"},
            {"default_branch": "other"}, {"private": True}, {"archived": True},
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                self.fixture_repository.update(variant)
                result = self.select()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.work / "source").exists())
                self.setUp()

    def test_only_successful_completed_matching_main_push_workflow_qualifies(self):
        variants = [
            {"status": "in_progress"}, {"conclusion": "failure"}, {"conclusion": "cancelled"},
            {"conclusion": "skipped"}, {"head_sha": "b" * 40}, {"head_branch": "other"},
            {"event": "pull_request"}, {"workflow_id": 1}, {"path": ".github/workflows/other.yml"},
            {"repository": {"id": 1}}, {"head_repository": {"id": 1}},
            {"repository": {"id": POLICY["repository"]["id"], "owner": {"id": 1}}},
            {"head_repository": {"id": POLICY["repository"]["id"], "owner": {"id": 1}}},
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                self.fixture_overrides = variant
                result = self.select()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_ci_run_refuses(self):
        self.fixture_runs = False
        result = self.select()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no qualifying CI run", result.stdout)

    def test_api_unavailability_or_rate_limit_fails_closed(self):
        for status in (403, 429, 503):
            with self.subTest(status=status):
                self.fixture_status = status
                result = self.select()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.work / "source").exists())

    def test_actual_daily_job_cleans_its_checkout_after_ci_refusal(self):
        self.fixture_runs = False
        result = self.select(whole_job=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no qualifying CI run", result.stdout)
        self.assertIn("Remove only this run's controller checkout", result.stdout)
        self.assertEqual(list(self.work.glob("home-lab-compose-*")), [])
        self.assertNotIn("Acquire durable production ownership", result.stdout)


class InstallationValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="compose-install-validation-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.checkout = self.work / "checkout"
        self.role = self.checkout / "ansible/roles/compose_schedule"
        for relative in ("defaults/main.yml", "tasks/validate.yml"):
            destination = self.role / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "ansible/roles/compose_schedule" / relative, destination)
        self.playbook = self.checkout / "validate.yml"
        self.playbook.write_text("""---
- name: Exercise the controller installation admission without installing software
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Validate installation inputs
      ansible.builtin.include_role:
        name: compose_schedule
        tasks_from: validate
    - name: Report the admitted controller tool version
      ansible.builtin.debug:
        var: compose_schedule_sops_version
""")
        (self.checkout / ".gitignore").write_text(".env\n")
        git(self.checkout, "init", "--initial-branch=main")
        git(self.checkout, "config", "user.name", "Synthetic fixture")
        git(self.checkout, "config", "user.email", "fixture@example.invalid")
        git(self.checkout, "add", ".")
        git(self.checkout, "commit", "-m", "reviewed controller fixture")
        self.revision = git(self.checkout, "rev-parse", "HEAD")
        self.age = self.work / "age-key"
        self.age.write_text("SYNTHETIC\n")
        self.age.chmod(0o600)

    def validate(self, *, check=False):
        variable_file = self.work / "variables.json"
        variable_file.write_text(json.dumps({
            "compose_schedule_source_root": str(self.checkout),
            "compose_schedule_enabled": True,
            "compose_schedule_apply_confirmed": True,
            "compose_schedule_age_source": str(self.age),
            "ansible_become": False,
            "ansible_facts": {"architecture": "x86_64", "python": {"version": {"major": 3, "minor": 14}}},
        }))
        environment = os.environ.copy()
        environment.update({
            "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
            "ANSIBLE_ROLES_PATH": str(self.checkout / "ansible/roles"),
            "ANSIBLE_LOCAL_TEMP": str(self.work / "ansible"),
            "TMPDIR": str(self.work), "PYTHONDONTWRITEBYTECODE": "1",
        })
        return subprocess.run(
            ["ansible-playbook", "-i", "localhost,", "-c", "local", str(self.playbook),
             "-e", f"@{variable_file}", *(["--check"] if check else [])],
            env=environment, text=True, capture_output=True, timeout=60, check=False,
        )

    def test_clean_committed_controller_passes_validation(self):
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(git(self.checkout, "status", "--porcelain=v1"), "")

    def test_tracked_controller_changes_are_refused(self):
        with (self.role / "defaults/main.yml").open("a") as output:
            output.write("compose_schedule_sops_version: v0.0.0\n")
        result = self.validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refuse an uncommitted controller implementation", result.stdout)

    def test_untracked_role_variables_are_refused_in_apply_and_check(self):
        variables = self.role / "vars/main.yml"
        variables.parent.mkdir()
        variables.write_text("---\ncompose_schedule_sops_version: v0.0.0\n")
        for check in (False, True):
            with self.subTest(check=check):
                result = self.validate(check=check)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Refuse an uncommitted controller implementation", result.stdout)

    def test_ignored_controller_artifacts_do_not_dirty_reviewed_source(self):
        (self.checkout / ".env").write_text("SYNTHETIC=fixture\n")
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class InstallationDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="compose-install-download-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.body = b"synthetic controller tool\n"
        self.requests = []
        fixture = self

        class DownloadHandler(BaseHTTPRequestHandler):
            def log_message(self, *_arguments):
                pass

            def do_HEAD(self):
                fixture.requests.append(self.command)
                self.send_response(200)
                self.send_header("Content-Length", str(len(fixture.body)))
                self.end_headers()

            def do_GET(self):
                self.do_HEAD()
                self.wfile.write(fixture.body)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), DownloadHandler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_http)

    def close_http(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()

    def install(self, *, check=False, checksum=None):
        # Exercise the real role tasks, replacing only the release endpoint and
        # root ownership with a local fixture. No controller/host installation.
        tasks = deepcopy(yaml.safe_load((ROOT / "ansible/roles/compose_schedule/tasks/sops.yml").read_text()))
        download = next(task["ansible.builtin.get_url"] for task in tasks if "ansible.builtin.get_url" in task)
        download.update(url=f"http://127.0.0.1:{self.http.server_port}/sops",
                        owner=str(os.getuid()), group=str(os.getgid()))
        playbook = self.work / "install.yml"
        playbook.write_text(yaml.safe_dump([{
            "name": "Exercise native controller tool installation", "hosts": "localhost",
            "gather_facts": False,
            "vars": {
                "compose_schedule_bin": str(self.work / "bin"),
                "compose_schedule_sops_version": "fixture",
                "compose_schedule_sops_sha256": checksum or hashlib.sha256(self.body).hexdigest(),
            },
            "tasks": [{"name": "Prepare the controller tool directory",
                       "ansible.builtin.file": {"path": "{{ compose_schedule_bin }}",
                                                "state": "directory", "mode": "0700"}}, *tasks],
        }]))
        environment = os.environ.copy()
        environment.update({
            "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(self.work / "ansible"),
            "ANSIBLE_REMOTE_TEMP": str(self.work / "remote"),
            "TMPDIR": str(self.work), "PYTHONDONTWRITEBYTECODE": "1",
        })
        return subprocess.run(
            ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
             "-e", "ansible_become=false", *(["--check"] if check else [])],
            env=environment, text=True, capture_output=True, timeout=60, check=False,
        )

    def test_first_install_check_reports_deferred_download_without_writes(self):
        result = self.install(check=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.work / "bin").exists())
        self.assertEqual(self.requests, [])
        self.assertIn("checksum verification are deferred to apply", result.stdout)

    def test_existing_install_check_does_not_replace_tool(self):
        binary = self.work / "bin/sops"
        binary.parent.mkdir()
        binary.write_bytes(b"existing tool\n")
        result = self.install(check=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(binary.read_bytes(), b"existing tool\n")
        self.assertEqual(self.requests, [])

    def test_apply_installs_checksum_verified_tool(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.work / "bin/sops").read_bytes(), self.body)
        self.assertIn("GET", self.requests)

    def test_apply_refuses_wrong_checksum(self):
        result = self.install(checksum="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "bin/sops").exists())
        self.assertIn("GET", self.requests)


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_arguments):
        pass

    def do_GET(self):
        fixture = self.server.fixture.current
        fixture.fixture_requests.append((self.path, self.headers.get("Authorization")))
        parsed = urlparse(self.path)
        if "/actions/workflows/" in parsed.path:
            selected = parse_qs(parsed.query)["head_sha"][0]
            if fixture.fixture_advance:
                (fixture.remote / "later.txt").write_text("later commit\n")
                git(fixture.remote, "add", ".")
                git(fixture.remote, "commit", "-m", "advance main during CI read")
                fixture.fixture_advance = False
            run = {
                "head_sha": selected, "head_branch": "main", "event": "push",
                "workflow_id": POLICY["ci"]["workflow_id"], "path": ".github/workflows/ci.yml",
                "repository": {"id": POLICY["repository"]["id"], "owner": {"id": POLICY["repository"]["owner_id"]}},
                "head_repository": {"id": POLICY["repository"]["id"], "owner": {"id": POLICY["repository"]["owner_id"]}},
                "status": "completed", "conclusion": "success",
            }
            run.update(deepcopy(fixture.fixture_overrides))
            data = {"workflow_runs": [run] if fixture.fixture_runs else []}
        else:
            data = fixture.fixture_repository
        encoded = json.dumps(data).encode()
        self.send_response(fixture.fixture_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


if __name__ == "__main__":
    unittest.main()
