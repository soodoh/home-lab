#!/usr/bin/env python3
"""Exercise native ownership and Compose source wiring on disposable Linux only.

Real Ansible roles and real root-owned locks run against private paths. External
host/application operations are replaced at their existing role/module seams;
owner validation itself is not mocked. Never run on a managed host.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parent.parent
DISPOSABLE = (platform.system() == "Linux" and os.geteuid() == 0
              and os.environ.get("HOME_LAB_LOCK_TEST_DISPOSABLE") == "true")
STARTED = "2000-01-01T00:00:00Z"


def role(name, entry="main", *, static=False, **variables):
    return {
        "name": f"Exercise {name} {entry}",
        f"ansible.builtin.{'import' if static else 'include'}_role": {
            "name": name, "tasks_from": entry,
        },
        "vars": variables,
    }


def assertion(*conditions):
    return {"name": "Verify observable behavior", "ansible.builtin.assert": {"that": list(conditions)}}


def owner_observation():
    """Fixture adapter: real observer checks under the real backup guard."""
    if not DISPOSABLE:
        raise SystemExit("owner fixture requires explicitly disposable root Linux")
    import fcntl
    spec = importlib.util.spec_from_file_location("observer", ROOT / "scripts/observe-restic-backups.py")
    observer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(observer)
    work, digest, admission, scheduled = sys.argv[2:]
    work = Path(work)
    observer.OWNERS = (work / "production.lock", work / "other.lock")
    with (work / "backup.guard").open("a+") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        observer.validate_owners(work / "journal", digest)
    (work / "admission.json").write_text(json.dumps({
        "digest": digest, "admission": admission, "scheduled": scheduled == "True",
    }))


@unittest.skipUnless(DISPOSABLE, "requires explicitly disposable root Linux execution")
class DeploymentInterfaces(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="deployment-interfaces-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.installed = self.work / "installed"
        self.roles = self.installed / "ansible/roles"
        self.playbook = self.installed / "ansible/playbooks/fixture.yml"
        self.lock = self.work / "production.lock"
        self.owner = self.lock / "owner"
        for name in ("apply_lock", "compose_native"):
            shutil.copytree(ROOT / "ansible/roles" / name, self.roles / name)
        # Observe/credential/runtime tasks are independent external operations.
        # The actual apply, admission and convergence task sequences stay intact.
        for name in ("observe", "credentials", "runtime-paths"):
            self.put(self.roles / f"compose_native/tasks/{name}.yml", [])
        # Redirect the one inline application directory too; the task sequence
        # and source routing remain real, but nothing writes into host /srv.
        convergence = self.roles / "compose_native/tasks/converge.yml"
        tasks = yaml.safe_load(convergence.read_text())
        for task in tasks:
            directory = task.get("ansible.builtin.file", {})
            if directory.get("path") == "/srv/home-lab-state/cli-proxy-api/auths":
                directory["path"] = str(self.work / "synthetic-auths")
        self.put(convergence, tasks)
        self.put(self.roles / "compose_native/tasks/deploy.yml", [
            {"name": "Simulate a refused application mutation", "ansible.builtin.fail": {
                "msg": "synthetic mutation refusal"}, "when": "fixture_fail_mutation | default(false)"},
            {"name": "Record admitted mutation", "ansible.builtin.copy": {
                "dest": str(self.work / "mutated"), "content": "synthetic", "mode": "0600"}},
        ])
        self.put(self.roles / "restic_backup/tasks/observe.yml", [
            {"name": "Observe the real acquired owner", "ansible.builtin.command": {"argv": [
                sys.executable, str(Path(__file__).resolve()), "--observe-owner", str(self.work),
                "{{ restic_backup_observation_apply_owner_sha256 }}",
                "{{ restic_backup_admission }}",
                "{{ restic_backup_observation_scheduled_deployment }}",
            ]}, "changed_when": False},
            {"name": "Simulate backup-policy refusal", "ansible.builtin.fail": {
                "msg": "synthetic backup refusal"}, "when": "fixture_refuse_backup | default(false)"},
        ])
        self.variables = {
            "ansible_connection": "local", "ansible_become": False,
            "ansible_python_interpreter": sys.executable, "ansible_user": "ansible-deploy",
            "ansible_facts": {"date_time": {"iso8601": STARTED}},
            "apply_lock_path": str(self.lock), "apply_lock_backup_guard_path": str(self.work / "backup.guard"),
            "compose_native_apply_lock_path": str(self.lock), "compose_native_apply_confirmed": True,
        }

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(value, sort_keys=False, explicit_start=True))

    def run_tasks(self, tasks, *, check=False, variables=None, playbook=None):
        if playbook is None:
            self.put(self.playbook, [{"name": "Exercise deployment interfaces", "hosts": "docker-host",
                                      "gather_facts": False, "vars": self.variables | (variables or {}),
                                      "tasks": tasks}])
            playbook = self.playbook
        environment = os.environ.copy()
        environment.update({
            "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
            "ANSIBLE_ROLES_PATH": str(self.roles),
            "ANSIBLE_COLLECTIONS_PATH": str(self.work / "collections"),
            "ANSIBLE_LOCAL_TEMP": str(self.work / "ansible-tmp"),
            "ANSIBLE_REMOTE_TEMP": str(self.work / "remote-tmp"),
            "TMPDIR": str(self.work), "PYTHONDONTWRITEBYTECODE": "1",
        })
        return subprocess.run(
            ["ansible-playbook", "-i", "docker-host,", "-c", "local", str(playbook),
             *(["--check"] if check else [])],
            env=environment, capture_output=True, text=True, timeout=90, check=False,
        )

    def success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def acquire(self, *, static=False, operation="fixture"):
        return role("apply_lock", static=static, apply_lock_action="acquire", apply_lock_operation=operation)

    def release(self, operation="fixture"):
        return role("apply_lock", apply_lock_action="release", apply_lock_operation=operation)

    def observe(self, *, change_class="data", automated=False):
        return role("compose_native", "admission", compose_native_change_class=change_class,
                    compose_native_automated=automated)

    def test_acquisition_output_matches_owner_bytes_and_release_is_unchanged(self):
        for static, controller in ((False, "root"), (True, "ansible-deploy")):
            with self.subTest(static=static, controller=controller):
                self.success(self.run_tasks([
                    self.acquire(static=static), self.observe(),
                    assertion("apply_lock_owner_sha256 is match('^[0-9a-f]{64}$')"),
                ], variables={"ansible_user": controller}))
                expected = f"controller={controller}\noperation=fixture\nstarted={STARTED}\n".encode()
                self.assertEqual(self.owner.read_bytes(), expected)
                self.assertEqual(self.owner.stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.lock.stat().st_mode & 0o777, 0o700)
                observed = json.loads((self.work / "admission.json").read_text())
                self.assertEqual(observed["digest"], hashlib.sha256(expected).hexdigest())
                # Legacy release still accepts the existing path/controller/operation inputs.
                self.success(self.run_tasks([self.release(), assertion("apply_lock_owner_sha256 == ''")],
                                            variables={"ansible_user": controller}))
                self.assertFalse(self.lock.exists())

    def test_failed_reacquisition_and_invalid_action_clear_stale_output(self):
        self.success(self.run_tasks([self.acquire()]))
        before = self.owner.read_bytes()
        for action in ("acquire", "invalid"):
            with self.subTest(action=action):
                self.success(self.run_tasks([
                    {"ansible.builtin.set_fact": {"apply_lock_owner_sha256": "a" * 64}},
                    {"block": [role("apply_lock", apply_lock_action=action),
                               {"ansible.builtin.fail": {"msg": "unexpected acquisition success"}}],
                     "rescue": [assertion("apply_lock_owner_sha256 == ''")]},
                ]))
                self.assertEqual(self.owner.read_bytes(), before)

    def test_check_mode_invalidates_output_without_creating_or_adopting(self):
        for action in ("acquire", "adopt", "release"):
            with self.subTest(action=action):
                self.success(self.run_tasks([
                    {"ansible.builtin.set_fact": {"apply_lock_owner_sha256": "a" * 64}},
                    role("apply_lock", apply_lock_action=action),
                    assertion("apply_lock_owner_sha256 == ''"), self.observe(),
                ], check=True))
                self.assertFalse(self.lock.exists())
                self.assertFalse((self.work / "admission.json").exists())

    def test_adoption_requires_exact_reviewed_identity(self):
        self.success(self.run_tasks([self.acquire()]))
        before = self.owner.read_bytes()
        digest = hashlib.sha256(before).hexdigest()
        for expected in ("", "0" * 64, digest):
            with self.subTest(expected=expected):
                adoption = role("apply_lock", apply_lock_action="adopt", apply_lock_operation="fixture",
                                apply_lock_expected_owner_sha256=expected)
                if expected == digest:
                    tasks = [adoption, assertion(f"apply_lock_owner_sha256 == '{digest}'"), self.observe()]
                else:
                    tasks = [{"ansible.builtin.set_fact": {"apply_lock_owner_sha256": digest}},
                             {"block": [adoption, {"ansible.builtin.fail": {"msg": "unexpected adoption"}}],
                              "rescue": [assertion("apply_lock_owner_sha256 == ''")]}]
                self.success(self.run_tasks(tasks))
                self.assertEqual(self.owner.read_bytes(), before)

    def test_missing_or_replaced_owner_refuses_admission(self):
        result = self.run_tasks([self.observe()])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "admission.json").exists())
        result = self.run_tasks([
            self.acquire(),
            {"ansible.builtin.copy": {"dest": str(self.owner), "content": "foreign owner", "mode": "0600"}},
            self.observe(), self.release(),
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reviewed_source_drift", result.stdout)
        self.assertEqual(self.owner.read_text(), "foreign owner")

    def test_shared_apply_releases_only_after_success_for_both_controllers(self):
        for controller, automated in (("ansible-deploy", False), ("root", True)):
            with self.subTest(controller=controller):
                self.success(self.run_tasks([
                    role("compose_native", "apply", compose_native_automated=automated,
                         compose_native_change_class="routine" if automated else "data"),
                    assertion("apply_lock_owner_sha256 == ''"),
                ], variables={"ansible_user": controller}))
                self.assertFalse(self.lock.exists())
                self.assertTrue((self.work / "mutated").exists())
                (self.work / "mutated").unlink()

    def test_shared_apply_retains_owner_on_backup_or_mutation_failure(self):
        for failure in ("fixture_refuse_backup", "fixture_fail_mutation"):
            with self.subTest(failure=failure):
                result = self.run_tasks([role("compose_native", "apply")], variables={failure: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.owner.is_file())
                self.assertFalse((self.work / "mutated").exists())
                self.owner.unlink()
                self.lock.rmdir()

    def test_shared_admission_accepts_each_existing_operation_and_policy(self):
        operations = ("compose-native-deploy", "native-site-convergence", "shelfmark-connections",
                      "host-locales", "download-client-credentials", "compose-schedule-convergence",
                      "grimmory-authentication", "wolf-security")
        tasks = []
        for operation in operations:
            tasks += [self.acquire(static=True, operation=operation), self.observe(), self.release(operation)]
        tasks += [self.acquire(), self.observe(change_class="routine", automated=True), self.release()]
        self.success(self.run_tasks(tasks, variables={"ansible_user": "root"}))
        observed = json.loads((self.work / "admission.json").read_text())
        self.assertEqual(observed["admission"], "routine")
        self.assertTrue(observed["scheduled"])
        self.assertFalse(self.lock.exists())

    def test_actual_wolf_playbook_uses_shared_identity_and_strict_policy(self):
        playbook = self.playbook.parent / "converge-wolf-security.yml"
        plays = yaml.safe_load((ROOT / "ansible/playbooks/converge-wolf-security.yml").read_text())
        # Only inventory inputs and external observers/mutation are substituted.
        for play in plays:
            if "hosts" in play:
                play["gather_facts"] = False
                play["vars"] = self.variables | {
                    "wolf_security_apply_confirmed": True, "wolf_security_console_confirmed": True,
                }
        self.put(playbook, plays)
        for name in ("observe-hosts", "observe-backups"):
            self.put(playbook.parent / f"{name}.yml", [{
                "name": "Substitute external observation", "hosts": "docker-host",
                "gather_facts": False, "tasks": [],
            }])
        self.put(self.roles / "wolf_security/tasks/main.yml", [assertion("apply_lock_owner_sha256 | length == 64")])
        self.success(self.run_tasks([], playbook=playbook))
        self.assertEqual(json.loads((self.work / "admission.json").read_text())["admission"], "strict")
        self.assertFalse(self.lock.exists())

    def prepare_source_readers(self):
        """Keep real defaults; substitute application I/O, not source routing."""
        self.selected = self.work / "selected"
        for tree, label in ((self.installed, "installed"), (self.selected, "selected")):
            (tree / "secrets").mkdir(parents=True)
            for name in ("production", "download-clients"):
                (tree / f"secrets/{name}.sops.yaml").write_text(label)
            (tree / "services/data/wolf").mkdir(parents=True)
            (tree / "services/data/wolf/security.json").write_text(json.dumps({"source": label}))
            (tree / "scripts").mkdir()
            (tree / "scripts/check-qbittorrent-password.py").write_text(f"print('{label}')\n")
        (self.installed / "scripts/compose-mounts.py").write_text("print('{}')\n")
        (self.selected / "scripts/compose-mounts.py").write_text("raise RuntimeError('candidate code executed')\n")
        self.put(self.selected / "ansible/roles/shelfmark/tasks/main.yml", [
            {"ansible.builtin.fail": {"msg": "candidate role executed"}},
        ])
        for name in ("shelfmark", "wolf_security"):
            destination = self.roles / name / "defaults/main.yml"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "ansible/roles" / name / "defaults/main.yml", destination)
        self.put(self.roles / "shelfmark/tasks/main.yml", [
            {"name": "Read through the installed helper", "ansible.builtin.command": {"argv": [
                sys.executable, "{{ shelfmark_implementation_root }}/scripts/check-qbittorrent-password.py",
            ]}, "register": "fixture_helper", "changed_when": False},
            {"name": "Expose only synthetic reader outcomes", "ansible.builtin.copy": {
                "dest": str(self.work / "shelfmark.json"), "mode": "0600", "content":
                "{{ {'source': lookup('ansible.builtin.file', shelfmark_production_sops_file), "
                "'clients': lookup('ansible.builtin.file', shelfmark_download_clients_sops_file), "
                "'implementation': fixture_helper.stdout} | to_json }}",
            }},
        ])
        self.put(self.roles / "wolf_security/tasks/images.yml", [
            {"ansible.builtin.copy": {"dest": str(self.work / "wolf.json"), "mode": "0600",
                                      "content": "{{ wolf_security_policy | to_json }}"}},
        ])
        self.put(self.roles / "grimmory/tasks/directories.yml", [])
        # Docker is an external dependency here; exercise the real task sequence
        # without launching applications or reading a production daemon.
        collection = self.work / "collections/ansible_collections/community/docker/plugins"
        for name in ("docker_compose_v2", "docker_compose_v2_pull"):
            (collection / "action").mkdir(parents=True, exist_ok=True)
            (collection / "action" / f"{name}.py").write_text(
                "from ansible.plugins.action import ActionBase\n"
                "class ActionModule(ActionBase):\n"
                "    def run(self, tmp=None, task_vars=None):\n"
                "        return {'changed': False, 'containers': [{'Name': 'fixture'}]}\n"
            )
            (collection / "modules").mkdir(exist_ok=True)
            (collection / "modules" / f"{name}.py").write_text("# Fixture action executes controller-side.\n")
        (self.work / "candidate.tar").write_text("synthetic archive")
        self.variables.update({
            "compose_native_source_changed": False, "compose_native_automated": True,
            "compose_native_expected_service_count": 1,
            "compose_native_current_dir": str(self.selected),
            "compose_native_runtime_cli": [sys.executable, "-c", "print('fixture')"],
            "compose_native_source_archives": {"results": [{}, {"stat": {"checksum": "a" * 64}}]},
            "compose_native_artifact_identity_path": str(self.work / "artifact"),
            "compose_native_source_candidate_path": str(self.work / "candidate.tar"),
            "compose_native_source_archive_path": str(self.work / "accepted.tar"),
        })

    def test_compose_routes_selected_data_but_not_selected_code(self):
        self.prepare_source_readers()
        self.success(self.run_tasks([role("compose_native", "converge",
                                          compose_native_controller_root=str(self.selected))]))
        self.assertEqual(json.loads((self.work / "shelfmark.json").read_text()), {
            "source": "selected", "clients": "selected", "implementation": "installed",
        })
        self.assertEqual(json.loads((self.work / "wolf.json").read_text()), {"source": "selected"})
        self.assertTrue((self.work / "accepted.tar").exists())

    def test_scheduled_composition_routes_source_and_cleans_scratch_on_failure(self):
        self.prepare_source_readers()
        self.put(self.roles / "compose_schedule/tasks/select.yml", [
            {"ansible.builtin.copy": {"src": str(self.selected) + "/",
                                      "dest": "{{ compose_schedule_workspace.path }}/source/", "mode": "preserve"}},
        ])
        self.put(self.roles / "compose_native/tasks/deploy.yml", [
            {"ansible.builtin.fail": {"msg": "synthetic mutation refusal"},
             "when": "fixture_fail_mutation | default(false)"},
            {"ansible.builtin.include_tasks": "converge.yml"},
        ])
        playbook = self.playbook.parent / "deploy-compose-automatic.yml"
        for fail in (False, True):
            with self.subTest(fail=fail):
                plays = yaml.safe_load((ROOT / "ansible/playbooks/deploy-compose-automatic.yml").read_text())
                plays[0]["gather_facts"] = False
                plays[0].setdefault("vars", {}).update(self.variables | {
                    "ansible_user": "root", "fixture_fail_mutation": fail,
                })
                self.put(playbook, plays)
                result = self.run_tasks([], playbook=playbook)
                if fail:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(self.owner.is_file())
                else:
                    self.success(result)
                    self.assertFalse(self.lock.exists())
                    self.assertEqual(json.loads((self.work / "shelfmark.json").read_text()), {
                        "source": "selected", "clients": "selected", "implementation": "installed",
                    })
                    self.assertEqual(json.loads((self.work / "wolf.json").read_text()), {"source": "selected"})
                self.assertEqual(list(self.work.glob("home-lab-compose-*")), [])

    def test_standalone_reader_retains_independent_source_selection(self):
        self.prepare_source_readers()
        self.success(self.run_tasks([role("shelfmark", shelfmark_controller_root=str(self.selected))]))
        self.assertEqual(json.loads((self.work / "shelfmark.json").read_text()), {
            "source": "selected", "clients": "selected", "implementation": "installed",
        })


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--observe-owner":
        owner_observation()
    else:
        unittest.main()
