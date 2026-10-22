#!/usr/bin/env python3
"""Exercise deployment ownership and lifecycles on disposable Linux only.

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
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
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
        publication = self.roles / "compose_native/tasks/publish.yml"
        tasks = yaml.safe_load(publication.read_text())
        for task in tasks:
            directory = task.get("ansible.builtin.file", {})
            if directory.get("path") == "/srv/home-lab-state/cli-proxy-api/auths":
                directory["path"] = str(self.work / "synthetic-auths")
        self.put(publication, tasks)
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

    def install_docker_adapter(self):
        """Replace external Docker calls, recording targets and controllable failures."""
        collection = self.work / "collections/ansible_collections/community/docker/plugins"
        action = '''from pathlib import Path
import json
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        variables = task_vars or {}
        arguments = self._task.args
        kind = self._task.action.rsplit('.', 1)[-1]
        work = Path(variables['fixture_work'])
        event = {'kind': kind, 'firewall_exists': (work / 'firewall').exists(), **arguments}
        with (work / 'docker-events.jsonl').open('a') as output:
            output.write(json.dumps(event) + '\\n')
        if kind == 'docker_container_info':
            return {'changed': False, 'exists': True, 'container': {
                'State': {'Running': True}, 'HostConfig': {'NetworkMode': 'host'},
                'Config': {'Env': []}, 'Mounts': [
                    {'Destination': '/etc/wolf', 'Source': '/mnt/games/wolf'},
                    {'Destination': '/run/user/wolf', 'Source': str(work)},
                ],
            }}
        failure = variables.get('fixture_docker_failure', '')
        state = arguments.get('state')
        wolf = arguments.get('services') == ['wolf']
        if wolf and state == 'stopped' and failure == 'concurrent':
            path = Path(variables['wolf_security_config_path'])
            path.write_text(path.read_text() + '# concurrent edit\\n')
        if wolf and state == 'present':
            if failure == 'startup-rewrite':
                path = Path(variables['wolf_security_config_path'])
                path.write_text(path.read_text() + '# startup rewrite\\n')
            if failure == 'restart':
                return {'failed': True, 'msg': 'synthetic restart failure'}
        if failure == 'recreate' and arguments.get('recreate') == 'always':
            return {'failed': True, 'msg': 'synthetic recreation failure'}
        return {'changed': False, 'containers': [{'Name': 'fixture'}]}
'''
        for name in ("docker_compose_v2", "docker_compose_v2_pull", "docker_container_info"):
            (collection / "action").mkdir(parents=True, exist_ok=True)
            (collection / "action" / f"{name}.py").write_text(action)
            (collection / "modules").mkdir(exist_ok=True)
            (collection / "modules" / f"{name}.py").write_text("# Fixture action executes controller-side.\n")
        self.variables["fixture_work"] = str(self.work)

    def docker_events(self):
        path = self.work / "docker-events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

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
        self.install_docker_adapter()
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

    def prepare_publication(self, *, changed=False):
        """Real publication and mount observation; only Docker/secret authority vary."""
        self.prepare_source_readers()
        for name in ("app", "stable", "removed"):
            (self.selected / name).write_text("original")
        credentials = self.work / "credentials"
        credentials.mkdir()
        (credentials / "secret").write_text("synthetic-original")
        (credentials / "secret").chmod(0o600)
        incoming = self.work / "incoming"
        shutil.copytree(self.selected, incoming)
        (incoming / "model-image").write_text("synthetic image-only change")
        if changed:
            (incoming / "app").write_text("replacement")
            (incoming / "removed").unlink()
        mounts = {
            name: [{"Type": "bind", "Source": str(path), "RW": False}]
            for name, path in {
                "app": self.selected / "app", "stable": self.selected / "stable",
                "removed": self.selected / "removed", "secret-app": credentials / "secret",
            }.items()
        }
        projection = "\n".join(json.dumps(value) + " " + name for name, value in mounts.items())
        # Run the real CLI and filesystem observer. Substitute only daemon output
        # and the credential root; never observe a host daemon or secret values.
        (self.installed / "scripts/compose-mounts.py").write_text(
            "import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('mounts', {str(ROOT / 'scripts/compose-mounts.py')!r})\n"
            "module = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\n"
            f"module.run = lambda args: 'synthetic-id' if args[1] == 'ps' else {projection!r}\n"
            f"sys.argv[sys.argv.index('--credentials-root') + 1] = {str(credentials)!r}\n"
            "module.main()\n"
        )
        self.put(self.roles / "compose_native/tasks/credentials.yml", [
            {"name": "Publish a synthetic credential through native atomic copy", "ansible.builtin.copy": {
                "dest": str(credentials / "secret"), "mode": "0600",
                "content": "synthetic-replacement" if changed else "synthetic-original",
            }},
        ])
        self.variables.update({
            "compose_native_source_changed": True,
            "compose_native_incoming_source": {"path": str(incoming)},
            "compose_native_previous_dir": str(self.work / "previous"),
            "compose_native_runtime_cli": [sys.executable, "-c", "print('app\\nsecret-app\\nstable')"],
        })
        (self.work / "accepted.tar").write_text("previous accepted source")
        (self.work / "artifact").write_text("previous artifact")

    def publication(self):
        return [self.acquire(), role("compose_native", "converge",
                                     compose_native_controller_root=str(self.selected)), self.release()]

    def test_publication_keeps_unchanged_mount_consumers_running(self):
        self.prepare_publication()
        self.success(self.run_tasks(self.publication()))
        events = self.docker_events()
        self.assertEqual([event.get("recreate") for event in events], ["auto"])
        self.assertTrue(events[0]["remove_orphans"])
        self.assertEqual((self.work / "accepted.tar").read_text(), "synthetic archive")
        self.assertFalse((self.work / "previous").exists())
        self.assertFalse(self.lock.exists())

    def test_publication_recreates_only_changed_surviving_consumers(self):
        self.prepare_publication(changed=True)
        self.success(self.run_tasks(self.publication()))
        targeted, complete = self.docker_events()
        self.assertEqual(targeted["services"], ["app", "secret-app"])
        self.assertEqual(targeted["recreate"], "always")
        self.assertFalse(targeted["dependencies"])
        self.assertFalse(targeted["remove_orphans"])
        self.assertEqual(complete["recreate"], "auto")
        self.assertEqual((self.selected / "app").read_text(), "replacement")
        self.assertEqual((self.work / "credentials/secret").read_text(), "synthetic-replacement")
        self.assertEqual((self.work / "accepted.tar").read_text(), "synthetic archive")
        self.assertFalse(self.lock.exists())

    def assert_publication_retained(self):
        self.assertEqual((self.work / "accepted.tar").read_text(), "previous accepted source")
        self.assertEqual((self.work / "artifact").read_text(), "previous artifact")
        self.assertTrue((self.work / "candidate.tar").is_file())
        self.assertEqual((self.work / "previous/app").read_text(), "original")
        self.assertTrue(self.owner.is_file())

    def test_failed_recreation_retains_owner_before_image_and_accepted_source(self):
        self.prepare_publication(changed=True)
        result = self.run_tasks(self.publication(), variables={"fixture_docker_failure": "recreate"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event.get("recreate") for event in self.docker_events()], ["always"])
        self.assert_publication_retained()

    def test_failed_final_verification_does_not_accept_published_source(self):
        self.prepare_publication(changed=True)
        self.put(self.roles / "compose_native/tasks/observe.yml", [
            {"ansible.builtin.fail": {"msg": "synthetic health refusal"}},
        ])
        result = self.run_tasks(self.publication())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("synthetic health refusal", result.stdout)
        self.assertEqual([event.get("recreate") for event in self.docker_events()], ["always", "auto"])
        self.assert_publication_retained()

    def prepare_wolf(self, *, current=False, active=False):
        shutil.copytree(ROOT / "ansible/roles/wolf_security", self.roles / "wolf_security")
        self.install_docker_adapter()
        self.wolf_config = self.work / "config.toml"
        self.wolf_original = (
            "hostname = 'synthetic'\n"
            "image = 'ghcr.io/games-on-whales/es-de:edge@sha256:" + "a" * 64 + "'\n"
            "image = 'ghcr.io/games-on-whales/steam:edge@sha256:" + ("b" if current else "c") * 64 + "'\n"
        )
        self.wolf_config.write_text(self.wolf_original)
        self.wolf_config.chmod(0o600)
        os.chown(self.wolf_config, 1000, 1000)
        policy = json.loads((ROOT / "services/data/wolf/security.json").read_text())
        policy["image_pins"] = [
            {"source": f"ghcr.io/games-on-whales/{name}:edge",
             "image": f"ghcr.io/games-on-whales/{name}:edge@sha256:" + digest * 64}
            for name, digest in (("es-de", "a"), ("steam", "b"))
        ]
        self.variables.update({
            "wolf_security_policy": policy, "wolf_security_config_path": str(self.wolf_config),
            "wolf_security_before_image_parent": str(self.work), "wolf_security_console_confirmed": True,
            "compose_native_current_dir": str(self.work), "compose_native_project_name": "synthetic",
            "compose_native_runtime_env_path": str(self.work / "unused.env"),
            "compose_native_home": str(self.work),
        })
        # Sandbox only the adopted absolute configuration path. Full-security
        # console, policy and sequencing checks remain the production tasks.
        main = self.roles / "wolf_security/tasks/main.yml"
        main.write_text(main.read_text().replace("/mnt/games/wolf/cfg/config.toml", str(self.wolf_config)))
        self.put(self.roles / "wolf_security/tasks/firewall.yml", [
            {"name": "Record the external firewall mutation", "ansible.builtin.copy": {
                "dest": str(self.work / "firewall"), "content": "synthetic", "mode": "0600"}},
        ])
        # The real Unix-socket uri tasks and idle admission read this native HTTP
        # stand-in. No internal preview/metadata registers are supplied by tests.
        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                key = handler.path.rsplit("/", 1)[-1]
                data = [{"id": "synthetic"}] if active and key == "sessions" else []
                payload = json.dumps({"success": True, key: data}).encode()
                handler.send_response(200)
                handler.send_header("Content-Length", str(len(payload)))
                handler.end_headers()
                handler.wfile.write(payload)

            def log_message(handler, *args):
                pass

        server = socketserver.UnixStreamServer(str(self.work / "wolf.sock"), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

    def wolf(self, entry="images"):
        return [self.acquire(), role("wolf_security", entry), self.release()]

    def test_wolf_changed_entry_updates_later_pin_restarts_and_is_idempotent(self):
        self.prepare_wolf()
        self.success(self.run_tasks(self.wolf()))
        self.assertEqual(self.wolf_config.read_text(), self.wolf_original.replace("c" * 64, "b" * 64))
        self.assertEqual([event.get("state", "observe") for event in self.docker_events()],
                         ["observe", "stopped", "present"])
        metadata = self.wolf_config.stat()
        self.assertEqual((metadata.st_uid, metadata.st_gid, metadata.st_mode & 0o777), (1000, 1000, 0o600))
        self.assertEqual(list(self.work.glob("home-lab-wolf-security.*")), [])
        self.assertFalse((self.work / "firewall").exists())
        before = self.docker_events()
        self.success(self.run_tasks(self.wolf()))
        self.assertEqual(self.docker_events(), before)
        self.assertFalse(self.lock.exists())

    def test_wolf_noop_avoids_even_busy_writer_observation(self):
        self.prepare_wolf(current=True, active=True)
        self.success(self.run_tasks(self.wolf()))
        self.assertEqual(self.docker_events(), [])
        self.assertEqual(self.wolf_config.read_text(), self.wolf_original)
        self.assertFalse((self.work / "firewall").exists())

    def test_wolf_changed_entry_refuses_busy_writer_before_mutation(self):
        self.prepare_wolf(active=True)
        result = self.run_tasks(self.wolf())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event["kind"] for event in self.docker_events()], ["docker_container_info"])
        self.assertEqual(self.wolf_config.read_text(), self.wolf_original)
        self.assertTrue(self.owner.is_file())
        self.assertEqual(list(self.work.glob("home-lab-wolf-security.*")), [])

    def test_wolf_check_mode_admits_without_mutating(self):
        self.prepare_wolf()
        self.success(self.run_tasks([role("wolf_security", "images")], check=True))
        self.assertEqual([event["kind"] for event in self.docker_events()], ["docker_container_info"])
        self.assertEqual(self.wolf_config.read_text(), self.wolf_original)
        self.assertEqual(list(self.work.glob("home-lab-wolf-security.*")), [])

    def test_wolf_full_security_admits_configuration_before_firewall(self):
        self.prepare_wolf()
        self.wolf_config.write_text(self.wolf_original + "image = 'unknown:latest'\n")
        result = self.run_tasks(self.wolf("main"))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "firewall").exists())
        self.assertEqual([event["kind"] for event in self.docker_events()], ["docker_container_info"])
        self.assertTrue(self.owner.is_file())

    def test_wolf_full_security_still_requires_idle_writer_with_current_pins(self):
        self.prepare_wolf(current=True, active=True)
        result = self.run_tasks(self.wolf("main"))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "firewall").exists())
        self.assertTrue(self.owner.is_file())

    def test_wolf_full_security_changes_firewall_before_image_restart(self):
        self.prepare_wolf()
        result = self.run_tasks(self.wolf("main"), variables={"fixture_docker_failure": "restart"})
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.work / "firewall").exists())
        self.assertEqual([event.get("state", "observe") for event in self.docker_events()],
                         ["observe", "stopped", "present"])
        self.assertEqual([event["firewall_exists"] for event in self.docker_events()], [False, True, True])
        self.assertTrue(self.owner.is_file())
        self.assertEqual(len(list(self.work.glob("home-lab-wolf-security.*/config.toml"))), 1)

    def test_wolf_entries_do_not_leak_mode_or_preview_between_calls(self):
        self.prepare_wolf()
        self.success(self.run_tasks([
            self.acquire(), role("wolf_security"), role("wolf_security", "images"),
            role("wolf_security"), self.release(),
        ]))
        self.assertEqual([event.get("state", "observe") for event in self.docker_events()],
                         ["observe", "stopped", "present", "observe"])
        self.assertEqual(self.wolf_config.read_text(), self.wolf_original.replace("c" * 64, "b" * 64))
        self.assertFalse(self.lock.exists())

    def test_wolf_failures_retain_before_images_without_automatic_rollback(self):
        self.prepare_wolf()
        for failure in ("concurrent", "restart", "startup-rewrite"):
            with self.subTest(failure=failure):
                self.wolf_config.write_text(self.wolf_original)
                result = self.run_tasks(self.wolf(), variables={"fixture_docker_failure": failure})
                self.assertNotEqual(result.returncode, 0)
                before_images = list(self.work.glob("home-lab-wolf-security.*/config.toml"))
                self.assertEqual(len(before_images), 1)
                expected = self.wolf_original + ("# concurrent edit\n" if failure == "concurrent" else "")
                self.assertEqual(before_images[0].read_text(), expected)
                self.assertEqual(before_images[0].stat().st_mode & 0o777, 0o600)
                self.assertTrue(self.owner.is_file())
                if failure == "concurrent":
                    self.assertEqual(self.wolf_config.read_text(), expected)
                    self.assertEqual(self.docker_events()[-1]["state"], "stopped")
                else:
                    self.assertIn("b" * 64, self.wolf_config.read_text())
                # Inspect and discard only this synthetic failure's retained state.
                shutil.rmtree(before_images[0].parent)
                self.owner.unlink()
                self.lock.rmdir()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--observe-owner":
        owner_observation()
    else:
        unittest.main()
