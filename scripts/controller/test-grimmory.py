#!/usr/bin/env python3
"""Exercise Grimmory's native Ansible/API contract using synthetic state only."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible/roles/grimmory/tasks"
ISSUER = "https://auth.diloreto.com/application/o/grimmory/"
SECRET = "synthetic-oidc-secret"
PASSWORD = "synthetic-admin-password"
TOKEN = "synthetic-access-token"
FIELDS = {
    "OIDC_PROVIDER_DETAILS": "oidcProviderDetails",
    "OIDC_PROVIDER_CLIENT_SECRET": "oidcProviderClientSecret",
    "OIDC_AUTO_PROVISION_DETAILS": "oidcAutoProvisionDetails",
    "OIDC_GROUP_SYNC_MODE": "oidcGroupSyncMode",
    "OIDC_ENABLED": "oidcEnabled",
    "OIDC_FORCE_ONLY_MODE": "oidcForceOnlyMode",
}


@contextmanager
def api_server(mode="normal", initialized=True):
    state = {
        "initialized": initialized,
        "settings": {"unrelatedSetting": {"preserve": True}, "oidcEnabled": False, "oidcForceOnlyMode": False},
        "writes": [], "setups": 0, "reads": 0,
        "library": {"id": 73, "name": "Audiobooks", "paths": [{"id": 9, "path": "/audiobooks"}],
                    "organizationMode": "BOOK_PER_FOLDER", "watch": False,
                    "allowedFormats": ["AUDIOBOOK"], "unrelatedPreference": "preserve"},
        "library_writes": [],
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body):
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def body(self):
            return json.loads(self.rfile.read(int(self.headers["Content-Length"])))

        def authorized(self):
            if self.headers.get("Authorization") != "Bearer " + TOKEN:
                self.reply(401, {})
                return False
            return True

        def do_GET(self):
            if self.path == "/discovery":
                self.reply(200, {"issuer": ISSUER, "authorization_endpoint": "https://auth.diloreto.com/application/o/authorize/",
                                 "token_endpoint": "https://auth.diloreto.com/application/o/token/"})
            elif self.path == "/api/v1/setup/status":
                self.reply(200, {"data": state["initialized"]})
            elif self.path == "/api/v1/libraries" and self.authorized():
                libraries = [state['library']]
                if mode == 'library-missing':
                    libraries = []
                elif mode == 'library-ambiguous':
                    libraries.append(state['library'] | {'id': 99})
                elif mode == 'library-multiroot':
                    state['library']['paths'].append({'id': 10, 'path': '/books/shared'})
                elif mode == 'library-file-mode':
                    state['library']['organizationMode'] = 'BOOK_PER_FILE'
                self.reply(200, libraries)
            elif self.path == "/api/v1/libraries/73" and self.authorized():
                if mode == 'library-concurrent' and not state['library_writes']:
                    state['library']['fileNamingPattern'] = 'concurrent-edit'
                self.reply(200, state['library'])
            elif self.path == "/api/v1/settings" and self.authorized():
                state["reads"] += 1
                if mode == "concurrent" and state["reads"] == 2:
                    state["settings"]["unrelatedSetting"] = {"preserve": "concurrent edit"}
                self.reply(200, state["settings"])
            else:
                self.reply(404, {})

        def do_POST(self):
            body = self.body()
            if self.path == "/api/v1/setup" and not state["initialized"]:
                if body.get("password") != PASSWORD or body.get("username") != "grimmory-admin":
                    self.reply(400, {})
                    return
                state["initialized"] = True
                state["setups"] += 1
                self.reply(200, {"data": True})
            elif self.path == "/api/v1/auth/login":
                if mode == "login-denied" or body != {"username": "grimmory-admin", "password": PASSWORD}:
                    self.reply(401, {})
                    return
                self.reply(200, {"accessToken": TOKEN})
            else:
                self.reply(404, {})

        def do_PATCH(self):
            if self.path != '/api/v1/libraries/73/file-naming-pattern' or not self.authorized():
                self.reply(404, {})
                return
            body = self.body()
            if set(body) != {'fileNamingPattern'}:
                self.reply(400, {})
                return
            if mode != 'library-not-persisted':
                state['library']['fileNamingPattern'] = body['fileNamingPattern']
            state['library_writes'].append(copy.deepcopy(body))
            self.reply(200, state['library'])

        def do_PUT(self):
            if self.path != "/api/v1/settings" or not self.authorized():
                return
            body = self.body()
            for entry in body:
                if entry["name"] not in FIELDS:
                    self.reply(400, {})
                    return
                if mode != "not-persisted" and entry["name"] == "OIDC_FORCE_ONLY_MODE" and not state["settings"].get("oidcEnabled"):
                    self.reply(400, {})
                    return
                if mode != "not-persisted":
                    state["settings"][FIELDS[entry["name"]]] = entry["value"]
            state["writes"].append(copy.deepcopy(body))
            self.reply(200, {})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class NativeAuthenticationTests(unittest.TestCase):
    def run_native(self, url, *, check=False, initialize=False, secret=SECRET, linking=False, discovery_url=None,
                   preflight=False):
        with tempfile.TemporaryDirectory(prefix="grimmory-native-test-") as directory:
            work = Path(directory)
            tasks = yaml.safe_load((ROLE / "controller.yml").read_text())
            # Replace only the discovery transport origin, not the production issuer assertion.
            tasks[0]["ansible.builtin.uri"]["url"] = discovery_url or url + "/discovery"
            (work / "controller.yml").write_text(yaml.safe_dump(tasks, sort_keys=False))
            shutil.copyfile(ROLE / "apply.yml", work / "apply.yml")
            play = [{
                "name": "Exercise synthetic native Grimmory API behavior", "hosts": "localhost", "gather_facts": False,
                "vars": {
                    "ansible_become": False, "ansible_python_interpreter": sys.executable,
                    "grimmory_base_url": url, "grimmory_admin_username": "grimmory-admin",
                    "grimmory_admin_email": "admin@example.invalid", "grimmory_initialize_confirmed": initialize,
                    "grimmory_allow_local_account_linking": linking,
                    "grimmory_production_secrets": {"GRIMMORY_ADMIN_PASSWORD": PASSWORD},
                    "grimmory_oidc_secrets": {"oauthProviders": {"grimmory": {"client_secret": secret}}},
                    "grimmory_oidc_desired": {"oauthProviders": {"grimmory": {"client_id": "synthetic-client"}}},
                },
                "tasks": [{
                    "name": "Run the native controller interface with private output",
                    "ansible.builtin.include_tasks": {
                        "file": str(work / "controller.yml"),
                        "apply": {"no_log": True, "module_defaults": {"ansible.builtin.uri": {
                            "follow_redirects": "none", "use_proxy": False, "timeout": 5,
                        }}},
                    },
                }],
            }]
            if preflight:
                role_tasks = work / "roles/grimmory/tasks"
                role_tasks.mkdir(parents=True)
                for name in ("controller.yml", "apply.yml"):
                    shutil.copyfile(work / name, role_tasks / name)
                entrypoint = yaml.safe_load((ROOT / "ansible/playbooks/converge-grimmory.yml").read_text())[-1]
                convergence = next(task for task in entrypoint["tasks"]
                                   if task.get("ansible.builtin.import_role", {}).get("name") == "grimmory")
                actual = {"ansible.builtin.import_role": {"name": "grimmory", "tasks_from": "controller"}}
                if "check_mode" in convergence:
                    actual["check_mode"] = convergence["check_mode"]
                preflight_tasks = []
                for task in entrypoint["pre_tasks"]:
                    if task.get("ansible.builtin.import_role", {}).get("name") == "grimmory":
                        invocation = {"ansible.builtin.import_role": {"name": "grimmory", "tasks_from": "controller"}}
                        if "check_mode" in task:
                            invocation["check_mode"] = task["check_mode"]
                        preflight_tasks.append(invocation)
                play[0]["tasks"] = preflight_tasks + [actual]
                play[0]["module_defaults"] = {"ansible.builtin.uri": {
                    "follow_redirects": "none", "use_proxy": False, "timeout": 5}}
                play[0]["no_log"] = True
            path = work / "playbook.json"
            path.write_text(json.dumps(play))
            command = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(path)]
            if check:
                command.append("--check")
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, env={
                **os.environ, "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
                "ANSIBLE_NOCOLOR": "1", "ANSIBLE_LOCAL_TEMP": str(work / "ansible"),
            })
            for sensitive in (secret, PASSWORD, TOKEN):
                self.assertNotIn(sensitive, result.stdout + result.stderr)
            return result

    def test_exact_settings_idempotency_and_secret_rotation(self):
        with api_server() as (url, state):
            first = self.run_native(url)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertEqual(len(state["writes"]), 1)
            self.assertEqual(state["settings"]["oidcProviderClientSecret"], SECRET)
            self.assertEqual(state["settings"]["oidcAutoProvisionDetails"]["enableAutoProvisioning"], True)
            self.assertEqual(state["settings"]["oidcAutoProvisionDetails"]["allowLocalAccountLinking"], False)
            self.assertEqual(state["settings"]["unrelatedSetting"], {"preserve": True})
            self.assertEqual(state["setups"], 0)
            second = self.run_native(url)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertEqual(len(state["writes"]), 1)
            self.assertRegex(second.stdout, r"changed=0\s")
            third = self.run_native(url, secret="synthetic-rotated-secret")
            self.assertEqual(third.returncode, 0, third.stdout + third.stderr)
            self.assertEqual(state["writes"][-1], [{"name": "OIDC_PROVIDER_CLIENT_SECRET", "value": "synthetic-rotated-secret"}])

    def test_enabling_provisioning_changes_only_onboarding_policy(self):
        with api_server() as (url, state):
            configured = self.run_native(url)
            self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
            before = copy.deepcopy(state["settings"])
            state["settings"]["oidcAutoProvisionDetails"]["enableAutoProvisioning"] = False
            state["writes"].clear()
            enabled = self.run_native(url)
            self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
            self.assertEqual(state["writes"], [[{"name": "OIDC_AUTO_PROVISION_DETAILS", "value": {
                "enableAutoProvisioning": True, "allowLocalAccountLinking": False,
                "defaultPermissions": [], "defaultLibraryIds": []}}]])
            self.assertEqual(state["settings"], before)
            self.assertEqual(state["settings"]["oidcGroupSyncMode"], "DISABLED")
            repeated = self.run_native(url)
            self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
            self.assertRegex(repeated.stdout, r"changed=0\s")
            self.assertEqual(len(state["writes"]), 1)

    def test_authentication_entrypoint_applies_but_cli_check_remains_read_only(self):
        for check in (False, True):
            with self.subTest(check=check), api_server() as (url, state):
                result = self.run_native(url, check=check, preflight=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(len(state["writes"]), 0 if check else 1)
                self.assertEqual(state["setups"], 0)

    def test_check_mode_does_not_write_settings(self):
        with api_server() as (url, state):
            result = self.run_native(url, check=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(state["writes"], [])
            self.assertEqual(state["setups"], 0)

    def test_first_user_requires_separate_confirmation_and_is_not_recreated(self):
        with api_server(initialized=False) as (url, state):
            result = self.run_native(url)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(state["setups"], 0)
            approved = self.run_native(url, initialize=True)
            self.assertEqual(approved.returncode, 0, approved.stdout + approved.stderr)
            self.assertEqual(state["setups"], 1)
            repeat = self.run_native(url, initialize=True)
            self.assertEqual(repeat.returncode, 0, repeat.stdout + repeat.stderr)
            self.assertEqual(state["setups"], 1)

    def test_account_linking_window_is_explicit_and_reversible_without_account_writes(self):
        with api_server() as (url, state):
            opened = self.run_native(url, linking=True)
            self.assertEqual(opened.returncode, 0, opened.stdout + opened.stderr)
            self.assertTrue(state["settings"]["oidcAutoProvisionDetails"]["allowLocalAccountLinking"])
            closed = self.run_native(url)
            self.assertEqual(closed.returncode, 0, closed.stdout + closed.stderr)
            self.assertFalse(state["settings"]["oidcAutoProvisionDetails"]["allowLocalAccountLinking"])

    def test_concurrent_edits_bad_login_and_failed_persistence_refuse(self):
        for mode in ("concurrent", "login-denied", "not-persisted"):
            with self.subTest(mode=mode), api_server(mode) as (url, state):
                result = self.run_native(url)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(state["writes"]), 1 if mode == "not-persisted" else 0)
                self.assertEqual(state["setups"], 0)


class LibraryImportPatternTests(unittest.TestCase):
    def run_native(self, url, *, check=False):
        with tempfile.TemporaryDirectory(prefix='grimmory-import-pattern-test-') as directory:
            path = Path(directory) / 'playbook.json'
            desired = yaml.safe_load((ROOT / 'ansible/inventory/host_vars/docker-host.yml').read_text())['grimmory_library_import_patterns']
            path.write_text(json.dumps([{'hosts': 'localhost', 'gather_facts': False, 'vars': {
                'ansible_become': False, 'ansible_python_interpreter': sys.executable,
                'grimmory_base_url': url, 'grimmory_api_headers': {'Authorization': 'Bearer ' + TOKEN},
                'grimmory_library_import_pattern': {'key': '/audiobooks', 'value': desired['/audiobooks']},
            }, 'tasks': [{'ansible.builtin.include_tasks': {'file': str(ROLE / 'library-import-pattern.yml'),
                'apply': {'no_log': True, 'module_defaults': {'ansible.builtin.uri': {
                    'follow_redirects': 'none', 'use_proxy': False, 'timeout': 5}}}}}]}]))
            command = ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(path)]
            if check:
                command.append('--check')
            return subprocess.run(command, capture_output=True, text=True, cwd=ROOT)

    def test_check_apply_preservation_and_idempotency(self):
        with api_server() as (url, state):
            before = copy.deepcopy(state['library'])
            checked = self.run_native(url, check=True)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            self.assertEqual(state['library'], before)
            self.assertEqual(state['library_writes'], [])
            applied = self.run_native(url)
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            self.assertEqual(len(state['library_writes']), 1)
            self.assertEqual(state['library'], before | state['library_writes'][0])
            repeated = self.run_native(url)
            self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
            self.assertRegex(repeated.stdout, r'changed=0\s')
            self.assertEqual(len(state['library_writes']), 1)

    def test_ownership_concurrent_edits_and_persistence_failures_refuse(self):
        for mode in ('library-missing', 'library-ambiguous', 'library-multiroot', 'library-file-mode',
                     'library-concurrent', 'library-not-persisted'):
            with self.subTest(mode=mode), api_server(mode) as (url, state):
                result = self.run_native(url)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(state['library_writes']), 1 if mode == 'library-not-persisted' else 0)
                self.assertEqual(state['writes'], [])


class LibraryStorageTests(unittest.TestCase):
    def test_mount_admission_precedes_directory_creation(self):
        for source, filesystem, returncode, admitted in (
            ("192.168.0.123:/storage/docker", "nfs4", 0, True),
            ("192.168.0.123:/storage/other", "nfs4", 0, False),
            ("/dev/sda1", "ext4", 0, False),
            ("", "", 1, False),
        ):
            with self.subTest(source=source, filesystem=filesystem, returncode=returncode):
                with tempfile.TemporaryDirectory(prefix="grimmory-storage-test-") as directory:
                    work = Path(directory)
                    mount = work / "findmnt"
                    response = json.dumps({"filesystems": [{"target": "/mnt/storage",
                                                          "source": source, "fstype": filesystem}]})
                    mount.write_text("#!/bin/sh\nprintf '%s\\n' '" + response + "'\nexit " + str(returncode) + "\n")
                    mount.chmod(0o700)
                    paths = [work / name for name in ("books", "audiobooks")]
                    play = [{"name": "Exercise library storage admission", "hosts": "localhost", "gather_facts": False,
                             "vars": {"grimmory_storage_findmnt_path": str(mount),
                                      "grimmory_state_directories": [{"path": str(p), "uid": os.getuid(), "gid": os.getgid()} for p in paths]},
                             "tasks": [{"name": "Prepare admitted library storage", "ansible.builtin.import_role":
                                        {"name": "grimmory", "tasks_from": "directories"}}]}]
                    playbook = work / "play.yml"
                    playbook.write_text(yaml.safe_dump(play))
                    environment = os.environ | {"ANSIBLE_ROLES_PATH": str(ROOT / "ansible/roles")}
                    result = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
                                             "-e", "ansible_become=false"], capture_output=True, text=True, env=environment)
                    self.assertEqual(result.returncode == 0, admitted, result.stdout + result.stderr)
                    for path in paths:
                        self.assertEqual(path.exists(), admitted)
                        if admitted:
                            self.assertEqual(path.stat().st_mode & 0o777, 0o700)


class ComposeContractTests(unittest.TestCase):
    def test_health_admission_uses_active_source_but_refuses_missing_or_unhealthy_services(self):
        with tempfile.TemporaryDirectory(prefix="compose-health-test-") as directory:
            work = Path(directory)
            fake = work / "docker"
            fake.write_text("#!" + sys.executable + "\n" + '''
import json, pathlib, sys
root = pathlib.Path(__file__).parent
fixture = json.loads((root / 'fixture.json').read_text())
if sys.argv[1] == 'config':
    print('\\n'.join(fixture['declared']))
elif sys.argv[1] == 'ps':
    print('\\n'.join(fixture['running']))
else:
    name = sys.argv[-1]
    with (root / 'checked').open('a') as out:
        out.write(name + '\\n')
    print(fixture['health'][name])
''')
            fake.chmod(0o755)
            names = {'List declared Compose services', 'List running Compose services',
                     'Require the complete running Compose service set', 'Check required container health',
                     'Require healthy container states'}
            tasks = [task for task in yaml.safe_load((ROOT / 'ansible/roles/compose_native/tasks/observe.yml').read_text())
                     if task['name'] in names]
            for task in tasks:
                task['become'] = False
                if task['name'] == 'Check required container health':
                    task['ansible.builtin.command']['argv'][0] = str(fake)
            playbook = work / 'playbook.json'
            playbook.write_text(json.dumps([{'hosts': 'localhost', 'gather_facts': False, 'vars': {
                'ansible_become': False, 'ansible_python_interpreter': sys.executable,
                'compose_native_runtime_cli': [str(fake)], 'compose_native_home': str(work),
                'compose_native_required_healthy_containers': ['gluetun', 'grimmory', 'grimmory-db'],
            }, 'tasks': tasks}]))
            for phase in ('before', 'after', 'unhealthy', 'missing'):
                with self.subTest(phase=phase):
                    declared = ['gluetun'] if phase == 'before' else ['gluetun', 'grimmory', 'grimmory-db']
                    (work / 'fixture.json').write_text(json.dumps({
                        'declared': declared, 'running': ['gluetun'] if phase == 'missing' else declared,
                        'health': {'gluetun': 'healthy', 'grimmory': 'unhealthy' if phase == 'unhealthy' else 'healthy',
                                   'grimmory-db': 'healthy'},
                    }))
                    (work / 'checked').write_text('')
                    result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                                            cwd=ROOT, capture_output=True, text=True, env={
                                                **os.environ, 'ANSIBLE_CONFIG': str(ROOT / 'ansible/ansible.cfg'),
                                                'ANSIBLE_NOCOLOR': '1', 'ANSIBLE_LOCAL_TEMP': str(work / 'ansible'),
                                            })
                    if phase in ('before', 'after'):
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(set((work / 'checked').read_text().splitlines()), set(declared))
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        if phase == 'missing':
                            self.assertEqual((work / 'checked').read_text(), '')

    def test_shelfmark_inbox_and_native_policy_have_one_owner(self):
        result = subprocess.run(["docker", "compose", "config", "--no-interpolate", "--no-env-resolution", "--format", "json"],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        model = json.loads(result.stdout)
        service = model['services']['shelfmark']
        bindings = yaml.safe_load((ROOT / 'ansible/roles/shelfmark/tasks/bind-settings.yml').read_text())
        settings = next(task['ansible.builtin.set_fact']['shelfmark_settings'] for task in bindings
                        if 'shelfmark_settings' in task.get('ansible.builtin.set_fact', {}))
        inbox = next(mount for mount in service['volumes']
                     if mount['target'] == settings['downloads']['DESTINATION'])
        self.assertEqual(inbox['target'], settings['downloads']['DESTINATION_AUDIOBOOK'])
        grimmory_inbox = next(mount for mount in model['services']['grimmory']['volumes']
                              if mount['target'] == '/bookdrop')
        self.assertEqual(inbox['source'], grimmory_inbox['source'])
        self.assertFalse(inbox.get('read_only', False))
        self.assertFalse(inbox['bind']['create_host_path'])
        self.assertTrue(next(mount for mount in service['volumes']
                             if mount['target'] == '/data/downloads')['read_only'])
        policy = set(settings['downloads']) | {'INGEST_DIR', 'QBITTORRENT_CATEGORY',
                                               'QBITTORRENT_CATEGORY_AUDIOBOOK', 'PROWLARR_TORRENT_ACTION'}
        self.assertFalse(policy.intersection(service['environment']))
        library_sources = {mount['source'] for mount in model['services']['grimmory']['volumes']
                           if mount['target'] in ('/books', '/audiobooks')}
        self.assertFalse(library_sources.intersection(mount['source'] for mount in service['volumes']))

    def test_library_writer_secret_readers_and_backup_scope(self):
        result = subprocess.run(["docker", "compose", "config", "--no-interpolate", "--no-env-resolution", "--format", "json"],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        model = json.loads(result.stdout)
        service = model["services"]["grimmory"]
        database = model["services"]["grimmory-db"]
        self.assertFalse(service.get("ports"))
        self.assertFalse(database.get("ports"))
        self.assertEqual(set(database["networks"]), {"grimmory-db"})
        self.assertTrue(model["networks"]["grimmory-db"]["internal"])
        for target, source in (("/books", "/mnt/storage/media/books"),
                               ("/audiobooks", "/mnt/storage/media/audiobooks")):
            mount = next(v for v in service["volumes"] if v["target"] == target)
            self.assertEqual(mount["source"], source)
            self.assertFalse(mount.get("read_only", False))
            self.assertFalse(mount["bind"]["create_host_path"])
        self.assertEqual(service["environment"]["DISK_TYPE"], "LOCAL")
        self.assertEqual(service["environment"]["ALLOWED_ORIGINS"], "https://books.diloreto.com")
        desired = json.loads((ROOT / "infrastructure/tofu/authentik/desired.json").read_text())
        self.assertEqual(desired["oauthProviders"]["grimmory"]["allowed_redirect_uris"], [{
            "matching_mode": "strict", "redirect_uri_type": "authorization",
            "url": "https://books.diloreto.com/oauth2-callback",
        }])
        self.assertEqual(service["environment"]["SPRING_CONFIG_IMPORT"], "configtree:/run/secrets/")
        self.assertEqual(service["secrets"], [{"source": "grimmory_datasource_password", "target": "spring.datasource.password"}])
        self.assertEqual({item["source"] for item in database["secrets"]}, {"grimmory_db_password", "grimmory_db_root_password"})
        bindings = {item["path"]: item for item in json.loads((ROOT / "services/credentials.json").read_text())["files"]}
        readers = {name: bindings[model["secrets"][name]["file"]] for name in
                   ("grimmory_datasource_password", "grimmory_db_password", "grimmory_db_root_password")}
        self.assertEqual(readers["grimmory_datasource_password"]["key"], readers["grimmory_db_password"]["key"])
        self.assertEqual(readers["grimmory_datasource_password"]["group"], "1000")
        for name in ("grimmory_db_password", "grimmory_db_root_password"):
            self.assertEqual(readers[name]["group"], "999")
        for reader in readers.values():
            self.assertEqual((reader["owner"], reader["mode"]), ("0", "0440"))
        self.assertNotIn("DATABASE_PASSWORD", service["environment"])
        self.assertFalse(any("OIDC_CLIENT_SECRET" in k for k in service["environment"]))
        policy = json.loads((ROOT / "services/data/restic/policy.json").read_text())
        self.assertIn("grimmory", policy["stop_groups"]["applications"])
        self.assertIn("grimmory-db", policy["stop_groups"]["databases"])
        scope = (ROOT / "services/data/restic/files-from").read_text().splitlines()
        recovery = json.loads((ROOT / "recovery/groups.json").read_text())["groups"]["books"]
        for name in ("grimmory", "grimmory-db"):
            self.assertIn(name, recovery["services"])
        for path in ("/mnt/storage/media/books", "/mnt/storage/media/audiobooks"):
            self.assertIn(path, scope)
            self.assertIn(path, recovery["paths"])
        for name in ("grimmory-data", "grimmory-db-data", "grimmory-bookdrop"):
            path = "/srv/home-lab-state/" + name
            self.assertIn(path, scope)
            self.assertIn(path, recovery["paths"])


if __name__ == "__main__":
    unittest.main()
