#!/usr/bin/env python3
"""Offline fixed snapshot protocol, collector parity and real descriptor contention."""
import ast
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'infrastructure/host-lifecycle/proxmox/controller-observer-template.py'


def load():
    module = types.ModuleType('controller_observer')
    module.__file__ = str(SOURCE)
    source = SOURCE.read_text().replace("'@CONTROLLER_SPEC@'", repr(json.dumps({'observer_sha256': hashlib.sha256(b'observer').hexdigest(), 'collector_sha256': hashlib.sha256(b'collector').hexdigest()})))
    source = source.replace("@ACTIVATOR_SHA256@", hashlib.sha256(b"activator").hexdigest())
    exec(compile(source, str(SOURCE), 'exec'), module.__dict__)
    return module


class ControllerObserverTests(unittest.TestCase):
    def test_summary_functions_preserve_retained_protected_collector_semantics(self):
        old = ast.parse((ROOT / 'nix/proxmox/private-preparer-template.py').read_text())
        new = ast.parse((ROOT / 'infrastructure/host-lifecycle/proxmox/protected-collector-template.py').read_text())
        original = {n.name: ast.dump(n, include_attributes=False) for n in old.body if isinstance(n, ast.FunctionDef)}
        retained = {n.name: ast.dump(n, include_attributes=False) for n in new.body if isinstance(n, ast.FunctionDef)}
        self.assertGreater(len(retained), 20)
        for name, body in retained.items():
            self.assertEqual(body, original[name], name)
        self.assertNotIn('prepare', retained)
        self.assertNotIn('validate_plan', retained)
        self.assertNotIn('install_manifest', retained)
        source = (ROOT / 'infrastructure/host-lifecycle/proxmox/protected-collector-template.py').read_text()
        self.assertIn("sys.argv[1:] != [\"summary\"]", source)

    def test_fixed_invocation_rejects_every_non_nonce_or_legacy_verb(self):
        module = load()
        for raw in [b'', b'a' * 64, b'a' * 63 + b'\n', b'a' * 64 + b'\nextra', b'{"command":"apply"}\n']:
            with self.subTest(raw=raw), mock.patch.object(module.os, 'geteuid', return_value=0), \
                    mock.patch.object(module.sys, 'argv', ['helper', 'observe']), \
                    mock.patch.object(module.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(raw))), \
                    mock.patch.object(module, 'observe') as observe:
                with self.assertRaises(ValueError): module.main()
                observe.assert_not_called()
        for argv in [['helper'], ['helper', 'apply'], ['helper', 'observe', 'extra']]:
            with mock.patch.object(module.os, 'geteuid', return_value=0), mock.patch.object(module.sys, 'argv', argv):
                with self.assertRaises(ValueError): module.main()

    def test_nonce_installed_producer_host_key_and_scope_are_bound(self):
        module = load()
        def content(path, *_):
            if path.name == 'proxmox-ansible-deploy-activator': return b'activator'
            if path.name == 'proxmox-observer': return b'observer'
            if path.name == 'proxmox-protected-collector': return b'collector'
            if path.name == 'ssh_host_ed25519_key.pub': return b'ssh-ed25519 ' + base64.b64encode(b'synthetic-host-key') + b' fixture\n'
            return b'controller'
        result = types.SimpleNamespace(returncode=0, stderr=b'', stdout=b'{"fixture":true}\n')
        with mock.patch.object(module, 'acquire_locks', return_value=[]), mock.patch.object(module, 'read_fixed', side_effect=content), \
                mock.patch.object(module.subprocess, 'run', return_value=result) as run:
            observed = module.observe('a' * 64)
            self.assertEqual(observed['nonce'], 'a' * 64)
            self.assertEqual(observed['producer_sha256'], hashlib.sha256(b'controller').hexdigest())
            self.assertEqual(observed['host_key'], 'SHA256:' + base64.b64encode(hashlib.sha256(b'synthetic-host-key').digest()).decode().rstrip('='))
            self.assertEqual(observed['locks'], 'snapshot-exclusive-v1')
            self.assertEqual(observed['scope'], 'audit')
            self.assertEqual(run.call_args.args[0], ['/usr/local/libexec/home-lab/proxmox-observer', 'observe'])

    def test_changed_producer_fails_before_observer_runs(self):
        module = load()
        with mock.patch.object(module, 'acquire_locks', return_value=[]), mock.patch.object(module, 'read_fixed', return_value=b'wrong'), \
                mock.patch.object(module.subprocess, 'run') as run:
            with self.assertRaises(ValueError): module.observe('a' * 64)
            run.assert_not_called()

    def test_old_installed_activator_protocol_refuses_observation(self):
        module = load()
        def content(path, *_):
            return {'proxmox-observer': b'observer', 'proxmox-protected-collector': b'collector'}.get(path.name, b'old-activator')
        with mock.patch.object(module, 'acquire_locks', return_value=[]), mock.patch.object(module, 'read_fixed', side_effect=content), mock.patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'mutex participant mismatch'): module.observe('a' * 64)
            run.assert_not_called()

    def test_real_lock_contention_interruption_and_persistent_inode(self):
        module = load()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            lock = root / 'operation.lock'
            module.LOCKS = [lock]; module.APT_LOCKS = []; module.JOURNALS = []
            original_fstat = os.fstat
            def root_info(fd):
                info = original_fstat(fd)
                return types.SimpleNamespace(**{name: (0 if name in ("st_uid", "st_gid") else getattr(info, name)) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})
            with mock.patch.object(module, 'parent_fd', side_effect=lambda p: os.open(p.parent, os.O_RDONLY)), \
                    mock.patch.object(module.os, 'fstat', side_effect=root_info), \
                    mock.patch.object(module, 'fingerprint', side_effect=lambda i: (i.st_dev, i.st_ino, i.st_mode, i.st_nlink)):
                # Read-only observation cannot provision even a missing mutex.
                with self.assertRaises(FileNotFoundError): module.acquire_locks()
                self.assertFalse(lock.exists())
                lock.touch(mode=0o600)
                # Missing later mutex releases all earlier acquired descriptors.
                missing = root / 'missing.lock'; module.LOCKS = [lock, missing]
                with self.assertRaises(FileNotFoundError): module.acquire_locks()
                self.assertFalse(missing.exists())
                probe = os.open(lock, os.O_RDWR)
                try: fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally: os.close(probe)
                module.LOCKS = [lock]
                descriptors = module.acquire_locks()
                inode = lock.stat().st_ino
                with self.assertRaises(BlockingIOError): module.acquire_locks()
                for fd in descriptors: os.close(fd)
                # Owner journal presence is never mistaken for an unlocked file.
                journal = root / 'apply.lock'; journal.write_bytes(b'failed-session')
                module.JOURNALS = [journal]
                with self.assertRaises(ValueError): module.acquire_locks()
                self.assertEqual(journal.read_bytes(), b'failed-session')
                self.assertEqual(lock.stat().st_ino, inode)
                probe = os.open(lock, os.O_RDWR)
                try: fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally: os.close(probe)
                self.assertEqual(lock.stat().st_ino, inode)
                # Symlinks cannot be converted into locks or silently removed.
                module.JOURNALS = []; module.LOCKS = [root / 'alias']; (root / 'alias').symlink_to(lock)
                with self.assertRaises(OSError): module.acquire_locks()
                self.assertTrue((root / 'alias').is_symlink())

    def test_existing_protocol_paths_remain_distinct(self):
        module = load()
        self.assertIn(Path('/var/lib/home-lab/reconciliation/operation.lock'), module.LOCKS)
        self.assertIn(Path('/var/lib/iac-ansible-production.lock'), module.JOURNALS)
        self.assertIn(Path('/var/lib/home-lab/firewall-transaction/active.json'), module.JOURNALS)
        self.assertIn(Path('/var/lib/dpkg/lock-frontend'), module.APT_LOCKS)
        self.assertEqual(len(module.LOCKS), len(set(module.LOCKS)))
        self.assertEqual(set(module.LOCKS) & set(module.JOURNALS), set())


class NativeObservationTests(unittest.TestCase):
    """Real Ansible assertions only: no role execution, SSH, NSS or native host calls."""

    def test_protected_response_assertions_fail_closed_without_printing_input(self):
        loader = "const fs=require('node:fs'), y=require('js-yaml'); process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1], 'utf8'))));"
        loaded = subprocess.run(['node', '-e', loader,
                                 str(ROOT / 'ansible/roles/proxmox_observe/tasks/main.yml')],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        tasks = json.loads(loaded.stdout)
        selected = [task for task in tasks if 'ansible.builtin.assert' in task and
                    'proxmox_observe_protected.stdout' in json.dumps(task)]
        self.assertEqual(len(selected), 3)
        self.assertTrue(all(task.get('no_log') is True for task in selected))
        service_assert = next(task for task in tasks if task['name'] == 'Verify required services are loaded and active')
        owner_assert = next(task for task in tasks if task['name'] == 'Refuse a retained operation owner without reconciling it')
        record = {'expectedCount': 3, 'observedCount': 3, 'matches': True, 'status': 'complete'}
        valid = {'protectedAccess': record, 'protectedHardware': record}
        cases = [
            ('valid', json.dumps(valid), '', 0, True),
            ('malformed', 'SYNTHETIC_PRIVATE_SENTINEL', '', 0, False),
            ('extra-field', json.dumps({**valid, 'private': 'SYNTHETIC_PRIVATE_SENTINEL'}), '', 0, False),
            ('missing-domain', json.dumps({'protectedAccess': record}), '', 0, False),
            ('unavailable', json.dumps({**valid, 'protectedAccess': {'expectedCount': 3, 'observedCount': None,
                                                                  'matches': None, 'status': 'unavailable'}}), '', 0, False),
            ('hardware-drift', json.dumps({**valid, 'protectedHardware': {**record, 'matches': False,
                                                                        'observedCount': 2}}), '', 0, False),
            ('oversized', 'SYNTHETIC_PRIVATE_SENTINEL' * 200, '', 0, False),
            ('stderr', json.dumps(valid), 'SYNTHETIC_PRIVATE_SENTINEL', 0, False),
            ('nonzero', json.dumps(valid), '', 1, False),
        ]
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            config = directory / 'ansible.cfg'
            config.write_text('[defaults]\nhost_key_checking=True\nretry_files_enabled=False\n')
            environment = {**os.environ, 'ANSIBLE_CONFIG': str(config), 'ANSIBLE_NOCOLOR': '1',
                           'ANSIBLE_LOCAL_TEMP': str(directory / 'tmp'), 'ANSIBLE_STDOUT_CALLBACK': 'default',
                           'ANSIBLE_LOG_PATH': str(directory / 'ansible.log')}
            for label, stdout, stderr, rc, success in cases:
                with self.subTest(case=label):
                    play = [{'name': 'Isolated response assertion fixture', 'hosts': 'localhost',
                             'connection': 'local', 'gather_facts': False,
                             'vars': {'proxmox_observe_protected': {'stdout': stdout, 'stderr': stderr, 'rc': rc}},
                             'tasks': selected}]
                    playbook = directory / 'assertions.json'
                    playbook.write_text(json.dumps(play))
                    result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                                            cwd=directory, env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, success, label + '\n' + result.stdout + result.stderr)
                    self.assertNotIn('SYNTHETIC_PRIVATE_SENTINEL', result.stdout + result.stderr)
            for state, load, owner, success in [('active', 'loaded', False, True),
                                                ('inactive', 'loaded', False, False),
                                                ('active', 'not-found', False, False),
                                                ('active', 'loaded', True, False)]:
                with self.subTest(service=state, load=load, retained_owner=owner):
                    variables = {
                        'proxmox_observe_services': {'results': [{'item': 'nfs-server.service', 'stdout_lines':
                            ['LoadState=' + load, 'ActiveState=' + state, 'SubState=exited']}]},
                        'proxmox_observe_owners': {'results': [{'item': '/synthetic/apply.lock', 'stat': {'exists': owner}}]},
                    }
                    playbook.write_text(json.dumps([{'hosts': 'localhost', 'connection': 'local',
                        'gather_facts': False, 'vars': variables, 'tasks': [service_assert, owner_assert]}]))
                    result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                                            cwd=directory, env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
            self.assertNotIn('SYNTHETIC_PRIVATE_SENTINEL', (directory / 'ansible.log').read_text())

    def test_native_package_response_assertions_and_redacted_diagnostics(self):
        loader = "const fs=require('node:fs'), y=require('js-yaml'); process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1], 'utf8'))));"
        loaded = subprocess.run(['node', '-e', loader,
                                 str(ROOT / 'ansible/roles/proxmox_package_observe/tasks/main.yml')],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        tasks = json.loads(loaded.stdout)
        # Never run the remote collector or its commands in this local fixture.
        selected = tasks[2:]
        self.assertEqual(len(selected), 6)
        self.assertIn('ansible.builtin.fail', selected[0])
        self.assertTrue(all(task.get('no_log') is True for task in selected[1:-1]))
        self.assertTrue(all('ansible.builtin.command' not in task for task in selected))
        sample = {'version': 2, 'host': 'proxmox', 'metadata_refresh_performed': False,
                  'installed_records': 1, 'expected_manifest_records': 1, 'manifest_matches': True,
                  'apt_tree_safe': True, 'size_parse_complete': False, 'metadata_age_seconds': 10,
                  'solver': {'returncode': 0}, 'holds': [], 'kept_back': [], 'active_lifecycle_locks': [],
                  'change_counts': {'install': 0, 'upgrade': 1, 'downgrade': 0, 'remove': 0}}
        cases = [('valid', json.dumps(sample), '', 0, True),
                 ('malformed', 'SYNTHETIC_PRIVATE_SENTINEL', '', 0, False),
                 ('wrong-host', json.dumps({**sample, 'host': 'debian'}), '', 0, False),
                 ('refresh', json.dumps({**sample, 'metadata_refresh_performed': True}), '', 0, False),
                 ('bool-count', json.dumps({**sample, 'installed_records': True}), '', 0, False),
                 ('bad-change-count', json.dumps({**sample, 'change_counts': {**sample['change_counts'], 'upgrade': -1}}), '', 0, False),
                 ('missing-key', json.dumps({key: value for key, value in sample.items() if key != 'solver'}), '', 0, False),
                 ('stderr', json.dumps(sample), 'SYNTHETIC_PRIVATE_SENTINEL', 0, False),
                 ('nonzero', json.dumps(sample), '', 1, False),
                 ('unavailable-metadata', json.dumps({**sample, 'metadata_age_seconds': None}), '', 0, True),
                 ('redaction', json.dumps({**sample, 'holds': ['SYNTHETIC_PRIVATE_SENTINEL']}), '', 0, True)]
        categories = {
            'package observer command unavailable': 'native-command-unavailable',
            'package observer command exceeded bound': 'native-command-output-limit',
            'package inventory unavailable': 'inventory-unavailable',
            'APT policy unavailable': 'apt-policy-unavailable',
            'APT policy candidate differs': 'apt-candidate-mismatch',
            'unrecognized APT transition': 'apt-transition-unrecognized',
            'version comparison unavailable': 'version-comparison-unavailable',
            'APT state changed during observation': 'apt-state-changed',
            'APT state read differs': 'apt-state-read-differs',
            'lock observation unavailable': 'lock-observation-unavailable',
        }
        expected_errors = {}
        for message, category in categories.items():
            for ending in ('', '\n'):
                label = category + repr(ending)
                cases.append((label, '', 'package-candidate-observer: ' + message + ending, 1, False))
                expected_errors[label] = 'Package observation failed: ' + category + '.'
        cases.append(('unknown-private-error', '', 'package-candidate-observer: SYNTHETIC_PRIVATE_SENTINEL', 1, False))
        expected_errors['unknown-private-error'] = 'unclassified; raw diagnostics withheld.'
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            config = directory / 'ansible.cfg'
            config.write_text('[defaults]\nhost_key_checking=True\nretry_files_enabled=False\n')
            environment = {**os.environ, 'ANSIBLE_CONFIG': str(config), 'ANSIBLE_NOCOLOR': '1',
                           'ANSIBLE_LOCAL_TEMP': str(directory / 'tmp'), 'ANSIBLE_STDOUT_CALLBACK': 'default',
                           'ANSIBLE_LOG_PATH': str(directory / 'ansible.log')}
            # Render and stream the actual stdin expression into a local hash-only
            # process. Never execute the collector or its native host commands.
            expected_packages = json.loads((ROOT / 'infrastructure/host-lifecycle/proxmox/package-manifest.json').read_text())['packages']
            encoded = base64.b64encode(json.dumps(expected_packages).encode()).decode()
            expected_source = (ROOT / 'infrastructure/maintenance/host/package-candidate-observer').read_text().rstrip().replace('@EXPECTED_PACKAGES_BASE64@', encoded) + '\n'
            render_tasks = [
                {'ansible.builtin.set_fact': {'fixture_source': tasks[1]['ansible.builtin.command']['stdin']}, 'no_log': True},
                {'ansible.builtin.command': {'argv': [sys.executable, '-I', '-B', '-c',
                    'import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'],
                    'stdin': tasks[1]['ansible.builtin.command']['stdin']},
                    'register': 'fixture_stream_hash', 'changed_when': False, 'no_log': True},
                {'ansible.builtin.assert': {'that': [
                    "fixture_stream_hash.stdout == fixture_expected_sha256",
                    "'@EXPECTED_PACKAGES_BASE64@' not in fixture_source",
                    "((lookup('ansible.builtin.file', role_path + '/../../../infrastructure/host-lifecycle/proxmox/package-manifest.json') | from_json).packages | to_json | b64encode) in fixture_source",
                ]}, 'no_log': True},
            ]
            playbook = directory / 'render.json'
            playbook.write_text(json.dumps([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                'vars': {'role_path': str(ROOT / 'ansible/roles/proxmox_package_observe'),
                         'fixture_expected_sha256': hashlib.sha256(expected_source.encode()).hexdigest()},
                'tasks': render_tasks}]))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                                    cwd=directory, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for label, stdout, stderr, rc, success in cases:
                with self.subTest(case=label):
                    variables = {'proxmox_package_observe_raw': {'stdout': stdout, 'stderr': stderr, 'rc': rc},
                                 'proxmox_package_observe_max_age_seconds': 86400}
                    playbook = directory / 'assertions.json'
                    playbook.write_text(json.dumps([{'hosts': 'localhost', 'connection': 'local',
                        'gather_facts': False, 'vars': variables, 'tasks': selected}]))
                    result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                                            cwd=directory, env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, success, label + '\n' + result.stdout + result.stderr)
                    self.assertNotIn('SYNTHETIC_PRIVATE_SENTINEL', result.stdout + result.stderr)
                    if label in expected_errors:
                        self.assertIn(expected_errors[label], result.stdout)
                        self.assertNotIn('"apply_authorized"', result.stdout)
                    if success:
                        self.assertIn('"apply_authorized": false', result.stdout)
                        self.assertIn('"metadata_refresh_performed": false', result.stdout)
            self.assertNotIn('SYNTHETIC_PRIVATE_SENTINEL', (directory / 'ansible.log').read_text())


if __name__ == '__main__': unittest.main()
