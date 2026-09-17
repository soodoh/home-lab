#!/usr/bin/env python3
"""Native observation fixtures and opt-in real Linux module tests."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

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
        self.assertEqual(len(selected), 4)
        self.assertTrue(all(task.get('no_log') is True for task in selected))
        service_assert = next(task for task in tasks if task['name'] == 'Verify required services are loaded and active')
        owners = json.loads(subprocess.run(['node', '-e', loader,
            str(ROOT / 'ansible/roles/proxmox_observe/tasks/owners.yml')],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout)
        owner_assert = next(task for task in owners if task['name'] == 'Refuse a retained operation owner without reconciling it')
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

    def test_native_package_inventory_assertions_and_redaction(self):
        loader = "const fs=require('node:fs'), y=require('js-yaml'); process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1], 'utf8'))));"
        tasks = json.loads(subprocess.run(['node', '-e', loader,
            str(ROOT / 'ansible/roles/proxmox_package_observe/tasks/main.yml')],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout)
        # Exercise actual assertions/reporting, never package_facts or host commands.
        selected = [tasks[3], tasks[5], tasks[6]]
        self.assertTrue(all(task.get('no_log') is True for task in selected[:-1]))
        self.assertTrue(all('ansible.builtin.assert' in task for task in selected[:-1]))
        self.assertIn('ansible.builtin.debug', selected[-1])
        sentinel = 'SYNTHETIC_PRIVATE_SENTINEL'
        valid = {'ansible_facts': {'packages': {sentinel: [{'version': sentinel}]}},
                 'proxmox_package_audit': {'rc': 0, 'stdout': '', 'stderr': ''},
                 'proxmox_package_holds': {'rc': 0, 'stderr': '', 'stdout_lines': [sentinel]}}
        cases = [('valid-private-inventory', {}, True),
                 ('unfinished-dpkg', {'proxmox_package_audit': {'rc': 0, 'stdout': sentinel, 'stderr': ''}}, False),
                 ('dpkg-failure', {'proxmox_package_audit': {'rc': 1, 'stdout': '', 'stderr': sentinel}}, False),
                 ('holds-failure', {'proxmox_package_holds': {'rc': 1, 'stderr': sentinel}}, False),
                 ('holds-stderr', {'proxmox_package_holds': {'rc': 0, 'stderr': sentinel}}, False),
                 ('empty-inventory', {'ansible_facts': {'packages': {}}}, False),
                 ('missing-inventory', {'ansible_facts': {}}, False),
                 ('malformed-inventory', {'ansible_facts': {'packages': sentinel}}, False)]
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            config = directory / 'ansible.cfg'
            config.write_text('[defaults]\nhost_key_checking=True\nretry_files_enabled=False\nfact_caching=memory\n')
            environment = {**os.environ, 'ANSIBLE_CONFIG': str(config), 'ANSIBLE_NOCOLOR': '1',
                           'ANSIBLE_LOCAL_TEMP': str(directory / 'tmp'), 'ANSIBLE_STDOUT_CALLBACK': 'default',
                           'ANSIBLE_LOG_PATH': str(directory / 'ansible.log')}
            for label, changes, success in cases:
                with self.subTest(case=label):
                    playbook = directory / 'assertions.json'
                    playbook.write_text(json.dumps([{'hosts': 'localhost', 'connection': 'local',
                        'gather_facts': False, 'vars': {**valid, **changes}, 'tasks': selected}]))
                    result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                        cwd=directory, env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, success, label + '\n' + result.stdout + result.stderr)
                    self.assertNotIn(sentinel, result.stdout + result.stderr)
                    if success:
                        for field in ('apply_authorized', 'metadata_refresh_performed', 'candidate_preview_performed'):
                            self.assertIn('"' + field + '": false', result.stdout)
                        self.assertIn('"installed_package_names": 1', result.stdout)
                    else:
                        self.assertNotIn('"apply_authorized"', result.stdout)
            self.assertNotIn(sentinel, (directory / 'ansible.log').read_text())

    def test_native_package_scope_requires_an_explicit_choice(self):
        loader = "const fs=require('node:fs'), y=require('js-yaml'); process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1], 'utf8'))));"
        tasks = json.loads(subprocess.run(['node', '-e', loader,
            str(ROOT / 'ansible/roles/proxmox_package_maintenance/tasks/main.yml')],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout)
        selected = tasks[:2]
        self.assertTrue(all('ansible.builtin.assert' in task for task in selected))
        cases = [(['fixture-app=1.2-3'], False, True),
                 (['fixture-app:amd64=1:2.0~rc1-1+deb13u1'], False, True),
                 ([], True, True), ([], False, False),
                 (['fixture-app=1'], True, False), ('fixture-app=1', False, False),
                 (['fixture-app=1', 'fixture-app=2'], False, False),
                 (['fixture-app'], False, False), (['fixture-app=*'], False, False),
                 (['/tmp/package.deb'], False, False), (['fixture-app=1;true'], False, False),
                 (['fixture-app=1'], 'false', False), ([123], False, False)]
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            config = directory / 'ansible.cfg'
            config.write_text('[defaults]\nretry_files_enabled=False\n')
            environment = {**os.environ, 'ANSIBLE_CONFIG': str(config), 'ANSIBLE_NOCOLOR': '1',
                           'ANSIBLE_LOCAL_TEMP': str(directory / 'tmp'), 'ANSIBLE_STDOUT_CALLBACK': 'default'}
            for specs, upgrade, success in cases:
                with self.subTest(specs=specs, upgrade=upgrade):
                    playbook = directory / 'assertions.json'
                    # Controller-only assertions: no connection, facts or APT
                    # action is included. A synthetic alias tests the real guard.
                    playbook.write_text(json.dumps([{'hosts': 'proxmox', 'gather_facts': False,
                        'vars': {'ansible_connection': 'ssh', 'ansible_become': True,
                                 'proxmox_package_specs': specs, 'proxmox_package_dist_upgrade': upgrade,
                                 'proxmox_package_refresh_metadata': False},
                        'tasks': selected}]))
                    result = subprocess.run(['ansible-playbook', '-i', 'proxmox,', str(playbook)],
                        cwd=directory, env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)


@unittest.skipUnless(os.environ.get('HOME_LAB_NATIVE_APT_TESTS') == '1',
                     'opt-in isolated Linux APT fixture; never a host validation command')
class NativeAptModuleTests(unittest.TestCase):
    """Real core modules and synthetic debs, confined to a networkless container.

    Requires the separately approved test image with Ansible and python3-apt.
    No repository/home mounts. Root is read-only; all package data, databases,
    metadata and logs live beneath a fresh /tmp directory. Never run on PVE.
    """

    @classmethod
    def setUpClass(cls):
        if not (sys.platform == 'linux' and os.geteuid() == 0 and
                Path('/.dockerenv').is_file() and
                Path('/opt/home-lab-native-apt-fixture').is_file() and
                os.statvfs('/').f_flag & os.ST_RDONLY):
            raise RuntimeError('native APT tests require the approved read-only-root container')
        routes = Path('/proc/net/route').read_text().splitlines()[1:]
        if any(line.split()[1] == '00000000' for line in routes):
            raise RuntimeError('native APT tests require networking disabled')
        import yaml
        cls.maintenance = yaml.safe_load((ROOT / 'ansible/roles/proxmox_package_maintenance/tasks/main.yml').read_text())
        cls.inventory = yaml.safe_load((ROOT / 'ansible/roles/proxmox_package_observe/tasks/main.yml').read_text())
        cls.configuration = yaml.safe_load((ROOT / 'ansible/roles/proxmox_maintenance/tasks/main.yml').read_text())
        # Scope assertions are tested separately with real Ansible above. Only
        # native module tasks run here, under synthetic local connection/state.
        assert all('ansible.builtin.assert' in task for task in cls.maintenance[:2])
        assert 'ansible.builtin.assert' in cls.inventory[0]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-apt-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repo = self.directory / 'repo'; self.repo.mkdir()
        self.db = self.directory / 'dpkg'; self.db.mkdir()
        (self.db / 'status').write_text('')
        self.payload = self.directory / 'installed'; self.payload.mkdir()
        self.debs = []
        apt_config = self.directory / 'apt.conf'
        sources = self.directory / 'sources.list'
        sources.write_text(f'deb [trusted=yes] file:{self.repo} ./\n')
        apt_config.write_text(f'''
Dir::Etc::sourcelist "{sources}";
Dir::Etc::sourceparts "-";
Dir::State "{self.directory}/apt-state";
Dir::State::status "{self.db}/status";
Dir::Cache "{self.directory}/apt-cache";
Dir::Log "{self.directory}/apt-log";
DPkg::Options {{ "--admindir={self.db}"; "--log={self.directory}/dpkg.log"; }};
APT::Sandbox::User "root";
''')
        for path in ('apt-state/lists/partial', 'apt-cache/archives/partial', 'apt-log'):
            (self.directory / path).mkdir(parents=True)
        config = self.directory / 'ansible.cfg'
        config.write_text(f'[defaults]\nretry_files_enabled=False\nfact_caching=memory\nremote_tmp={self.directory}/remote-tmp\n')
        self.environment = {**os.environ, 'HOME': str(self.directory),
                            'APT_CONFIG': str(apt_config), 'DPKG_ADMINDIR': str(self.db),
                            'ANSIBLE_CONFIG': str(config), 'ANSIBLE_NOCOLOR': '1',
                            'ANSIBLE_LOCAL_TEMP': str(self.directory / 'ansible-tmp'),
                            'ANSIBLE_STDOUT_CALLBACK': 'default',
                            'ANSIBLE_LOG_PATH': str(self.directory / 'ansible.log')}

    def command(self, argv, **kwargs):
        return subprocess.run(argv, env=self.environment, capture_output=True, text=True, timeout=60, **kwargs)

    def package(self, name, version, extra='', fail_configure=False, conffile=False):
        build = self.directory / f'build-{name}-{version}'
        control = build / 'DEBIAN'; control.mkdir(parents=True)
        metadata = (f'Package: {name}\nVersion: {version}\nArchitecture: all\n'
                    f'Maintainer: Fixture <fixture@example.invalid>\nDescription: isolated synthetic fixture\n{extra}')
        (control / 'control').write_text(metadata)
        target = self.payload / (name + ('.conf' if conffile else '.txt'))
        staged = build / target.relative_to('/')
        staged.parent.mkdir(parents=True, exist_ok=True); staged.write_text(version + '\n')
        if conffile: (control / 'conffiles').write_text(str(target) + '\n')
        if fail_configure:
            (control / 'postinst').write_text('#!/bin/sh\nexit 23\n')
            (control / 'postinst').chmod(0o755)
        deb = self.repo / f'{name}_{version}_all.deb'
        result = self.command(['/usr/bin/dpkg-deb', '--build', '--root-owner-group', str(build), str(deb)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.debs.append((deb, metadata))
        return deb

    def index(self):
        records = []
        for deb, metadata in self.debs:
            raw = deb.read_bytes()
            records.append(metadata + f'Filename: ./{deb.name}\nSize: {len(raw)}\n'
                           f'SHA256: {hashlib.sha256(raw).hexdigest()}\n')
        (self.repo / 'Packages').write_text('\n'.join(records))
        result = self.command(['/usr/bin/apt-get', 'update'])
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_tasks(self, tasks, variables=None, check=False, success=True):
        playbook = self.directory / 'fixture.json'
        playbook.write_text(json.dumps([{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
            'vars': {'ansible_python_interpreter': '/usr/bin/python3', **(variables or {})},
            'tasks': tasks}]))
        argv = ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)]
        if check: argv.append('--check')
        result = self.command(argv)
        self.assertNotIn('UNREACHABLE!', result.stdout, result.stdout + result.stderr)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result.stdout

    def maintain(self, specs=None, dist=False, check=False, success=True):
        return self.run_tasks(self.maintenance[2:],
            {'proxmox_package_specs': specs or [], 'proxmox_package_dist_upgrade': dist,
             'proxmox_package_refresh_metadata': False}, check, success)

    def version(self, name):
        result = self.command(['/usr/bin/dpkg-query', '--show', '--showformat=${Version}', name])
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_install_preview_upgrade_and_idempotence(self):
        self.package('fixture-app', '1'); self.package('fixture-app', '2'); self.index()
        self.maintain(['fixture-app=1'])
        before = (self.db / 'status').read_bytes()
        output = self.maintain(['fixture-app=2'], check=True)
        self.assertIn('"package_change_reported": true', output)
        self.assertEqual((self.db / 'status').read_bytes(), before)
        self.assertEqual(self.version('fixture-app'), '1')
        self.maintain(['fixture-app=2'])
        self.assertEqual(self.version('fixture-app'), '2')
        self.assertIn('"package_change_reported": false', self.maintain(['fixture-app=2']))
        output = self.run_tasks(self.inventory[1:])
        self.assertIn('"installed_package_names": 1', output)
        self.assertIn('"dpkg_audit": "clean"', output)
        self.assertIn('"held_packages": 0', output)

    def test_native_dist_upgrade(self):
        self.package('fixture-app', '1'); self.package('fixture-app', '2'); self.index()
        self.maintain(['fixture-app=1'])
        self.maintain(dist=True, check=True)
        self.assertEqual(self.version('fixture-app'), '1')
        self.maintain(dist=True)
        self.assertEqual(self.version('fixture-app'), '2')

    def test_removal_is_refused(self):
        self.package('fixture-app', '1')
        self.package('fixture-app', '2', extra='Conflicts: fixture-guard\n')
        self.package('fixture-guard', '1'); self.index()
        self.maintain(['fixture-app=1', 'fixture-guard=1'])
        self.maintain(['fixture-app=2'], success=False)
        self.assertEqual(self.version('fixture-app'), '1')
        self.assertEqual(self.version('fixture-guard'), '1')

    def test_holds_and_downgrades_are_not_overridden(self):
        self.package('fixture-app', '1'); self.package('fixture-app', '2'); self.index()
        self.maintain(['fixture-app=1'])
        result = self.command(['/usr/bin/dpkg', '--set-selections'], input='fixture-app hold\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"held_packages": 1', self.run_tasks(self.inventory[1:]))
        self.maintain(['fixture-app=2'], success=False)
        self.assertEqual(self.version('fixture-app'), '1')
        result = self.command(['/usr/bin/dpkg', '--set-selections'], input='fixture-app install\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.maintain(['fixture-app=2'])
        self.maintain(['fixture-app=1'], success=False)
        self.assertEqual(self.version('fixture-app'), '2')

    def test_package_contention_preserves_lock_and_installed_state(self):
        self.package('fixture-app', '1'); self.package('fixture-app', '2'); self.index()
        self.maintain(['fixture-app=1'])
        lock = self.db / 'lock-frontend'
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            inode = os.fstat(descriptor).st_ino
            fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.maintain(['fixture-app=2'], success=False)
            self.assertEqual(lock.stat().st_ino, inode)
            self.assertEqual(self.version('fixture-app'), '1')
        finally:
            os.close(descriptor)

    def test_failed_configuration_is_not_repaired_by_inventory(self):
        self.package('fixture-broken', '1', fail_configure=True); self.index()
        self.maintain(['fixture-broken=1'], success=False)
        status = (self.db / 'status').read_bytes()
        self.assertIn(b'half-configured', status)
        self.assertTrue((self.directory / 'dpkg.log').is_file())
        self.assertTrue((self.directory / 'apt-log/history.log').is_file())
        self.run_tasks(self.inventory[1:], success=False)
        self.assertEqual((self.db / 'status').read_bytes(), status)

    def test_existing_conffile_is_preserved(self):
        self.package('fixture-config', '1', conffile=True)
        self.package('fixture-config', '2', conffile=True); self.index()
        self.maintain(['fixture-config=1'])
        config = self.payload / 'fixture-config.conf'; config.write_text('operator-content\n')
        self.maintain(['fixture-config=2'])
        self.assertEqual(config.read_text(), 'operator-content\n')
        self.assertEqual(config.with_suffix('.conf.dpkg-dist').read_text(), '2\n')

    def configuration_fixture(self):
        # Rebase only fixed /etc/apt paths; execute real stat/find/assert/copy
        # tasks. A non-systemd container cannot qualify the chrony service task.
        apt_dir = self.directory / 'etc/apt'; sources = apt_dir / 'sources.list.d'
        sources.mkdir(parents=True)
        records = []
        for path in (apt_dir / 'sources.list', sources / 'fixture.sources'):
            path.write_text('before\n'); path.chmod(0o644)
            records.append({'path': str(path), 'content': 'after\n', 'mode': '0644', 'owner': 'root', 'group': 'root'})
        key = self.directory / 'fixture.pgp'; key.write_bytes(b'public fixture key'); key.chmod(0o644)
        link = self.directory / 'fixture.gpg'; link.symlink_to(key.name)
        policy = {'repository_files': records,
                  'keyrings': [{'path': str(link), 'symlink_target': key.name,
                                'sha256': hashlib.sha256(key.read_bytes()).hexdigest()}],
                  'chrony_service': {'active': True, 'enabled': True}}
        tasks = json.loads(json.dumps(self.configuration).replace('/etc/apt', str(apt_dir)))
        files_only = [task for task in tasks if 'ansible.builtin.systemd_service' not in task]
        self.assertEqual(len(tasks) - len(files_only), 1)
        return files_only, policy, sources

    def test_native_copy_preview_before_images_and_idempotence(self):
        tasks, policy, _ = self.configuration_fixture()
        variables = {'proxmox_maintenance_policy': policy}
        self.run_tasks(tasks, variables, check=True)
        for record in policy['repository_files']:
            path = Path(record['path'])
            self.assertEqual(path.read_text(), 'before\n')
            self.assertEqual(list(path.parent.glob(path.name + '.*~')), [])
        self.run_tasks(tasks, variables)
        for record in policy['repository_files']:
            path = Path(record['path'])
            self.assertEqual(path.read_text(), 'after\n')
            backups = list(path.parent.glob(path.name + '.*~'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), 'before\n')
        output = self.run_tasks(tasks, variables)
        self.assertIn('"repository_changes": 0', output)
        for record in policy['repository_files']:
            path = Path(record['path'])
            self.assertEqual(len(list(path.parent.glob(path.name + '.*~'))), 1)

    def test_native_copy_refuses_unknown_sources_before_writing(self):
        tasks, policy, sources = self.configuration_fixture()
        (sources / 'unknown.sources').write_text('unreviewed\n')
        self.run_tasks(tasks, {'proxmox_maintenance_policy': policy}, success=False)
        for record in policy['repository_files']:
            self.assertEqual(Path(record['path']).read_text(), 'before\n')
        self.assertEqual((sources / 'unknown.sources').read_text(), 'unreviewed\n')

    def test_native_copy_refuses_alias_and_changed_key_before_writing(self):
        tasks, policy, _ = self.configuration_fixture()
        path = Path(policy['repository_files'][0]['path'])
        target = self.directory / 'alias-target'; target.write_text('untouched\n')
        path.unlink(); path.symlink_to(target)
        self.run_tasks(tasks, {'proxmox_maintenance_policy': policy}, success=False)
        self.assertTrue(path.is_symlink()); self.assertEqual(target.read_text(), 'untouched\n')
        # Repair only this fixture's alias to test the independent signing-key refusal.
        path.unlink(); path.write_text('before\n'); path.chmod(0o644)
        policy['keyrings'][0]['sha256'] = '0' * 64
        self.run_tasks(tasks, {'proxmox_maintenance_policy': policy}, success=False)
        for record in policy['repository_files']:
            self.assertEqual(Path(record['path']).read_text(), 'before\n')


if __name__ == '__main__': unittest.main()
