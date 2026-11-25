#!/usr/bin/env python3
"""Behavior tests for the complete-backup lifecycle and failure boundaries."""
import configparser
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RUNNER = runpy.run_path(str(ROOT / 'scripts/restic-backup'))
LOCAL = RUNNER['LocalCapture']
CAPTURE = runpy.run_path(str(ROOT / 'scripts/restic-capture-files.py'))
OK = subprocess.CompletedProcess([], 0, '', '')

class Runtime(unittest.TestCase):
    def test_reviewed_bindings(self):
        policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        for key, name in (('runner', 'restic-backup'), ('capture', 'restic-capture-files.py')):
            actual = hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
            self.assertEqual(policy[key]['sha256' if key == 'runner' else 'adapter_sha256'], actual)
        self.assertEqual(policy['replication']['max_capture_age_seconds'], 48 * 3600)
        self.assertEqual(policy['capture']['zfs']['expiry_seconds'], 72 * 3600)
        self.assertEqual(CAPTURE['zfs_spec'](policy), policy['capture']['zfs'])
        for service in ('cli-proxy-api', 'traefik', 'traefik-tailnet'):
            self.assertNotIn(service, policy['stop_groups']['applications'])

    def test_runner_rechecks_evidence_before_executing_it(self):
        load = RUNNER['snapshot_evidence']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'restic_snapshot_evidence.py').write_text('raise AssertionError("unreviewed evidence executed")')
            load.cache_clear()
            with mock.patch.dict(load.__wrapped__.__globals__, {'__file__': str(root / 'restic-backup')}):
                with self.assertRaisesRegex(RUNNER['WorkflowError'], 'snapshot_evidence_identity'):
                    load()

    def test_frozen_radio_check_reads_wal_without_requiring_snapshot_sidecar_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            state = work / 'files/srv/home-lab-state'
            store = state / 'zwave-data'
            nvm = store / 'backups/nvm'
            nvm.mkdir(parents=True)
            (nvm / 'NVM_synthetic').write_bytes(b'fixture')
            (store / 'settings.json').write_text('{"zwave":{"port":"synthetic"}}')
            (store / 'cache.jsonl').write_text('{"k":"node","v":1}\n')
            scratch = work / 'scratch'
            scratch.mkdir()
            db_dir = state / 'hass-data'
            db_dir.mkdir()
            original = work / 'zigbee.db'
            with contextlib.closing(sqlite3.connect(original)) as writer:
                writer.execute('PRAGMA journal_mode=WAL')
                writer.execute('PRAGMA wal_autocheckpoint=0')
                writer.execute('CREATE TABLE network_backups_v1(backup_json)')
                from datetime import datetime, timezone
                record = json.dumps({'backup_time': datetime.now(timezone.utc).isoformat()})
                writer.execute('INSERT INTO network_backups_v1 VALUES (?)', (record,))
                writer.commit()
                database = db_dir / original.name
                wal = database.with_name(database.name + '-wal')
                shutil.copyfile(original, database)
                shutil.copyfile(original.with_name(original.name + '-wal'), wal)
                original_bytes = {p.name: p.read_bytes() for p in db_dir.iterdir()}
                db_dir.chmod(0o500)
                try:
                    CAPTURE['radio_check'](work / 'files', 60, snapshot_scratch=scratch)
                    self.assertEqual({p.name: p.read_bytes() for p in db_dir.iterdir()}, original_bytes)
                    self.assertEqual(list(scratch.iterdir()), [])
                finally:
                    db_dir.chmod(0o700)
                # Home Assistant's clean stop leaves a WAL-mode header but no WAL
                # or shared-memory file on the frozen filesystem.
                writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            shutil.copyfile(original, database)
            wal.unlink()
            CAPTURE['radio_check'](work / 'files', 60, snapshot_scratch=scratch)
            self.assertEqual(list(db_dir.iterdir()), [database])
            self.assertEqual(list(scratch.iterdir()), [])

    def test_frozen_zwave_store_refuses_torn_json_and_jsonl(self):
        check = CAPTURE['frozen_zwave_store_check']
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory).resolve()
            settings = store / 'settings.json'
            scenes = store / 'scenes.json'
            cache = store / 'network.jsonl'
            with self.assertRaisesRegex(CAPTURE['CaptureError'], 'zwave_store_invalid'):
                check(store)
            valid = {settings: '{"zwave":{"port":"synthetic"}}', scenes: '[]', cache: '{"k":"x","v":1}\n'}
            for path, data in valid.items():
                path.write_text(data)
            check(store)
            for path, broken in ((settings, '{"zwave":'), (settings, '{}'), (scenes, '[1,'),
                                 (cache, '{"k":"x","v":1}\n{"k":"x"'), (cache, '{"k":"x"}')):
                with self.subTest(path=path.name, broken=broken):
                    path.write_text(broken)
                    with self.assertRaisesRegex(CAPTURE['CaptureError'], 'zwave_store_invalid'):
                        check(store)
                    self.assertEqual(path.read_text(), broken)
                    path.write_text(valid[path])
            scenes.unlink()
            scenes.symlink_to(settings)
            with self.assertRaisesRegex(CAPTURE['CaptureError'], 'zwave_store_invalid'):
                check(store)

    def test_state_source_survives_device_renumbering_but_not_identity_or_mount_loss(self):
        policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        mount = next(item for item in policy['capture']['mounts'] if item['path'] == '/srv/home-lab-state')
        verify = RUNNER['verify_sources']
        policy = {'capture': {'mounts': [mount]}}
        row = {'target': mount['path'], 'fstype': 'ext4', 'source': '/dev/sdb1',
               'uuid': 'd4a19647-7879-4079-9fc9-b3e79711b449'}
        def findmnt(entries):
            return mock.Mock(return_value=subprocess.CompletedProcess(
                [], 0, json.dumps({'filesystems': entries}), ''))
        for device in ('/dev/sda1', '/dev/sdb1', '/dev/vda1'):
            native = findmnt([{**row, 'source': device}])
            with self.subTest(device=device), mock.patch.dict(verify.__globals__, {'run': native}):
                verify(policy)
                self.assertEqual(native.call_args.args[0], [
                    '/usr/bin/findmnt', '--json', '--nofsroot', '--target', mount['path'],
                    '--output', 'TARGET,FSTYPE,SOURCE,UUID'])
        for entries in ([], [row, row], [{**row, 'uuid': 'another-filesystem'}],
                        [{**row, 'uuid': None}], [{**row, 'fstype': 'xfs'}],
                        [{**row, 'target': '/'}], [{**row, 'target': '/somewhere-else'}]):
            with self.subTest(entries=entries), mock.patch.dict(verify.__globals__, {'run': findmnt(entries)}):
                with self.assertRaisesRegex(RUNNER['WorkflowError'], 'source_mount_identity'):
                    verify(policy)

    def test_nfs_preflight_accepts_only_exact_host_export_or_bound_repository(self):
        policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        repository = policy['repositories']['nfs']
        preflight = RUNNER['preflight']
        root = repository['mountpoint']
        path = repository['path']
        source = repository['mount_source']
        subtree = source + '/' + str(Path(path).relative_to(root))
        for target, native_source in [(root, source), (path, subtree)]:
            row = {'target': target, 'fstype': 'nfs4', 'source': native_source, 'uuid': None}
            native = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps({'filesystems': [row]}), ''))
            with self.subTest(target=target), mock.patch.dict(preflight.__globals__, {
                    'testing': lambda: False, 'run': native,
                    'verify_repository': lambda *_: {'chunker_polynomial': 'synthetic'}}):
                preflight(policy, ['nfs'])
                self.assertEqual(native.call_args.args[0][native.call_args.args[0].index('--target') + 1], path)

    def test_nfs_preflight_refuses_wrong_server_export_target_or_bound_subtree(self):
        policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        repository = policy['repositories']['nfs']
        preflight = RUNNER['preflight']
        root, path, source = repository['mountpoint'], repository['path'], repository['mount_source']
        for target, native_source, filesystem in [
                (path, source, 'nfs4'), (path, source + '/other', 'nfs4'),
                (path, '192.168.0.124:/storage/docker/restic/home-lab', 'nfs4'),
                (path, '192.168.0.123:/storage/other/restic/home-lab', 'nfs4'),
                (root + '/restic', source, 'nfs4'), (root, source, 'ext4')]:
            row = {'target': target, 'fstype': filesystem, 'source': native_source, 'uuid': None}
            native = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps({'filesystems': [row]}), ''))
            with self.subTest(target=target, source=native_source), mock.patch.dict(preflight.__globals__, {
                    'testing': lambda: False, 'run': native,
                    'verify_repository': mock.Mock(side_effect=AssertionError('must refuse before repository access'))}):
                with self.assertRaisesRegex(RUNNER['WorkflowError'], 'source_mount_identity'):
                    preflight(policy, ['nfs'])

    def coordination_fixture(self, directory):
        root = Path(directory).resolve()
        gate = root / 'run/lock/home-lab-restic-repositories.lock'
        gate.parent.mkdir(parents=True)
        for name in ('home-lab-restic-repositories.lock', 'home-lab-backup.lock',
                     'home-lab-restic-daily-nfs.lock', 'home-lab-restic-daily-proton.lock'):
            path = gate.with_name(name)
            path.touch(mode=0o660)
            path.chmod(0o660)
        policy = root / 'etc/home-lab/restic-policy.json'
        policy.parent.mkdir(parents=True)
        policy.write_text(json.dumps({'policy_version': 1, 'runner': {
            'lock_path': '/run/lock/home-lab-backup.lock',
            'deploy_lock_path': '/var/lib/iac-ansible-production.lock',
        }}))
        policy.chmod(0o440)
        fence = root / 'var/lib/home-lab-restic/tools-updating'
        fence.parent.mkdir(parents=True)
        return root, gate, fence

    def interruption_fixture(self, directory, *, production=True, journal_owner='bound'):
        root, _, _ = self.coordination_fixture(directory)
        owner = root / 'var/lib/iac-ansible-production.lock/owner'
        owner_bytes = b'synthetic strict-change owner\n'
        digest = hashlib.sha256(owner_bytes).hexdigest()
        if production:
            owner.parent.mkdir(mode=0o700)
            owner.write_bytes(owner_bytes)
            owner.chmod(0o600)
        journal = root / 'var/lib/home-lab-restic/interruption.json'
        value = {'version': 1, 'running_services': ['app'], 'stop_order': ['app', 'inactive']}
        if journal_owner != 'legacy':
            value['owner'] = digest if journal_owner == 'bound' else journal_owner
        journal.write_text(json.dumps(value))
        journal.chmod(0o600)
        path = root / 'etc/home-lab/restic-policy.json'
        policy = json.loads(path.read_text())
        policy['runner']['journal_path'] = '/var/lib/home-lab-restic/interruption.json'
        policy['stop_groups'] = {'applications': ['app', 'inactive'], 'databases': []}
        path.chmod(0o600)
        path.write_text(json.dumps(policy))
        path.chmod(0o440)
        return root, owner, journal

    def test_boot_recovery_resumes_only_recorded_services_and_retains_production_owner(self):
        main = RUNNER['main']
        for production, binding in ((True, 'bound'), (False, None), (False, 'legacy')):
            with self.subTest(production=production, binding=binding), tempfile.TemporaryDirectory() as directory:
                root, owner, journal = self.interruption_fixture(directory, production=production, journal_owner=binding)
                before = owner.read_bytes() if production else None
                compose = mock.Mock(return_value=OK)
                with mock.patch.dict(os.environ, {
                    'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root),
                }), mock.patch.object(sys, 'argv', ['restic-backup', 'recover']), mock.patch('signal.signal'), \
                        mock.patch.dict(main.__globals__, {
                            'compose': compose, 'service_healthy': lambda *_: True,
                            'preflight': mock.Mock(side_effect=AssertionError('recovery must not open repositories')),
                        }):
                    main()
                compose.assert_called_once_with(mock.ANY, ['start', 'app'])
                self.assertFalse(journal.exists())
                self.assertEqual(owner.read_bytes() if production else None, before)
                self.assertEqual(owner.parent.exists(), production)

    def test_recovery_refuses_unbound_mismatched_or_missing_production_ownership(self):
        main = RUNNER['main']
        cases = [(True, binding, 'recover') for binding in ('legacy', None, 'f' * 64, 123, {})]
        cases += [(False, 'bound', 'recover'), (True, 'bound', 'preflight'), (True, 'bound', 'daily-local')]
        for production, binding, command in cases:
            with self.subTest(production=production, binding=binding, command=command), tempfile.TemporaryDirectory() as directory:
                root, owner, journal = self.interruption_fixture(directory, production=production, journal_owner=binding)
                before = journal.read_bytes()
                compose = mock.Mock()
                with mock.patch.dict(os.environ, {
                    'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root),
                }), mock.patch.object(sys, 'argv', ['restic-backup', command]), mock.patch('signal.signal'), \
                        mock.patch.dict(main.__globals__, {'compose': compose}), \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                    main()
                self.assertEqual(failure.exception.code, 1)
                compose.assert_not_called()
                self.assertEqual(journal.read_bytes(), before)
                self.assertEqual(owner.parent.exists(), production)

    def test_failed_owned_boot_recovery_retains_both_journal_and_owner(self):
        main = RUNNER['main']
        with tempfile.TemporaryDirectory() as directory:
            root, owner, journal = self.interruption_fixture(directory)
            before = (owner.read_bytes(), journal.read_bytes())
            compose = mock.Mock(return_value=OK)
            with mock.patch.dict(os.environ, {
                'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root),
            }), mock.patch.object(sys, 'argv', ['restic-backup', 'recover']), mock.patch('signal.signal'), \
                    mock.patch.dict(main.__globals__, {'compose': compose, 'service_healthy': lambda *_: False}), \
                    mock.patch('time.monotonic', side_effect=[0, 1, 4]), mock.patch('time.sleep'), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                main()
            self.assertEqual(failure.exception.code, 1)
            compose.assert_called_once_with(mock.ANY, ['start', 'app'])
            self.assertEqual((owner.read_bytes(), journal.read_bytes()), before)

    def test_copy_reads_policy_and_reconciles_under_the_shared_gate(self):
        main = RUNNER['main']
        load_policy = RUNNER['load_policy']
        with tempfile.TemporaryDirectory() as directory:
            root, gate, _ = self.coordination_fixture(directory)
            def require_shared_gate():
                with gate.open('a+') as updater:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(updater, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def load():
                require_shared_gate()
                return load_policy()
            def reconcile(_policy, _destination):
                require_shared_gate()
            for command in ('daily-nfs', 'daily-proton'):
                with self.subTest(command=command), mock.patch.dict(os.environ, {
                    'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root),
                }), mock.patch.object(sys, 'argv', ['restic-backup', command]), mock.patch('signal.signal'), \
                        mock.patch.dict(main.__globals__, {'load_policy': load, 'reconcile': reconcile}):
                    main()
                with gate.open('a+') as updater:
                    fcntl.flock(updater, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_owner_bound_capture_can_start_during_both_replica_transfers(self):
        main = RUNNER['main']
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            root, owner, _ = self.interruption_fixture(directory)
            digest = hashlib.sha256(owner.read_bytes()).hexdigest()
            locks = root / 'run/lock'
            gate = stack.enter_context((locks / 'home-lab-restic-repositories.lock').open('a+'))
            fcntl.flock(gate, fcntl.LOCK_SH | fcntl.LOCK_NB)
            for destination in ('nfs', 'proton'):
                lock = stack.enter_context((locks / f'home-lab-restic-daily-{destination}.lock').open('a+'))
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (mock.patch.dict(os.environ, HOME_LAB_RESTIC_TESTING='1', HOME_LAB_RESTIC_TEST_ROOT=str(root)),
                  mock.patch.object(sys, 'argv', ['restic-backup', 'daily-local', '--owner-sha256', digest]),
                  mock.patch('signal.signal'), mock.patch.object(LOCAL, 'run', autospec=True) as capture):
                main()
            capture.assert_called_once()
            self.assertEqual(capture.call_args.args[0].policy['_owner'], digest)

    def test_ordinary_nfs_still_refuses_a_concurrent_copy(self):
        main = RUNNER['main']
        with tempfile.TemporaryDirectory() as directory:
            root, gate, _ = self.coordination_fixture(directory)
            reconcile = mock.Mock()
            with gate.with_name('home-lab-restic-daily-nfs.lock').open('a+') as active, \
                    mock.patch.dict(os.environ, {
                        'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root),
                    }), mock.patch.object(sys, 'argv', ['restic-backup', 'daily-nfs']), \
                    mock.patch('signal.signal'), mock.patch.dict(main.__globals__, {'reconcile': reconcile}), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit):
                fcntl.flock(active, fcntl.LOCK_EX | fcntl.LOCK_NB)
                main()
            self.assertIn('reason=concurrent_operation', stderr.getvalue())
            reconcile.assert_not_called()

    def test_maintenance_waits_for_copy_then_succeeds_without_manual_reset(self):
        main = RUNNER['main']
        flock = fcntl.flock
        with tempfile.TemporaryDirectory() as directory:
            root, gate, _ = self.coordination_fixture(directory)
            requested, finished = threading.Event(), threading.Event()
            flags_seen, errors = [], []
            maintenance = mock.Mock()
            def acquire(stream, flags):
                if Path(stream.name) == gate:
                    flags_seen.append(flags)
                    requested.set()
                return flock(stream, flags)
            def invoke():
                try:
                    main()
                except BaseException as error:
                    errors.append(error)
                finally:
                    finished.set()
            with gate.open('a+') as copy, mock.patch.dict(os.environ, {
                'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root),
            }), mock.patch.object(sys, 'argv', ['restic-backup', 'maintenance']), mock.patch('signal.signal'), \
                    mock.patch.object(fcntl, 'flock', side_effect=acquire), \
                    mock.patch.dict(main.__globals__, {'maintenance': maintenance}):
                flock(copy, fcntl.LOCK_SH | fcntl.LOCK_NB)
                worker = threading.Thread(target=invoke, daemon=True)
                worker.start()
                try:
                    self.assertTrue(requested.wait(5))
                    self.assertEqual(flags_seen, [fcntl.LOCK_EX])
                    self.assertFalse(finished.is_set())
                    maintenance.assert_not_called()
                finally:
                    flock(copy, fcntl.LOCK_UN)
                    worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                maintenance.assert_called_once()
            observer = runpy.run_path(str(ROOT / 'scripts/observe-restic-backups.py'))
            observer['validate_unit_state']('home-lab-restic-maintenance-local.service', {
                'ActiveState': 'inactive', 'SubState': 'dead', 'Result': 'success'}, routine=True)
            with self.assertRaises(observer['ObservationError']):
                observer['validate_unit_state']('home-lab-restic-maintenance-local.service', {
                    'ActiveState': 'failed', 'SubState': 'failed', 'Result': 'exit-code'}, routine=True)

    def test_copy_rechecks_fence_after_gate_acquisition(self):
        main = RUNNER['main']
        flock = fcntl.flock
        with tempfile.TemporaryDirectory() as directory:
            root, _, fence = self.coordination_fixture(directory)
            # Publish the update fence while the reader is about to acquire its
            # gate, after any pre-lock check. No timing or sleeps are needed.
            def publish_before_lock(stream, flags):
                if flags & fcntl.LOCK_SH:
                    fence.touch(mode=0o600)
                return flock(stream, flags)
            reconcile = mock.Mock()
            with mock.patch.dict(os.environ, {
                'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root),
            }), mock.patch.object(sys, 'argv', ['restic-backup', 'daily-nfs']), mock.patch('signal.signal'), \
                    mock.patch.object(fcntl, 'flock', side_effect=publish_before_lock), \
                    mock.patch.dict(main.__globals__, {'reconcile': reconcile}), \
                    mock.patch('builtins.print'), self.assertRaises(SystemExit) as failure:
                main()
            self.assertEqual(failure.exception.code, 1)
            reconcile.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'requires native util-linux flock')
    def test_tool_update_barrier_refuses_a_direct_copy_and_succeeds_after_it_exits(self):
        import yaml
        tasks = yaml.safe_load((ROOT / 'ansible/roles/restic_backup/tasks/tools-native.yml').read_text())
        task = next(t for t in tasks if t['name'] == 'Require every repository reader to finish before replacement')
        with tempfile.TemporaryDirectory() as directory:
            _, gate, _ = self.coordination_fixture(directory)
            argv = [str(gate) if value == '/run/lock/home-lab-restic-repositories.lock' else value
                    for value in task['ansible.builtin.command']['argv']]
            with gate.open('a+') as reader:
                fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
                refused = subprocess.run(argv, capture_output=True, timeout=5)
                self.assertNotEqual(refused.returncode, 0)
            accepted = subprocess.run(argv, capture_output=True, timeout=5)
            self.assertEqual(accepted.returncode, 0)

    def pause_policy(self, *services, owner=None):
        return {'capture': {'live_files': [], 'online_json': [], 'cli_auth': '/unused/auth', 'jellyfin': '/unused/jellyfin'},
                'stop_groups': {'applications': list(services), 'databases': []},
                'runner': {'exclude_file_path': '/excluded'}, '_owner': owner}

    def cold_plan(self, policy, steps, declared):
        return CAPTURE['capture_plan']({**policy, 'capture': {**policy['capture'], 'cold': steps}}, declared)

    def test_stop_copy_restart_has_no_repository_phase_and_preserves_inactive_services(self):
        cold = LOCAL._pause_writers
        events = []
        adapter = mock.Mock()
        adapter.copy_paths.side_effect = lambda *_: events.append('copy')
        adapter.retry.side_effect = lambda action: action()
        adapter.database_dump.side_effect = lambda *_: events.append('dump')
        policy = self.pause_policy('app', 'inactive', owner='a' * 64)
        recorded = mock.Mock()
        step = {'name': 'example', 'services': ['app', 'inactive'], 'paths': ['/protected'],
                'databases': [{'engine': 'postgres', 'name': 'db.dump'}]}
        state = {'app': True, 'inactive': False}
        def compose(_policy, args):
            events.append(args)
            state['app'] = False
            return OK
        with mock.patch.dict(cold.__globals__, {
            'rooted': Path, 'journal_path': lambda _: Path('/unused'),
            'service_running': lambda _, s: state[s], 'atomic_json': recorded,
            'compose': compose,
            'restic_result': mock.Mock(side_effect=AssertionError('upload during cold window')),
        }), mock.patch.object(LOCAL, '_restart', side_effect=lambda _: events.append('restart')):
            cold(LOCAL(policy), adapter, self.cold_plan(policy, [step], {'app', 'inactive'}), Path('/unused'), 'b' * 32)
        self.assertEqual(events, [['stop', '--timeout', '120', 'app'], 'copy', 'dump', 'restart'])
        self.assertEqual(recorded.call_args.args[1]['owner'], policy['_owner'])

    def test_reviewed_capture_plan_keeps_online_writers_and_stops_other_services_at_most_once(self):
        policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        snapshot_online = {service: f'/srv/home-lab-state/{service}-data' for service in (
            'karaoke-eternal', 'seerr', 'prowlarr', 'sonarr', 'radarr', 'qbittorrent', 'zwave')}
        snapshot_online['homeassistant'] = '/srv/home-lab-state/hass-data'
        snapshot_online['omada'] = '/srv/home-lab-state/omada-data/data'
        kept = {'cli-proxy-api', 'traefik', 'traefik-tailnet', 'gluetun', 'flaresolverr',
                'ddns-updater', 'recyclarr', 'vaultwarden', 'openfit', 'mindwtr-cloud', 'mosquitto', 'wolf',
                'authentik-server', 'authentik-worker'} | snapshot_online.keys()
        declared = kept | {s for step in policy['capture']['cold'] for s in step['services']}
        plan = CAPTURE['capture_plan'](policy, declared)
        self.assertTrue(set(map(Path, snapshot_online.values())) <= set(plan.sources.state))
        running = set(declared)
        stops = []
        adapter = mock.Mock()
        adapter.retry.side_effect = lambda operation: operation()
        adapter.database_dump.side_effect = lambda *_: self.assertEqual(running, kept)
        token = 'b' * 32
        adapter.state_snapshot_record.side_effect = CAPTURE['state_snapshot_record']
        adapter.zfs_spec.return_value = policy['capture']['zfs']
        adapter.zfs_record.side_effect = CAPTURE['zfs_record']
        scope = {'capture': token, 'owner': hashlib.sha256(token.encode()).hexdigest()}
        def snapshots(_spec, request):
            self.assertEqual(running, kept)
            if request['action'] == 'state-create':
                return {**scope, 'id': 'abcdef-aaaa-bbbb-cccc-dddd-eeee-ffffff', 'created': 1,
                        'bytes': policy['capture']['state_snapshot']['bytes']}
            self.assertEqual(request['action'], 'create')
            return {**scope, 'guid': '123', 'created': 1, 'dataset_guid': policy['capture']['zfs']['dataset_guid']}
        adapter.zfs_call.side_effect = snapshots
        def compose(_policy, args):
            if args[0] == 'stop':
                self.assertTrue(kept.isdisjoint(args[3:]))
                stops.append(args[3:])
                running.difference_update(args[3:])
            else:
                self.assertTrue(kept.isdisjoint(args[1:]))
                running.update(args[1:])
            return OK
        cold = LOCAL._pause_writers
        with mock.patch.dict(cold.__globals__, {
            'rooted': Path, 'journal_path': lambda _: Path('/unused'), 'atomic_json': mock.Mock(),
            'durable_unlink': mock.Mock(), 'service_container': lambda _, s: s,
            'service_running': lambda _, s: s in running, 'service_healthy': lambda *_: True,
            'nextcloud_healthy': lambda *_: True,
            'compose': compose,
        }):
            cold(LOCAL(policy), adapter, plan, Path('/unused'), token)
        self.assertEqual(running, declared)
        self.assertEqual(stops, [policy['stop_groups']['applications']])
        self.assertEqual(set(stops[0]), declared - kept)
        self.assertTrue({'nextcloud', 'nextcloud-cron', 'shelfmark', 'bookorbit', 'sabnzbd'} <= set(stops[0]))
        self.assertEqual([call.args[1]['action'] for call in adapter.zfs_call.call_args_list],
                         ['create', 'state-create'])
        adapter.copy_paths.assert_not_called()
        adapter.precopy.assert_not_called()
        adapter.finish_copy.assert_not_called()

    def test_fresh_capture_and_ready_retry_use_the_same_archive_sources(self):
        daily = LOCAL.run
        capacity = CAPTURE['capacity_check']
        policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        settings = policy['capture']
        state_path = Path('/srv/home-lab-state/omada-data/data')
        zfs_path = '/mnt/storage/media/caro-tachidesk'
        live_path = Path('/mnt/games/roms')
        state_receipt = {'created': 1, 'id': 'abcdef-aaaa-bbbb-cccc-dddd-eeee-ffffff',
                         'bytes': settings['state_snapshot']['bytes']}
        zfs_receipt = {'created': int(time.time()), 'guid': '789', 'dataset_guid': settings['zfs']['dataset_guid']}
        declared = mock.Mock(return_value={*policy['stop_groups']['applications'],
                                            *settings['state_snapshot']['online_paths'],
                                            'authentik-server', 'authentik-worker', 'mosquitto'})
        adapter = mock.Mock(CaptureError=CAPTURE['CaptureError'], capture_plan=CAPTURE['capture_plan'],
                            capture_sources=CAPTURE['capture_sources'], capacity_check=capacity,
                            zfs_record=CAPTURE['zfs_record'], state_snapshot_record=CAPTURE['state_snapshot_record'],
                            zfs_spec=CAPTURE['zfs_spec'])
        adapter.zfs_inventory.return_value = []
        adapter.state_snapshot_attached.side_effect = lambda *_: contextlib.nullcontext()
        adapter.live_games_mounted.side_effect = lambda *_: contextlib.nullcontext()
        adapter.fresh_stage.side_effect = lambda path, _: (path.mkdir(mode=0o700) or path)
        adapter.retry.side_effect = lambda operation: operation()
        adapter.state_snapshot_exclusions.return_value = []
        def snapshot_receipts(_adapter, _plan, stage, token):
            owner = hashlib.sha256(token.encode()).hexdigest()
            for record in (zfs_receipt, state_receipt):
                record.update(capture=token, owner=owner)
            RUNNER['atomic_json'](stage / 'zfs-source.json', {
                'version': 1, 'capture': token, 'owner': owner, 'production_owner': None,
                'running_services': [], 'record': zfs_receipt,
            })
            RUNNER['atomic_json'](stage / 'state-source.json', state_receipt)
        cold = mock.Mock(side_effect=snapshot_receipts)
        adapter.zfs_call.side_effect = lambda _, request: state_receipt if request['action'] == 'state-ready' else zfs_receipt
        upload = mock.Mock(return_value=subprocess.CompletedProcess([], 3, '', ''))
        du = mock.Mock(return_value=f'10\t{settings["jellyfin"]}\n20\ttotal\n'.encode())
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(daily.__globals__, {
            'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
            'capture_adapter': lambda _: adapter, 'rooted': Path, 'declared_services': declared,
            'artifact_hash': lambda _: 'b' * 64, 'restic_result': upload,
            'service_container': lambda _, service: service, 'service_running': lambda *_: True,
            'inventory': lambda *_: [],
        }), mock.patch.object(LOCAL, 'recover'), mock.patch.object(LOCAL, '_pause_writers', cold), \
                mock.patch.dict(capacity.__globals__, {
            'command': du, 'verify_live_games_sources': mock.Mock(),
            'shutil': types.SimpleNamespace(disk_usage=lambda _: types.SimpleNamespace(free=10**12)),
        }):
            stage = Path(directory).resolve() / 'capture'
            settings['stage'] = str(stage)
            for retry in (False, True):
                if retry:
                    declared.side_effect = AssertionError('ready retry consulted Compose')
                with self.subTest(retry=retry), self.assertRaisesRegex(RUNNER['WorkflowError'], 'restic_partial_source'):
                    daily(LOCAL(policy), 'a' * 64)
            manifest = json.loads((stage / 'manifest.json').read_text())
        du.assert_called_once()
        estimate = du.call_args.args[0]
        self.assertNotIn(str(state_path), estimate)
        self.assertNotIn(zfs_path, estimate)
        self.assertIn(str(live_path), estimate)
        self.assertIn('/srv/home-lab-state/authentik-data/media', estimate)
        cold.assert_called_once()
        self.assertEqual(adapter.zfs_mount.call_count, 2)
        self.assertEqual(upload.call_count, 2)
        first_state, retry_state = [call.args[-1] for call in adapter.state_snapshot_attached.call_args_list]
        self.assertEqual(first_state, retry_state)
        self.assertIn(state_path, first_state)
        first_live, retry_live = [call.args[0] for call in adapter.live_games_mounted.call_args_list]
        self.assertEqual(first_live, retry_live)
        self.assertIn(live_path, first_live)
        self.assertEqual(manifest['state_source'], state_receipt)
        self.assertEqual(manifest['zfs_source'], zfs_receipt)
        self.assertIn(zfs_path, manifest['zfs_paths'])
        self.assertIn('omada', [row['name'] for row in manifest['captures']])

    def test_invalid_capture_scope_refuses_before_staging_or_pausing_writers(self):
        daily = LOCAL.run
        for service, path, extra, error in (
                ('stopped', '/srv/home-lab-state/online', [], 'state_snapshot_online_services'),
                ('undeclared', '/srv/home-lab-state/online', [], 'state_snapshot_online_services'),
                ('online', '/mnt/storage/media/online', [], 'state_snapshot_scope'),
                ('online', '/srv/home-lab-state/app/nested', [], 'state_snapshot_scope'),
                ('online', '/srv/home-lab-state/../outside', [], 'state_snapshot_scope'),
                ('online', '/srv/home-lab-state/online', ['/srv/home-lab-state/online'], 'capture_path_scope')):
            with self.subTest(service=service, path=path, extra=extra), tempfile.TemporaryDirectory() as directory:
                policy = self.pause_policy('stopped')
                stage = Path(directory) / 'capture'
                steps = [{'name': 'app', 'services': ['stopped'],
                          'paths': ['/srv/home-lab-state/app', *CAPTURE['zfs_paths']()]}]
                policy['capture'].update(stage=str(stage), zfs=True, cold=steps, live_files=extra,
                                         state_snapshot={'online_paths': {service: path}})
                adapter = mock.Mock(CaptureError=CAPTURE['CaptureError'], capture_plan=CAPTURE['capture_plan'])
                compose, journal, upload = mock.Mock(), mock.Mock(), mock.Mock()
                with mock.patch.dict(daily.__globals__, {
                    'rooted': Path, 'capture_adapter': lambda _: adapter,
                    'declared_services': lambda _: {'stopped', 'online'},
                    'preflight': mock.Mock(), 'verify_sources': mock.Mock(), 'compose': compose,
                    'atomic_json': journal, 'restic_result': upload,
                }), mock.patch.object(LOCAL, 'recover'), self.assertRaisesRegex(RUNNER['WorkflowError'], error):
                    daily(LOCAL(policy), 'a' * 64)
                self.assertFalse(stage.exists())
                adapter.fresh_stage.assert_not_called()
                compose.assert_not_called()
                journal.assert_not_called()
                upload.assert_not_called()

    def test_failed_precopy_never_interrupts_a_writer_or_publishes_a_journal(self):
        cold = LOCAL._pause_writers
        adapter = mock.Mock()
        adapter.retry.side_effect = lambda operation: operation()
        adapter.precopy.side_effect = CAPTURE['CaptureError']('copy_failed')
        journal, compose = mock.Mock(), mock.Mock()
        policy = self.pause_policy('app')
        plan = self.cold_plan(policy, [{'name': 'library', 'services': ['app'], 'paths': ['/library'], 'precopy': True}], {'app'})
        with mock.patch.dict(cold.__globals__, {'rooted': Path, 'atomic_json': journal, 'compose': compose}), \
                self.assertRaisesRegex(CAPTURE['CaptureError'], 'copy_failed'):
            cold(LOCAL(policy), adapter, plan, Path('/stage'), 'b' * 32)
        journal.assert_not_called()
        compose.assert_not_called()

    def test_precopy_runs_online_and_final_sync_finishes_before_restart(self):
        cold = LOCAL._pause_writers
        events, running = [], {'app'}
        baseline = {'synthetic': 'before'}
        adapter = mock.Mock()
        adapter.retry.side_effect = lambda operation: operation()
        def precopy(*_):
            self.assertEqual(running, {'app'})
            events.append('precopy')
            return baseline
        def finish(*_, **kwargs):
            self.assertEqual(running, set())
            self.assertEqual(kwargs['baseline'], baseline)
            events.append('final-sync')
        adapter.precopy.side_effect = precopy
        adapter.finish_copy.side_effect = finish
        def compose(_policy, args):
            self.assertEqual(args, ['stop', '--timeout', '120', 'app'])
            events.append('stop')
            running.clear()
            return OK
        def restart(*_):
            events.append('restart')
            running.add('app')
        policy = self.pause_policy('app')
        plan = self.cold_plan(policy, [{'name': 'library', 'services': ['app'], 'paths': ['/library'], 'precopy': True}], {'app'})
        with mock.patch.dict(cold.__globals__, {
            'rooted': Path, 'journal_path': lambda _: Path('/unused'), 'atomic_json': mock.Mock(),
            'service_running': lambda _, s: s in running, 'compose': compose,
        }), mock.patch.object(LOCAL, '_restart', side_effect=restart):
            cold(LOCAL(policy), adapter, plan, Path('/stage'), 'b' * 32)
        self.assertEqual(events, ['precopy', 'stop', 'final-sync', 'restart'])
        self.assertEqual(running, {'app'})

    def test_failed_stop_or_copy_always_attempts_restart(self):
        cold = LOCAL._pause_writers
        for phase in ('stop', 'copy'):
            with self.subTest(phase=phase):
                adapter = mock.Mock()
                adapter.retry.side_effect = lambda operation: operation()
                if phase == 'copy':
                    adapter.copy_paths.side_effect = CAPTURE['CaptureError']('copy')
                restart = mock.Mock()
                policy = self.pause_policy('app')
                plan = self.cold_plan(policy, [{'name': 'app', 'services': ['app'], 'paths': ['/data']}], {'app'})
                with mock.patch.dict(cold.__globals__, {
                    'rooted': Path, 'journal_path': lambda _: Path('/unused'),
                    'service_running': mock.Mock(side_effect=[True, False]), 'atomic_json': mock.Mock(),
                    'compose': mock.Mock(return_value=OK if phase == 'copy' else subprocess.CompletedProcess([], 1, '', '')),
                }), mock.patch.object(LOCAL, '_restart', restart), self.assertRaises((RUNNER['WorkflowError'], CAPTURE['CaptureError'])):
                    cold(LOCAL(policy), adapter, plan, Path('/unused'), 'b' * 32)
                self.assertEqual(restart.call_args.args[0]['running_services'], ['app'])

    def test_authentik_online_capture_precedes_stops_and_preserves_restore_descriptor(self):
        daily = LOCAL.run
        reviewed = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        step = next(s for s in reviewed['capture']['online'] if s['name'] == 'authentik')
        books = next(s for s in reviewed['capture']['cold'] if s['name'] == 'bookorbit')
        for outcome in ('ready', 'changed_files', 'overlapping_stop'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                stage = Path(directory).resolve() / 'capture'
                policy = self.pause_policy(*books['services'])
                policy['capture'] = {'stage': str(stage), 'reserve_bytes': 0, 'radio_max_age_seconds': 10,
                                     'online': [step], 'cold': [books], 'live_files': [], 'online_json': [],
                                     'cli_auth': '/unused/auth', 'jellyfin': '/unused/jellyfin'}
                if outcome == 'overlapping_stop':
                    policy['stop_groups']['applications'].append('authentik-worker')
                    policy['capture']['cold'] = [{**books, 'services': [*books['services'], 'authentik-worker']}]
                adapter = mock.Mock(CaptureError=CAPTURE['CaptureError'], capture_plan=CAPTURE['capture_plan'])
                adapter.retry.side_effect = CAPTURE['retry']
                adapter.fresh_stage.side_effect = lambda path, _: (path.mkdir() or path)
                cold, upload = mock.Mock(), mock.Mock()
                events = []
                def online(*_args, **_kwargs):
                    events.append('authentik')
                    if outcome == 'changed_files':
                        raise CAPTURE['CaptureError']('online_source_changed')
                adapter.online_postgres.side_effect = online
                cold.side_effect = lambda *_: events.append('cold')
                def restic(*_args, **_kwargs):
                    events.append('upload')
                    # Do not need a real repository to observe the ready manifest.
                    return subprocess.CompletedProcess([], 3, '', '')
                upload.side_effect = restic
                with mock.patch.dict(daily.__globals__, {
                    'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                    'capture_adapter': lambda _: adapter, 'rooted': Path,
                    'declared_services': lambda _: {*step['services'], *books['services']},
                    'artifact_hash': lambda _: 'b' * 64, 'restic_result': upload,
                }), mock.patch.object(LOCAL, 'recover'), mock.patch.object(LOCAL, '_pause_writers', cold), \
                        mock.patch('time.sleep'), self.assertRaisesRegex(RUNNER['WorkflowError'], {
                    'ready': 'restic_partial_source', 'changed_files': 'capture_phase_failed',
                    'overlapping_stop': 'online_postgres_scope',
                }[outcome]):
                    daily(LOCAL(policy), 'a' * 64)
                if outcome == 'ready':
                    self.assertEqual(events, ['authentik', 'cold', 'upload'])
                    adapter.online_postgres.assert_called_once_with(
                        step['paths'], stage / 'files', Path('/excluded'), spec=step['databases'][0],
                        target=stage / 'databases/authentik.dump')
                    manifest = json.loads((stage / 'manifest.json').read_text())
                    self.assertEqual(manifest['databases'], [*step['databases'], *books['databases']])
                    self.assertIn('authentik', [capture['name'] for capture in manifest['captures']])
                else:
                    self.assertEqual(events, ['authentik'] * 3 if outcome == 'changed_files' else [])
                    if outcome == 'overlapping_stop':
                        adapter.fresh_stage.assert_not_called()
                    cold.assert_not_called()
                    upload.assert_not_called()
                    self.assertFalse((stage / 'manifest.json').exists())

    def test_unready_stage_is_preserved_without_restarting_capture(self):
        daily = LOCAL.run
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory).resolve() / 'capture'
            stage.mkdir(mode=0o700)
            payload = stage / 'partial-copy'
            payload.write_bytes(b'synthetic interrupted capture')
            declared, cold = mock.Mock(), mock.Mock()
            with mock.patch.dict(daily.__globals__, {
                'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                'capture_adapter': lambda _: types.SimpleNamespace(CaptureError=CAPTURE['CaptureError']),
                'rooted': Path, 'declared_services': declared,
            }), mock.patch.object(LOCAL, 'recover'), mock.patch.object(LOCAL, '_pause_writers', cold), \
                    self.assertRaisesRegex(RUNNER['WorkflowError'], 'previous_capture_requires_inspection'):
                daily(LOCAL({'capture': {'stage': str(stage)}}), 'a' * 64)
            self.assertEqual(payload.read_bytes(), b'synthetic interrupted capture')
            declared.assert_not_called()
            cold.assert_not_called()

    def test_ready_stage_retries_upload_without_another_stop_copy_or_export(self):
        daily = LOCAL.run
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory).resolve() / 'stage'
            stage.mkdir(mode=0o700)
            manifest = {'version': 2, 'capture': '1' * 32, 'policy': 'a' * 64, 'artifact': 'b' * 64,
                        'owner': None, 'captured_at': '2026-11-10T00:00:00+00:00'}
            (stage / 'manifest.json').write_text(json.dumps(manifest))
            adapter = types.SimpleNamespace(CaptureError=CAPTURE['CaptureError'], capture_sources=CAPTURE['capture_sources'])
            events = []
            def restic(_policy, _repository, args, **kwargs):
                events.append(args[0])
                if args[0] == 'backup':
                    return subprocess.CompletedProcess([], 0, json.dumps({'message_type': 'summary', 'snapshot_id': 'c' * 64}), '')
                return OK
            with mock.patch.dict(daily.__globals__, {
                'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                'capture_adapter': lambda _: adapter, 'rooted': Path,
                'artifact_hash': lambda _: 'b' * 64, 'read_json': lambda *_: manifest,
                'declared_services': mock.Mock(side_effect=AssertionError('replanning ready stage')),
                'restic_result': restic,
                'inventory': mock.Mock(side_effect=[[], [{'id': 'd' * 64, 'tags': [
                    'capture=' + '1' * 32, 'complete=full-v2', 'format=full-v2', 'cadence=daily',
                    'policy=' + 'a' * 64, 'artifact=' + 'b' * 64]}]]),
            }), mock.patch.object(LOCAL, 'recover'), mock.patch.object(LOCAL, '_pause_writers',
                    side_effect=AssertionError('recapture')), mock.patch('builtins.print'):
                daily(LOCAL({'capture': {'stage': str(stage)}}), 'a' * 64)
            self.assertEqual(events, ['backup', 'tag'])
            self.assertFalse(stage.exists())

    def test_replication_cancellation_does_not_retry(self):
        reconcile = RUNNER['reconcile']
        source = {'id': 'a' * 64, 'time': '2026-11-13T00:00:00Z',
                  'tags': ['cadence=daily', 'format=full-v2', 'complete=full-v2']}
        for reason, attempts in [('interrupted', 1), ('copy_stop_timeout', 1), ('copy_proton', 3)]:
            copying = mock.Mock(side_effect=RUNNER['WorkflowError'](reason))
            with self.subTest(reason=reason), mock.patch.dict(reconcile.__globals__, {
                    'preflight': mock.Mock(),
                    'inventory': lambda _policy, name: [source] if name == 'games' else [],
                    'copy_snapshot': copying,
                }), mock.patch('time.sleep'), self.assertRaisesRegex(RUNNER['WorkflowError'], reason):
                reconcile({}, 'proton')
            self.assertEqual(copying.call_count, attempts, 'only ordinary copy failures may retry')

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux process ownership checks')
    def test_copy_stop_keeps_gate_until_child_cleanup_and_never_retries(self):
        for number, stubborn in [(signal.SIGINT, False), (signal.SIGTERM, False), (signal.SIGINT, True)]:
            with self.subTest(signal=number, stubborn=stubborn), tempfile.TemporaryDirectory() as directory:
                root, gate, _ = self.coordination_fixture(directory)
                owner = root / 'var/lib/iac-ansible-production.lock/owner'
                owner.parent.mkdir(mode=0o700)
                owner.write_bytes(b'unrelated production owner must remain unchanged')
                helper = root / 'restic-fixture'
                helper.write_text(f'''#!{sys.executable}
import os, pathlib, signal, sys, time
root = pathlib.Path({str(root)!r})
with (root / 'attempts').open('a') as stream: stream.write(str(os.getpid()) + '\\n')
(root / 'child-pid').write_text(str(os.getpid()))
(root / 'source-lock').touch()
(root / 'destination-lock').touch()
def stop(number, frame):
    (root / 'stopping').touch()
    deadline = time.monotonic() + 5
    while not (root / 'allow-cleanup').exists():
        if time.monotonic() > deadline: sys.exit(4)
        time.sleep(0.01)
    (root / 'source-lock').unlink()
    (root / 'destination-lock').unlink()
    (root / 'cleaned').touch()
    sys.exit(0)
signal.signal(signal.SIGINT, signal.SIG_IGN if {stubborn!r} else stop)
signal.signal(signal.SIGTERM, signal.SIG_IGN if {stubborn!r} else stop)
(root / 'child-ready').touch()
while True: signal.pause()
''')
                helper.chmod(0o755)
                path = root / 'etc/home-lab/restic-policy.json'
                policy = json.loads(path.read_text())
                policy.update({'tools': {'restic': {'installed_path': str(helper)}},
                               'repositories': {name: {'path': '/' + name} for name in ('games', 'proton')}})
                path.chmod(0o600); path.write_text(json.dumps(policy)); path.chmod(0o440)
                probe = root / 'probe.py'
                probe.write_text(f'''
import runpy, sys, types
m = runpy.run_path({str(ROOT / 'scripts/restic-backup')!r})
g = m['main'].__globals__
source = {{'id': 'a' * 64, 'time': '2026-11-13T00:00:00Z', 'tags': ['cadence=daily','format=full-v2','complete=full-v2']}}
g['preflight'] = lambda *a: None
g['inventory'] = lambda policy, name: [source] if name == 'games' else []
g['repository_environment'] = lambda *a: {{}}
g['COPY_STOP_GRACE_SECONDS'] = {0.15 if stubborn else 240}
g['time'] = types.SimpleNamespace(sleep=lambda seconds: None)
def copy(policy, source_name, destination, snapshot):
    result = g['restic_result'](policy, destination, ['copy', snapshot['id']], source=source_name, timeout=30)
    g['require_success'](result, 'synthetic_copy')
g['copy_snapshot'] = copy
sys.argv = ['restic-backup','daily-proton']
g['main']()
''')
                env = {**os.environ, 'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root)}
                child = subprocess.Popen([sys.executable, str(probe)], env=env, start_new_session=True,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 5
                    while not (root / 'child-ready').exists():
                        self.assertIsNone(child.poll())
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.01)
                    child.send_signal(number)
                    if not stubborn:
                        deadline = time.monotonic() + 3
                        while not (root / 'stopping').exists():
                            self.assertLess(time.monotonic(), deadline,
                                            'copy child never received a graceful stop')
                            time.sleep(0.01)
                        with gate.open('a+') as barrier:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(barrier, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        self.assertIsNone(child.poll(), 'gate owner exited before child cleanup')
                        (root / 'allow-cleanup').touch()
                    stdout, stderr = child.communicate(timeout=5)
                    self.assertNotEqual(child.returncode, 0)
                    reason = 'copy_stop_timeout' if stubborn else 'interrupted'
                    self.assertIn('reason=' + reason, stdout + stderr)
                    self.assertEqual(len((root / 'attempts').read_text().splitlines()), 1)
                    self.assertEqual((root / 'cleaned').exists(), not stubborn)
                    self.assertEqual((root / 'source-lock').exists(), stubborn)
                    self.assertEqual((root / 'destination-lock').exists(), stubborn)
                    self.assertEqual(owner.read_bytes(), b'unrelated production owner must remain unchanged')
                    with gate.open('a+') as barrier:
                        fcntl.flock(barrier, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                    child.communicate(timeout=5)
                    pid_file = root / 'child-pid'
                    if pid_file.exists():
                        pid = int(pid_file.read_text())
                        try:
                            args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\\0')
                            if str(helper).encode() in args:
                                try: os.killpg(pid, signal.SIGKILL)
                                except ProcessLookupError: os.kill(pid, signal.SIGKILL)
                        except (FileNotFoundError, ProcessLookupError):
                            pass

    @unittest.skipUnless(sys.platform == 'linux' and os.environ.get('RESTIC') and os.environ.get('RCLONE'),
                         'requires pinned native Linux Restic and rclone')
    def test_native_copy_stop_removes_destination_lock_without_unlock(self):
        with tempfile.TemporaryDirectory() as directory:
            root, gate, _ = self.coordination_fixture(directory)
            restic = str(Path(os.environ['RESTIC']).resolve())
            rclone = str(Path(os.environ['RCLONE']).resolve())
            declared = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
            for name, binary in [('restic', restic), ('rclone', rclone)]:
                self.assertEqual(hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                                 declared['tools'][name]['installed_sha256'])
            config = root / 'rclone.conf'
            config.write_text(f'[proton-backup]\ntype = alias\nremote = {root / "cloud"}\n')
            config.chmod(0o600)
            environment = {'PATH': f'{Path(rclone).parent}:/usr/local/bin:/usr/bin:/bin',
                           'HOME': str(root), 'RCLONE_CONFIG': str(config),
                           'RESTIC_PASSWORD': 'synthetic-copy-interruption-password',
                           'RESTIC_FROM_PASSWORD': 'synthetic-copy-interruption-password',
                           'RESTIC_CACHE_DIR': str(root / 'cache')}
            local = str(root / 'local')
            remote = declared['repositories']['proton']['path']
            raw = root / 'cloud/Backups/home-lab-restic'
            data = root / 'payload'
            data.write_bytes(os.urandom(16 * 1024 * 1024))
            def command(repository, *args):
                result = subprocess.run([restic, '--repo', repository, *args], env=environment,
                                        text=True, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result
            command(local, 'init')
            command(local, 'backup', str(data), '--tag', 'cadence=daily',
                    '--tag', 'format=full-v2', '--tag', 'complete=full-v2')
            source = json.loads(command(local, 'snapshots', '--json').stdout)[0]
            command(remote, 'init', '--copy-chunker-params', '--from-repo', local)
            path = root / 'etc/home-lab/restic-policy.json'
            policy = json.loads(path.read_text())
            policy.update({'tools': {'restic': {'installed_path': restic}},
                           'repositories': {'games': {'path': local}, 'proton': {'path': remote}}})
            path.chmod(0o600); path.write_text(json.dumps(policy)); path.chmod(0o440)
            slow_environment = {**environment, 'RCLONE_BWLIMIT': '1MiB'}
            probe = root / 'probe.py'
            probe.write_text(f'''
import runpy, sys
m = runpy.run_path({str(ROOT / 'scripts/restic-backup')!r})
g = m['main'].__globals__
source = {source!r}
g['preflight'] = lambda *a: None
g['inventory'] = lambda policy, name: [source] if name == 'games' else []
g['repository_environment'] = lambda *a: {slow_environment!r}
sys.argv = ['restic-backup','daily-proton']
g['main']()
''')
            env = {**os.environ, 'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root)}
            child = subprocess.Popen([sys.executable, str(probe)], env=env, start_new_session=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 20
                while not (any((raw / 'locks').glob('*'))
                           and any(p.is_file() and p.stat().st_size > 0 for p in (raw / 'data').rglob('*'))):
                    self.assertIsNone(child.poll(), 'copy ended before its interruption point')
                    self.assertLess(time.monotonic(), deadline, 'copy never reached payload upload')
                    time.sleep(0.01)
                self.assertEqual(list((Path(local) / 'locks').glob('*')), [])
                os.killpg(child.pid, signal.SIGINT)
                stdout, stderr = child.communicate(timeout=20)
                self.assertNotEqual(child.returncode, 0)
                self.assertIn('reason=interrupted', stdout + stderr)
                self.assertEqual(list((Path(local) / 'locks').glob('*')), [])
                self.assertEqual(list((raw / 'locks').glob('*')), [])
                self.assertEqual(json.loads(command(remote, 'snapshots', '--json').stdout), [])
                with gate.open('a+') as barrier:
                    fcntl.flock(barrier, fcntl.LOCK_EX | fcntl.LOCK_NB)
                command(remote, 'copy', '--from-repo', local, source['id'])
                command(remote, 'check', '--read-data')
                restore = root / 'restore'
                command(remote, 'restore', 'latest', '--target', str(restore), '--verify')
                self.assertEqual((restore / str(data).lstrip('/')).read_bytes(), data.read_bytes())
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=5)

    def test_copy_timeout_reaches_the_subprocess_and_matches_replica_budgets(self):
        copy = RUNNER['copy_snapshot']
        snapshot = {'id': 'a' * 64, 'tags': ['complete=full-v2'], 'tree': 'b' * 64,
                    'time': '2026-11-10T00:00:00Z', 'paths': ['/stage']}
        replica = {**snapshot, 'id': 'c' * 64, 'original': snapshot['id']}
        policy = {'tools': {'restic': {'installed_path': '/restic'}},
                  'repositories': {name: {'path': '/' + name} for name in ('games', 'nfs', 'proton')}}
        for destination in ('nfs', 'proton'):
            unit = configparser.ConfigParser(interpolation=None)
            unit.read(ROOT / f'ansible/roles/restic_backup/templates/home-lab-restic-daily-{destination}.service.j2')
            budget = int(unit['Service']['TimeoutStartSec'].removesuffix('h')) * 3600
            self.assertEqual(unit['Service']['KillMode'], 'mixed')
            self.assertLess(RUNNER['COPY_STOP_GRACE_SECONDS'],
                            int(unit['Service']['TimeoutStopSec'].removesuffix('min')) * 60)
            with self.subTest(destination=destination), mock.patch.dict(copy.__globals__, {
                'repository_environment': lambda *_: {}, 'inventory': lambda *_: [replica],
                'testing': lambda: True,
                'run': mock.Mock(return_value=OK),
            }):
                command = copy.__globals__['run']
                self.assertEqual(copy(policy, 'games', destination, snapshot), replica['id'])
                self.assertEqual(command.call_args.args[0], [
                    '/restic', '--repo', '/' + destination, '--from-repo', '/games', '--no-lock', 'copy', snapshot['id'],
                ])
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.kwargs['timeout'], budget)
                self.assertTrue(command.call_args.kwargs['graceful_interrupt'])

    def test_failed_retries_and_partial_scan_never_qualify_a_snapshot(self):
        daily = LOCAL.run
        for code in (1, 3):
            with tempfile.TemporaryDirectory() as directory, self.subTest(code=code):
                stage = Path(directory).resolve()
                manifest = {'version': 2, 'capture': '1' * 32, 'policy': 'a' * 64, 'artifact': 'b' * 64,
                            'owner': None, 'captured_at': '2026-11-10T00:00:00+00:00'}
                calls = mock.Mock(return_value=subprocess.CompletedProcess([], code, '', 'private-error-not-logged'))
                with mock.patch.dict(daily.__globals__, {
                    'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                    'capture_adapter': lambda _: types.SimpleNamespace(CaptureError=CAPTURE['CaptureError'],
                                                                       capture_sources=CAPTURE['capture_sources']),
                    'rooted': Path, 'artifact_hash': lambda _: 'b' * 64,
                    'read_json': lambda *_: manifest, 'inventory': lambda *_: [], 'restic_result': calls,
                }), mock.patch.object(LOCAL, 'recover'), mock.patch('time.sleep'), self.assertRaises(RUNNER['WorkflowError']):
                    daily(LOCAL({'capture': {'stage': str(stage)}}), 'a' * 64)
                self.assertEqual(calls.call_count, 1 if code == 3 else 3)
                self.assertTrue(all(c.args[2][0] == 'backup' for c in calls.call_args_list))
                self.assertTrue(stage.exists())

    def test_retention_defers_without_writes_when_either_format_is_uncopied(self):
        maintenance = RUNNER['maintenance']
        for tags in (['cadence=daily'], ['cadence=daily', 'format=full-v2', 'complete=full-v2']):
            with tempfile.TemporaryDirectory() as directory, self.subTest(tags=tags):
                source = {'id': 'a' * 64, 'time': '2026-11-10T00:00:00Z', 'tags': tags}
                writes = mock.Mock(side_effect=AssertionError('unsafe retention'))
                stage = Path(directory) / 'stage'
                with (mock.patch.dict(maintenance.__globals__, {
                        'journal_path': lambda _: Path(directory) / 'journal', 'rooted': Path,
                        'preflight': mock.Mock(), 'inventory': lambda _, n: [source] if n == 'games' else [],
                        'restic_result': writes,
                    }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'),
                      contextlib.redirect_stdout(io.StringIO()) as output):
                    maintenance({'capture': {'stage': str(stage)}, 'retention': {'read_data_subset': '10%'}})
                self.assertIn('deferred=replication_pending', output.getvalue())
                self.assertFalse((stage.parent / 'retention.json').exists())
                writes.assert_not_called()

    def test_legacy_retention_is_replica_safe_and_keeps_unqualified_captures(self):
        maintenance = RUNNER['maintenance']
        legacy = {'id': 'a' * 64, 'time': '2020-01-01T00:00:00Z', 'tags': ['cadence=daily']}
        complete = {'id': 'b' * 64, 'time': '2026-11-10T00:00:00Z', 'tags': [
            'cadence=daily', 'format=full-v2', 'complete=full-v2']}
        incomplete = {'id': 'c' * 64, 'tags': ['cadence=daily', 'format=full-v2']}
        unknown = {'id': 'd' * 64, 'tags': ['cadence=daily', 'format=future']}
        sources = [legacy, complete, incomplete, unknown]
        replicas = [{**row, 'id': str(i + 5) * 64, 'original': row['id']}
                    for i, row in enumerate((legacy, complete))]
        # Shared ancestry alone is not permission to delete different content.
        replicas.append({**replicas[0], 'id': 'e' * 64, 'tree': 'f' * 64})
        expired_copy = replicas[0]['id']
        replica_rows = {name: list(replicas) for name in ('nfs', 'proton')}
        keep = {'read_data_subset': '10%', 'keep_daily': 7, 'keep_weekly': 5, 'keep_monthly': 12,
                'prune_max_repack_size': '10G', 'prune_max_unused': '10%', 'group_by': 'host,paths'}
        with tempfile.TemporaryDirectory() as directory:
            def inventory(_policy, name):
                return list(sources) if name == 'games' else list(replica_rows[name])
            def restic(_policy, name, args):
                if name == 'games' and args[0] == 'forget' and args[args.index('--tag') + 1] == 'cadence=daily':
                    self.assertEqual(args[args.index('--tag') + 1], 'cadence=daily')
                    protected = {args[i + 1] for i, value in enumerate(args) if value == '--keep-tag'}
                    self.assertEqual(protected, {'format=full-v2', 'format=future'})
                    sources.remove(legacy)
                elif name in replica_rows and args[0] == 'forget':
                    replica_rows[name] = [row for row in replica_rows[name] if row['id'] not in args[1:]]
                return OK
            writes = mock.Mock(side_effect=restic)
            with mock.patch.dict(maintenance.__globals__, {
                'journal_path': lambda _: Path(directory).resolve() / 'journal', 'rooted': Path,
                'preflight': mock.Mock(), 'inventory': inventory, 'restic_result': writes,
            }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'):
                maintenance({'capture': {'stage': str(Path(directory) / 'stage')}, 'retention': keep,
                             'repositories': {name: {'id': str(i + 1) * 64}
                                              for i, name in enumerate(('games', 'nfs', 'proton'))}})
            self.assertIn(complete, sources)
            self.assertIn(incomplete, sources)
            self.assertIn(unknown, sources)
            for name in ('nfs', 'proton'):
                self.assertIn(mock.call(mock.ANY, name, ['forget', expired_copy]), writes.call_args_list)

    def test_retention_restarts_safely_at_each_deletion_boundary(self):
        maintenance = RUNNER['maintenance']
        unlink = RUNNER['durable_unlink']
        for boundary in ('before_source', 'after_source', 'after_nfs', 'after_proton', 'before_cleanup'):
            with tempfile.TemporaryDirectory() as directory, self.subTest(boundary=boundary):
                root = Path(directory).resolve()
                pending = root / 'retention.json'
                old = {'id': 'a' * 64, 'tags': ['cadence=daily']}
                kept = {'id': 'b' * 64, 'tags': ['cadence=daily', 'format=full-v2', 'complete=full-v2']}
                records = {'games': [old, kept]}
                for name in ('nfs', 'proton'):
                    records[name] = [{**row, 'id': digit * 64, 'original': row['id']}
                                     for row, digit in ((old, 'c'), (kept, 'd'))]
                    records[name].append({'id': 'e' * 64, 'original': old['id'], 'tags': ['manual']})
                policy = {'capture': {'stage': str(root / 'stage')}, 'retention': {
                    'keep_daily': 1, 'keep_weekly': 0, 'keep_monthly': 0, 'group_by': 'host,paths',
                    'prune_max_repack_size': '10G', 'prune_max_unused': '10%', 'read_data_subset': '10%'},
                    'repositories': {name: {'id': str(i + 1) * 64} for i, name in enumerate(records)}}
                interrupted = False
                def interrupt(point):
                    nonlocal interrupted
                    if boundary == point and not interrupted:
                        interrupted = True
                        raise RUNNER['WorkflowError']('synthetic_interruption')
                def restic(_policy, name, args):
                    if args[0] == 'forget':
                        self.assertTrue(pending.exists(), 'journal must precede every deletion')
                        self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
                        if name == 'games':
                            interrupt('before_source')
                            records[name] = [row for row in records[name] if row['id'] != old['id']]
                            interrupt('after_source')
                        else:
                            self.assertNotIn(old, records['games'])
                            self.assertEqual(args[1:], ['c' * 64])
                            records[name] = [row for row in records[name] if row['id'] not in args[1:]]
                            interrupt('after_' + name)
                    return OK
                def cleanup(path):
                    interrupt('before_cleanup')
                    unlink(path)
                with mock.patch.dict(maintenance.__globals__, {
                    'journal_path': lambda _: root / 'interruption.json', 'rooted': Path,
                    'preflight': mock.Mock(), 'inventory': lambda _, n: list(records[n]),
                    'restic_result': restic, 'durable_unlink': cleanup,
                }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'):
                    with self.assertRaisesRegex(RUNNER['WorkflowError'], 'synthetic_interruption'):
                        maintenance(policy)
                    self.assertTrue(pending.exists())
                    maintenance(policy)
                self.assertFalse(pending.exists())
                self.assertEqual(records['games'], [kept])
                for name in ('nfs', 'proton'):
                    self.assertEqual({row['id'] for row in records[name]}, {'d' * 64, 'e' * 64})

    def test_retention_journal_refuses_invalid_or_rebound_deletions(self):
        maintenance = RUNNER['maintenance']
        repositories = {name: str(i + 1) * 64 for i, name in enumerate(('games', 'nfs', 'proton'))}
        row = {'games': 'a' * 64, 'nfs': 'b' * 64, 'proton': 'c' * 64}
        good = {'version': 1, 'repositories': repositories, 'snapshots': [row]}
        bad = [None, {**good, 'version': 2}, {**good, 'repositories': {**repositories, 'games': 'f' * 64}},
               {**good, 'snapshots': [row, row]}, {**good, 'snapshots': [{**row, 'nfs': 'b' * 8}]},
               {**good, 'snapshots': [{'games': row['games'], 'nfs': row['nfs']}]}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pending = root / 'retention.json'
            writes = mock.Mock(side_effect=AssertionError('invalid journal must never delete'))
            policy = {'capture': {'stage': str(root / 'stage')}, 'retention': {'read_data_subset': '10%'},
                      'repositories': {name: {'id': rid} for name, rid in repositories.items()}}
            with mock.patch.dict(maintenance.__globals__, {
                'journal_path': lambda _: root / 'interruption.json', 'restic_result': writes,
                'rooted': Path, 'preflight': mock.Mock(),
            }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'):
                for value in bad:
                    with self.subTest(value=value):
                        pending.write_text(json.dumps(value))
                        pending.chmod(0o600)
                        with self.assertRaisesRegex(RUNNER['WorkflowError'], 'retention_journal_schema'):
                            maintenance(policy)
                        self.assertTrue(pending.exists())
            writes.assert_not_called()

    def test_retention_keeps_journal_until_replica_absence_is_verified(self):
        maintenance = RUNNER['maintenance']
        repositories = {name: str(i + 1) * 64 for i, name in enumerate(('games', 'nfs', 'proton'))}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pending = root / 'retention.json'
            pending.write_text(json.dumps({'version': 1, 'repositories': repositories, 'snapshots': [
                {'games': 'a' * 64, 'nfs': 'b' * 64, 'proton': 'c' * 64}]}))
            pending.chmod(0o600)
            records = {'games': [], 'nfs': [{'id': 'b' * 64}], 'proton': [{'id': 'c' * 64}]}
            policy = {'capture': {'stage': str(root / 'stage')}, 'retention': {'read_data_subset': '10%'},
                      'repositories': {name: {'id': rid} for name, rid in repositories.items()}}
            with mock.patch.dict(maintenance.__globals__, {
                'journal_path': lambda _: root / 'interruption.json', 'inventory': lambda _, n: records[n],
                'restic_result': lambda *_: OK, 'rooted': Path, 'preflight': mock.Mock(),
            }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'), \
                    self.assertRaisesRegex(RUNNER['WorkflowError'], 'forget_copy_verify'):
                maintenance(policy)
            self.assertTrue(pending.exists())

    def test_retention_refuses_shared_replica_binding_before_local_expiry(self):
        maintenance = RUNNER['maintenance']
        source = {'id': 'a' * 64, 'original': 'f' * 64, 'tags': ['cadence=daily']}
        records = {'games': [source, {**source, 'id': 'b' * 64}],
                   'nfs': [{**source, 'id': 'c' * 64}], 'proton': [{**source, 'id': 'd' * 64}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            writes = mock.Mock(side_effect=AssertionError('unreplayable expiry must never delete'))
            policy = {'capture': {'stage': str(root / 'stage')}, 'retention': {'read_data_subset': '10%'},
                      'repositories': {name: {'id': str(i + 1) * 64} for i, name in enumerate(records)}}
            with mock.patch.dict(maintenance.__globals__, {
                'journal_path': lambda _: root / 'interruption.json', 'inventory': lambda _, n: records[n],
                'restic_result': writes, 'rooted': Path, 'preflight': mock.Mock(),
            }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'), \
                    self.assertRaisesRegex(RUNNER['WorkflowError'], 'retention_journal_schema'):
                maintenance(policy)
            writes.assert_not_called()
            self.assertFalse((root / 'retention.json').exists())

    def test_replication_includes_legacy_but_not_partial_or_unknown_formats(self):
        reconcile = RUNNER['reconcile']
        legacy = {'id': 'a' * 64, 'time': '2020-01-01T00:00:00Z', 'tags': ['cadence=daily']}
        partial = {'id': 'b' * 64, 'tags': ['cadence=daily', 'format=full-v2']}
        unknown = {'id': 'c' * 64, 'tags': ['cadence=daily', 'format=future']}
        unrelated = {'id': 'd' * 64, 'tags': []}
        conflict = {'id': 'e' * 64, 'tags': ['cadence=daily', 'format=full-v2', 'complete=full-v2', 'format=future']}
        copy = mock.Mock()
        with mock.patch.dict(reconcile.__globals__, {
            'preflight': mock.Mock(),
            'inventory': lambda _, n: [legacy, partial, unknown, unrelated, conflict] if n == 'games' else [],
            'copy_snapshot': copy,
        }):
            reconcile({}, 'nfs')
        copy.assert_called_once_with({}, 'games', 'nfs', legacy)

    def test_replication_retries_only_missing_copies_oldest_first(self):
        reconcile = RUNNER['reconcile']
        tags = ['complete=full-v2', 'format=full-v2', 'cadence=daily']
        first = {'id': 'a' * 64, 'time': '2026-11-09T00:00:00Z', 'tags': tags}
        second = {'id': 'b' * 64, 'time': '2026-11-10T00:00:00Z', 'tags': tags}
        copied = {**first, 'id': 'c' * 64, 'original': first['id']}
        copy = mock.Mock(side_effect=[RUNNER['WorkflowError']('copy'), 'd' * 64])
        with mock.patch.dict(reconcile.__globals__, {
            'preflight': mock.Mock(), 'inventory': lambda _, n: [second, first] if n == 'games' else [copied],
            'copy_snapshot': copy,
        }), mock.patch('time.sleep'):
            reconcile({}, 'proton')
        self.assertEqual(copy.call_args_list, [mock.call({}, 'games', 'proton', second)] * 2)

    def test_unknown_journal_services_are_not_executed_or_cleared(self):
        recover = LOCAL.recover
        restart = mock.Mock()
        with mock.patch.dict(recover.__globals__, {
            'journal_path': lambda _: Path('/unused'),
            'read_json': lambda *_: {'version': 1, 'running_services': ['--attach'], 'stop_order': ['--attach']},
        }), mock.patch.object(LOCAL, '_restart', restart), self.assertRaisesRegex(RUNNER['WorkflowError'], 'journal_schema'):
            recover(LOCAL({'stop_groups': {'applications': ['app'], 'databases': []}}))
        restart.assert_not_called()

    def test_shared_restart_failure_does_not_strand_other_recorded_writers(self):
        restart = LOCAL._restart
        policy = self.pause_policy('client', 'provider', 'inactive')
        compose = mock.Mock(side_effect=[subprocess.CompletedProcess([], 1, '', ''), OK])
        unlink = mock.Mock()
        with mock.patch.dict(restart.__globals__, {'compose': compose, 'durable_unlink': unlink}), \
                self.assertRaisesRegex(RUNNER['WorkflowError'], 'service_restart'):
            restart(LOCAL(policy), {'running_services': ['client', 'provider']})
        self.assertEqual(compose.call_args_list, [mock.call(policy, ['start', 'provider']),
                                                  mock.call(policy, ['start', 'client'])])
        unlink.assert_not_called()

    def test_namespace_health_failure_retains_journal(self):
        restart = LOCAL._restart
        policy = {'stop_groups': {'applications': ['qbittorrent', 'gluetun'], 'databases': []}}
        compose, unlink = mock.Mock(return_value=OK), mock.Mock()
        with mock.patch.dict(restart.__globals__, {
            'compose': compose, 'service_healthy': lambda *_: False,
            'durable_unlink': unlink, 'testing': lambda: True,
        }), mock.patch('time.monotonic', side_effect=[0, 1, 4]), mock.patch('time.sleep'):
            with self.assertRaisesRegex(RUNNER['WorkflowError'], 'service_health'):
                restart(LOCAL(policy), {'running_services': ['qbittorrent', 'gluetun']})
        compose.assert_called_once_with(policy, ['start', 'gluetun'])
        unlink.assert_not_called()

if __name__ == '__main__':
    unittest.main()
