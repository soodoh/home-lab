#!/usr/bin/env python3
"""Exercise the restricted native snapshot interface, not source-text assertions."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BROKER = runpy.run_path(str(ROOT / 'scripts/zfs-backup-snapshot'))


class NativeZfsFixture:
    def __init__(self):
        self.dataset_guid = '123456'
        self.available = 1024**4
        self.snapshots = {}
        self.commands = []
        self.busy = False

    def __call__(self, *args):
        self.commands.append(args)
        if args[:2] == ('list', '-H'):
            return '\n'.join(self.snapshots)
        if args[:2] == ('get', '-H') and args[-1] == 'storage/docker':
            return str(self.available) if args[-2] == 'available' else self.dataset_guid
        if args[0] == 'get':
            value = self.snapshots[args[-1]]
            return '\n'.join(k + '\t' + str(v) for k, v in value.items())
        if args[0] == 'snapshot':
            self.snapshots[args[-1]] = {'guid': '789', 'creation': 100,
                'org.home-lab:purpose': 'nextcloud-backup',
                'org.home-lab:capture': args[-1].split('home-lab-nextcloud-')[1],
                'org.home-lab:owner': 'a' * 64}
            return ''
        if args[0] == 'destroy':
            if self.busy:
                raise BROKER['Refusal']('native_zfs_refused')
            del self.snapshots[args[-1]]
            return ''
        raise AssertionError(args)


class SnapshotAuthority(unittest.TestCase):
    def setUp(self):
        self.native = NativeZfsFixture()
        self.call = BROKER['execute']
        self.patch = mock.patch.dict(self.call.__globals__, {
            'zfs': self.native, 'pool_healthy': lambda: True, 'source_is_current': lambda: True,
            'ensure_export': mock.Mock(), 'withdraw_export': mock.Mock(),
        })
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.identity = {'capture': 'b' * 32, 'owner': 'a' * 64}
        self.name = 'storage/docker@home-lab-nextcloud-' + 'b' * 32

    def request(self, action, **values):
        return self.call({'action': action, **self.identity, **values}, '123456', now=100 + 72 * 3600)

    def test_create_is_atomically_tagged_and_idempotent_for_exact_owner(self):
        first = self.request('create')
        self.assertEqual(first, self.request('create'))
        self.assertEqual(first['guid'], '789')
        self.assertEqual(sum(c[0] == 'snapshot' for c in self.native.commands), 1)
        self.assertEqual(self.request('inspect')['dataset_guid'], '123456')

    def test_completion_deletes_only_exact_owned_snapshot_and_is_idempotent(self):
        self.request('create')
        self.native.snapshots['storage/docker@unrelated'] = {}
        self.assertTrue(self.request('complete', guid='789', backup='c' * 64)['deleted'])
        self.assertIn('storage/docker@unrelated', self.native.snapshots)
        self.assertTrue(self.request('complete', guid='789', backup='c' * 64)['already_absent'])
        self.assertEqual([c for c in self.native.commands if c[0] == 'destroy'], [('destroy', self.name)])

    def test_abandon_requires_72_hours_and_never_uses_force_or_recursive_destroy(self):
        self.request('create')
        with self.assertRaisesRegex(ValueError, 'not_expired'):
            self.call({'action': 'abandon', **self.identity, 'guid': '789'}, '123456', now=100 + 72 * 3600 - 1)
        self.assertIn(self.name, self.native.snapshots)
        self.assertTrue(self.request('abandon', guid='789')['deleted'])
        self.assertEqual(self.native.commands[-1], ('destroy', self.name))

    def test_owner_guid_dataset_and_foreign_snapshot_refusals_preserve_native_state(self):
        for field, changed in (('owner', 'c' * 64), ('guid', '790'), ('dataset', '555'), ('purpose', 'unrelated')):
            with self.subTest(field=field):
                self.native = NativeZfsFixture()
                self.call.__globals__['zfs'] = self.native
                self.request('create')
                if field == 'dataset':
                    self.native.dataset_guid = changed
                else:
                    key = {'owner': 'org.home-lab:owner', 'guid': 'guid', 'purpose': 'org.home-lab:purpose'}[field]
                    self.native.snapshots[self.name][key] = changed
                before = copy.deepcopy(self.native.snapshots)
                with self.assertRaises(ValueError):
                    self.request('complete', guid='789', backup='c' * 64)
                self.assertEqual(self.native.snapshots, before)

    def test_busy_snapshot_remains_owned_and_is_not_force_destroyed(self):
        self.request('create')
        self.native.busy = True
        with self.assertRaises(ValueError):
            self.request('complete', guid='789', backup='c' * 64)
        self.assertIn(self.name, self.native.snapshots)
        self.assertEqual(self.native.commands[-1], ('destroy', self.name))

    def test_untrusted_requests_cannot_choose_dataset_paths_commands_or_properties(self):
        valid = {'action': 'create', **self.identity}
        for invalid in (
            {**valid, 'dataset': 'storage'}, {**valid, 'capture': '../docker'},
            {**valid, 'owner': 'a' * 64 + '; id'}, {**valid, 'action': 'rollback'},
            {**valid, 'recursive': True}, {**valid, 'capture': '-R'},
            {'action': 'list', 'dataset': 'storage/docker'},
        ):
            with self.subTest(invalid=invalid):
                self.native.commands.clear()
                with self.assertRaises(ValueError):
                    self.call(invalid, '123456')
                self.assertEqual(self.native.commands, [])

    def test_list_does_not_adopt_unrelated_snapshots_and_refuses_false_owned_names(self):
        self.request('create')
        self.native.snapshots['storage/docker@unrelated'] = {}
        records = self.call({'action': 'list'}, '123456')['snapshots']
        self.assertEqual(len(records), 1)
        self.native.snapshots[self.name]['org.home-lab:purpose'] = 'foreign'
        with self.assertRaisesRegex(ValueError, 'not_owned'):
            self.call({'action': 'list'}, '123456')

    def test_unhealthy_pool_blocks_creation_but_not_safe_cleanup(self):
        with mock.patch.dict(self.call.__globals__, {'pool_healthy': lambda: False}):
            with self.assertRaisesRegex(ValueError, 'pool_not_healthy'):
                self.request('create')
        self.assertEqual(self.native.snapshots, {})
        self.request('create')
        with mock.patch.dict(self.call.__globals__, {'pool_healthy': lambda: False}):
            self.assertFalse(self.call({'action': 'list'}, '123456')['pool_healthy'])
            self.assertTrue(self.request('complete', guid='789', backup='c' * 64)['deleted'])

    def test_pool_health_requires_no_reported_errors_not_just_online_devices(self):
        healthy = BROKER['pool_healthy']
        for text, expected in (("pool 'storage' is healthy\n", True),
                               ('pool: storage\n state: ONLINE\nerrors: permanent errors', False),
                               ('pool: storage\n state: DEGRADED', False)):
            with self.subTest(text=text), mock.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, text, '')):
                self.assertEqual(healthy(), expected)

    def test_migrated_or_overmounted_live_source_refuses_a_new_parent_dataset_snapshot(self):
        with mock.patch.dict(self.call.__globals__, {'source_is_current': lambda: False}):
            with self.assertRaisesRegex(ValueError, 'source_mount_changed'):
                self.request('create')
        self.assertEqual(self.native.snapshots, {})

    def test_nested_nextcloud_mounts_are_refused_instead_of_silently_omitted_from_snapshot(self):
        probe = BROKER['source_is_current']
        for target, expected in (('/storage/docker/.zfs/snapshot/unrelated', True),
                                 ('/storage/docker/media/nextcloud/data/user/external', False)):
            value = {'filesystems': [{'target': '/storage/docker', 'source': 'storage/docker', 'fstype': 'zfs',
                                     'children': [{'target': target, 'source': 'storage/other', 'fstype': 'zfs'}]}]}
            with self.subTest(target=target), mock.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(value), '')):
                self.assertEqual(probe(), expected)

    def test_export_fsid_is_namespaced_and_cannot_select_the_callers_raw_uuid(self):
        value = BROKER['export_fsid']('0' * 32)
        self.assertNotEqual(value, '00000000-0000-0000-0000-000000000000')
        self.assertEqual(value, BROKER['export_fsid']('0' * 32))

    def test_ready_republishes_only_an_existing_exact_snapshot_and_never_recaptures(self):
        self.request('create')
        self.request('ready', guid='789')
        with self.assertRaisesRegex(ValueError, 'snapshot_replaced'):
            self.request('ready', guid='790')
        self.assertEqual(sum(c[0] == 'snapshot' for c in self.native.commands), 1)
        del self.native.snapshots[self.name]
        with self.assertRaisesRegex(ValueError, 'snapshot_missing'):
            self.request('ready', guid='789')
        self.assertEqual(sum(c[0] == 'snapshot' for c in self.native.commands), 1)

    def test_low_source_capacity_blocks_new_snapshots_but_not_deletion(self):
        self.native.available = 0
        with self.assertRaisesRegex(ValueError, 'source_capacity'):
            self.request('create')
        self.assertEqual(self.native.snapshots, {})
        self.native.available = 1024**4
        self.request('create')
        self.native.available = 0
        self.assertTrue(self.request('complete', guid='789', backup='c' * 64)['deleted'])

    def test_outstanding_snapshot_blocks_a_new_capture_instead_of_accumulating_space(self):
        self.request('create')
        with self.assertRaisesRegex(ValueError, 'previous_snapshot'):
            self.call({'action': 'create', 'capture': 'c' * 32, 'owner': 'd' * 64}, '123456')
        self.assertEqual(len(self.native.snapshots), 1)

    def test_export_lifecycle_is_readonly_one_client_one_immutable_subtree(self):
        ensure = BROKER['ensure_export']
        withdraw = BROKER['withdraw_export']
        path = BROKER['export_path']('b' * 32)
        table = ''
        commands = []
        def export(*args):
            nonlocal table
            commands.append(args)
            if args == ('-s',):
                return table
            if args[0] == '-i':
                self.assertEqual(args[-1], '192.168.0.100:' + path)
                self.assertTrue({'ro', 'sync', 'subtree_check', 'no_root_squash', 'secure', 'sec=sys'} <= set(args[2].split(',')))
                table = path + ' 192.168.0.100(' + args[2] + ')\n'
                return ''
            if args[0] == '-u':
                self.assertEqual(args, ('-u', '192.168.0.100:' + path))
                table = ''
                return ''
            raise AssertionError(args)
        with mock.patch.dict(ensure.__globals__, {'exportfs': export}), \
                mock.patch('pathlib.Path.is_symlink', return_value=False), \
                mock.patch('pathlib.Path.is_dir', return_value=True), \
                mock.patch('pathlib.Path.is_file', return_value=True):
            ensure('b' * 32)
            ensure('b' * 32)
            withdraw('b' * 32)
        self.assertEqual(sum(c[0] == '-i' for c in commands), 1)
        self.assertEqual(sum(c[0] == '-u' for c in commands), 1)

    def test_unfamiliar_or_broader_exports_are_never_repaired_or_withdrawn(self):
        inspect = BROKER['export_present']
        path = BROKER['export_path']('b' * 32)
        for client, options in (('*', 'ro,subtree_check,no_root_squash'),
                                ('192.168.0.100', 'rw,no_subtree_check,no_root_squash'),
                                ('192.168.0.101', 'ro,subtree_check,no_root_squash')):
            native = mock.Mock(return_value=path + ' ' + client + '(' + options + ')\n')
            with mock.patch.dict(inspect.__globals__, {'exportfs': native}):
                with self.assertRaisesRegex(ValueError, 'unfamiliar_snapshot_export'):
                    inspect('b' * 32)
                self.assertEqual(native.call_args_list, [mock.call('-s')])

    def test_request_stream_is_size_and_time_bounded_before_native_commands(self):
        read = BROKER['read_request']
        with mock.patch('signal.alarm') as alarm:
            self.assertEqual(read(io.BytesIO(b'{"action":"list"}')), {'action': 'list'})
            self.assertEqual(alarm.call_args_list, [mock.call(15), mock.call(0)])
        with mock.patch('signal.alarm'):
            with self.assertRaisesRegex(ValueError, 'request_size'):
                read(io.BytesIO(b' ' * 4097))
            with self.assertRaises(ValueError):
                read(io.BytesIO(b'not-json'))

    def test_worker_requires_root_and_fixed_entrypoint_before_reading_privileged_inputs(self):
        main = BROKER['main']
        with mock.patch.object(sys, 'argv', ['zfs-backup-snapshot', '--privileged']), \
                mock.patch('os.geteuid', return_value=1000):
            with self.assertRaisesRegex(ValueError, 'fixed_command_required'):
                main()
        for command in ('bash', 'snapshot; id', 'snapshot --dataset storage', 'scp -t /tmp/input', ''):
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/zfs-backup-snapshot'), '-c', command],
                                    text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.strip(), 'zfs_backup_snapshot=refused')


RUNNER = runpy.run_path(str(ROOT / 'scripts/restic-backup'))
CAPTURE = runpy.run_path(str(ROOT / 'scripts/restic-capture-files.py'))


class SnapshotCapture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.stage = self.root / 'mnt/games/home-lab-backup/capture'
        for name in ('files', 'databases', 'native'):
            (self.stage / name).mkdir(parents=True, mode=0o700)
        self.stage.chmod(0o700)
        self.token = 'b' * 32
        self.owner = hashlib.sha256(self.token.encode()).hexdigest()
        self.spec = {'dataset_guid': '123456', 'expiry_seconds': 72 * 3600, 'broker_ipv4': '100.113.54.34'}
        self.record = {'capture': self.token, 'owner': self.owner, 'guid': '789',
                       'created': int(time.time()), 'dataset_guid': '123456'}
        self.policy = {'_owner': None, '_capture': self.token,
            'capture': {'stage': '/mnt/games/home-lab-backup/capture', 'zfs': self.spec},
            'runner': {'journal_path': '/var/lib/home-lab-restic/interruption.json',
                       'deploy_lock_path': '/var/lib/iac-ansible-production.lock',
                       'exclude_file_path': '/etc/home-lab/restic/excludes'},
            'stop_groups': {'applications': ['nextcloud-cron', 'nextcloud'], 'databases': []}}
        self.events = []
        self.running = {'nextcloud', 'nextcloud-cron'}
        def remote(_spec, request):
            self.events.append(request['action'])
            return {'deleted': True} if request['action'] in {'complete', 'abandon'} else copy.deepcopy(self.record)
        def compose(_policy, args):
            if args[0] == 'stop':
                self.running.difference_update(args[3:])
            if args[0] == 'start':
                self.running.add(args[1]); self.events.append('start:' + args[1])
            return subprocess.CompletedProcess(args, 0, '', '')
        self.adapter = types.SimpleNamespace(CaptureError=CAPTURE['CaptureError'],
            ZFS_DATA_PATH=CAPTURE['ZFS_DATA_PATH'], zfs_spec=lambda _: self.spec,
            zfs_record=CAPTURE['zfs_record'], zfs_call=mock.Mock(side_effect=remote),
            zfs_inventory=mock.Mock(return_value=[self.record]),
            zfs_mount=mock.Mock(side_effect=lambda *_: self.events.append('mount')),
            zfs_unmount=mock.Mock(side_effect=lambda *_: self.events.append('unmount')),
            copy_paths=mock.Mock(side_effect=lambda *_: self.events.append('copy')),
            database_dump=mock.Mock(side_effect=lambda *_: self.events.append('dump')),
            command=mock.Mock(side_effect=lambda *_: self.events.append('sync')),
            safe_source=mock.Mock(), retry=lambda call: call())
        self.globals = RUNNER['cold_capture'].__globals__
        patch = mock.patch.dict(self.globals, {
            'capture_adapter': lambda _: self.adapter,
            'compose': compose, 'service_running': lambda _, service: service in self.running,
            'service_healthy': lambda _, service: service in self.running,
            'nextcloud_healthy': lambda _: 'nextcloud' in self.running,
            'verify_sources': mock.Mock(), 'inventory': mock.Mock(return_value=[]),
        })
        patch.start(); self.addCleanup(patch.stop)
        env = mock.patch.dict(os.environ, {'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(self.root)})
        env.start(); self.addCleanup(env.stop)

    def state(self, **changes):
        value = {'version': 1, 'capture': self.token, 'owner': self.owner,
                 'production_owner': None, 'running_services': ['nextcloud', 'nextcloud-cron'],
                 'record': self.record}
        value.update(changes)
        RUNNER['atomic_json'](self.stage / 'zfs-source.json', value)
        return value

    def step(self):
        return {'name': 'nextcloud', 'snapshot': 'zfs',
                'services': ['nextcloud-cron', 'nextcloud'],
                'paths': ['/srv/home-lab-state/nextcloud-config', CAPTURE['ZFS_DATA_PATH']],
                'databases': [{'engine': 'mariadb', 'container': 'nextcloud-db', 'name': 'nextcloud.sql'}]}

    def test_cold_capture_exports_then_snapshots_then_recovers_before_mounting_bulk_data(self):
        RUNNER['cold_capture'](self.policy, self.adapter, self.step(), self.stage, set(self.running))
        copied = self.adapter.copy_paths.call_args.args[0]
        self.assertEqual(copied, ['/srv/home-lab-state/nextcloud-config'])
        self.assertLess(self.events.index('dump'), self.events.index('create'))
        self.assertLess(self.events.index('create'), self.events.index('start:nextcloud'))
        self.assertFalse(self.adapter.zfs_mount.called)
        RUNNER['zfs_ready'](self.policy, self.adapter, self.stage)
        self.assertLess(self.events.index('start:nextcloud-cron'), self.events.index('mount'))
        self.assertFalse(RUNNER['journal_path'](self.policy).exists())

    def test_lost_create_acknowledgement_recovers_writers_and_retains_intent_without_retry(self):
        self.adapter.zfs_call.side_effect = CAPTURE['CaptureError']('snapshot_remote_refused')
        with self.assertRaises(CAPTURE['CaptureError']):
            RUNNER['cold_capture'](self.policy, self.adapter, self.step(), self.stage, set(self.running))
        self.assertEqual(self.running, {'nextcloud', 'nextcloud-cron'})
        self.assertEqual(self.adapter.zfs_call.call_count, 1)
        self.assertIsNone(json.loads((self.stage / 'zfs-source.json').read_text())['record'])
        self.assertFalse(self.adapter.zfs_mount.called)

    def test_intentionally_stopped_cron_stays_stopped(self):
        self.running.remove('nextcloud-cron')
        RUNNER['cold_capture'](self.policy, self.adapter, self.step(), self.stage, {'nextcloud', 'nextcloud-cron'})
        self.assertEqual(self.running, {'nextcloud'})
        self.assertEqual(json.loads((self.stage / 'zfs-source.json').read_text())['running_services'], ['nextcloud'])

    def test_ready_retries_reuse_exact_guid_and_missing_receipt_never_falls_back_to_live_files(self):
        self.state()
        RUNNER['zfs_ready'](self.policy, self.adapter, self.stage)
        self.assertEqual(self.adapter.zfs_call.call_args.args[1], {
            'action': 'ready', 'capture': self.token, 'owner': self.owner, 'guid': '789'})
        self.assertFalse(self.adapter.copy_paths.called)
        self.state(record=None)
        with self.assertRaisesRegex(RuntimeError, 'snapshot_receipt_missing'):
            RUNNER['zfs_ready'](self.policy, self.adapter, self.stage)
        self.assertEqual(self.adapter.zfs_mount.call_count, 1)

    def test_expired_ready_source_is_not_reopened_by_automatic_retries(self):
        self.record['created'] = int(time.time()) - 72 * 3600 - 5
        self.state()
        with self.assertRaisesRegex(RuntimeError, 'snapshot_expired_cleanup_required'):
            RUNNER['zfs_ready'](self.policy, self.adapter, self.stage)
        self.assertFalse(self.adapter.zfs_call.called)
        self.assertFalse(self.adapter.zfs_mount.called)
        self.assertTrue(self.stage.exists())

    def test_successful_completion_unmounts_before_withdrawing_and_deleting_exact_snapshot(self):
        self.state()
        RUNNER['zfs_release'](self.policy, self.adapter, self.stage, 'c' * 64)
        self.assertEqual(self.events, ['unmount', 'complete'])
        self.assertEqual(self.adapter.zfs_call.call_args.args[1]['guid'], '789')
        self.assertEqual(self.adapter.zfs_call.call_args.args[1]['backup'], 'c' * 64)

    def test_expiry_before_72_hours_does_not_delete_or_discard_retry_state(self):
        self.record['created'] = int(time.time()) - 72 * 3600 + 60
        self.state()
        RUNNER['expire_snapshots'](self.policy)
        self.assertTrue(self.stage.exists())
        self.assertFalse(self.adapter.zfs_call.called)

    def test_expired_unowned_recovered_capture_is_abandoned_without_false_completion(self):
        self.record['created'] = int(time.time()) - 72 * 3600 - 5
        self.state()
        RUNNER['expire_snapshots'](self.policy)
        self.assertEqual(self.adapter.zfs_call.call_args.args[1], {
            'action': 'abandon', 'capture': self.token, 'owner': self.owner, 'guid': '789'})
        self.assertFalse(self.stage.exists())

    def test_failed_recovery_unknown_owner_or_replaced_receipt_preserve_source_and_stage(self):
        self.record['created'] = int(time.time()) - 72 * 3600 - 5
        for problem in ('health', 'production_owner', 'guid'):
            with self.subTest(problem=problem):
                self.running = {'nextcloud', 'nextcloud-cron'}
                value = self.state()
                if problem == 'health': self.running.remove('nextcloud')
                if problem == 'production_owner': self.state(production_owner='c' * 64)
                if problem == 'guid':
                    value['record'] = {**self.record, 'guid': '790'}
                    RUNNER['atomic_json'](self.stage / 'zfs-source.json', value)
                self.adapter.zfs_call.reset_mock()
                with self.assertRaises(RuntimeError): RUNNER['expire_snapshots'](self.policy)
                self.assertFalse(self.adapter.zfs_call.called)
                self.assertTrue(self.stage.exists())

    def test_completed_capture_can_release_snapshot_without_waiting_for_expiry(self):
        self.record['created'] = int(time.time())
        self.state()
        self.globals['inventory'].return_value = [{'id': 'c' * 64, 'tags': [
            'format=full-v2', 'complete=full-v2', 'cadence=daily', 'capture=' + self.token]}]
        RUNNER['expire_snapshots'](self.policy)
        self.assertEqual(self.adapter.zfs_call.call_args.args[1]['action'], 'complete')
        self.assertFalse(self.stage.exists())

    def test_lost_destroy_acknowledgement_cleans_verified_stage_without_recapture(self):
        self.state()
        self.adapter.zfs_inventory.return_value = []
        self.globals['inventory'].return_value = [{'id': 'c' * 64, 'tags': [
            'format=full-v2', 'complete=full-v2', 'cadence=daily', 'capture=' + self.token]}]
        RUNNER['expire_snapshots'](self.policy)
        self.assertFalse(self.stage.exists())
        self.assertEqual(self.adapter.zfs_call.call_args.args[1]['action'], 'complete')
        self.assertFalse(self.adapter.zfs_mount.called)
        self.assertFalse(self.adapter.copy_paths.called)

    def test_missing_unqualified_source_retains_stage_and_fails_for_inspection(self):
        self.state()
        self.adapter.zfs_inventory.return_value = []
        with self.assertRaisesRegex(RuntimeError, 'snapshot_missing_requires_inspection'):
            RUNNER['expire_snapshots'](self.policy)
        self.assertTrue(self.stage.exists())
        self.assertFalse(self.adapter.zfs_call.called)

    def test_unknown_orphan_ownership_is_preserved_even_after_expiry(self):
        self.record['owner'] = 'd' * 64
        with self.assertRaisesRegex(RuntimeError, 'owner_requires_inspection'):
            RUNNER['expire_snapshots'](self.policy)
        self.assertFalse(self.adapter.zfs_call.called)

    def test_native_snapshot_mount_is_readonly_exact_source_and_refuses_live_or_nonempty_fallback(self):
        mount = CAPTURE['zfs_mount']
        source = '192.168.0.123:/storage/docker/.zfs/snapshot/home-lab-nextcloud-' + self.token + '/media/nextcloud/data'
        commands = []
        def command(args):
            commands.append(args)
            return json.dumps({'filesystems': [{'source': source, 'fstype': 'nfs4', 'options': 'ro,vers=4.2'}]}).encode()
        namespace = types.SimpleNamespace(stat=lambda path: types.SimpleNamespace(st_ino=1 if path == '/proc/self/ns/mnt' else 2))
        with mock.patch.dict(mount.__globals__, {'command': command, 'os': namespace}):
            mount(self.spec, self.record, self.stage)
        self.assertEqual(commands[0][:5], ['/usr/bin/mount', '-n', '-t', 'nfs4', '-o'])
        self.assertIn('ro,vers=4.2', commands[0][5])
        self.assertEqual(commands[0][-2], source)
        target = self.stage / 'files' / CAPTURE['ZFS_DATA_PATH'].lstrip('/')
        (target / 'unexpected').touch()
        with mock.patch.dict(mount.__globals__, {'command': command, 'os': namespace}):
            with self.assertRaisesRegex(ValueError, 'target_not_empty'): mount(self.spec, self.record, self.stage)
        self.assertEqual(len(commands), 2)

    def test_application_recovery_requires_native_status_and_live_data_marker(self):
        healthy = RUNNER['nextcloud_healthy']
        status = {'installed': True, 'maintenance': False, 'needsDbUpgrade': False}
        native = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(status), ''))
        with mock.patch.dict(healthy.__globals__, {'service_container': lambda *_: 'a' * 64, 'run': native}):
            self.assertFalse(healthy(self.policy))
            data = self.root / 'mnt/storage/media/nextcloud/data'
            data.mkdir(parents=True); (data / '.ncdata').touch()
            self.assertTrue(healthy(self.policy))
            native.return_value = subprocess.CompletedProcess([], 0, json.dumps({**status, 'maintenance': True}), '')
            self.assertFalse(healthy(self.policy))

    def test_transport_uses_pinned_peer_fixed_port_and_rejects_oversized_or_invalid_responses(self):
        call = CAPTURE['zfs_call']
        with mock.patch('socket.socket') as factory:
            stream = factory.return_value
            stream.recv.side_effect = [b'{"snapshots":[],"pool_healthy":true}', b'']
            self.assertEqual(call(self.spec, {'action': 'list'})['snapshots'], [])
            factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            stream.connect.assert_called_once_with(('100.113.54.34', 2444))
            self.assertEqual(json.loads(stream.sendall.call_args.args[0]), {'action': 'list'})
            stream.shutdown.assert_called_once_with(socket.SHUT_WR)
            stream.close.assert_called_once()
            for chunks in ([b'not-json', b''], [b'x' * 65537], [b'[]', b'']):
                with self.subTest(chunks=len(chunks)):
                    stream.recv.side_effect = chunks
                    with self.assertRaisesRegex(ValueError, 'snapshot_remote_refused'):
                        call(self.spec, {'action': 'list'})

    def test_native_tcp_half_close_frames_exactly_one_json_request_and_response(self):
        received = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
            def serve():
                with listener.accept()[0] as peer:
                    peer.settimeout(5)
                    raw = bytearray()
                    while chunk := peer.recv(4097):
                        raw.extend(chunk)
                    received.append(json.loads(raw))
                    peer.sendall(b'{"snapshots":[],"pool_healthy":true}')
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                with mock.patch.dict(CAPTURE['zfs_call'].__globals__, {'ZFS_BROKER_PORT': listener.getsockname()[1]}):
                    result = CAPTURE['zfs_call']({**self.spec, 'broker_ipv4': '127.0.0.1'}, {'action': 'list'})
                self.assertEqual(result, {'snapshots': [], 'pool_healthy': True})
            finally:
                worker.join(6)
            self.assertFalse(worker.is_alive())
        self.assertEqual(received, [{'action': 'list'}])
        with self.assertRaises(ValueError):
            CAPTURE['zfs_spec']({'capture': {'zfs': {**self.spec, 'broker_ipv4': '127.0.0.1'}}})

    def test_mounting_in_global_namespace_is_refused_before_any_mount_command(self):
        mount = CAPTURE['zfs_mount']
        namespace = types.SimpleNamespace(stat=lambda _: types.SimpleNamespace(st_ino=1))
        native = mock.Mock()
        with mock.patch.dict(mount.__globals__, {'os': namespace, 'command': native}):
            with self.assertRaisesRegex(ValueError, 'private_mount_namespace_required'):
                mount(self.spec, self.record, self.stage)
        self.assertFalse(native.called)


INSTALL_FIXTURE = (sys.platform == 'linux' and os.geteuid() == 0 and
                   os.environ.get('HOME_LAB_ZFS_TEST_DISPOSABLE') == 'true' and
                   Path('/.dockerenv').is_file())


@unittest.skipUnless(INSTALL_FIXTURE, 'socket installation requires explicitly disposable root Docker Linux')
class SnapshotInstallation(unittest.TestCase):
    def test_native_ansible_check_apply_idempotence_and_unknown_state_refusal(self):
        # Native Ansible and tmpfiles run for real. Only the unavailable systemd
        # manager and ZFS/Tailscale CLIs are fixtures; live WireGuard qualification
        # is deliberately not inferred from these tests.
        binary, pool, tailscale = Path('/usr/sbin/zfs'), Path('/usr/sbin/zpool'), Path('/usr/bin/tailscale')
        program = Path('/usr/local/libexec/home-lab/zfs-backup-snapshot')
        socket_unit = Path('/etc/systemd/system/home-lab-zfs-backup-snapshot.socket')
        service_unit = socket_unit.with_name('home-lab-zfs-backup-snapshot@.service')
        owned = (binary, pool, tailscale, program, BROKER['CONFIG'], BROKER['LOCK'], socket_unit, service_unit,
                 Path('/etc/tmpfiles.d/home-lab-zfs-backup-snapshot.conf'))
        for path in owned:
            self.assertFalse(path.exists(), path)
        self.assertFalse(Path('/var/lib/iac-ansible-production.lock').exists())
        for tool in ('ansible-playbook', 'systemd-tmpfiles', 'systemd-analyze', 'ss'):
            self.assertTrue(shutil.which(tool), tool)
        canary = Path('/run/systemd/system')
        created_canary = not canary.exists()
        with tempfile.TemporaryDirectory(prefix='snapshot-installation-') as directory:
            work = Path(directory)
            metadata = work / 'native.json'
            metadata.write_text(json.dumps({'guid': '123456', 'pending': False, 'active': False, 'enabled': False, 'foreign': False}))
            binary.write_text('#!/usr/bin/python3\nimport json,pathlib,sys\n'
                + 'd=json.loads(pathlib.Path(' + repr(str(metadata)) + ').read_text())\n'
                + "if sys.argv[1:]==['get','-H','-p','-o','value','guid','storage/docker']: print(d['guid'])\n"
                + "elif sys.argv[1:]==['list','-H','-r','-d','1','-t','snapshot','-o','name','storage/docker']:\n"
                + "    print('storage/docker@home-lab-nextcloud-'+'b'*32 if d['pending'] else '',end='')\n"
                + 'else: sys.exit(1)\n')
            binary.chmod(0o755)
            pool.write_text("#!/usr/bin/python3\nimport sys\nassert sys.argv[1:]==['status','-x','storage']\nprint(\"pool 'storage' is healthy\")\n")
            pool.chmod(0o755)
            tailscale.write_text('#!/bin/sh\n[ "$*" = "ip -4" ] || exit 1\necho 100.113.54.34\n')
            tailscale.chmod(0o755)
            mock_bin = work / 'bin'; mock_bin.mkdir()
            systemctl = mock_bin / 'systemctl'
            systemctl.write_text('#!/usr/bin/python3\nimport json,pathlib,sys\n'
                + 'p=pathlib.Path(' + repr(str(metadata)) + '); d=json.loads(p.read_text()); args=sys.argv[1:]\n'
                + "if 'show' in args:\n"
                + " print('LoadState=loaded\\nUnitFileState='+('enabled' if d['enabled'] else 'disabled')+'\\nActiveState='+('active' if d['active'] else 'inactive')+'\\nNeedDaemonReload=no')\n"
                + " print('BindToDevice='+('eth0' if d['foreign'] else 'tailscale0'))\n"
                + " print('Listen=100.113.54.34:2444 (Stream)')\n"
                + "elif 'is-enabled' in args: print('enabled' if d['enabled'] else 'disabled'); sys.exit(0 if d['enabled'] else 1)\n"
                + "elif 'enable' in args: d['enabled']=True\n"
                + "elif 'start' in args or 'restart' in args: d['active']=True\n"
                + "elif 'daemon-reload' not in args: sys.exit(1)\n"
                + 'p.write_text(json.dumps(d))\n')
            systemctl.chmod(0o755)
            canary.mkdir(parents=True, exist_ok=True)
            config = work / 'ansible.cfg'
            config.write_text('[defaults]\nroles_path=' + str(ROOT / 'ansible/roles') + '\ninterpreter_python=' + sys.executable + '\n')
            inventory = work / 'inventory.yml'
            inventory.write_text('all:\n  hosts:\n    proxmox:\n      ansible_connection: local\n'
                + '      ansible_become: false\n      ansible_user: fixture-controller\n'
                + '      ansible_python_interpreter: ' + sys.executable + '\n'
                + "      zfs_backup_snapshot_dataset_guid: '123456'\n"
                + "      zfs_backup_snapshot_tailscale_ipv4: '100.113.54.34'\n")
            command = [shutil.which('ansible-playbook'), '-i', str(inventory),
                       str(ROOT / 'ansible/playbooks/configure-zfs-backup-snapshots.yml')]
            env = {**os.environ, 'ANSIBLE_CONFIG': str(config), 'ANSIBLE_LOCAL_TEMP': str(work / 'controller-tmp'),
                   'PATH': str(mock_bin) + ':' + os.environ['PATH']}
            def play(*args):
                result = subprocess.run([*command, *args], env=env, text=True, capture_output=True, timeout=120)
                return result.returncode, result.stdout + result.stderr
            def update(**changes):
                metadata.write_text(json.dumps({**json.loads(metadata.read_text()), **changes}))
            try:
                code, output = play()
                self.assertNotEqual(code, 0, output)
                self.assertFalse(Path('/var/lib/iac-ansible-production.lock').exists())
                code, output = play('--check')
                self.assertEqual(code, 0, output)
                self.assertFalse(program.exists())
                self.assertFalse(Path('/var/lib/iac-ansible-production.lock').exists())
                code, output = play('-e', 'zfs_backup_snapshot_apply_confirmed=true')
                self.assertEqual(code, 0, output)
                self.assertFalse(Path('/var/lib/iac-ansible-production.lock').exists())
                self.assertEqual(program.read_bytes(), (ROOT / 'scripts/zfs-backup-snapshot').read_bytes())
                self.assertEqual(Path(BROKER['CONFIG']).stat().st_mode & 0o777, 0o600)
                self.assertEqual(Path(BROKER['LOCK']).stat().st_mode & 0o777, 0o600)
                self.assertTrue(json.loads(metadata.read_text())['enabled'])
                self.assertTrue(json.loads(metadata.read_text())['active'])
                # Exercise the installed worker's real socket stdio, protected
                # files and flock, not just the mock systemd manager's status.
                client, server = socket.socketpair()
                process = subprocess.Popen(['/usr/bin/python3', '-I', str(program), '--privileged'],
                    stdin=server, stdout=server, stderr=subprocess.PIPE)
                server.close()
                with client:
                    client.settimeout(10)
                    client.sendall(b'{"action":"list"}'); client.shutdown(socket.SHUT_WR)
                    with client.makefile('rb') as response:
                        reply = response.read(65537)
                _, errors = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, errors)
                self.assertEqual(json.loads(reply), {'snapshots': [], 'pool_healthy': True})
                units = work / 'units'; units.mkdir()
                for dependency in ('nfs-server.service', 'tailscaled.service'):
                    (units / dependency).write_text('[Service]\nExecStart=/bin/true\n')
                checked = subprocess.run(['systemd-analyze', 'verify', '--man=no', str(socket_unit), str(service_unit)],
                    capture_output=True, text=True, env={**os.environ, 'SYSTEMD_UNIT_PATH': str(units) + ':/etc/systemd/system:/usr/lib/systemd/system'})
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
                code, output = play('-e', 'zfs_backup_snapshot_apply_confirmed=true')
                self.assertEqual(code, 0, output)
                self.assertIn('changed=0', output)
                update(pending=True)
                code, output = play('--check')
                self.assertNotEqual(code, 0, output)
                self.assertIn('Refuse authority replacement', output)
                self.assertFalse(Path('/var/lib/iac-ansible-production.lock').exists())
                update(pending=False, foreign=True)
                code, output = play('--check')
                self.assertNotEqual(code, 0, output)
                self.assertIn('Refuse a foreign endpoint', output)
            finally:
                for path in owned:
                    path.unlink(missing_ok=True)
                if created_canary:
                    canary.rmdir()


if __name__ == '__main__':
    unittest.main()
