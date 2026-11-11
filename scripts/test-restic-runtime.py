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
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RUNNER = runpy.run_path(str(ROOT / 'scripts/restic-backup'))
CAPTURE = runpy.run_path(str(ROOT / 'scripts/restic-capture-files.py'))
OK = subprocess.CompletedProcess([], 0, '', '')

class Runtime(unittest.TestCase):
    def test_reviewed_bindings(self):
        policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        for key, name in (('runner', 'restic-backup'), ('capture', 'restic-capture-files.py')):
            actual = hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
            self.assertEqual(policy[key]['sha256' if key == 'runner' else 'adapter_sha256'], actual)
        self.assertEqual(policy['replication']['max_lag_seconds'], 48 * 3600)
        for service in ('cli-proxy-api', 'traefik', 'traefik-tailnet'):
            self.assertNotIn(service, policy['stop_groups']['applications'])

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

    def test_strict_nfs_waits_for_existing_work_before_reconciling_without_recapture(self):
        main = RUNNER['main']
        flock = fcntl.flock
        for lock_name in ('home-lab-restic-repositories.lock', 'home-lab-restic-daily-nfs.lock'):
            with self.subTest(lock=lock_name), tempfile.TemporaryDirectory() as directory:
                root, gate, _ = self.coordination_fixture(directory)
                held_path = gate.with_name(lock_name)
                requested, finished = threading.Event(), threading.Event()
                errors = []
                inventory_ready = root / 'fresh-inventory'
                def acquire(stream, flags):
                    if Path(stream.name) == held_path:
                        self.assertFalse(flags & fcntl.LOCK_NB)
                        requested.set()
                    return flock(stream, flags)
                def reconcile(_policy, destination):
                    self.assertEqual(destination, 'nfs')
                    self.assertTrue(inventory_ready.exists())
                reconciler = mock.Mock(side_effect=reconcile)
                def invoke():
                    try:
                        main()
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        finished.set()
                with held_path.open('a+') as active, mock.patch.dict(os.environ, {
                    'HOME_LAB_RESTIC_TESTING': '1', 'HOME_LAB_RESTIC_TEST_ROOT': str(root),
                }), mock.patch.object(sys, 'argv', ['restic-backup', 'daily-nfs', '--wait']), \
                        mock.patch('signal.signal'), mock.patch.object(fcntl, 'flock', side_effect=acquire), \
                        mock.patch.dict(main.__globals__, {
                            'reconcile': reconciler,
                            'daily_local': mock.Mock(side_effect=AssertionError('recapture')),
                        }):
                    flock(active, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    worker = threading.Thread(target=invoke, daemon=True)
                    worker.start()
                    try:
                        self.assertTrue(requested.wait(5))
                        self.assertFalse(finished.is_set())
                        reconciler.assert_not_called()
                        inventory_ready.touch()
                    finally:
                        flock(active, fcntl.LOCK_UN)
                        worker.join(5)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(errors, [])
                    reconciler.assert_called_once()

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

    @unittest.skipUnless(sys.platform == 'linux', 'requires native GNU timeout')
    def test_strict_nfs_native_timeout_bounds_lock_wait_and_preserves_ownership(self):
        import yaml
        tasks = yaml.safe_load((ROOT / 'ansible/roles/restic_backup/tasks/fresh.yml').read_text())
        task = next(t for t in tasks if t['name'] == 'Reconcile NFS without ever repeating application capture')
        argv = task['ansible.builtin.command']['argv']
        with tempfile.TemporaryDirectory() as directory:
            root, owner, _ = self.interruption_fixture(directory)
            before = owner.read_bytes()
            command = []
            for value in argv:
                if value == '/usr/local/libexec/home-lab/restic-backup':
                    command.extend([sys.executable, str(ROOT / 'scripts/restic-backup')])
                else:
                    command.append({'24h': '2s', '--kill-after=5m': '--kill-after=1s'}.get(value, value))
            environment = {**os.environ, 'HOME_LAB_RESTIC_TESTING': '1',
                           'HOME_LAB_RESTIC_TEST_ROOT': str(root)}
            with (root / 'run/lock/home-lab-restic-daily-nfs.lock').open('a+') as active:
                fcntl.flock(active, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertIn('reason=interrupted', result.stderr)
            self.assertEqual(owner.read_bytes(), before)

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

    def test_stop_copy_restart_has_no_repository_phase_and_preserves_inactive_services(self):
        cold = RUNNER['cold_capture']
        events = []
        adapter = mock.Mock()
        adapter.copy_paths.side_effect = lambda *_: events.append('copy')
        adapter.retry.side_effect = lambda action: action()
        adapter.database_dump.side_effect = lambda *_: events.append('dump')
        policy = {'runner': {'exclude_file_path': '/excluded'}, '_owner': 'a' * 64}
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
            'compose': compose, 'restart_recorded': lambda *_: events.append('restart'),
            'restic_result': mock.Mock(side_effect=AssertionError('upload during cold window')),
        }):
            cold(policy, adapter, step, Path('/unused'), {'app', 'inactive'})
        self.assertEqual(events, [['stop', '--timeout', '120', 'app'], 'copy', 'dump', 'restart'])
        self.assertEqual(recorded.call_args.args[1]['owner'], policy['_owner'])

    def test_reviewed_capture_plan_never_interrupts_cli_or_either_ingress(self):
        policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
        kept = {'cli-proxy-api', 'traefik', 'traefik-tailnet'}
        declared = kept | {s for step in policy['capture']['cold'] for s in step['services']}
        running = set(declared)
        adapter = mock.Mock()
        adapter.wolf_paths.return_value = ([], {})
        adapter.retry.side_effect = lambda operation: operation()
        adapter.copy_paths.side_effect = lambda *_: self.assertTrue(kept <= running)
        def compose(_policy, args):
            if args[0] == 'stop':
                self.assertTrue(kept.isdisjoint(args[3:]))
                running.difference_update(args[3:])
            else:
                running.update(args[1:])
            return OK
        cold = RUNNER['cold_capture']
        with mock.patch.dict(cold.__globals__, {
            'rooted': Path, 'journal_path': lambda _: Path('/unused'), 'atomic_json': mock.Mock(),
            'durable_unlink': mock.Mock(), 'service_container': lambda _, s: s,
            'service_running': lambda _, s: s in running, 'service_healthy': lambda *_: True,
            'wolf_siblings': lambda _: [], 'compose': compose,
        }):
            for step in policy['capture']['cold']:
                cold(policy, adapter, step, Path('/unused'), declared)
                self.assertEqual(running, declared)

    def test_failed_stop_or_copy_always_attempts_restart(self):
        cold = RUNNER['cold_capture']
        for phase in ('stop', 'copy'):
            with self.subTest(phase=phase):
                adapter = mock.Mock()
                adapter.retry.side_effect = lambda operation: operation()
                if phase == 'copy':
                    adapter.copy_paths.side_effect = CAPTURE['CaptureError']('copy')
                restart = mock.Mock()
                with mock.patch.dict(cold.__globals__, {
                    'rooted': Path, 'journal_path': lambda _: Path('/unused'),
                    'service_running': mock.Mock(side_effect=[True, False]), 'atomic_json': mock.Mock(),
                    'compose': mock.Mock(return_value=OK if phase == 'copy' else subprocess.CompletedProcess([], 1, '', '')),
                    'restart_recorded': restart,
                }), self.assertRaises((RUNNER['WorkflowError'], CAPTURE['CaptureError'])):
                    cold({'runner': {'exclude_file_path': '/unused'}}, adapter,
                         {'services': ['app'], 'paths': ['/data']}, Path('/unused'), {'app'})
                self.assertEqual(restart.call_args.args[1]['running_services'], ['app'])

    def test_busy_wolf_refuses_before_staging_or_interruption_and_can_retry_when_idle(self):
        daily = RUNNER['daily_local']
        for busy in ('session', 'writer'):
            with self.subTest(busy=busy), tempfile.TemporaryDirectory() as directory:
                policy = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
                stage = Path(directory).resolve() / 'capture'
                policy['capture']['stage'] = str(stage)
                declared = {s for step in policy['capture']['cold'] for s in step['services']}
                adapter = mock.Mock()
                adapter.CaptureError = CAPTURE['CaptureError']
                adapter.wolf_idle.side_effect = CAPTURE['CaptureError']('wolf_not_idle') if busy == 'session' else None
                adapter.fresh_stage.side_effect = lambda path, _: path.mkdir(mode=0o700) or path
                siblings = mock.Mock(return_value=['wolf', 'game'] if busy == 'writer' else ['wolf'])
                cold = mock.Mock(side_effect=RUNNER['WorkflowError']('capture_reached'))
                with mock.patch.dict(daily.__globals__, {
                    'recover_interruption': mock.Mock(), 'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                    'capture_adapter': lambda _: adapter, 'rooted': Path,
                    'declared_services': lambda _: declared, 'service_container': lambda _, s: s,
                    'service_running': lambda *_: True, 'wolf_siblings': siblings, 'cold_capture': cold,
                }):
                    reason = 'wolf_not_idle' if busy == 'session' else 'wolf_active_writer'
                    with self.assertRaisesRegex(RUNNER['WorkflowError'], reason):
                        daily(policy, 'a' * 64)
                    self.assertFalse(stage.exists())
                    cold.assert_not_called()
                    adapter.fresh_stage.assert_not_called()
                    adapter.capacity_check.assert_not_called()
                    # Ordinary activity must not require manual staging cleanup.
                    adapter.wolf_idle.side_effect = None
                    siblings.return_value = ['wolf']
                    with self.assertRaisesRegex(RUNNER['WorkflowError'], 'capture_reached'):
                        daily(policy, 'a' * 64)
                    self.assertTrue(stage.is_dir())
                    cold.assert_called_once()

    def test_unready_stage_is_preserved_without_restarting_capture(self):
        daily = RUNNER['daily_local']
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory).resolve() / 'capture'
            stage.mkdir(mode=0o700)
            payload = stage / 'partial-copy'
            payload.write_bytes(b'synthetic interrupted capture')
            declared, available, cold = mock.Mock(), mock.Mock(), mock.Mock()
            with mock.patch.dict(daily.__globals__, {
                'recover_interruption': mock.Mock(), 'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                'capture_adapter': lambda _: types.SimpleNamespace(CaptureError=CAPTURE['CaptureError']),
                'rooted': Path, 'declared_services': declared, 'verify_wolf_available': available,
                'cold_capture': cold,
            }), self.assertRaisesRegex(RUNNER['WorkflowError'], 'previous_capture_requires_inspection'):
                daily({'capture': {'stage': str(stage)}}, 'a' * 64)
            self.assertEqual(payload.read_bytes(), b'synthetic interrupted capture')
            declared.assert_not_called()
            available.assert_not_called()
            cold.assert_not_called()

    def test_wolf_is_rechecked_immediately_before_interruption(self):
        cold = RUNNER['cold_capture']
        adapter = mock.Mock()
        adapter.wolf_paths.return_value = ([], {})
        adapter.wolf_idle.side_effect = CAPTURE['CaptureError']('wolf_not_idle')
        journal, compose = mock.Mock(), mock.Mock()
        with mock.patch.dict(cold.__globals__, {
            'service_container': lambda _, s: s, 'service_running': lambda *_: True,
            'wolf_siblings': lambda _: ['wolf'], 'atomic_json': journal, 'compose': compose,
        }), self.assertRaisesRegex(CAPTURE['CaptureError'], 'wolf_not_idle'):
            cold({}, adapter, {'services': ['wolf'], 'paths': [], 'wolf': '/wolf'}, Path('/unused'), {'wolf'})
        journal.assert_not_called()
        compose.assert_not_called()

    def test_ready_stage_retries_upload_without_another_stop_copy_or_export(self):
        daily = RUNNER['daily_local']
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory).resolve() / 'stage'
            stage.mkdir(mode=0o700)
            manifest = {'version': 2, 'capture': 'fixture', 'policy': 'a' * 64, 'artifact': 'b' * 64,
                        'owner': None, 'captured_at': '2026-11-10T00:00:00+00:00'}
            (stage / 'manifest.json').write_text(json.dumps(manifest))
            adapter = types.SimpleNamespace(CaptureError=CAPTURE['CaptureError'])
            events = []
            def restic(_policy, _repository, args, **kwargs):
                events.append(args[0])
                if args[0] == 'backup':
                    return subprocess.CompletedProcess([], 0, json.dumps({'message_type': 'summary', 'snapshot_id': 'c' * 64}), '')
                # Healthy copies must fit inside one completion invocation, not
                # consume the service's three rate-limited start attempts.
                budgets = {}
                for name in ('local', 'nfs', 'proton'):
                    unit = configparser.ConfigParser(interpolation=None)
                    unit.read(ROOT / f'ansible/roles/restic_backup/templates/home-lab-restic-daily-{name}.service.j2')
                    budgets[name] = int(unit['Service']['TimeoutStartSec'].removesuffix('h')) * 3600
                wait = int(args[args.index('--retry-lock') + 1].removesuffix('h')) * 3600
                self.assertGreaterEqual(wait, max(budgets['nfs'], budgets['proton']))
                self.assertGreater(kwargs['timeout'], wait)
                self.assertGreaterEqual(budgets['local'], 8 * 3600 + kwargs['timeout'])
                return OK
            with mock.patch.dict(daily.__globals__, {
                'recover_interruption': mock.Mock(), 'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                'capture_adapter': lambda _: adapter, 'rooted': Path,
                'artifact_hash': lambda _: 'b' * 64, 'read_json': lambda *_: manifest,
                'restic_result': restic,
                'inventory': mock.Mock(side_effect=[[], [{'id': 'd' * 64, 'tags': [
                    'capture=fixture', 'complete=full-v2', 'format=full-v2', 'cadence=daily']}]]),
                'cold_capture': mock.Mock(side_effect=AssertionError('recapture')),
                'verify_wolf_available': mock.Mock(side_effect=AssertionError('gaming must not block ready-stage upload')),
            }), mock.patch('builtins.print'):
                daily({'capture': {'stage': str(stage)}}, 'a' * 64)
            self.assertEqual(events, ['backup', 'tag'])
            self.assertFalse(stage.exists())

    def test_restic_completion_timeout_reaches_the_subprocess(self):
        restic = RUNNER['restic_result']
        policy = {'tools': {'restic': {'installed_path': '/restic'}},
                  'repositories': {'games': {'path': '/repository'}}}
        args = ['tag', '--retry-lock', '12h', '--add', 'complete=full-v2', 'a' * 64]
        with mock.patch.dict(restic.__globals__, {'repository_environment': lambda *_: {}}), \
                mock.patch.dict(restic.__globals__, run=mock.Mock(return_value=OK)):
            restic(policy, 'games', args, timeout=13 * 3600)
            restic.__globals__['run'].assert_called_once_with(
                ['/restic', '--repo', '/repository', *args], environment={}, timeout=13 * 3600)

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
            with self.subTest(destination=destination), mock.patch.dict(copy.__globals__, {
                'repository_environment': lambda *_: {}, 'inventory': lambda *_: [replica],
                'testing': lambda: True,
            }), mock.patch('subprocess.run', return_value=OK) as command:
                self.assertEqual(copy(policy, 'games', destination, snapshot), replica['id'])
                self.assertEqual(command.call_args.args[0], [
                    '/restic', '--repo', '/' + destination, '--from-repo', '/games', 'copy', snapshot['id'],
                ])
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.kwargs['timeout'], budget)

    def test_failed_retries_and_partial_scan_never_qualify_a_snapshot(self):
        daily = RUNNER['daily_local']
        for code in (1, 3):
            with tempfile.TemporaryDirectory() as directory, self.subTest(code=code):
                stage = Path(directory).resolve()
                manifest = {'version': 2, 'capture': 'fixture', 'policy': 'a' * 64, 'artifact': 'b' * 64,
                            'owner': None, 'captured_at': '2026-11-10T00:00:00+00:00'}
                calls = mock.Mock(return_value=subprocess.CompletedProcess([], code, '', 'private-error-not-logged'))
                with mock.patch.dict(daily.__globals__, {
                    'recover_interruption': mock.Mock(), 'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                    'capture_adapter': lambda _: types.SimpleNamespace(CaptureError=CAPTURE['CaptureError']),
                    'rooted': Path, 'artifact_hash': lambda _: 'b' * 64,
                    'read_json': lambda *_: manifest, 'inventory': lambda *_: [], 'restic_result': calls,
                }), mock.patch('time.sleep'), self.assertRaises(RUNNER['WorkflowError']):
                    daily({'capture': {'stage': str(stage)}}, 'a' * 64)
                self.assertEqual(calls.call_count, 1 if code == 3 else 3)
                self.assertTrue(all(c.args[2][0] == 'backup' for c in calls.call_args_list))
                self.assertTrue(stage.exists())

    def test_retention_never_forgets_uncopied_complete_sources(self):
        maintenance = RUNNER['maintenance']
        with tempfile.TemporaryDirectory() as directory:
            source = {'id': 'a' * 64, 'time': '2026-11-10T00:00:00Z', 'tags': [
                'complete=full-v2', 'format=full-v2', 'cadence=daily']}
            writes = mock.Mock(side_effect=AssertionError('unsafe retention'))
            with mock.patch.dict(maintenance.__globals__, {
                'journal_path': lambda _: Path(directory) / 'journal', 'rooted': Path,
                'preflight': mock.Mock(), 'inventory': lambda _, n: [source] if n == 'games' else [],
                'restic_result': writes,
            }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'):
                with self.assertRaisesRegex(RUNNER['WorkflowError'], 'replication_pending'):
                    maintenance({'capture': {'stage': str(Path(directory) / 'stage')},
                                 'retention': {'read_data_subset': '10%'}})
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
        finish = RUNNER['finish_retention']
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
            with mock.patch.dict(finish.__globals__, {
                'journal_path': lambda _: root / 'interruption.json', 'restic_result': writes,
            }):
                for value in bad:
                    with self.subTest(value=value):
                        pending.write_text(json.dumps(value))
                        pending.chmod(0o600)
                        with self.assertRaisesRegex(RUNNER['WorkflowError'], 'retention_journal_schema'):
                            finish({'repositories': {name: {'id': rid} for name, rid in repositories.items()}})
                        self.assertTrue(pending.exists())
            writes.assert_not_called()

    def test_retention_keeps_journal_until_replica_absence_is_verified(self):
        finish = RUNNER['finish_retention']
        repositories = {name: str(i + 1) * 64 for i, name in enumerate(('games', 'nfs', 'proton'))}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pending = root / 'retention.json'
            pending.write_text(json.dumps({'version': 1, 'repositories': repositories, 'snapshots': [
                {'games': 'a' * 64, 'nfs': 'b' * 64, 'proton': 'c' * 64}]}))
            pending.chmod(0o600)
            records = {'games': [], 'nfs': [{'id': 'b' * 64}], 'proton': [{'id': 'c' * 64}]}
            with mock.patch.dict(finish.__globals__, {
                'journal_path': lambda _: root / 'interruption.json', 'inventory': lambda _, n: records[n],
                'restic_result': lambda *_: OK,
            }), self.assertRaisesRegex(RUNNER['WorkflowError'], 'forget_copy_verify'):
                finish({'repositories': {name: {'id': rid} for name, rid in repositories.items()}})
            self.assertTrue(pending.exists())

    def test_retention_never_forgets_uncopied_legacy_sources(self):
        maintenance = RUNNER['maintenance']
        legacy = {'id': 'a' * 64, 'tags': ['cadence=daily']}
        with tempfile.TemporaryDirectory() as directory:
            writes = mock.Mock(side_effect=AssertionError('unsafe retention'))
            with mock.patch.dict(maintenance.__globals__, {
                'journal_path': lambda _: Path(directory) / 'journal', 'rooted': Path,
                'preflight': mock.Mock(), 'inventory': lambda _, n: [legacy] if n == 'games' else [],
                'restic_result': writes,
            }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'):
                with self.assertRaisesRegex(RUNNER['WorkflowError'], 'replication_pending'):
                    maintenance({'capture': {'stage': str(Path(directory) / 'stage')},
                                 'retention': {'read_data_subset': '10%'}})
            writes.assert_not_called()

    def test_replication_includes_legacy_but_not_partial_or_unknown_formats(self):
        reconcile = RUNNER['reconcile']
        legacy = {'id': 'a' * 64, 'time': '2020-01-01T00:00:00Z', 'tags': ['cadence=daily']}
        partial = {'id': 'b' * 64, 'tags': ['cadence=daily', 'format=full-v2']}
        unknown = {'id': 'c' * 64, 'tags': ['cadence=daily', 'format=future']}
        unrelated = {'id': 'd' * 64, 'tags': []}
        copy = mock.Mock()
        with mock.patch.dict(reconcile.__globals__, {
            'preflight': mock.Mock(), 'inventory': lambda _, n: [legacy, partial, unknown, unrelated] if n == 'games' else [],
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
        recover = RUNNER['recover_interruption']
        restart = mock.Mock()
        with mock.patch.dict(recover.__globals__, {
            'journal_path': lambda _: Path('/unused'),
            'read_json': lambda *_: {'version': 1, 'running_services': ['--attach'], 'stop_order': ['--attach']},
            'restart_recorded': restart,
        }), self.assertRaisesRegex(RUNNER['WorkflowError'], 'journal_schema'):
            recover({'stop_groups': {'applications': ['app'], 'databases': []}})
        restart.assert_not_called()

    def test_namespace_health_failure_retains_journal(self):
        restart = RUNNER['restart_recorded']
        policy = {'stop_groups': {'applications': ['qbittorrent', 'gluetun'], 'databases': []}}
        compose, unlink = mock.Mock(return_value=OK), mock.Mock()
        with mock.patch.dict(restart.__globals__, {
            'compose': compose, 'service_healthy': lambda *_: False,
            'durable_unlink': unlink, 'testing': lambda: True,
        }), mock.patch('time.monotonic', side_effect=[0, 1, 4]), mock.patch('time.sleep'):
            with self.assertRaisesRegex(RUNNER['WorkflowError'], 'service_health'):
                restart(policy, {'running_services': ['qbittorrent', 'gluetun']})
        compose.assert_called_once_with(policy, ['start', 'gluetun'])
        unlink.assert_not_called()

if __name__ == '__main__':
    unittest.main()
