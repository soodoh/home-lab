#!/usr/bin/env python3
"""Admission behavior: complete local recovery, capture-time lag, and ownership."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('observer', ROOT / 'scripts/observe-restic-backups.py')
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)
EVIDENCE_SPEC = importlib.util.spec_from_file_location('evidence', ROOT / 'scripts/restic_snapshot_evidence.py')
EVIDENCE = importlib.util.module_from_spec(EVIDENCE_SPEC)
EVIDENCE_SPEC.loader.exec_module(EVIDENCE)
POLICY, ARTIFACT, OWNER = 'a' * 64, 'b' * 64, 'c' * 64
STAGE = '/mnt/games/home-lab-backup/capture'


def snapshot(identifier='1', age=0, artifact=ARTIFACT, owner=None):
    tags = ['cadence=daily', 'format=full-v2', 'complete=full-v2', 'policy=' + POLICY, 'artifact=' + artifact]
    if owner:
        tags += ['owner=' + owner]
    return {'id': identifier * 64, 'time': (datetime.now(timezone.utc) - timedelta(hours=age)).isoformat(),
            'tags': tags, 'tree': 'd' * 64, 'paths': [STAGE]}


def copied(source, identifier):
    return {**source, 'original': source.get('original', source['id']), 'id': identifier * 64}


class Admission(unittest.TestCase):
    def select(self, games, nfs, proton, routine=True, owner=None):
        return OBSERVER.select_full(EVIDENCE, {'games': games, 'nfs': nfs, 'proton': proton},
                                    POLICY, ARTIFACT, STAGE, routine=routine, owner=owner)

    def test_routine_can_use_an_earlier_artifact_with_bounded_replica_lag(self):
        newest = snapshot(artifact='e' * 64)
        older = snapshot('2', age=47)
        result = self.select([newest, older], [copied(older, '3')], [copied(older, '4')])
        self.assertEqual(result[0], newest)

    def test_lag_is_original_capture_time_not_recent_upload_time(self):
        newest, older = snapshot(), snapshot('2', age=49)
        for destination in ('nfs', 'proton'):
            with self.subTest(destination=destination), self.assertRaisesRegex(OBSERVER.ObservationError, 'replication_stale'):
                self.select([newest, older], [copied(older if destination == 'nfs' else newest, '3')],
                            [copied(older if destination == 'proton' else newest, '4')])

    def test_missing_initial_replica_coverage_blocks_routine(self):
        source = snapshot()
        for nfs, proton in (([], [copied(source, '2')]), ([copied(source, '2')], [])):
            with self.assertRaisesRegex(OBSERVER.ObservationError, 'baseline_missing'):
                self.select([source], nfs, proton)

    def test_strict_requires_exact_owned_local_and_nfs_but_not_newest_proton(self):
        newest = snapshot(owner=OWNER)
        previous = snapshot('2', age=47)
        result = self.select([newest, previous], [copied(newest, '3')], [copied(previous, '4')], routine=False, owner=OWNER)
        self.assertEqual(result[0], newest)
        with self.assertRaisesRegex(OBSERVER.ObservationError, 'replication_stale'):
            self.select([newest, previous], [copied(previous, '3')], [copied(previous, '4')], routine=False, owner=OWNER)
        with self.assertRaisesRegex(OBSERVER.ObservationError, 'local_missing'):
            self.select([newest], [copied(newest, '3')], [copied(newest, '4')], routine=False, owner='e' * 64)

    def test_current_policy_complete_scope_and_freshness_are_mandatory(self):
        source = snapshot()
        invalid = [
            {**source, 'tags': [t for t in source['tags'] if t != 'complete=full-v2']},
            {**source, 'paths': ['/somewhere-else']},
            {**source, 'tags': [t.replace(POLICY, 'e' * 64) for t in source['tags']]},
            snapshot(age=49), snapshot(age=-1),
        ]
        for bad in invalid:
            with self.subTest(bad=bad), self.assertRaises(OBSERVER.ObservationError):
                self.select([bad], [copied(bad, '2')], [copied(bad, '3')])

    def test_conflicting_format_cannot_replace_a_valid_baseline(self):
        valid = snapshot('2', age=1)
        conflict = snapshot()
        conflict['tags'].append('format=future')
        self.assertEqual(self.select([conflict, valid], [copied(conflict, '3'), copied(valid, '4')],
                                     [copied(conflict, '5'), copied(valid, '6')])[0], valid)
        with self.assertRaisesRegex(OBSERVER.ObservationError, 'complete_local_missing'):
            self.select([conflict], [copied(conflict, '3')], [copied(conflict, '5')])

    def test_rejects_changed_evidence_before_executing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'restic_snapshot_evidence.py'
            path.write_text('raise AssertionError("unreviewed evidence executed")')
            path.chmod(0o644)
            # Isolate the checksum check from root-owned file metadata.
            with mock.patch.object(OBSERVER, 'require_regular') as metadata:
                with self.assertRaisesRegex(OBSERVER.ObservationError, 'reviewed_source_drift'):
                    OBSERVER.load_snapshot_evidence(path, 'a' * 64)
                metadata.assert_called_once_with(path, 0o644)

    def test_native_retagged_copy_must_match_origin_tree_paths_time_and_tags(self):
        source = {**snapshot(), 'original': 'f' * 64}
        good = copied(source, '2')
        self.assertEqual(OBSERVER.match_copy(EVIDENCE, source, [good]), good)
        for field, value in (('original', source['id']), ('tree', 'e' * 64), ('paths', ['/wrong']),
                             ('time', snapshot(age=1)['time']), ('tags', [])):
            self.assertIsNone(OBSERVER.match_copy(EVIDENCE, source, [{**good, field: value}]))
        with self.assertRaisesRegex(OBSERVER.ObservationError, 'ambiguous'):
            OBSERVER.match_copy(EVIDENCE, source, [good, {**good, 'id': '3' * 64}])

    def test_unknown_owner_and_interruption_never_receive_routine_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / 'journal'
            owner = root / 'production.lock'
            with mock.patch.object(OBSERVER, 'OWNERS', (owner,)):
                owner.mkdir(mode=0o700)
                with self.assertRaises(OBSERVER.ObservationError):
                    OBSERVER.validate_owners(journal, None)
                owner.rmdir()
                journal.write_text('{}')
                with self.assertRaises(OBSERVER.ObservationError):
                    OBSERVER.validate_owners(journal, None)

    def rebooted_units(self, directory):
        policy = {'schedule': {'daily_calendar': '*-*-* 05:00:00',
                               'maintenance_calendar': 'Sun *-*-* 07:00:00'}}
        units = {name: {'LoadState': 'loaded', 'ActiveState': 'inactive',
                        'SubState': 'dead', 'Result': 'success', 'LastTriggerUSec': '',
                        'ExecMainStartTimestamp': '', 'ExecMainExitTimestamp': ''}
                 for name in OBSERVER.UNITS}
        for name in units:
            if name.endswith('.timer'):
                units[name].update(ActiveState='active', SubState='waiting', NextElapseUSecRealtime='next-trigger')
        root = Path(directory)
        for name, calendar in policy['schedule'].items():
            timer = 'daily' if name == 'daily_calendar' else 'maintenance'
            (root / ('home-lab-restic-' + timer + '.timer')).write_text(
                '[Timer]\nOnCalendar=' + calendar + '\nPersistent=false\n')
        return policy, units

    def validate_rebooted_units(self, directory, policy, units):
        def native_show(args):
            self.assertEqual(args[:2], ['/usr/bin/systemctl', 'show'])
            return '\n'.join(key + '=' + value for key, value in units[args[-1]].items())
        with mock.patch.object(OBSERVER, 'run', side_effect=native_show), \
                mock.patch.object(OBSERVER, 'require_regular'), \
                mock.patch.object(OBSERVER, 'Path', side_effect=lambda name: Path(directory) / Path(name).name):
            return OBSERVER.validate_units(policy)

    def test_strict_admission_uses_durable_complete_daily_snapshots_after_reboot(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, units = self.rebooted_units(directory)
            observed = self.validate_rebooted_units(directory, policy, units)
            self.assertEqual(set(observed), set(OBSERVER.UNITS))
            source = snapshot()
            self.assertEqual(self.select([source], [copied(source, '2')], [copied(source, '3')], routine=False)[0], source)
            # No wall-clock/job history is invented; the durable chain must still
            # prove the current policy/artifact, daily scope, completion and age.
            for bad in [snapshot(age=49), snapshot(age=-1), snapshot(artifact='e' * 64)] + [
                    {**source, 'tags': [tag for tag in source['tags'] if tag != required]}
                    for required in ('cadence=daily', 'complete=full-v2', 'policy=' + POLICY)]:
                with self.subTest(bad=bad), self.assertRaises(OBSERVER.ObservationError):
                    self.select([bad], [copied(bad, '2')], [copied(bad, '3')], routine=False)
            for games, nfs, proton in (([], [], []), ([source], [], [copied(source, '3')]),
                                       ([source], [copied(source, '2')], [])):
                with self.assertRaises(OBSERVER.ObservationError):
                    self.select(games, nfs, proton, routine=False)

    def test_reboot_does_not_waive_live_timer_writer_failure_or_calendar_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, units = self.rebooted_units(directory)
            for name, changes in [
                    ('home-lab-restic-daily.timer', {'ActiveState': 'inactive'}),
                    ('home-lab-restic-daily.timer', {'NextElapseUSecRealtime': ''}),
                    ('home-lab-restic-daily-local.service', {'ActiveState': 'active', 'SubState': 'running'}),
                    ('home-lab-restic-daily-local.service', {'Result': 'exit-code'}),
                    ('home-lab-restic-maintenance-local.service', {'Result': 'exit-code'})]:
                changed = {key: dict(value) for key, value in units.items()}
                changed[name].update(changes)
                with self.subTest(name=name, changes=changes), self.assertRaises(OBSERVER.ObservationError):
                    self.validate_rebooted_units(directory, policy, changed)
            timer = Path(directory) / 'home-lab-restic-daily.timer'
            timer.write_text('[Timer]\nOnCalendar=hourly\n')
            with self.assertRaisesRegex(OBSERVER.ObservationError, 'timer_cadence'):
                self.validate_rebooted_units(directory, policy, units)

    def test_scheduled_timer_exception_remains_narrow(self):
        values = {'ActiveState': 'active', 'SubState': 'running', 'Unit': 'home-lab-morning.target',
                  'LastTriggerUSec': 'scheduled'}
        OBSERVER.validate_timer_state('home-lab-restic-daily.timer', values, scheduled_deployment=True)
        with self.assertRaises(OBSERVER.ObservationError):
            OBSERVER.validate_timer_state('home-lab-restic-daily.timer', values)
        with self.assertRaises(OBSERVER.ObservationError):
            OBSERVER.validate_timer_state('home-lab-restic-replication.timer', values)
        OBSERVER.validate_timer_state('home-lab-restic-replication.timer', {
            **values, 'Unit': 'home-lab-restic-replication.target'})

    def test_slow_healthy_proton_metadata_has_a_bounded_remote_read_budget(self):
        policy = {'tools': {'restic': {'installed_path': '/restic'}},
                  'repositories': {'proton': {'path': 'rclone:fixture:repository'}, 'games': {'path': '/local'}},
                  'runner': {'local_cache_path': '/cache'}}
        def slow_metadata(args, **kwargs):
            if kwargs['timeout'] < 90:
                raise subprocess.TimeoutExpired(args, kwargs['timeout'])
            return subprocess.CompletedProcess(args, 0, '[]', '')
        for arguments in [['cat', 'config'], ['snapshots', '--json']]:
            with self.subTest(arguments=arguments), mock.patch('subprocess.run', side_effect=slow_metadata) as command:
                self.assertEqual(OBSERVER.proton_restic(policy, arguments), '[]')
                self.assertEqual(command.call_args.kwargs['timeout'], 180)
                self.assertEqual(command.call_count, 1)
        with mock.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as command:
            OBSERVER.local_restic(policy, 'games', ['cat', 'config'])
            self.assertEqual(command.call_args.kwargs['timeout'], 60)
            OBSERVER.run(['/usr/bin/systemctl', 'show', 'fixture.service'])
            self.assertEqual(command.call_args.kwargs['timeout'], 60)

    def test_proton_read_timeout_and_errors_still_fail_closed_without_retry(self):
        policy = {'tools': {'restic': {'installed_path': '/restic'}},
                  'repositories': {'proton': {'path': 'rclone:fixture:repository'}}}
        with mock.patch('subprocess.run', side_effect=subprocess.TimeoutExpired(['/restic'], 180)) as command:
            with self.assertRaisesRegex(OBSERVER.ObservationError, 'command_execution'):
                OBSERVER.proton_restic(policy, ['snapshots', '--json'])
            self.assertEqual(command.call_count, 1)
        with mock.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'failure')) as command:
            with self.assertRaisesRegex(OBSERVER.ObservationError, 'command_failed'):
                OBSERVER.proton_restic(policy, ['snapshots', '--json'])
            self.assertEqual(command.call_count, 1)

    def test_wrong_repository_identity_is_never_replication_lag(self):
        with self.assertRaises(OBSERVER.ObservationError):
            OBSERVER.require_repository_identity({'id': 'a' * 64}, 'b' * 64)

if __name__ == '__main__':
    unittest.main()
