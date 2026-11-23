#!/usr/bin/env python3
"""Admission behavior: complete local recovery, replica freshness, and ownership."""
from datetime import datetime, timedelta, timezone
import importlib.util
import os
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
NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


def snapshot(identifier='1', age=0, artifact=ARTIFACT, owner=None, policy=POLICY):
    tags = ['cadence=daily', 'format=full-v2', 'complete=full-v2', 'policy=' + policy, 'artifact=' + artifact]
    if owner:
        tags += ['owner=' + owner]
    return {'id': identifier * 64, 'time': (NOW - timedelta(hours=age)).isoformat(),
            'tags': tags, 'tree': 'd' * 64, 'paths': [STAGE]}


def copied(source, identifier):
    return {**source, 'original': source.get('original', source['id']), 'id': identifier * 64}


class Admission(unittest.TestCase):
    def select(self, games, nfs, proton, routine=True, owner=None):
        return OBSERVER.select_full(EVIDENCE, {'games': games, 'nfs': nfs, 'proton': proton},
                                    POLICY, ARTIFACT, STAGE, routine=routine, owner=owner,
                                    now=NOW, max_replica_age=48 * 3600)

    def test_routine_can_use_an_earlier_artifact_with_recent_replicas(self):
        newest = snapshot(artifact='e' * 64)
        older = snapshot('2', age=48)
        self.assertEqual(self.select([newest, older], [copied(older, '3')], [copied(older, '4')]),
                         (newest, copied(older, '3'), copied(older, '4')))

    def test_replica_age_is_measured_from_now_not_latest_local_or_upload_time(self):
        newest = snapshot(age=24, owner=OWNER)
        for age in (48 + 1 / 3600, -1):
            older = snapshot('2', age=age, policy='e' * 64)
            for routine in (True, False):
                for destination in ('nfs', 'proton'):
                    with self.subTest(destination=destination, age=age, routine=routine), self.assertRaisesRegex(
                            OBSERVER.ObservationError, destination + '_replication_stale'):
                        self.select([newest, older], [copied(older if destination == 'nfs' else newest, '3')],
                                    [copied(older if destination == 'proton' else newest, '4')], routine=routine)

    def test_missing_initial_replica_coverage_blocks_both_modes(self):
        source = snapshot()
        for routine in (True, False):
            for nfs, proton in (([], [copied(source, '2')]), ([copied(source, '2')], [])):
                with self.subTest(routine=routine), self.assertRaisesRegex(OBSERVER.ObservationError, 'baseline_missing'):
                    self.select([source], nfs, proton, routine=routine)

    def test_strict_requires_exact_owned_local_but_neither_replica_of_that_capture(self):
        newest = snapshot(owner=OWNER)
        previous = snapshot('2', age=47, policy='e' * 64, artifact='f' * 64)
        nfs = copied(previous, '3')
        proton = copied(previous, '4')
        self.assertEqual(self.select([newest, previous], [nfs], [proton], routine=False, owner=OWNER),
                         (newest, nfs, proton))
        with self.assertRaisesRegex(OBSERVER.ObservationError, 'local_missing'):
            self.select([newest, previous], [nfs], [proton], routine=False, owner='e' * 64)

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

    def test_routine_requires_capture_strictly_newer_than_cutoff(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        cutoff_time = now - timedelta(minutes=1)
        with tempfile.TemporaryDirectory() as directory:
            cutoff = Path(directory) / 'post-change-cutoff'
            cutoff.touch(mode=0o600)
            os.utime(cutoff, (cutoff_time.timestamp(), cutoff_time.timestamp()))
            with mock.patch.object(OBSERVER, 'require_regular') as protected:
                for seconds in (-1, 0, 1):
                    with self.subTest(seconds=seconds):
                        captured = {'time': (cutoff_time + timedelta(seconds=seconds)).isoformat()}
                        if seconds <= 0:
                            with self.assertRaisesRegex(OBSERVER.ObservationError, 'post_change_capture_required'):
                                OBSERVER.require_fresh(captured, now, cutoff=cutoff)
                        else:
                            OBSERVER.require_fresh(captured, now, cutoff=cutoff)
                self.assertEqual(protected.call_args_list, [mock.call(cutoff, 0o600)] * 3)

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

    def test_copy_and_queued_maintenance_do_not_block_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, units = self.rebooted_units(directory)
            for workflow in ('replication', 'maintenance'):
                units[f'home-lab-restic-{workflow}.timer'].update(
                    SubState='running', Unit=f'home-lab-restic-{workflow}.target', LastTriggerUSec='scheduled')
            for service in ('daily-nfs', 'maintenance-local'):
                units[f'home-lab-restic-{service}.service'].update(ActiveState='activating', SubState='start')
            units['home-lab-restic-daily-proton.service'].update(ActiveState='failed', SubState='failed', Result='exit-code')
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

    def test_wrong_repository_identity_is_never_treated_as_stale_replication(self):
        with self.assertRaises(OBSERVER.ObservationError):
            OBSERVER.require_repository_identity({'id': 'a' * 64}, 'b' * 64)

if __name__ == '__main__':
    unittest.main()
