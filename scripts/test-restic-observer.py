#!/usr/bin/env python3
"""Admission behavior: complete local recovery, capture-time lag, and ownership."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('observer', ROOT / 'scripts/observe-restic-backups.py')
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)
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
        return OBSERVER.select_full({'games': games, 'nfs': nfs, 'proton': proton},
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

    def test_native_retagged_copy_must_match_origin_tree_paths_time_and_tags(self):
        source = {**snapshot(), 'original': 'f' * 64}
        good = copied(source, '2')
        self.assertEqual(OBSERVER.match_copy(source, [good]), good)
        for field, value in (('tree', 'e' * 64), ('paths', ['/wrong']), ('time', snapshot(age=1)['time']), ('tags', [])):
            self.assertIsNone(OBSERVER.match_copy(source, [{**good, field: value}]))
        with self.assertRaisesRegex(OBSERVER.ObservationError, 'ambiguous'):
            OBSERVER.match_copy(source, [good, {**good, 'id': '3' * 64}])

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

    def test_wrong_repository_identity_is_never_replication_lag(self):
        with self.assertRaises(OBSERVER.ObservationError):
            OBSERVER.require_repository_identity({'id': 'a' * 64}, 'b' * 64)

if __name__ == '__main__':
    unittest.main()
