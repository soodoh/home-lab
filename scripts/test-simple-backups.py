#!/usr/bin/env python3
"""Real file/SQLite/Restic tests using only private disposable fixtures."""
import importlib.util
from http.server import BaseHTTPRequestHandler
from contextlib import closing
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import sqlite3
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / name)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

CAPTURE = module('restic-capture-files.py')
PREPARE = module('prepare-restic-files.py')
RUNNER = runpy.run_path(str(ROOT / 'scripts/restic-backup'))
OBSERVER = module('observe-restic-backups.py')

class Files(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name).resolve()
        self.root.chmod(0o700)

    def test_online_sqlite_includes_committed_wal_without_copying_it(self):
        source, target = self.root / 'live.db', self.root / 'stage/db.sqlite'
        with closing(sqlite3.connect(source)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE items (value TEXT)')
            db.execute("INSERT INTO items VALUES ('saved')")
            db.commit()
            self.assertTrue(Path(str(source) + '-wal').exists())
            CAPTURE.sqlite_backup(source, target)
            db.execute("INSERT INTO items VALUES ('later')")
            db.commit()
            with closing(sqlite3.connect(target)) as restored:
                self.assertEqual(restored.execute('SELECT value FROM items').fetchall(), [('saved',)])
                self.assertEqual(restored.execute('PRAGMA integrity_check').fetchone(), ('ok',))
        self.assertFalse(Path(str(target) + '-wal').exists())
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0 and
                         os.environ.get('HOME_LAB_READONLY_WAL_TEST_DISPOSABLE') == 'true',
                         'requires explicitly admitted disposable Linux mount privileges')
    def test_online_capture_from_readonly_wal_mount_finishes_and_preserves_committed_data(self):
        self.assertFalse(Path('/etc/home-lab/restic-policy.json').exists(), 'never run native fixtures on a managed host')
        source = self.root / 'source'
        source.mkdir(mode=0o700)
        stage = self.root / 'stage'
        stage.mkdir(mode=0o700)
        excludes = self.root / 'excludes'
        excludes.write_text('')
        with closing(sqlite3.connect(source / 'state.db')) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('PRAGMA wal_autocheckpoint=0')
            writer.execute('CREATE TABLE items (payload BLOB)')
            # More than one former 256-page backup step; keep the WAL live.
            writer.execute('INSERT INTO items VALUES (zeroblob(2097152))')
            writer.commit()
            writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            writer.execute('INSERT INTO items VALUES (zeroblob(17))')
            writer.commit()
            result = subprocess.run([
                'unshare', '--mount', '--propagation', 'private', sys.executable, str(Path(__file__).resolve()),
                '--readonly-wal-child', str(source), str(stage), str(excludes),
            ], capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
        restored = stage / str(source / 'state.db').lstrip('/')
        with closing(sqlite3.connect(restored)) as db:
            self.assertEqual(db.execute('SELECT length(payload) FROM items').fetchall(), [(2097152,), (17,)])
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone(), ('ok',))
        self.assertFalse(restored.with_name('state.db-wal').exists())

    def test_stable_store_validates_json_and_cookie_state_without_mutating_sources(self):
        source = self.root / 'store'
        source.mkdir()
        (source / 'settings.json').write_text('{"saved":true}')
        (source / 'session.cookies').write_text('# home-lab-bootstrap=synthetic-generation\n# Netscape HTTP Cookie File\nexample.invalid\tFALSE\t/\tTRUE\t0\tsession\tsynthetic\n')
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in source.iterdir()}
        target = self.root / 'copied'
        CAPTURE.stable_store(source, target)
        self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, {k: v[0] for k, v in before.items()})
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in target.iterdir()))
        self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in source.iterdir()}, before)
        for name, payload in [('settings.json', '{broken'), ('session.cookies', 'truncated'), ('unknown.bin', 'unknown')]:
            original = source / name
            previous = original.read_bytes() if original.exists() else None
            original.write_text(payload)
            try:
                with self.subTest(name=name), mock.patch('time.sleep'), self.assertRaises(CAPTURE.CaptureError):
                    CAPTURE.stable_store(source, self.root / ('bad-' + name))
            finally:
                original.unlink() if previous is None else original.write_bytes(previous)

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_precopy_reconciles_deletion_and_same_metadata_changes_without_touching_other_groups(self):
        source = self.root / 'library'
        source.mkdir()
        (source / 'changed').write_bytes(b'before')
        (source / 'removed').write_text('remove me')
        (source / 'unchanged').write_text('keep me')
        target = self.root / 'stage'
        target.mkdir()
        # Real capture groups share implied /srv/home-lab-state-like ancestors.
        other = target / str(source.parent).lstrip('/') / 'other-group/state'
        other.parent.mkdir(parents=True)
        other.write_text('preserved')
        excludes = self.root / 'excludes'
        excludes.write_text('')
        baseline = CAPTURE.precopy([str(source)], target, excludes)
        unchanged = target / str(source).lstrip('/') / 'unchanged'
        seed_inode = unchanged.stat().st_ino
        saved = (source / 'changed').stat()
        (source / 'changed').write_bytes(b'after!')
        os.utime(source / 'changed', ns=(saved.st_atime_ns, saved.st_mtime_ns))
        (source / 'removed').unlink()
        (source / 'new').write_text('new file')
        CAPTURE.finish_copy([str(source)], target, excludes, baseline=baseline)
        copied = target / str(source).lstrip('/')
        self.assertEqual({p.name: p.read_bytes() for p in copied.iterdir()},
                         {'changed': b'after!', 'unchanged': b'keep me', 'new': b'new file'})
        self.assertEqual(other.read_text(), 'preserved')
        self.assertEqual(unchanged.stat().st_ino, seed_inode, 'unchanged bulk files must not be copied again while stopped')
        self.assertEqual((source / 'changed').stat().st_mtime_ns, saved.st_mtime_ns)

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_native_json_tree_preserves_attachments_but_not_runtime_sqlite_locks(self):
        source = self.root / 'json-store'
        source.mkdir()
        (source / 'namespace.json').write_text('{"tasks":[],"saved":true}')
        attachments = source / 'namespace/attachments'
        attachments.mkdir(parents=True)
        (attachments / 'opaque.json').write_bytes(b'opaque upload, not JSON')
        locks = source / '.locks'
        locks.mkdir()
        (locks / 'shard-00.sqlite').touch()
        (locks / 'shard-00.sqlite-journal').write_bytes(b'live coordination')
        target = self.root / 'json-copy'
        target.mkdir()
        excludes = self.root / 'excludes'
        excludes.write_text('')
        CAPTURE.online_tree([str(source)], target, excludes, sqlite_paths=[],
                            json_roots=[str(source)], ephemeral=[str(locks)])
        restored = target / str(source).lstrip('/')
        self.assertEqual(json.loads((restored / 'namespace.json').read_text()), {'tasks': [], 'saved': True})
        self.assertEqual((restored / 'namespace/attachments/opaque.json').read_bytes(), b'opaque upload, not JSON')
        self.assertFalse((restored / '.locks').exists())
        (source / 'namespace.json').write_text('{broken')
        with self.assertRaisesRegex(CAPTURE.CaptureError, 'online_json_invalid'):
            CAPTURE.online_tree([str(source)], target, excludes, sqlite_paths=[],
                                json_roots=[str(source)], ephemeral=[str(locks)])

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_online_tree_captures_sqlite_wal_and_related_files_without_stale_journals(self):
        source = self.root / 'online'
        source.mkdir()
        (source / 'config.json').write_text('{"setting":"saved"}')
        (source / 'attachments').mkdir()
        (source / 'attachments/item').write_bytes(b'synthetic attachment')
        # User uploads are opaque bytes, not databases for the adapter to convert.
        opaque = b'SQLite format 3\x00opaque-user-attachment'
        (source / 'attachments/upload.sqlite3').write_bytes(opaque)
        (source / 'attachments/upload.json').write_bytes(b'opaque encrypted attachment, not JSON')
        db_path = source / 'state.sqlite3'
        excludes = self.root / 'excludes'
        excludes.write_text('')
        stage = self.root / 'files'
        stage.mkdir()
        with closing(sqlite3.connect(db_path)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE items (value TEXT)')
            db.execute("INSERT INTO items VALUES ('saved')")
            db.commit()
            CAPTURE.online_tree([str(source)], stage, excludes, sqlite_paths=[str(db_path)])
            db.execute("INSERT INTO items VALUES ('later')")
            db.commit()
            restored = stage / str(source).lstrip('/')
            with closing(sqlite3.connect(restored / 'state.sqlite3')) as copied:
                self.assertEqual(copied.execute('SELECT value FROM items').fetchall(), [('saved',)])
                self.assertEqual(copied.execute('PRAGMA integrity_check').fetchone(), ('ok',))
            self.assertEqual((restored / 'attachments/item').read_bytes(), b'synthetic attachment')
            self.assertEqual((restored / 'attachments/upload.sqlite3').read_bytes(), opaque)
            self.assertEqual((restored / 'attachments/upload.json').read_bytes(), b'opaque encrypted attachment, not JSON')
            self.assertEqual(json.loads((restored / 'config.json').read_text()), {'setting': 'saved'})
            self.assertFalse((restored / 'state.sqlite3-wal').exists())
            self.assertFalse((restored / 'state.sqlite3-shm').exists())

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_readonly_connection_cache_epoch_is_not_mistaken_for_an_application_write(self):
        source = self.root / 'readonly-epoch'
        source.mkdir()
        database = source / 'state.db'
        excludes = self.root / 'excludes'
        excludes.write_text('')
        target = self.root / 'stage'
        target.mkdir()
        connect = sqlite3.connect
        class ReadonlyEpoch(sqlite3.Connection):
            epoch = 0
            def execute(self, sql, *args):
                if sql == 'PRAGMA data_version':
                    # Read-only WAL connections can rebuild a private wal-index
                    # between read transactions without an application commit.
                    self.epoch += 1
                    return mock.Mock(fetchone=lambda: (self.epoch,))
                return super().execute(sql, *args)
        def readonly_connect(path, *args, **kwargs):
            if str(path).startswith('file:'):
                kwargs['factory'] = ReadonlyEpoch
            return connect(path, *args, **kwargs)
        with closing(connect(database)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('CREATE TABLE items (value TEXT)')
            writer.execute("INSERT INTO items VALUES ('saved')")
            writer.commit()
            with mock.patch.object(CAPTURE.sqlite3, 'connect', side_effect=readonly_connect):
                CAPTURE.online_tree([str(source)], target, excludes, sqlite_paths=[str(database)])
        with closing(connect(target / str(database).lstrip('/'))) as restored:
            self.assertEqual(restored.execute('SELECT value FROM items').fetchall(), [('saved',)])

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_online_tree_refuses_database_commits_or_file_mutation_during_capture(self):
        source = self.root / 'busy'
        source.mkdir()
        settings = source / 'config.json'
        settings.write_text('{"setting":"before"}')
        excludes = self.root / 'excludes'
        excludes.write_text('')
        copy = CAPTURE.copy_paths
        with closing(sqlite3.connect(source / 'state.db')) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('CREATE TABLE items (value TEXT)')
            writer.commit()
            for kind in ('database', 'file'):
                target = self.root / kind
                target.mkdir()
                def mutate(*args, **kwargs):
                    copy(*args, **kwargs)
                    if kind == 'database':
                        writer.execute("INSERT INTO items VALUES ('concurrent')")
                        writer.commit()
                    else:
                        settings.write_text('{"setting":"changed"}')
                with self.subTest(kind=kind), mock.patch.object(CAPTURE, 'copy_paths', side_effect=mutate):
                    with self.assertRaisesRegex(CAPTURE.CaptureError, 'online_source_changed'):
                        CAPTURE.online_tree([str(source)], target, excludes, sqlite_paths=[str(source / 'state.db')])

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_online_postgres_retries_changed_companions_and_reconciles_staged_bytes(self):
        source, stage = self.root / 'source', self.root / 'stage'
        source.mkdir()
        stage.mkdir()
        media = source / 'media'
        media.write_bytes(b'before')
        (source / 'removed').write_bytes(b'old')
        (source / 'link').symlink_to('media')
        excludes = self.root / 'excludes'
        excludes.touch()
        target = self.root / 'database.dump'
        spec = {'engine': 'postgres', 'container': 'synthetic-postgres'}
        times = media.stat()
        def mutate(_spec, _target):
            media.write_bytes(b'change')
            os.utime(media, ns=(times.st_atime_ns, times.st_mtime_ns))
        with mock.patch.object(CAPTURE, 'database_dump', side_effect=mutate):
            with self.assertRaisesRegex(CAPTURE.CaptureError, 'online_source_changed'):
                CAPTURE.online_postgres([str(source)], stage, excludes, spec=spec, target=target)
        restored = stage / str(source).lstrip('/')
        self.assertEqual((restored / 'media').read_bytes(), b'before')
        # Source and prior stage have equal size/mtime; the retry must compare
        # contents and remove deleted entries even without a newer timestamp.
        (source / 'removed').unlink()
        with mock.patch.object(CAPTURE, 'database_dump', side_effect=lambda _, path: path.write_bytes(b'fixture-dump')) as dump:
            CAPTURE.online_postgres([str(source)], stage, excludes, spec=spec, target=target)
            dump.assert_called_once_with(spec, target)
        self.assertEqual((restored / 'media').read_bytes(), b'change')
        self.assertEqual((restored / 'link').readlink(), Path('media'))
        self.assertFalse((restored / 'removed').exists())
        self.assertEqual(target.read_bytes(), b'fixture-dump')

    def test_online_postgres_honors_policy_excludes_and_toggles_retry_checksum(self):
        source, stage = self.root / 'source', self.root / 'stage'
        cache = source / 'cache'
        cache.mkdir(parents=True)
        stage.mkdir()
        keep = source / 'book.epub'
        keep.write_bytes(b'book-data')
        (cache / 'tmp.log').write_bytes(b'v1')
        excludes = self.root / 'excludes'
        excludes.write_text(f'# comment\n{cache}/**\n')
        spec = {'engine': 'postgres', 'container': 'bookorbit-db'}
        target = self.root / 'bookorbit.dump'

        def mutate_excluded(_spec, _target):
            (cache / 'tmp.log').write_bytes(b'v2-mutated')
            (cache / 'new.log').write_bytes(b'created')

        with mock.patch.object(CAPTURE, 'copy_paths') as copy_fresh, \
                mock.patch.object(CAPTURE, 'database_dump', side_effect=mutate_excluded):
            CAPTURE.online_postgres([str(source)], stage, excludes, spec=spec, target=target)
        self.assertFalse(copy_fresh.call_args.kwargs['checksum'])

        # When staged paths already exist (retry), online_postgres enables --checksum.
        staged_source = stage / str(source).lstrip('/')
        staged_source.mkdir(parents=True)
        with mock.patch.object(CAPTURE, 'copy_paths') as copy_retry, \
                mock.patch.object(CAPTURE, 'database_dump', side_effect=mutate_excluded):
            CAPTURE.online_postgres([str(source)], stage, excludes, spec=spec, target=target)
        self.assertTrue(copy_retry.call_args.kwargs['checksum'])

        # A dangling symlink in staging also triggers --checksum reconciliation.
        shutil.rmtree(staged_source)
        staged_source.symlink_to(self.root / 'missing-target')
        with mock.patch.object(CAPTURE, 'copy_paths') as copy_symlink_retry, \
                mock.patch.object(CAPTURE, 'database_dump', side_effect=mutate_excluded):
            CAPTURE.online_postgres([str(source)], stage, excludes, spec=spec, target=target)
        self.assertTrue(copy_symlink_retry.call_args.kwargs['checksum'])
        staged_source.unlink()

        def mutate_included(_spec, _target):
            keep.write_bytes(b'changed')

        with mock.patch.object(CAPTURE, 'copy_paths'), \
                mock.patch.object(CAPTURE, 'database_dump', side_effect=mutate_included), \
                self.assertRaisesRegex(CAPTURE.CaptureError, 'online_source_changed'):
            CAPTURE.online_postgres([str(source)], stage, excludes, spec=spec, target=target)

    def test_online_postgres_skips_unchanged_verified_roots_on_retry(self):
        data, media, stage = self.root / 'bookorbit-data', self.root / 'bookorbit-media', self.root / 'stage'
        data.mkdir(); media.mkdir(); stage.mkdir()
        (data / 'state.json').write_text('{"v": 1}')
        (media / 'book.epub').write_bytes(b'large-book')
        excludes = self.root / 'excludes'
        excludes.write_text('')
        spec = {'engine': 'postgres', 'container': 'bookorbit-db'}
        target = self.root / 'bookorbit.dump'
        verified = {}
        copies = []

        def fake_copy(paths, files, _excludes, **_kwargs):
            copies.append((list(paths), _kwargs.get('checksum')))
            for path in paths:
                (files / str(Path(path)).lstrip('/')).mkdir(parents=True, exist_ok=True)

        attempt = 0
        def dump_mutating_only_data(_spec, _target):
            nonlocal attempt
            attempt += 1
            if attempt == 1:
                (data / 'state.json').write_text('{"v": 2}')

        with mock.patch.object(CAPTURE, 'copy_paths', side_effect=fake_copy), \
                mock.patch.object(CAPTURE, 'database_dump', side_effect=dump_mutating_only_data):
            with self.assertRaisesRegex(CAPTURE.CaptureError, 'online_source_changed'):
                CAPTURE.online_postgres([str(data), str(media)], stage, excludes,
                                        spec=spec, target=target, verified=verified)
            # Media was unchanged across attempt 1 and is recorded verified; data is not.
            self.assertIn(str(media), verified)
            self.assertNotIn(str(data), verified)
            # Retry only re-syncs bookorbit-data with checksum=True, skipping unchanged bookorbit-media.
            CAPTURE.online_postgres([str(data), str(media)], stage, excludes,
                                    spec=spec, target=target, verified=verified)
        self.assertEqual(copies, [
            ([str(data)], False),
            ([str(media)], False),
            ([str(data)], True),
        ])

        # If bookorbit-media later changes before another retry, its verified entry is invalidated.
        copies.clear()
        (media / 'book.epub').write_bytes(b'revised-book')
        with mock.patch.object(CAPTURE, 'copy_paths', side_effect=fake_copy), \
                mock.patch.object(CAPTURE, 'database_dump'):
            CAPTURE.online_postgres([str(data), str(media)], stage, excludes,
                                    spec=spec, target=target, verified=verified)
        self.assertEqual(copies, [([str(media)], True)])

    def test_policy_exclude_validation_prefix_filtering_and_glob_matching(self):
        source, stage = self.root / 'source', self.root / 'stage'
        cache = source / 'cache'
        cache.mkdir(parents=True)
        stage.mkdir()

        bad_excludes = self.root / 'bad-excludes'
        for pattern in ('relative-pattern.log', '/tmp/[0-9].log', r'/tmp/a\ b', '/**', '**/**',
                        '/tmp/dir/', '**/', '/tmp/dir//**', '/tmp/dir//leaf', '/tmp/dir/***', '/tmp/dir/**/**',
                        '/tmp/**/**/leaf'):
            with self.subTest(pattern=pattern):
                bad_excludes.write_text(pattern + '\n')
                with self.assertRaisesRegex(CAPTURE.CaptureError, 'snapshot_exclude_shape'):
                    CAPTURE.file_inventory([str(source)], excludes_file=bad_excludes)
                with self.assertRaisesRegex(CAPTURE.CaptureError, 'snapshot_exclude_shape'):
                    CAPTURE.state_snapshot_exclusions(stage, bad_excludes)
        self.assertEqual(CAPTURE._glob_to_regex('/tmp/**/**/leaf'), r'^/tmp/(?:.*/)?leaf')

        # Unrelated anchored patterns are filtered out while **/ and matching anchored ones stay active.
        excludes = self.root / 'excludes'
        excludes.write_text(f'/unrelated/tree/**\n{cache}/**\n**/ignored.tmp\n')
        loaded = CAPTURE.load_policy_excludes(excludes, paths=[source])
        self.assertEqual(len(loaded), 2)

        # **/ after a non-slash character must still require a slash before the next segment,
        # and ** / dir/** must match filenames containing newlines.
        glob_excludes = self.root / 'glob-excludes'
        glob_excludes.write_text('/tmp/foo**/bar\n/tmp/tree/**\n')
        glob_rules = CAPTURE.load_policy_excludes(glob_excludes)
        self.assertIsNone(glob_rules[0].pattern.match('/tmp/foobar'))
        self.assertIsNotNone(glob_rules[0].pattern.match('/tmp/foo/bar'))
        self.assertIsNotNone(glob_rules[0].pattern.match('/tmp/foo1/nested/bar'))
        self.assertIsNotNone(glob_rules[0].pattern.match('/tmp/foo\nline/bar'))
        self.assertIsNotNone(glob_rules[1].child_pattern.match('/tmp/tree/sub\nfile.txt'))

    def test_file_inventory_excludes_apply_to_online_tree_precopy_and_ancestors(self):
        # dir/** still validates the directory itself (rejects symlinks/special files rsync would copy).
        tree_src = self.root / 'tree-source'
        tree_cache = tree_src / 'icon_cache'
        tree_cache.mkdir(parents=True)
        (tree_src / 'state.json').write_text('{"ok": true}')
        (tree_cache / 'icon.png').write_bytes(b'v1')
        tree_stage = self.root / 'tree-stage'
        (tree_stage / str(tree_src).lstrip('/')).mkdir(parents=True)
        (tree_stage / str(tree_src).lstrip('/') / 'state.json').write_text('{"ok": true}')
        tree_excludes = self.root / 'tree-excludes'
        tree_excludes.write_text(f'{tree_cache}/**\n')
        def mutate_tree_cache(*_args, **_kwargs):
            (tree_cache / 'icon.png').write_bytes(b'v2-changed')
        with mock.patch.object(CAPTURE, 'copy_paths', side_effect=mutate_tree_cache):
            CAPTURE.online_tree([str(tree_src)], tree_stage, tree_excludes,
                                sqlite_paths=[], json_roots=[str(tree_src)])

        shutil.rmtree(tree_cache)
        tree_cache.symlink_to(tree_src / 'state.json')
        with mock.patch.object(CAPTURE, 'copy_paths'), \
                self.assertRaisesRegex(CAPTURE.CaptureError, 'online_source_symlink'):
            CAPTURE.online_tree([str(tree_src)], tree_stage, tree_excludes,
                                sqlite_paths=[], json_roots=[str(tree_src)])

        # precopy and finish_copy also honor policy excludes.
        pre_src = self.root / 'pre-source'
        pre_excluded = pre_src / 'excluded'
        pre_excluded.mkdir(parents=True)
        os.mkfifo(pre_excluded / 'pipe')
        (pre_src / 'keep.txt').write_text('ok')
        pre_excludes = self.root / 'pre-excludes'
        pre_excludes.write_text(f'{pre_excluded}/**\n')
        with mock.patch.object(CAPTURE, 'copy_paths'):
            baseline = CAPTURE.precopy([str(pre_src)], self.root / 'pre-stage', pre_excludes)
            CAPTURE.finish_copy([str(pre_src)], self.root / 'pre-stage', pre_excludes, baseline=baseline)

        # Non-subtree exclude rules also match ancestor directories above a source root.
        nested_dir = self.root / '.local/share/Steam/userdata'
        nested_dir.mkdir(parents=True)
        (nested_dir / 'state.bin').write_bytes(b'ignored')
        ancestor_excludes = self.root / 'ancestor-excludes'
        ancestor_excludes.write_text('**/.local/share/Steam\n')
        self.assertEqual(CAPTURE.file_inventory([str(nested_dir)], excludes_file=ancestor_excludes), {})

    def test_mariadb_idle_parses_active_session_counts_and_bounds_timeout(self):
        with mock.patch.object(CAPTURE, '_run_probe',
                               return_value=subprocess.CompletedProcess([], 0, '0\n', '')) as probe:
            self.assertTrue(CAPTURE.mariadb_idle('nextcloud-db'))
            self.assertEqual(probe.call_args.args[0][:3], ['/usr/bin/docker', 'exec', 'nextcloud-db'])
            self.assertIn('--connect-timeout=10', probe.call_args.args[0][-1])
            self.assertIn('SET STATEMENT max_statement_time=15 FOR SELECT', probe.call_args.args[0][-1])
            self.assertIn("COALESCE(USER, '') != 'system user'", probe.call_args.args[0][-1])
            self.assertIn("COALESCE(COMMAND, '') NOT IN ('Sleep', 'Daemon')", probe.call_args.args[0][-1])
            self.assertEqual(probe.call_args.kwargs.get('timeout'), 30)
        with mock.patch.object(CAPTURE, '_run_probe',
                               return_value=subprocess.CompletedProcess([], 0, '2\n', '')):
            self.assertFalse(CAPTURE.mariadb_idle('nextcloud-db'))
        for bad_result in (subprocess.CompletedProcess([], 0, 'not-a-count\n', ''),
                           subprocess.CompletedProcess([], 0, '²\n', ''),
                           subprocess.CompletedProcess([], 1, '', 'connection refused')):
            with self.subTest(returncode=bad_result.returncode, stdout=bad_result.stdout), \
                    mock.patch.object(CAPTURE, '_run_probe', return_value=bad_result), \
                    self.assertRaisesRegex(CAPTURE.CaptureError, 'mariadb_drain_check'):
                CAPTURE.mariadb_idle('nextcloud-db')

    def test_retry_uses_progressive_backoff_for_online_source_changed_only(self):
        with mock.patch('time.sleep') as slept:
            with self.assertRaisesRegex(CAPTURE.CaptureError, 'capture_phase_failed'):
                CAPTURE.retry(lambda: (_ for _ in ()).throw(CAPTURE.CaptureError('online_source_changed')))
        self.assertEqual([call.args[0] for call in slept.call_args_list], list(CAPTURE.ONLINE_SOURCE_RETRY_DELAYS))

        with mock.patch('time.sleep') as slept:
            with self.assertRaisesRegex(CAPTURE.CaptureError, 'capture_phase_failed'):
                CAPTURE.retry(lambda: (_ for _ in ()).throw(CAPTURE.CaptureError('online_source_changed')), attempts=1)
        slept.assert_not_called()

        with mock.patch('time.sleep') as slept:
            with self.assertRaisesRegex(CAPTURE.CaptureError, 'capture_phase_failed'):
                CAPTURE.retry(lambda: (_ for _ in ()).throw(CAPTURE.CaptureError('capture_command')))
        self.assertEqual([call.args[0] for call in slept.call_args_list], [2, 2])

        # Mixed live-churn followed by a transient command error keeps its own retry budget.
        outcomes = iter([
            CAPTURE.CaptureError('online_source_changed'),
            CAPTURE.CaptureError('online_source_changed'),
            CAPTURE.CaptureError('online_source_changed'),
            CAPTURE.CaptureError('capture_command'),
            'ok',
        ])
        def flaky():
            item = next(outcomes)
            if isinstance(item, Exception):
                raise item
            return item
        with mock.patch('time.sleep') as slept:
            self.assertEqual(CAPTURE.retry(flaky), 'ok')
        self.assertEqual([call.args[0] for call in slept.call_args_list], [2, 4, 8, 2])

        # Caller-specified attempts larger than the backoff schedule are honored.
        with mock.patch('time.sleep') as slept:
            with self.assertRaisesRegex(CAPTURE.CaptureError, 'capture_phase_failed'):
                CAPTURE.retry(lambda: (_ for _ in ()).throw(CAPTURE.CaptureError('online_source_changed')), attempts=8)
        self.assertEqual([call.args[0] for call in slept.call_args_list], [2, 4, 8, 12, 16, 16, 16])

        # A child file vanishing mid-walk during file_inventory surfaces as online_source_changed.
        vanish_root = self.root / 'vanish-root'
        vanish_root.mkdir()
        vanishing = vanish_root / 'ephemeral.tmp'
        vanishing.write_text('temp')
        real_lstat = Path.lstat
        def lstat_vanished(path_obj):
            if path_obj == vanishing:
                raise FileNotFoundError(str(path_obj))
            return real_lstat(path_obj)
        with mock.patch.object(Path, 'lstat', lstat_vanished), \
                self.assertRaisesRegex(CAPTURE.CaptureError, '^online_source_changed$'):
            CAPTURE.file_inventory([str(vanish_root)])

    def test_mariadb_client_prologue_cleans_up_and_exits_on_signal(self):
        secret = self.root / 'db-password'
        secret.write_text('p"a\\s\n')
        continued = self.root / 'continued'
        script = (
            CAPTURE.MARIADB_CLIENT_PROLOGUE
            + f'printf "%s\\n" "$f"; sleep 0.3; : > "{continued}"'
        )
        proc = subprocess.Popen(
            ['/bin/sh', '-ec', script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={'PATH': '/usr/bin:/bin', 'MARIADB_ROOT_PASSWORD_FILE': str(secret)},
        )
        try:
            temp_path = Path(proc.stdout.readline().strip())
            self.assertTrue(temp_path.exists())
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(proc.returncode, 143)
        self.assertFalse(temp_path.exists())
        self.assertFalse(continued.exists())

    def test_nextcloud_write_fds_busy_inspects_host_proc_and_fails_closed_on_permission_error(self):
        proc_root = self.root / 'proc'
        def setup_pid(pid, fds):
            fd_dir = proc_root / str(pid) / 'fd'
            info_dir = proc_root / str(pid) / 'fdinfo'
            fd_dir.mkdir(parents=True, exist_ok=True)
            info_dir.mkdir(parents=True, exist_ok=True)
            for num, (target, flags) in fds.items():
                link = fd_dir / str(num)
                if link.exists() or link.is_symlink():
                    link.unlink()
                link.symlink_to(target)
                (info_dir / str(num)).write_text(f'pos:\t0\nflags:\t{flags}\n')

        top_ok = subprocess.CompletedProcess([], 0, 'PID\n101\n102\n', '')
        # Read-only data FD, unrelated writable FD, and writable nextcloud.log -> idle.
        setup_pid(101, {3: ('/var/www/html/data/user/file.bin', '0100000')})
        setup_pid(102, {
            4: ('/var/www/html/data/nextcloud.log', '0102001'),
            5: ('/var/www/html/data/nextcloud.log.1 (deleted)', '0102001'),
            6: ('/var/log/apache2/access.log', '0102001'),
        })
        with mock.patch.object(CAPTURE, '_run_probe', return_value=top_ok):
            self.assertFalse(CAPTURE.nextcloud_write_fds_busy('nextcloud', proc_root=proc_root))

        # Writable FD under /var/www/html/data or /tmp/php* (or malformed fdinfo flags) -> busy.
        for target, flags in (
            ('/var/www/html/data/user/upload.part', '0100001'),
            ('/var/www/html/config/config.php', '0100002'),
            ('/tmp/phpAbCdEf', '02100002'),
            ('/var/tmp/oc_tmp_123', '0100001'),
            ('/var/www/html/data/user/file.bin', '0100000xyz'),
        ):
            with self.subTest(target=target, flags=flags):
                setup_pid(102, {7: (target, flags)})
                with mock.patch.object(CAPTURE, '_run_probe', return_value=top_ok):
                    self.assertTrue(CAPTURE.nextcloud_write_fds_busy('nextcloud', proc_root=proc_root))

        # Vanished PID between docker top and /proc scan -> conservative busy (retry).
        with mock.patch.object(CAPTURE, '_run_probe',
                               return_value=subprocess.CompletedProcess([], 0, 'PID\n101\n99999\n', '')):
            self.assertTrue(CAPTURE.nextcloud_write_fds_busy('nextcloud', proc_root=proc_root))

        # PermissionError reading a worker's /proc/<pid>/fd fails closed instead of returning idle.
        setup_pid(102, {4: ('/var/log/apache2/access.log', '0100000')})
        real_iterdir = Path.iterdir
        def deny_worker(path):
            if path == proc_root / '102' / 'fd':
                raise PermissionError('EACCES')
            return real_iterdir(path)
        with mock.patch.object(CAPTURE, '_run_probe', return_value=top_ok), \
                mock.patch.object(Path, 'iterdir', deny_worker), \
                self.assertRaisesRegex(CAPTURE.CaptureError, 'nextcloud_drain_check'):
            CAPTURE.nextcloud_write_fds_busy('nextcloud', proc_root=proc_root)

        # Invalid or failing docker top output fails closed.
        for bad_top in (
            subprocess.CompletedProcess([], 1, '', 'daemon error'),
            subprocess.CompletedProcess([], 0, 'PID\n', ''),
            subprocess.CompletedProcess([], 0, 'WRONG\n101\n', ''),
            subprocess.CompletedProcess([], 0, 'PID\nnotapid\n', ''),
            subprocess.CompletedProcess([], 0, 'PID\n²\n', ''),
        ):
            with self.subTest(bad_top=bad_top.stdout), \
                    mock.patch.object(CAPTURE, '_run_probe', return_value=bad_top), \
                    self.assertRaisesRegex(CAPTURE.CaptureError, 'nextcloud_drain_check'):
                CAPTURE.nextcloud_write_fds_busy('nextcloud', proc_root=proc_root)

    def test_nextcloud_cron_busy_interprets_exit_codes_and_fails_closed(self):
        with mock.patch.object(CAPTURE, '_run_probe', return_value=subprocess.CompletedProcess([], 10, '', '')):
            self.assertTrue(CAPTURE.nextcloud_cron_busy('nextcloud-cron'))
        with mock.patch.object(CAPTURE, '_run_probe', return_value=subprocess.CompletedProcess([], 0, '', '')):
            self.assertFalse(CAPTURE.nextcloud_cron_busy('nextcloud-cron'))
        for code in (1, 2):
            with mock.patch.object(CAPTURE, '_run_probe', return_value=subprocess.CompletedProcess([], code, '', 'err')), \
                    self.assertRaisesRegex(CAPTURE.CaptureError, 'nextcloud_drain_check'):
                CAPTURE.nextcloud_cron_busy('nextcloud-cron')

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_mosquitto_requires_a_fresh_atomic_native_flush_and_preserves_stopped_state(self):
        source = self.root / 'mosquitto'
        source.mkdir()
        persistence = source / 'mosquitto.db'
        persistence.write_bytes(b'previous-native-database')
        (source / 'mosquitto.conf').write_text('persistence true\n')
        excludes = self.root / 'excludes'
        excludes.write_text('')
        step = {'paths': [str(source)], 'persistence': str(persistence)}
        command = CAPTURE.command
        signals = []
        def publish(args, *a, **kwargs):
            if args[0] != '/usr/bin/docker':
                return command(args, *a, **kwargs)
            self.assertEqual(args, ['/usr/bin/docker', 'kill', '--signal', 'USR1', 'synthetic-container'])
            signals.append(args)
            temporary = source / 'mosquitto.db.new'
            temporary.write_bytes(b'fresh-native-database')
            temporary.replace(persistence)
        target = self.root / 'online-mqtt'
        target.mkdir()
        with mock.patch.object(CAPTURE, 'command', side_effect=publish):
            CAPTURE.mosquitto(step, target, excludes, container='synthetic-container', running=True)
        self.assertEqual(len(signals), 1)
        self.assertEqual((target / str(persistence).lstrip('/')).read_bytes(), b'fresh-native-database')
        offline = self.root / 'offline-mqtt'
        offline.mkdir()
        command = CAPTURE.command
        def no_signal(args, *a, **kw):
            self.assertNotEqual(args[0], '/usr/bin/docker', 'intentionally stopped MQTT must not be signalled/started')
            return command(args, *a, **kw)
        with mock.patch.object(CAPTURE, 'command', side_effect=no_signal):
            CAPTURE.mosquitto(step, offline, excludes, container='synthetic-container', running=False)
        with mock.patch.object(CAPTURE, 'command'), mock.patch.object(CAPTURE, 'copy_paths') as copied, \
                mock.patch('time.monotonic', side_effect=[0, 31]), self.assertRaisesRegex(CAPTURE.CaptureError, 'mqtt_flush_timeout'):
            CAPTURE.mosquitto(step, self.root / 'unacknowledged', excludes, container='synthetic-container', running=True)
        copied.assert_not_called()

    @unittest.skipUnless(shutil.which('my_print_defaults'), 'requires the native MariaDB option parser')
    def test_mariadb_password_round_trip_and_private_option_file_cleanup(self):
        parser = shutil.which('my_print_defaults')
        binary = self.root / 'bin/mariadb-dump'
        binary.parent.mkdir()
        metadata = self.root / 'option-file.json'
        # Replace only the dump operation, using MariaDB's actual option parser
        # instead of a second implementation of its quoting/escaping rules.
        binary.write_text(f'''#!{sys.executable}
import json, os, pathlib, stat, subprocess, sys
path = pathlib.Path(sys.argv[1].removeprefix('--defaults-extra-file='))
pathlib.Path({str(metadata)!r}).write_text(json.dumps({{
    'path': str(path), 'mode': stat.S_IMODE(path.stat().st_mode),
}}))
subprocess.run([{parser!r}, '--defaults-file=' + str(path), 'client'],
               stdout=sys.stdout.buffer, check=True)
sys.exit(int(os.environ['DUMP_RESULT']))
''')
        binary.chmod(0o755)
        password = self.root / 'password'
        target = self.root / 'export.sql'
        def docker(argv, output):
            self.assertEqual(argv[:3], ['/usr/bin/docker', 'exec', 'synthetic-mariadb'])
            result = subprocess.run(argv[3:], stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.PIPE, timeout=10, env=environment)
            if result.returncode:
                raise CAPTURE.CaptureError('capture_command')
        for variable in ('MARIADB_ROOT_PASSWORD_FILE', 'MYSQL_ROOT_PASSWORD_FILE'):
            environment = {'PATH': str(binary.parent) + ':/usr/local/bin:/usr/bin:/bin',
                           'HOME': str(self.root), 'TMPDIR': str(self.root),
                           variable: str(password), 'MARIADB_DATABASE': 'synthetic'}
            for value in (b'synthetic\\test\\new\\root\\back\\\\slash',
                          b' \t"quotes" \'apostrophe\' # comment ; = $ `literal` ',
                          b'first\nsecond\r\nthird\n', b''):
                for result in (0, 1):
                    with self.subTest(variable=variable, password=value, result=result):
                        password.write_bytes(value + b'\n')
                        environment['DUMP_RESULT'] = str(result)
                        with mock.patch.object(CAPTURE, 'command', side_effect=docker):
                            if result:
                                with self.assertRaises(CAPTURE.CaptureError):
                                    CAPTURE.database_dump({'engine': 'mariadb', 'container': 'synthetic-mariadb'}, target)
                            else:
                                CAPTURE.database_dump({'engine': 'mariadb', 'container': 'synthetic-mariadb'}, target)
                        self.assertEqual(target.read_bytes(), b'--user=root\n--password=' + value.rstrip(b'\n') + b'\n')
                        info = json.loads(metadata.read_text())
                        self.assertEqual(info['mode'], 0o600)
                        self.assertFalse(Path(info['path']).exists())

    def test_codex_capture_is_private_validated_and_does_not_stop_a_service(self):
        source = self.root / 'auths'
        source.mkdir()
        (source / 'account.json').write_text('{"token":"synthetic"}')
        (source / 'account.json.lock').touch()
        CAPTURE.cli_auth(source, self.root / 'copied')
        self.assertEqual((self.root / 'copied/account.json').stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.root / 'copied/account.json.lock').exists())
        (source / 'account.json').write_text('{broken')
        with mock.patch('time.sleep'), self.assertRaises(CAPTURE.CaptureError):
            CAPTURE.cli_auth(source, self.root / 'invalid')

    def test_acme_copy_validates_private_keys_without_stopping_ingress(self):
        source = self.root / 'acme.json'
        target = self.root / 'stage/acme.json'
        value = {'resolver': {'Account': {'PrivateKey': 'synthetic'},
                              'Certificates': [{'key': 'synthetic', 'certificate': 'synthetic'}]}}
        source.write_text(json.dumps(value))
        CAPTURE.acme_store(source, target)
        self.assertEqual(json.loads(target.read_text()), value)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        value['resolver']['Account'].pop('PrivateKey')
        source.write_text(json.dumps(value))
        with mock.patch('time.sleep'), self.assertRaises(CAPTURE.CaptureError):
            CAPTURE.acme_store(source, self.root / 'missing/acme.json')

    def test_jellyfin_endpoint_uses_only_the_observed_published_binding(self):
        for address, host in [('192.0.2.10', '192.0.2.10'), ('100.64.0.10', '100.64.0.10'),
                              ('0.0.0.0', '127.0.0.1'), ('::', '[::1]'), ('::1', '[::1]')]:
            with self.subTest(address=address), mock.patch.object(CAPTURE, 'command', return_value=json.dumps({
                '8096/tcp': [{'HostIp': address, 'HostPort': '18096'}]}).encode()) as command:
                self.assertEqual(CAPTURE.jellyfin_endpoint(), 'http://' + host + ':18096')
                command.assert_called_once_with(['/usr/bin/docker', 'inspect', '--format',
                                                '{{json .NetworkSettings.Ports}}', 'jellyfin'])
        binding = {'HostIp': '127.0.0.1', 'HostPort': '8096'}
        for ports in ({}, {'8096/tcp': None}, {'8096/tcp': []}, {'8096/tcp': [binding, binding]},
                      {'8096/tcp': [{'HostIp': 'example.invalid', 'HostPort': '8096'}]},
                      {'8096/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '0'}]},
                      {'8096/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '65536'}]}):
            with self.subTest(ports=ports), mock.patch.object(CAPTURE, 'command', return_value=json.dumps(ports).encode()):
                with self.assertRaisesRegex(CAPTURE.CaptureError, 'jellyfin_port_binding'):
                    CAPTURE.jellyfin_endpoint()

    def test_jellyfin_captures_via_published_port_and_cleans_only_its_archive_outside_host_sandbox(self):
        source = self.root / 'jellyfin'
        backups = source / 'data/backups'
        backups.mkdir(parents=True)
        with closing(sqlite3.connect(source / 'data/jellyfin.db')) as db:
            db.execute('CREATE TABLE ApiKeys (Id INTEGER, AccessToken TEXT)')
            db.execute("INSERT INTO ApiKeys VALUES (1, 'synthetic-api-key')")
            db.commit()
        existing = backups / 'existing.zip'
        existing.write_bytes(b'pre-existing-native-backup')
        archive = backups / 'created.zip'
        requests, removals = [], []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, self.headers.get('Authorization'), self.headers.get('X-Emby-Token'),
                                 json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                if self.headers.get('Authorization') != 'MediaBrowser Token="synthetic-api-key"':
                    self.send_response(401)
                    self.end_headers()
                    return
                with zipfile.ZipFile(archive, 'w') as zipped:
                    zipped.writestr('settings.xml', 'synthetic-settings')
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{}')
            def log_message(self, *_):
                pass
        unlink = Path.unlink
        def readonly_unlink(path, *args, **kwargs):
            if path.is_relative_to(source):
                raise OSError(errno.EROFS, 'read-only capture source')
            return unlink(path, *args, **kwargs)
        with socketserver.TCPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def docker(args):
                if args[1] == 'inspect':
                    return json.dumps({'8096/tcp': [{'HostIp': '127.0.0.1',
                                                     'HostPort': str(server.server_address[1])}]}).encode()
                self.assertEqual(args, ['/usr/bin/docker', 'exec', 'jellyfin', '/bin/rm', '--',
                                        '/config/data/backups/created.zip'])
                removals.append(archive.name)
                # The daemon/container is outside the backup service's read-only
                # mount namespace; only that dependency may remove the archive.
                unlink(archive)
            try:
                target = self.root / 'jellyfin.zip'
                with mock.patch.object(CAPTURE, 'command', side_effect=docker), mock.patch.object(Path, 'unlink', readonly_unlink):
                    CAPTURE.jellyfin(source, target)
                with zipfile.ZipFile(target) as zipped:
                    self.assertEqual(zipped.read('settings.xml'), b'synthetic-settings')
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                self.assertEqual(requests, [('/Backup/Create', 'MediaBrowser Token="synthetic-api-key"', None,
                                           {'Metadata': True, 'Subtitles': True, 'Trickplay': False})])
                self.assertEqual(removals, ['created.zip'])
                self.assertFalse(archive.exists())
                self.assertEqual(existing.read_bytes(), b'pre-existing-native-backup')
            finally:
                server.shutdown()
                thread.join()

    def test_jellyfin_http_refusal_is_classified_without_retry_or_archive_cleanup(self):
        source = self.root / 'jellyfin-refused'
        (source / 'data/backups').mkdir(parents=True)
        with closing(sqlite3.connect(source / 'data/jellyfin.db')) as db:
            db.execute('CREATE TABLE ApiKeys (Id INTEGER, AccessToken TEXT)')
            db.execute("INSERT INTO ApiKeys VALUES (1, 'synthetic-api-key')")
            db.commit()
        for status, reason in [(401, 'jellyfin_backup_auth'), (403, 'jellyfin_backup_auth'),
                               (500, 'jellyfin_backup_ambiguous')]:
            error = CAPTURE.urllib.error.HTTPError('http://127.0.0.1/Backup/Create', status, 'refused', {}, None)
            opener = mock.Mock()
            opener.open.side_effect = error
            target = self.root / 'refused.zip'
            with self.subTest(status=status), mock.patch.object(CAPTURE, 'jellyfin_endpoint', return_value='http://127.0.0.1'), \
                    mock.patch.object(CAPTURE.urllib.request, 'build_opener', return_value=opener), \
                    mock.patch.object(CAPTURE, 'command') as native:
                with self.assertRaisesRegex(CAPTURE.CaptureError, '^' + reason + '$'):
                    CAPTURE.jellyfin(source, target)
                self.assertEqual(opener.open.call_count, 1)
                native.assert_not_called()
                self.assertFalse(target.exists())
                self.assertEqual(list((source / 'data/backups').iterdir()), [])

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_online_exports_do_not_restore_stale_journals(self):
        source = self.root / 'plugin'
        source.mkdir()
        for name in ('state.db', 'state.db-wal', 'state.db-shm', 'settings.xml'):
            (source / name).write_text('synthetic')
        excludes = self.root / 'excludes'
        excludes.write_text('*.db\n*.db-wal\n*.db-shm\n')
        target = self.root / 'copied'
        target.mkdir()
        CAPTURE.copy_paths([str(source)], target, excludes)
        selected = target / str(source).lstrip('/')
        self.assertEqual([p.name for p in selected.iterdir()], ['settings.xml'])

    def test_restore_rejects_unknown_format_and_target_collisions(self):
        stage = self.root / PREPARE.STAGE
        (stage / 'files/srv/example').mkdir(parents=True)
        (stage / 'files/srv/example/value').write_text('saved')
        for name in ('native', 'databases'):
            (stage / name).mkdir()
        (stage / 'manifest.json').write_text('{"version":100}')
        with self.assertRaisesRegex(ValueError, 'format'):
            PREPARE.normalize(self.root)
        (stage / 'manifest.json').write_text('{"version":2}')
        (self.root / 'srv').symlink_to(self.root / 'outside')
        with self.assertRaisesRegex(ValueError, 'collision'):
            PREPARE.normalize(self.root)

    def restore_fixture(self, name='restored'):
        target = self.root / name
        target.mkdir(mode=0o700)
        stage = target / PREPARE.STAGE
        for folder in ('files', 'databases', 'native'):
            (stage / folder).mkdir(parents=True)
        return target, stage

    def test_restore_rejects_manifest_links_without_changing_external_files(self):
        external = self.root / 'external.json'
        original = '{"version":2,"value":"synthetic"}\n'
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                target, stage = self.restore_fixture('restored-' + kind)
                external.write_text(original)
                manifest = stage / 'manifest.json'
                if kind == 'symlink':
                    manifest.symlink_to(external)
                else:
                    os.link(external, manifest)
                try:
                    with self.assertRaises((ValueError, OSError)):
                        PREPARE.normalize(target)
                    self.assertEqual(external.read_text(), original)
                    self.assertFalse((target / 'recovery-exports').exists())
                finally:
                    manifest.unlink(missing_ok=True)

    def test_restore_checks_capture_ancestors_before_reading_the_manifest(self):
        target = self.root / 'restored'
        target.mkdir(mode=0o700)
        external = self.root / 'external'
        stage = external / Path(*PREPARE.STAGE.parts[1:])
        stage.mkdir(parents=True)
        (stage / 'manifest.json').write_text('not JSON and must not be read')
        (target / PREPARE.STAGE.parts[0]).symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'restore_collision'):
            PREPARE.normalize(target)

    def test_restore_publishes_a_new_private_manifest_and_inactive_link_instructions(self):
        target, stage = self.restore_fixture()
        (stage / 'manifest.json').write_text('{"version":2}')
        (stage / 'files/value').write_text('saved')
        (stage / 'files/pointer').symlink_to('/outside')
        metadata = PREPARE.normalize(target)
        exported = target / 'recovery-exports/manifest.json'
        self.assertEqual(json.loads(exported.read_text()), metadata)
        self.assertEqual(metadata['symlinks'], {'/pointer': '/outside'})
        self.assertEqual(exported.stat().st_mode & 0o777, 0o600)
        self.assertFalse(exported.is_symlink())
        self.assertEqual(exported.stat().st_nlink, 1)
        self.assertEqual((target / 'value').read_text(), 'saved')
        self.assertFalse((target / 'pointer').is_symlink())
        self.assertFalse(stage.exists())

    @unittest.skipUnless(os.environ.get('RESTIC'), 'native Restic is required in CI')
    def test_native_local_completion_and_cleanup_do_not_wait_for_replication(self):
        binary = os.environ['RESTIC']
        games, nfs = self.root / 'games', self.root / 'nfs'
        environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(self.root), 'LC_ALL': 'C',
                       'RESTIC_PASSWORD': 'synthetic-only', 'RESTIC_FROM_PASSWORD': 'synthetic-only',
                       'RESTIC_CACHE_DIR': str(self.root / 'cache')}
        def native(repository, *arguments):
            return subprocess.run([binary, '-r', str(repository), *arguments], env=environment,
                                  check=True, capture_output=True, timeout=30).stdout
        native(games, 'init')
        native(nfs, 'init', '--from-repo', str(games), '--copy-chunker-params')
        previous = self.root / 'previous'
        previous.write_bytes(os.urandom(8 * 1024 * 1024))
        native(games, 'backup', str(previous), '--tag', 'cadence=daily',
               '--tag', 'format=full-v2', '--tag', 'complete=full-v2')
        source = json.loads(native(games, 'snapshots', '--json'))[0]
        stage = self.root / 'stage'
        stage.mkdir(mode=0o700)
        (stage / 'value').write_text('synthetic ready capture')
        manifest = {'version': 2, 'capture': '1' * 32, 'policy': 'a' * 64,
                    'artifact': 'b' * 64, 'owner': None, 'captured_at': datetime.now(timezone.utc).isoformat()}
        (stage / 'manifest.json').write_text(json.dumps(manifest))
        (stage / 'manifest.json').chmod(0o600)
        policy = {'capture': {'stage': str(stage)}, 'tools': {'restic': {'installed_path': binary}},
                  'repositories': {'games': {'path': str(games)}}}
        local = RUNNER['LocalCapture'](policy)
        with subprocess.Popen([binary, '-r', str(nfs), '--from-repo', str(games), '--no-lock',
                               '--limit-upload', '1024', 'copy', source['id']], env=environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as reader:
            try:
                deadline = time.monotonic() + 10
                while not list((nfs / 'locks').iterdir()):
                    self.assertIsNone(reader.poll(), 'copy exited before acquiring its destination lock')
                    self.assertLess(time.monotonic(), deadline, 'copy did not acquire its destination lock')
                    time.sleep(.02)
                self.assertEqual(list((games / 'locks').iterdir()), [])
                with mock.patch.dict(local.run.__globals__, {
                    'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                    'capture_adapter': lambda _: CAPTURE, 'rooted': Path, 'artifact_hash': lambda _: 'b' * 64,
                    'repository_environment': lambda *_: environment,
                    'declared_services': mock.Mock(side_effect=AssertionError('ready capture replanned')),
                }), mock.patch.object(local, 'recover'), mock.patch('builtins.print'):
                    local.run('a' * 64)
                self.assertFalse(stage.exists())
                self.assertIsNone(reader.poll(), 'replication must still be running after local cleanup')
                self.assertTrue(list((nfs / 'locks').iterdir()))
                completed = json.loads(native(games, 'snapshots', '--json', '--tag', 'capture=' + manifest['capture']))
                self.assertEqual(len(completed), 1)
                self.assertIn('complete=full-v2', completed[0]['tags'])
                _, stderr = reader.communicate(timeout=30)
                self.assertEqual(reader.returncode, 0, stderr.decode())
                copies = json.loads(native(nfs, 'snapshots', '--json'))
                self.assertEqual([copy['original'] for copy in copies], [source['id']])
            finally:
                if reader.poll() is None:
                    reader.terminate()
                    reader.communicate(timeout=10)

    @unittest.skipUnless(os.environ.get('RESTIC'), 'native Restic is required in CI')
    def test_native_complete_copy_ancestry_retry_and_restore(self):
        binary = os.environ['RESTIC']
        environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(self.root), 'LC_ALL': 'C', 'TZ': 'UTC',
                       'RESTIC_PASSWORD': 'synthetic-only', 'RESTIC_FROM_PASSWORD': 'synthetic-only',
                       'RESTIC_CACHE_DIR': str(self.root / 'cache')}
        def restic(repository, args, source=None):
            argv = [binary, '-r', str(self.root / repository)]
            if source:
                argv += ['--from-repo', str(self.root / source)]
            result = subprocess.run([*argv, *args], check=True, text=True, capture_output=True, env=environment)
            return result.stdout
        restic('games', ['init'])
        restic('nfs', ['init', '--from-repo', str(self.root / 'games'), '--copy-chunker-params'])
        fixture = self.root / 'input'
        stage = fixture / PREPARE.STAGE
        (stage / 'files/mnt/storage/media/nextcloud/data').mkdir(parents=True)
        (stage / 'files/mnt/storage/media/nextcloud/data/user.txt').write_text('user data')
        online = self.root / 'online-application'
        online.mkdir()
        (online / 'config.json').write_text('{"setting":"captured"}')
        excludes = self.root / 'excludes'
        excludes.write_text('')
        with closing(sqlite3.connect(online / 'db.sqlite')) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('CREATE TABLE items (value TEXT)')
            writer.execute("INSERT INTO items VALUES ('saved')")
            writer.commit()
            CAPTURE.online_tree([str(online)], stage / 'files', excludes, sqlite_paths=[str(online / 'db.sqlite')])
            writer.execute("INSERT INTO items VALUES ('later')")
            writer.commit()
        (stage / 'native').mkdir()
        (stage / 'native/jellyfin.zip').write_bytes(b'native-archive-fixture')
        (stage / 'databases').mkdir()
        (stage / 'databases/authentik.dump').write_bytes(b'PGDMP-fixture')
        (stage / 'manifest.json').write_text('{"version":2,"links":{}}')
        policy = 'a' * 64
        tags = ['cadence=daily', 'format=full-v2', 'policy=' + policy, 'artifact=' + 'b' * 64]
        captured_at = datetime.now(timezone.utc)
        args = ['backup', '--json', '--time', RUNNER['restic_backup_time'](captured_at.isoformat()), str(stage)]
        for tag in tags:
            args += ['--tag', tag]
        restic('games', args)
        incomplete = json.loads(restic('games', ['snapshots', '--json']))
        self.assertEqual(RUNNER['replication_sources'](incomplete), [])
        restic('games', ['tag', '--add', 'complete=full-v2', incomplete[0]['id']])
        sources = json.loads(restic('games', ['snapshots', '--json']))
        source = RUNNER['replication_sources'](sources)[0]
        self.assertEqual(OBSERVER.snapshot_time(source), captured_at.replace(microsecond=0))
        self.assertNotEqual(source['id'], source['original'])
        for _ in range(2):  # Retrying an interrupted/acknowledgment-lost copy is native-idempotent.
            restic('nfs', ['copy', source['id']], source='games')
        copies = json.loads(restic('nfs', ['snapshots', '--json']))
        self.assertEqual(len(copies), 1)
        self.assertTrue(RUNNER['same_capture'](source, copies[0]))
        self.assertEqual(OBSERVER.match_copy(RUNNER['snapshot_evidence'](), source, copies), copies[0])
        target = self.root / 'restored'
        target.mkdir()
        restic('nfs', ['restore', copies[0]['id'], '--target', str(target), '--verify'])
        # Restic stores the absolute fixture path; normalize that parent root.
        recovered = target / str(fixture).lstrip('/')
        recovered.chmod(0o700)
        PREPARE.normalize(recovered)
        self.assertEqual((recovered / 'mnt/storage/media/nextcloud/data/user.txt').read_text(), 'user data')
        restored_online = recovered / str(online).lstrip('/')
        with closing(sqlite3.connect(restored_online / 'db.sqlite')) as db:
            self.assertEqual(db.execute('SELECT value FROM items').fetchall(), [('saved',)])
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone(), ('ok',))
        self.assertEqual(json.loads((restored_online / 'config.json').read_text()), {'setting': 'captured'})
        self.assertFalse((restored_online / 'db.sqlite-wal').exists())
        self.assertEqual((recovered / 'recovery-exports/databases/authentik.dump').read_bytes(), b'PGDMP-fixture')
        self.assertFalse((recovered / PREPARE.STAGE).exists())

    @unittest.skipUnless(os.environ.get('RESTIC'), 'native Restic is required in CI')
    def test_native_retention_expires_legacy_and_complete_snapshots_but_preserves_other_formats(self):
        binary = os.environ['RESTIC']
        environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(self.root), 'LC_ALL': 'C', 'TZ': 'UTC',
                       'RESTIC_PASSWORD': 'synthetic-only', 'RESTIC_FROM_PASSWORD': 'synthetic-only',
                       'RESTIC_CACHE_DIR': str(self.root / 'cache')}
        def restic(_policy, repository, args, source=None, timeout=7200):
            argv = [binary, '-r', str(self.root / repository)]
            if source:
                argv += ['--from-repo', str(self.root / source)]
            result = subprocess.run([*argv, *args], text=True, capture_output=True, env=environment, timeout=timeout)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result
        def inventory(_policy, repository):
            return json.loads(restic(None, repository, ['snapshots', '--json']).stdout)
        restic(None, 'games', ['init'])
        for name in ('nfs', 'proton'):
            restic(None, name, ['init', '--from-repo', str(self.root / 'games'), '--copy-chunker-params'])
        legacy, full, held = (self.root / name for name in ('legacy', 'full', 'held'))
        for path in (legacy, full, held):
            path.mkdir()
        rows = {}
        for name, path, date, tags in (
            ('old-legacy', legacy, '2020-01-01', ['cadence=daily']),
            ('latest-legacy', legacy, '2020-01-02', ['cadence=daily']),
            ('old-full', full, '2026-11-01', ['cadence=daily', 'format=full-v2']),
            ('latest-full', full, '2026-11-02', ['cadence=daily', 'format=full-v2']),
            ('partial', full, '2026-11-03', ['cadence=daily', 'format=full-v2']),
            ('unknown', full, '2026-11-04', ['cadence=daily', 'format=future']),
            ('unrelated', legacy, '2026-11-05', ['manual']),
            ('held-full', held, '2026-11-01', ['cadence=daily', 'format=full-v2']),
            ('conflict', held, '2026-11-06', ['cadence=daily', 'format=full-v2', 'complete=full-v2', 'format=future']),
        ):
            (path / 'value').write_text(name)
            args = ['backup', '--json', '--time', date + ' 00:00:00', str(path)]
            for tag in tags:
                args += ['--tag', tag]
            snapshot = RUNNER['parse_backup_snapshot'](restic(None, 'games', args))
            if name.endswith('full'):
                restic(None, 'games', ['tag', '--add', 'complete=full-v2', snapshot])
                row = next(r for r in inventory(None, 'games') if r.get('original') == snapshot)
            else:
                row = next(r for r in inventory(None, 'games') if r['id'] == snapshot)
            rows[name] = row
        maintenance, reconcile = RUNNER['maintenance'], RUNNER['reconcile']
        with mock.patch.dict(maintenance.__globals__, {
            'rooted': Path, 'journal_path': lambda _: self.root / 'journal', 'preflight': mock.Mock(),
            'restic_result': restic, 'inventory': inventory,
        }), mock.patch.dict(os.environ, HOME_LAB_RESTIC_MAINTENANCE_SCOPE='local'):
            for destination in ('nfs', 'proton'):
                reconcile({}, destination)
                self.assertFalse(any(RUNNER['same_capture'](rows['conflict'], row)
                                     for row in inventory(None, destination)))
                # Previously copied noneligible history must not be deleted either.
                for name in ('partial', 'unknown', 'unrelated', 'conflict'):
                    restic(None, destination, ['copy', rows[name]['id']], source='games')
            policy = {'capture': {'stage': str(self.root / 'pending')}, 'retention': {
                'keep_daily': 1, 'keep_weekly': 0, 'keep_monthly': 0, 'group_by': 'host,paths',
                'prune_max_repack_size': '10G', 'prune_max_unused': '10%', 'read_data_subset': '10%',
            }, 'repositories': {name: {'id': json.loads(restic(None, name, ['cat', 'config']).stdout)['id']}
                                for name in ('games', 'nfs', 'proton')}}
            interrupted = False
            def lost_acknowledgment(_policy, name, args):
                nonlocal interrupted
                result = restic(_policy, name, args)
                if name == 'nfs' and args[0] == 'forget' and not interrupted:
                    interrupted = True
                    raise RUNNER['WorkflowError']('synthetic_lost_acknowledgment')
                return result
            with mock.patch.dict(maintenance.__globals__, {'restic_result': lost_acknowledgment}):
                with self.assertRaisesRegex(RUNNER['WorkflowError'], 'synthetic_lost_acknowledgment'):
                    maintenance(policy)
            pending = self.root / 'retention.json'
            self.assertTrue(pending.exists())
            for name in ('old-legacy', 'old-full'):
                self.assertNotIn(rows[name]['id'], {r['id'] for r in inventory(None, 'games')})
                self.assertTrue(any(RUNNER['same_capture'](rows[name], row) for row in inventory(None, 'proton')))
            maintenance(policy)
            self.assertFalse(pending.exists())
        expected = [rows[name] for name in (
            'latest-legacy', 'latest-full', 'partial', 'unknown', 'unrelated', 'held-full', 'conflict',
        )]
        self.assertEqual({r['id'] for r in inventory(None, 'games')}, {r['id'] for r in expected})
        for destination in ('nfs', 'proton'):
            copies = inventory(None, destination)
            self.assertEqual(len(copies), len(expected))
            self.assertTrue(all(any(RUNNER['same_capture'](source, copy) for copy in copies) for source in expected))

    def sqlite_fixture(self):
        path = self.root / 'original.sqlite'
        with closing(sqlite3.connect(path)) as db:
            db.execute('CREATE TABLE items (value TEXT)')
            db.execute("INSERT INTO items VALUES ('saved')")
            db.commit()
        return path

if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--readonly-wal-child':
        if (os.geteuid() != 0 or os.environ.get('HOME_LAB_READONLY_WAL_TEST_DISPOSABLE') != 'true'
                or Path('/etc/home-lab/restic-policy.json').exists()):
            raise SystemExit('disposable fixture admission required')
        source, target, excludes = map(Path, sys.argv[2:])
        subprocess.run(['mount', '--bind', str(source), str(source)], check=True)
        subprocess.run(['mount', '-o', 'remount,bind,ro', str(source)], check=True)
        if not os.statvfs(source).f_flag & os.ST_RDONLY:
            raise SystemExit('fixture source must be read-only')
        try:
            descriptor = os.open(source / 'state.db-shm', os.O_RDWR)
        except OSError as error:
            if error.errno != errno.EROFS:
                raise
        else:
            os.close(descriptor)
            raise SystemExit('fixture WAL index unexpectedly writable')
        with closing(sqlite3.connect('file:' + str(source / 'state.db') + '?mode=ro', uri=True)) as reader:
            reader.execute('PRAGMA journal_mode').fetchone()
            CAPTURE.sqlite_backup(source / 'state.db', target / 'probe.db', reader=reader)
        CAPTURE.online_tree([str(source)], target, excludes, sqlite_paths=[str(source / 'state.db')])
    else:
        unittest.main()
