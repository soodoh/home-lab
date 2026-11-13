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

    def test_wolf_preserves_selected_saves_not_installed_games(self):
        wolf = self.root / 'wolf'
        (wolf / 'cfg').mkdir(parents=True)
        profile = wolf / 'profile-data/user/Steam'
        userdata = profile / '.steam/steam/userdata/123/456/remote'
        userdata.mkdir(parents=True)
        (userdata / 'save').write_text('saved')
        prefix = profile / '.steam/steam/steamapps/compatdata/456/pfx'
        saves = prefix / 'drive_c/users/steamuser/Saved Games'
        saves.mkdir(parents=True)
        (saves / 'save').write_text('saved')
        (prefix / 'system.reg').write_text('registry')
        launcher = profile / 'icons/icon.png'
        launcher.parent.mkdir()
        launcher.write_text('launcher')
        pointer = profile / '.local/share/applications/icon.png'
        pointer.parent.mkdir(parents=True)
        pointer.symlink_to('/home/retro/icons/icon.png')
        paths, links = CAPTURE.wolf_paths(wolf)
        self.assertEqual(links[str(pointer)]['resolved'], str(launcher))
        self.assertIn(str(launcher), paths)
        self.assertIn(str(saves), paths)
        self.assertIn(str(prefix / 'system.reg'), paths)
        self.assertIn(str(profile / '.steam/steam/userdata'), paths)
        self.assertFalse(any(p.endswith('compatdata') or p.endswith('pfx') for p in paths))
        external = profile / '.config'
        external.symlink_to(self.root)
        with self.assertRaisesRegex(CAPTURE.CaptureError, 'external'):
            CAPTURE.wolf_paths(wolf)

    def wolf_link_fixture(self):
        wolf = self.root / 'wolf'
        (wolf / 'cfg').mkdir(parents=True)
        profile = wolf / 'profile-data/user/Steam'
        settings = profile / 'owned-settings'
        settings.mkdir(parents=True)
        (profile / '.config').symlink_to('owned-settings')
        return wolf, profile, settings

    def test_wolf_follows_directory_targets_and_maps_nested_save_links(self):
        wolf, profile, settings = self.wolf_link_fixture()
        saves = profile / 'owned-saves'
        saves.mkdir()
        save = profile / 'saved-game'
        save.write_text('saved')
        (settings / 'saves').symlink_to('../owned-saves')
        (saves / 'slot').symlink_to('../saved-game')
        # An ancestor cycle and an alias must not restart directory traversal.
        (saves / 'settings').symlink_to('../owned-settings')
        (settings / 'alias').symlink_to('../owned-saves')
        paths, links = CAPTURE.wolf_paths(wolf)
        self.assertIn(str(save), paths)
        self.assertIn(str(saves), paths)
        self.assertEqual(links[str(saves / 'slot')]['resolved'], str(save))
        self.assertEqual(links[str(saves / 'settings')]['resolved'], str(settings))
        self.assertEqual(links[str(settings / 'alias')]['resolved'], str(saves))
        self.assertEqual(links[str(profile / '.config')]['resolved'], str(settings))

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_wolf_copy_includes_nested_directory_link_targets(self):
        wolf, profile, settings = self.wolf_link_fixture()
        saves = profile / 'owned-saves'
        saves.mkdir()
        save = profile / 'saved-game'
        save.write_text('saved')
        (settings / 'saves').symlink_to('../owned-saves')
        (saves / 'slot').symlink_to('../saved-game')
        paths, links = CAPTURE.wolf_paths(wolf)
        target = self.root / 'copied'
        target.mkdir()
        CAPTURE.copy_paths(paths, target, ROOT / 'services/data/restic/excludes')
        self.assertEqual((target / str(save).lstrip('/')).read_text(), 'saved')
        self.assertEqual(links[str(saves / 'slot')]['target'], '../saved-game')
        self.assertTrue((target / str(saves / 'slot').lstrip('/')).is_symlink())

    def test_wolf_refuses_external_or_broken_links_inside_resolved_directories(self):
        wolf, _, settings = self.wolf_link_fixture()
        external = self.root / 'external-save'
        external.write_text('saved')
        link = settings / 'save'
        for target in (external, settings / 'missing', link):
            with self.subTest(target=target.name):
                link.symlink_to(target)
                try:
                    with self.assertRaises(CAPTURE.CaptureError):
                        CAPTURE.wolf_paths(wolf)
                finally:
                    link.unlink()

    def test_wolf_does_not_traverse_bulk_steam_in_a_resolved_share_directory(self):
        wolf, profile, _ = self.wolf_link_fixture()
        share = profile / '.local/share'
        bulk = share / 'Steam/steamapps/common/game'
        bulk.mkdir(parents=True)
        (bulk / 'unqualified').symlink_to(self.root / 'missing')
        (profile / '.config').unlink()
        (profile / '.config').symlink_to('.local/share')
        paths, _ = CAPTURE.wolf_paths(wolf)
        self.assertIn(str(share), paths)
        self.assertFalse(any(Path(p).is_relative_to(share / 'Steam') for p in paths))

    @unittest.skipUnless(sys.platform == 'linux', 'requires native Linux rsync metadata support')
    def test_wolf_copy_preserves_resolved_steam_saves_without_copying_bulk_or_whole_prefixes(self):
        wolf = self.root / 'wolf'
        (wolf / 'cfg').mkdir(parents=True)
        # Include the previously hard-coded profile as well as a second owner.
        for owner in ('paul/WolfES-DE', 'user/Steam'):
            profile = wolf / 'profile-data' / owner
            steam = profile / '.local/share/Steam'
            prefix = steam / 'steamapps/compatdata/456/pfx'
            selected = ['userdata/123/456/remote/save', 'steamapps/compatdata/456/pfx/system.reg',
                        'steamapps/compatdata/456/pfx/drive_c/users/steamuser/Saved Games/save']
            omitted = ['steamapps/common/game/bulk', 'steamapps/compatdata/456/pfx/drive_c/windows/bulk',
                       'steamapps/compatdata/456/pfx/drive_c/users/steamuser/AppData/Local/Temp/cache',
                       'appcache/bulk', 'steamclient.so']
            for relative in selected + omitted:
                path = steam / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic-' + path.name)
            (profile / '.steam').mkdir()
            (profile / '.steam/steam').symlink_to('../.local/share/Steam')
            paths, _ = CAPTURE.wolf_paths(wolf)
            target = self.root / owner.replace('/', '-')
            target.mkdir()
            CAPTURE.copy_paths(paths, target, ROOT / 'services/data/restic/excludes')
            for relative in selected:
                self.assertEqual((target / str(steam / relative).lstrip('/')).read_bytes(),
                                 (steam / relative).read_bytes())
            for relative in omitted:
                self.assertFalse((target / str(steam / relative).lstrip('/')).exists(), relative)
            self.assertFalse((target / str(prefix / 'drive_c/windows').lstrip('/')).exists())

    @unittest.skipUnless(sys.platform == 'linux', 'native Wolf socket interface')
    def test_wolf_uses_native_idle_api_and_refuses_active_sessions(self):
        state = {'sessions': [], 'lobbies': []}
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                kind = self.path.rsplit('/', 1)[-1]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, kind: state[kind]}).encode())
            def log_message(self, *_):
                pass
        with socketserver.UnixStreamServer(str(self.root / 'wolf.sock'), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            mounts = json.dumps([{'Source': str(self.root), 'Destination': '/run/user/wolf'}]).encode()
            try:
                with mock.patch.object(CAPTURE, 'command', return_value=mounts):
                    CAPTURE.wolf_idle('synthetic')
                    state['sessions'] = [{}]
                    with self.assertRaisesRegex(CAPTURE.CaptureError, 'not_idle'):
                        CAPTURE.wolf_idle('synthetic')
            finally:
                server.shutdown()
                thread.join()

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
    def test_native_completion_waits_for_a_shared_repository_lock_without_recapture(self):
        binary = os.environ['RESTIC']
        repository = self.root / 'games'
        environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(self.root), 'LC_ALL': 'C',
                       'RESTIC_PASSWORD': 'synthetic-only', 'RESTIC_CACHE_DIR': str(self.root / 'cache')}
        subprocess.run([binary, '-r', str(repository), 'init'], env=environment,
                       check=True, capture_output=True, timeout=30)
        stage = self.root / 'stage'
        stage.mkdir(mode=0o700)
        (stage / 'value').write_text('synthetic ready capture')
        manifest = {'version': 2, 'capture': 'lock-fixture', 'policy': 'a' * 64,
                    'artifact': 'b' * 64, 'owner': None, 'captured_at': datetime.now(timezone.utc).isoformat()}
        (stage / 'manifest.json').write_text(json.dumps(manifest))
        (stage / 'manifest.json').chmod(0o600)
        policy = {'capture': {'stage': str(stage)}, 'tools': {'restic': {'installed_path': binary}},
                  'repositories': {'games': {'path': str(repository)}}}
        daily, restic = RUNNER['daily_local'], RUNNER['restic_result']
        tagging, finished = threading.Event(), threading.Event()
        errors = []
        def command(*args, **kwargs):
            if args[2][0] == 'tag':
                tagging.set()
                # Bound fixture teardown even if a native lock fails to clear.
                kwargs['timeout'] = 30
            return restic(*args, **kwargs)
        def complete():
            try:
                daily(policy, 'a' * 64)
            except BaseException as error:
                errors.append(error)
            finally:
                finished.set()
        # An open stdin keeps a native shared repository lock alive without
        # relying on transfer speed. Copies hold the same kind of source lock.
        with subprocess.Popen([binary, '-r', str(repository), 'backup', '--stdin',
                               '--stdin-filename', 'lock-holder'], env=environment,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as reader:
            worker = threading.Thread(target=complete, daemon=True)
            try:
                deadline = time.monotonic() + 10
                while not list((repository / 'locks').iterdir()):
                    self.assertIsNone(reader.poll(), 'native lock holder exited prematurely')
                    self.assertLess(time.monotonic(), deadline, 'native reader did not acquire its lock')
                    time.sleep(.02)
                with mock.patch.dict(daily.__globals__, {
                    'recover_interruption': mock.Mock(), 'preflight': mock.Mock(), 'verify_sources': mock.Mock(),
                    'capture_adapter': lambda _: CAPTURE, 'rooted': Path, 'artifact_hash': lambda _: 'b' * 64,
                    'repository_environment': lambda *_: environment, 'restic_result': command,
                    'cold_capture': mock.Mock(side_effect=AssertionError('recapture')),
                }), mock.patch('builtins.print'):
                    worker.start()
                    try:
                        self.assertTrue(tagging.wait(10), 'completion did not reach native tagging')
                        self.assertFalse(finished.wait(7), 'completion abandoned the shared lock')
                        self.assertTrue(stage.exists())
                        reader.communicate(input=b'synthetic lock-holder input', timeout=10)
                        self.assertEqual(reader.returncode, 0)
                    finally:
                        if reader.poll() is None:
                            reader.terminate()
                            reader.communicate(timeout=10)
                        worker.join(40)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(errors, [])
                    self.assertFalse(stage.exists())
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
        (stage / 'files/srv/home-lab-state/example').mkdir(parents=True)
        CAPTURE.sqlite_backup(self.sqlite_fixture(), stage / 'files/srv/home-lab-state/example/db.sqlite')
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
        self.assertEqual(RUNNER['qualified'](incomplete), [])
        restic('games', ['tag', '--add', 'complete=full-v2', incomplete[0]['id']])
        sources = json.loads(restic('games', ['snapshots', '--json']))
        source = RUNNER['qualified'](sources)[0]
        self.assertEqual(OBSERVER.snapshot_time(source), captured_at.replace(microsecond=0))
        self.assertNotEqual(source['id'], source['original'])
        for _ in range(2):  # Retrying an interrupted/acknowledgment-lost copy is native-idempotent.
            restic('nfs', ['copy', source['id']], source='games')
        copies = json.loads(restic('nfs', ['snapshots', '--json']))
        self.assertEqual(len(copies), 1)
        self.assertTrue(RUNNER['same_capture'](source, copies[0]))
        self.assertEqual(OBSERVER.match_copy(source, copies), copies[0])
        target = self.root / 'restored'
        target.mkdir()
        restic('nfs', ['restore', copies[0]['id'], '--target', str(target), '--verify'])
        # Restic stores the absolute fixture path; normalize that parent root.
        recovered = target / str(fixture).lstrip('/')
        recovered.chmod(0o700)
        PREPARE.normalize(recovered)
        self.assertEqual((recovered / 'mnt/storage/media/nextcloud/data/user.txt').read_text(), 'user data')
        with closing(sqlite3.connect(recovered / 'srv/home-lab-state/example/db.sqlite')) as db:
            self.assertEqual(db.execute('SELECT value FROM items').fetchone(), ('saved',))
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
        legacy, full = self.root / 'legacy', self.root / 'full'
        legacy.mkdir(); full.mkdir()
        rows = {}
        for name, path, date, tags in (
            ('old-legacy', legacy, '2020-01-01', ['cadence=daily']),
            ('latest-legacy', legacy, '2020-01-02', ['cadence=daily']),
            ('old-full', full, '2026-11-01', ['cadence=daily', 'format=full-v2']),
            ('latest-full', full, '2026-11-02', ['cadence=daily', 'format=full-v2']),
            ('partial', full, '2026-11-03', ['cadence=daily', 'format=full-v2']),
            ('unknown', full, '2026-11-04', ['cadence=daily', 'format=future']),
            ('unrelated', legacy, '2026-11-05', ['manual']),
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
                # Previously copied noneligible history must not be deleted either.
                for name in ('partial', 'unknown', 'unrelated'):
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
        expected = [rows[name] for name in ('latest-legacy', 'latest-full', 'partial', 'unknown', 'unrelated')]
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
    unittest.main()
