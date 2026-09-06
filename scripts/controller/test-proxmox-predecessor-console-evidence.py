#!/usr/bin/python3 -IBS
"""Synthetic offline tests. Native cases fork disposable chroots, never a host.

Positive main-entry fixtures substitute ONLY terminal identity and the cached
image's /usr/local/bin/python3 identity. Neither qualifies hardware or execution.
Real CLI non-TTY and controlling PTY cases use the unmodified guard.
"""
import sys
sys.dont_write_bytecode = True

import copy
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pty
import shutil
import socket
import stat
import subprocess
import tempfile
import types
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[2]
SCRIPT = ROOT / 'infrastructure/proxmox-access/host/proxmox-predecessor-console-evidence.py'


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


collector = load(SCRIPT)
protected = load(ROOT / 'scripts/controller/protected_execution.py')
with patch.dict(sys.modules, {'protected_execution': protected}):
    capability = load(ROOT / 'scripts/controller/proxmox-controller-observer-capability.py')
CHALLENGE = 'a1' * 32
SENTINEL = b'SECRET-SENTINEL-NEVER-READ-OR-HASH'
NATIVE = sys.platform == 'linux' and os.geteuid() == 0


def hardware_identity():
    return '/dev/tty1', stat.S_IFCHR | 0o600, os.makedev(4, 1)


def invoke_main(console=True):
    output = io.BytesIO()
    with patch.object(sys, 'stdout', types.SimpleNamespace(buffer=output)), \
            patch.object(sys, 'argv', [str(SCRIPT), '--challenge', CHALLENGE]), \
            patch.object(sys, 'executable', '/usr/bin/python3'):
        if console:
            with patch.object(collector, 'terminal_identity', hardware_identity):
                code = collector.main()
        else:
            code = collector.main()
    raw = output.getvalue()
    return code, json.loads(raw), raw


def assert_output(test, code, value, raw, measured=False):
    test.assertEqual(code, 0 if measured else 1)
    test.assertEqual(raw, collector.canonical(value))
    test.assertLessEqual(len(raw), collector.MAX_OUTPUT)
    test.assertFalse(value['authorized'])
    test.assertFalse(value['admission_eligible'])
    test.assertEqual(value['format'], collector.FORMAT)
    test.assertEqual(value['blockers'], collector.BLOCKERS)
    test.assertEqual(value['status'], 'measured' if measured else 'refused')
    test.assertNotIn(SENTINEL, raw)
    test.assertNotIn(hashlib.sha256(SENTINEL).hexdigest().encode(), raw)
    if not measured:
        test.assertEqual(value['error'], 'inspection-refused')
        test.assertNotIn('public_assets', value)
        test.assertNotIn('barriers_absent', value)


def reject_v1(test, value):
    for flipped in (False, True):
        candidate = copy.deepcopy(value)
        candidate.update(authorized=flipped, admission_eligible=flipped)
        with test.assertRaises(ValueError):
            capability.validate_access(candidate, collector.canonical(candidate),
                                       'a' * 40, 'b' * 64, 'c' * 64,
                                       datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))


class CliTests(unittest.TestCase):
    def cli(self, flags=('-I', '-B', '-S'), args=('--challenge', CHALLENGE), env=None):
        result = subprocess.run([sys.executable, *flags, str(SCRIPT), *args],
                                input=b'', capture_output=True, env=env, timeout=10)
        self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout)
        assert_output(self, result.returncode, value, result.stdout)
        return value

    def test_real_cli_non_tty_and_arguments(self):
        reject_v1(self, self.cli())
        for args in ((), ('--help',), ('--challenge', 'secret-path'),
                     ('--challenge', CHALLENGE, '--root', '/secret'),
                     ('--challenge', 'a' * 65), ('--challenge', 'A' * 64),
                     ('--challenge', CHALLENGE, '--challenge', CHALLENGE)):
            value = self.cli(args=args)
            self.assertNotIn('secret', json.dumps(value))

    def test_actual_startup_flags_and_environment_no_bytecode(self):
        for flags in ((), ('-I',), ('-B', '-S'), ('-I', '-S'), ('-I', '-B')):
            self.cli(flags=flags)
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'executed'
            injection = 'open(' + repr(str(marker)) + ', "w").write("injected")\n'
            for name in ('sitecustomize.py', 'usercustomize.py', 'startup.py'):
                (Path(temporary) / name).write_text(injection)
            before = sorted(p.name for p in Path(temporary).iterdir())
            env = {**os.environ, 'PYTHONPATH': temporary, 'PYTHONHOME': temporary,
                   'PYTHONSTARTUP': str(Path(temporary) / 'startup.py'),
                   'PYTHONPYCACHEPREFIX': temporary}
            self.cli(env=env)
            self.assertEqual(before, sorted(p.name for p in Path(temporary).iterdir()))
            self.assertFalse(marker.exists())


@unittest.skipUnless(NATIVE, 'requires confined Linux/root fixture, not Mac qualification')
class NativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        for path, mode in collector.PUBLIC:
            self.put(path, ('synthetic public asset ' + path + '\n').encode(), mode)
        self.put(collector.OPERATION, SENTINEL, 0o600)
        self.put(collector.SECRET, SENTINEL, 0o600)
        (self.root / collector.RUNTIME[1:]).chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, raw, mode):
        destination = self.root / path[1:]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(mode)
        return destination

    def confined(self, action):
        child = os.fork()
        if child == 0:
            try:
                os.chroot(self.root)
                os.chdir('/')
                action()
            except BaseException:
                traceback.print_exc()
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(child, 0)
        self.assertEqual(status, 0, 'confined child assertions failed')

    def refusal(self):
        assert_output(self, *invoke_main())

    def test_cli_startup_arguments_and_environment_against_positive_fixture(self):
        # Separate interpreter process running the exact collector source/main.
        # Only terminal identity and cached interpreter spelling are substituted;
        # flags, argv, environment, all filesystem reads and flock are real.
        bootstrap = '''import os,sys
source, root = sys.argv[1:3]
namespace = {"__name__": "console_fixture", "__file__": source}
with open(source, "rb") as handle:
    exec(compile(handle.read(), source, "exec"), namespace)
namespace["terminal_identity"] = lambda: ("/dev/tty1", 0o20600, os.makedev(4, 1))
sys.argv = [source] + sys.argv[3:]
sys.executable = "/usr/bin/python3"
os.chroot(root)
os.chdir("/")
sys.exit(namespace["main"]())
'''
        def cli(flags=('-I', '-B', '-S'), args=('--challenge', CHALLENGE), extra=None):
            result = subprocess.run([sys.executable, *flags, '-c', bootstrap,
                                     str(SCRIPT), str(self.root), *args],
                                    env={'PATH': '/usr/local/bin:/usr/bin:/bin', **(extra or {})},
                                    input=b'', capture_output=True, timeout=10)
            self.assertEqual(result.stderr, b'')
            return result.returncode, json.loads(result.stdout), result.stdout
        assert_output(self, *cli(), measured=True)
        for flags in ((), ('-I',), ('-B', '-S'), ('-I', '-S'), ('-I', '-B')):
            assert_output(self, *cli(flags=flags))
        for args in ((), ('--challenge', 'bad'), ('--challenge', CHALLENGE, '--root', '/secret')):
            assert_output(self, *cli(args=args))
        for name in ('SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'SSH_ORIGINAL_COMMAND', 'PYTHONPATH'):
            assert_output(self, *cli(extra={name: ''}))
        # This successful fixture on either side prevents unrelated startup
        # refusals from satisfying every negative test by accident.
        assert_output(self, *cli(), measured=True)

    def test_actual_main_fixed_hashes_metadata_secret_never_opened_for_read(self):
        def action():
            original_open = os.open
            original_read = os.read
            forbidden = set()

            def guarded_open(path, flags, *args, **kwargs):
                fd = original_open(path, flags, *args, **kwargs)
                if path in ('attestation.key', 'operation.lock'):
                    if path == 'attestation.key':
                        self.assertTrue(flags & os.O_PATH)
                    forbidden.add(fd)
                else:
                    forbidden.discard(fd)
                return fd

            def guarded_read(fd, size):
                self.assertNotIn(fd, forbidden, 'secret/mutex content was read')
                return original_read(fd, size)

            with patch.object(os, 'open', guarded_open), patch.object(os, 'read', guarded_read):
                code, value, raw = invoke_main()
            assert_output(self, code, value, raw, True)
            self.assertEqual(value['challenge'], CHALLENGE)
            self.assertEqual([a['path'] for a in value['public_assets']], [p for p, _ in collector.PUBLIC])
            for asset in value['public_assets']:
                path = Path(asset['path'])
                self.assertEqual(asset['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(asset['metadata'], collector.metadata(path.stat()))
            for asset in value['metadata_only']:
                self.assertEqual(set(asset), {'path', 'metadata'})
            reject_v1(self, value)
        self.confined(action)

    def test_missing_each_asset_and_runtime_no_mutation(self):
        paths = [p for p, _ in collector.PUBLIC] + [collector.SECRET, collector.OPERATION,
                                                    collector.RUNTIME, collector.RECONCILIATION]
        for path in paths:
            def action(path=path):
                target = Path(path)
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
                # Fixture-only enumeration; the collector never enumerates.
                def tree():
                    return {str(p): collector.identity(p.lstat()) for p in Path('/').rglob('*')}
                before = tree()
                self.refusal()
                self.assertEqual(before, tree())
            self.confined(action)
            # Child edits affect the fixture; rebuild, never reuse missing state.
            self.tearDown(); self.setUp()

    def test_file_shapes_owner_mode_size_and_ancestor_attacks(self):
        for target in (collector.PUBLIC[0][0], collector.SECRET, collector.OPERATION):
            for attack in ('symlink', 'hardlink', 'fifo', 'directory', 'oversize', 'uid', 'gid', 'mode'):
                def action(target=target, attack=attack):
                    path = Path(target)
                    if attack == 'symlink':
                        path.unlink(); path.symlink_to('/missing-sentinel')
                    elif attack == 'hardlink':
                        os.link(path, '/hardlink')
                    elif attack == 'fifo':
                        path.unlink(); os.mkfifo(path, 0o600)
                    elif attack == 'directory':
                        path.unlink(); path.mkdir()
                    elif attack == 'oversize':
                        with path.open('wb') as handle:
                            handle.truncate(collector.MAX_PUBLIC + 1)
                    elif attack == 'uid':
                        os.chown(path, 1, 0)
                    elif attack == 'gid':
                        os.chown(path, 0, 1)
                    else:
                        path.chmod(0o777)
                    self.refusal()
                self.confined(action)
                self.tearDown(); self.setUp()
        for target in ('/', '/usr', '/usr/local/libexec', collector.RUNTIME, collector.RECONCILIATION):
            for attack in ('mode', 'owner', 'symlink'):
                if target == '/' and attack == 'symlink':
                    continue
                def action(target=target, attack=attack):
                    path = Path(target)
                    if attack == 'mode':
                        path.chmod(0o1777)
                    elif attack == 'owner':
                        os.chown(path, 1, 0)
                    else:
                        path.rename('/displaced'); path.symlink_to('/displaced')
                    self.refusal()
                self.confined(action)
                self.tearDown(); self.setUp()

    def test_every_retained_barrier_shape_and_inspection_errors(self):
        for barrier in collector.BARRIERS:
            for shape in ('regular', 'symlink', 'fifo', 'directory', 'socket'):
                def action(barrier=barrier, shape=shape):
                    path = Path(barrier)
                    if shape == 'regular':
                        path.write_bytes(SENTINEL)
                    elif shape == 'symlink':
                        path.symlink_to('/absent')
                    elif shape == 'fifo':
                        os.mkfifo(path)
                    elif shape == 'socket':
                        sock = socket.socket(socket.AF_UNIX)
                        sock.bind(str(path)); sock.close()
                    else:
                        path.mkdir()
                    before = collector.identity(path.lstat())
                    self.refusal()
                    self.assertEqual(before, collector.identity(path.lstat()))
                self.confined(action)
                self.tearDown(); self.setUp()
        def errors():
            original = os.stat
            for error in (PermissionError, OSError):
                def faulty(path, *args, **kwargs):
                    if path == 'apply.lock':
                        raise error('SECRET EXCEPTION TEXT')
                    return original(path, *args, **kwargs)
                with patch.object(os, 'stat', faulty):
                    self.refusal()
        self.confined(errors)

    def test_named_content_and_directory_replacement_rechecks(self):
        for change in ('public-replace', 'public-bytes', 'secret-replace', 'lock-replace',
                       'ancestor-replace', 'barrier-appears', 'read-error', 'short-read'):
            def action(change=change):
                original = collector.Snapshot.digest
                count = 0
                def digest(snapshot, record):
                    nonlocal count
                    result = original(snapshot, record)
                    count += 1
                    if count == len(collector.PUBLIC):
                        target = Path(collector.PUBLIC[0][0])
                        if change in ('secret-replace', 'lock-replace'):
                            target = Path(collector.SECRET if change == 'secret-replace' else collector.OPERATION)
                        if change.endswith('replace') and change != 'ancestor-replace':
                            raw, mode = target.read_bytes(), stat.S_IMODE(target.stat().st_mode)
                            target.rename(str(target) + '.old')
                            target.write_bytes(raw); target.chmod(mode)
                        elif change == 'public-bytes':
                            target.write_bytes(b'changed')
                        elif change == 'ancestor-replace':
                            target.parent.rename('/old-parent')
                            target.parent.mkdir()
                        elif change == 'barrier-appears':
                            Path(collector.BARRIERS[0]).write_bytes(SENTINEL)
                    return result
                if change in ('read-error', 'short-read'):
                    kwargs = {'side_effect': OSError('SENTINEL')} if change == 'read-error' else {'return_value': b''}
                    with patch.object(os, 'read', **kwargs):
                        self.refusal()
                elif change == 'secret-replace':
                    original_recheck = collector.Snapshot.recheck
                    def replaced(snapshot):
                        path = Path(collector.SECRET)
                        path.rename(str(path) + '.old')
                        path.write_bytes(SENTINEL); path.chmod(0o600)
                        original_recheck(snapshot)
                    with patch.object(collector.Snapshot, 'recheck', replaced):
                        self.refusal()
                else:
                    with patch.object(collector.Snapshot, 'digest', digest):
                        self.refusal()
            self.confined(action)
            self.tearDown(); self.setUp()

    def test_real_conflicting_holder_release_and_retained_barrier(self):
        def action():
            ready_r, ready_w = os.pipe()
            release_r, release_w = os.pipe()
            child = os.fork()
            if child == 0:
                fd = os.open(collector.OPERATION, os.O_RDONLY)
                fcntl.flock(fd, fcntl.LOCK_EX)
                os.write(ready_w, b'1')
                os.read(release_r, 1)
                os.close(fd)
                os._exit(0)
            os.close(ready_w); os.close(release_r)
            try:
                self.assertEqual(os.read(ready_r, 1), b'1')
                self.refusal()
            finally:
                os.write(release_w, b'1')
                os.close(release_w); os.close(ready_r)
                self.assertEqual(os.waitpid(child, 0)[1], 0)
            assert_output(self, *invoke_main(), measured=True)
            Path(collector.BARRIERS[0]).mkdir()
            self.refusal()
            # The collector must neither remove nor adopt a released retained owner.
            self.assertTrue(Path(collector.BARRIERS[0]).is_dir())
            Path(collector.BARRIERS[0]).rmdir()  # explicit disposable fixture cleanup
            assert_output(self, *invoke_main(), measured=True)
        self.confined(action)

    def test_descriptor_exclusion_lifetime_and_failure_release(self):
        def action():
            original = collector.Snapshot.digest
            def checked(snapshot, record):
                # Separate open description in a real child must conflict during
                # both initial reads and final content rechecks.
                child = os.fork()
                if child == 0:
                    for fd in snapshot.fds:
                        os.close(fd)
                    fd = os.open(collector.OPERATION, os.O_RDONLY)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        os._exit(0)
                    os._exit(1)
                self.assertEqual(os.waitpid(child, 0)[1], 0)
                return original(snapshot, record)
            with patch.object(collector.Snapshot, 'digest', checked):
                assert_output(self, *invoke_main(), measured=True)
            Path(collector.PUBLIC[0][0]).unlink()
            self.refusal()
            fd = os.open(collector.OPERATION, os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(fd)
        self.confined(action)

    def test_metadata_only_size_boundaries_without_content_reads(self):
        for target, limit in ((collector.SECRET, 128), (collector.OPERATION, 4096)):
            for size in (limit, limit + 1):
                def action(target=target, limit=limit, size=size):
                    Path(target).write_bytes(b'K' * size)
                    forbidden = {(p.stat().st_dev, p.stat().st_ino)
                                 for p in map(Path, (collector.SECRET, collector.OPERATION))}
                    original_open, original_read = os.open, os.read

                    def guarded_open(path, flags, *args, **kwargs):
                        if path == 'attestation.key':
                            self.assertTrue(flags & os.O_PATH)
                        return original_open(path, flags, *args, **kwargs)

                    def guarded_read(fd, count):
                        info = os.fstat(fd)
                        self.assertNotIn((info.st_dev, info.st_ino), forbidden,
                                         'metadata-only content was read')
                        return original_read(fd, count)

                    with patch.object(os, 'open', guarded_open), \
                            patch.object(os, 'read', guarded_read):
                        code, value, raw = invoke_main()
                    assert_output(self, code, value, raw, measured=size == limit)
                    self.assertNotIn(hashlib.sha256(b'K' * size).hexdigest().encode(), raw)
                    if size == limit:
                        record = next(a for a in value['metadata_only'] if a['path'] == target)
                        self.assertEqual(set(record), {'path', 'metadata'})
                        self.assertEqual(record['metadata']['size'], size)
                self.confined(action)
                self.tearDown(); self.setUp()
    def test_environment_root_interpreter_and_console_guard_fail_closed(self):
        def action():
            for key in ('SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'SSH_ORIGINAL_COMMAND', 'PYTHONPATH'):
                with patch.dict(os.environ, {key: ''}):
                    self.refusal()
            # Exercise the real kernel-console allowlist, not a mocked success.
            for name, device in (('/dev/pts/0', os.makedev(136, 0)),
                                 ('/dev/console', os.makedev(5, 1)),
                                 ('/dev/tty0', os.makedev(4, 0)),
                                 ('/dev/ttyS4', os.makedev(4, 68))):
                with patch.object(sys, 'executable', '/usr/bin/python3'), \
                        patch.object(collector, 'terminal_identity', lambda: (name, stat.S_IFCHR, device)):
                    with self.assertRaisesRegex(collector.Refusal, 'console-required'):
                        collector.startup()
            with patch.object(sys, 'executable', '/unqualified/python'), \
                    patch.object(collector, 'terminal_identity', hardware_identity):
                with self.assertRaisesRegex(collector.Refusal, '^fixed-interpreter-required$'):
                    collector.startup()
            os.setgid(65534); os.setuid(65534)
            with patch.object(sys, 'executable', '/usr/bin/python3'), \
                    patch.object(collector, 'terminal_identity', hardware_identity):
                with self.assertRaisesRegex(collector.Refusal, '^linux-root-required$'):
                    collector.startup()
            with patch.object(collector.Snapshot, 'collect',
                              side_effect=AssertionError('startup reached asset collection')):
                self.refusal()
        self.confined(action)

    def test_real_controlling_pty_and_non_tty_rejected(self):
        # Run outside the chroot to retain /dev/pts. No target asset is reached.
        child, master = pty.fork()
        if child == 0:
            try:
                self.assertTrue(os.isatty(0))
                self.assertTrue(os.ttyname(0).startswith('/dev/pts/'))
                with patch.object(sys, 'executable', '/usr/bin/python3'):
                    with self.assertRaisesRegex(collector.Refusal, '^console-required$'):
                        collector.startup()
                with patch.object(collector.Snapshot, 'collect',
                                  side_effect=AssertionError('PTY reached asset collection')):
                    assert_output(self, *invoke_main(console=False))
            except BaseException:
                os._exit(1)
            os._exit(0)
        try:
            self.assertEqual(os.waitpid(child, 0)[1], 0)
        finally:
            os.close(master)
        def non_tty():
            self.assertFalse(os.isatty(0))
            with patch.object(sys, 'executable', '/usr/bin/python3'):
                with self.assertRaisesRegex(collector.Refusal, '^console-required$'):
                    collector.startup()
            with patch.object(collector.Snapshot, 'collect',
                              side_effect=AssertionError('non-TTY reached asset collection')):
                assert_output(self, *invoke_main(console=False))
        self.confined(non_tty)


if __name__ == '__main__':
    unittest.main()
