#!/usr/bin/env python3
"""Offline public select/plan and legacy artifact/diff compatibility tests.

Only Git and OS boundaries are substituted. Fixtures and failed attempts are retained
under COMPOSE_DEPLOYMENT_TEST_SCRATCH; no native engine is invoked.
"""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from types import MappingProxyType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


artifact = load('compose-artifact')


class GitPipe:
    """Inert subprocess boundary: real OS pipe, no external executable or Git metadata."""
    def __init__(self, data, returncode=0):
        reader, writer = os.pipe()
        self.stdout = os.fdopen(reader, 'rb')
        self.returncode = returncode
        self.done = threading.Event()
        def send():
            try:
                with os.fdopen(writer, 'wb') as stream:
                    stream.write(data)
            except BrokenPipeError:
                pass
            finally:
                self.done.set()
        self.thread = threading.Thread(target=send)
        self.thread.start()

    def wait(self, timeout=None):
        if not self.done.wait(timeout):
            raise subprocess.TimeoutExpired('inert-git-pipe', timeout)
        self.thread.join()
        return self.returncode

    def poll(self):
        return self.returncode if self.done.is_set() else None

    def kill(self):
        self.returncode = -9


class StalledGitPipe:
    """An inert pipe/exit stall with a safety release; kill releases and wait reaps its thread."""
    def __init__(self, close_stdout=False):
        reader, writer = os.pipe()
        self.stdout = os.fdopen(reader, 'rb')
        self.release = threading.Event()
        self.done = threading.Event()
        self.returncode = None
        self.killed = False
        self.reaped = False
        def stall():
            try:
                with os.fdopen(writer, 'wb') as stream:
                    if close_stdout:
                        stream.write(b'a' * 40 + b'\n')
                    else:
                        self.release.wait(0.3)
                        if not self.killed:
                            stream.write(b'a' * 40 + b'\n')
                if close_stdout:
                    self.release.wait(0.3)
                self.returncode = -9 if self.killed else 0
            except BrokenPipeError:
                self.returncode = -9
            finally:
                self.done.set()
        self.thread = threading.Thread(target=stall)
        self.thread.start()

    def wait(self, timeout=None):
        if not self.done.wait(timeout):
            raise subprocess.TimeoutExpired('inert-git-stall', timeout)
        self.thread.join()
        self.reaped = True
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.release.set()


class ArtifactCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=os.environ['COMPOSE_DEPLOYMENT_TEST_SCRATCH']))

    def file(self, name, data=b'example\n', mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def test_strict_identity_sees_mode_only_change_without_reinterpreting_v1(self):
        path = self.file('services/data/gluetun/gluetun_up.sh', b'exit 0\n', 0o644)
        paths = ['services/data/gluetun/gluetun_up.sh']
        legacy = artifact.artifact_hash(self.root, paths)
        first, _ = artifact.strict_snapshot(self.root, paths)
        path.chmod(0o755)
        second, _ = artifact.strict_snapshot(self.root, paths)
        self.assertEqual(legacy, artifact.artifact_hash(self.root, paths))
        self.assertNotEqual(first['sha256'], second['sha256'])
        self.assertEqual(second['entries'][0]['mode'], '0755')
        self.assertEqual(second['legacy_sha256'], legacy)

    def test_strict_snapshot_refuses_unsafe_inputs_before_reading(self):
        regular = self.file('services/data/gluetun/hook.sh')
        link = self.root / 'services/data/gluetun/link.sh'
        link.symlink_to(regular)
        hardlink = self.root / 'services/data/gluetun/hard.sh'
        os.link(regular, hardlink)
        unsafe = self.file('services/data/gluetun/writable.sh', mode=0o666)
        for paths in ([link.relative_to(self.root).as_posix()],
                      [hardlink.relative_to(self.root).as_posix()],
                      [unsafe.relative_to(self.root).as_posix()],
                      ['../escape'], ['services//data/a'], ['.env'],
                      ['docker-compose.yml', 'docker-compose.yml']):
            with self.subTest(paths=paths), self.assertRaisesRegex(ValueError, 'unsafe|duplicate'):
                artifact.strict_snapshot(self.root, paths)

    def test_strict_snapshot_bounds_file_count_and_bytes(self):
        with self.assertRaisesRegex(ValueError, 'limit'):
            artifact.strict_snapshot(self.root, ['a'] * 257)
        path = self.file('services/data/oversized')
        with path.open('r+b') as stream:
            stream.seek(8 * 1024 * 1024)
            stream.write(b'x')
        with self.assertRaisesRegex(ValueError, 'limit'):
            artifact.strict_snapshot(self.root, ['services/data/oversized'])

    def test_strict_snapshot_does_not_follow_parent_links_or_open_special_files(self):
        target = self.root / 'actual'
        target.mkdir(mode=0o700)
        self.file('actual/a')
        (self.root / 'linked').symlink_to(target, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            artifact.strict_snapshot(self.root, ['linked/a'])
        os.mkfifo(self.root / 'fifo', 0o600)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            artifact.strict_snapshot(self.root, ['fifo'])


class SelectPlanTests(ArtifactCompatibilityTests):
    def setUp(self):
        super().setUp()
        self.policy = {'version': 1, 'assets': [
            {'path': 'services/data/gluetun', 'kind': 'directory', 'disposition': 'compose-bind'}]}
        self.paths = sorted(artifact.EXPLICIT_PATHS | {
            'services/' + n + '.yml' for n in
            ('openfit', 'apps', 'hass', 'gaming', 'nextcloud', 'servarr', 'authentik', 'infra')
        } | {'services/data/gluetun/gluetun_up.sh'})
        for name in self.paths:
            self.file(name, mode=0o755 if name.endswith('.sh') else 0o600)
        self.file('docker-compose.yml', ('include:\n' + ''.join(
            '  - ./' + p + '\n' for p in self.paths if p.startswith('services/') and p.endswith('.yml'))).encode())
        self.file('infrastructure/contract/home-lab.yml', json.dumps({'compose_deployment': self.policy}).encode())
        self.file('infrastructure/contract/schema.json', (ROOT / 'infrastructure/contract/schema.json').read_bytes())
        for name in ('compose-deployment.py', 'compose-deployment-diff.py', 'compose-artifact.py',
                     'compose-action-plan.py', 'compose-model-inventory.py', 'compose-image-lock.py'):
            self.file('scripts/' + name, (ROOT / 'scripts' / name).read_bytes())
        self.tracked = self.paths + ['infrastructure/contract/home-lab.yml',
            'infrastructure/contract/schema.json', 'scripts/compose-deployment.py',
            'scripts/compose-deployment-diff.py', 'scripts/compose-action-plan.py']
        self.commits = {}
        self.freeze_commit('a' * 40)
        self.trust = self.file('known-hosts', b'fixture trust identity\n', 0o600)

    def freeze_commit(self, revision):
        """Capture explicit synthetic commit bytes/modes once, independently of future index edits."""
        self.assertNotIn(revision, self.commits)
        self.commits[revision] = MappingProxyType({
            p: ((self.root / p).read_bytes(),
                b'100755' if (self.root / p).stat().st_mode & 0o111 else b'100644')
            for p in self.tracked})
        self.head = revision

    @property
    def committed(self):
        return MappingProxyType({p: entry[0] for p, entry in self.commits[self.head].items()})

    def git(self, root, args):
        self.assertEqual(root, self.root)
        if args[0] == 'rev-parse':
            return self.head.encode() + b'\n'
        if args == ['ls-files', '-z']:
            return b'\0'.join(p.encode() for p in self.tracked) + b'\0'
        if args[0] == 'ls-tree':
            self.assertEqual(args[1], '-rz')
            snapshot = self.commits[self.head if args[2] == 'HEAD' else args[2]]
            # Model Git pathspec filtering, but enumerate only frozen committed entries.
            requested = args[4:] if len(args) > 3 and args[3] == '--' else []
            return b''.join(mode + b' blob ' + b'b' * 40 + b'\t' + p.encode() + b'\0'
                            for p, (_, mode) in sorted(snapshot.items())
                            if not requested or any(p == q or p.startswith(q + '/') for q in requested))
        if args[0] == 'show':
            revision, name = args[1].split(':', 1)
            return self.commits[self.head if revision == 'HEAD' else revision][name][0]
        raise AssertionError('unexpected Git operation: ' + repr(args))

    def select(self, output='selection'):
        deployment = load('compose-deployment')
        with patch('subprocess.run', side_effect=AssertionError('native effect')), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            deployment.main(['select', '--source', 'HEAD', '--root', str(self.root),
                             '--known-hosts', str(self.trust), '--output', str(self.root / output)], git=self.git)
        self.assertNotIn('example', stdout.getvalue())
        return json.loads((self.root / output / 'selection.json').read_bytes())

    def select_through_pipe(self, deployment, responder, output):
        def popen(argv, **kwargs):
            self.assertEqual(argv[:4], ['/usr/bin/git', '--no-optional-locks', '-c', 'core.fsmonitor=false'])
            return responder(argv[4:], kwargs)
        with patch('subprocess.Popen', side_effect=popen), contextlib.redirect_stdout(io.StringIO()):
            deployment.main(['select', '--source', 'HEAD', '--root', str(self.root),
                             '--known-hosts', str(self.trust), '--output', str(self.root / output)])
        return json.loads((self.root / output / 'selection.json').read_bytes())

    def test_select_retains_fixed_execution_material_as_private_canonical_data(self):
        modes = {
            'infrastructure/contract/home-lab.yml': 0o600,
            'infrastructure/contract/schema.json': 0o644,
            'scripts/compose-deployment.py': 0o700,
            'scripts/compose-deployment-diff.py': 0o755,
            'scripts/compose-artifact.py': 0o644,
            'scripts/compose-action-plan.py': 0o600,
            'scripts/compose-model-inventory.py': 0o644,
            'scripts/compose-image-lock.py': 0o644,
        }
        for name, mode in modes.items():
            (self.root / name).chmod(mode)
        self.freeze_commit('c' * 40)
        selected = self.select()
        path = self.root / 'selection/execution-material.json'
        self.assertTrue(path.exists(), 'select must retain the checked execution material')
        raw = path.read_bytes()
        material = json.loads(raw)
        self.assertEqual(set(material), {'format', 'executable', 'authority', 'source_commit',
                                         'selection_sha256', 'members'})
        self.assertEqual(material['format'], 'compose-execution-material-v1')
        self.assertFalse(material['executable'])
        self.assertEqual(material['authority'], 'untrusted-local-source-only')
        self.assertEqual(material['source_commit'], 'c' * 40)
        self.assertEqual(material['selection_sha256'], hashlib.sha256(
            (self.root / 'selection/selection.json').read_bytes()).hexdigest())
        self.assertEqual(raw, json.dumps(material, sort_keys=True, separators=(',', ':'),
                                        ensure_ascii=True).encode() + b'\n')
        self.assertEqual([row['path'] for row in material['members']], sorted(modes))
        for row in material['members']:
            name = row['path']
            data = self.committed[name]
            self.assertEqual(set(row), {'path', 'type', 'kind', 'mode', 'size', 'sha256', 'content_base64'})
            self.assertEqual(row['type'], 'file')
            self.assertEqual(row['kind'], 'python' if name.startswith('scripts/') else 'policy')
            self.assertEqual(row['mode'], f'{modes[name]:04o}')
            self.assertEqual(row['size'], len(data))
            self.assertEqual(base64.b64decode(row['content_base64'], validate=True), data)
            self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
            digest = selected['contract_sha256'] if name.endswith('home-lab.yml') else selected['checker_sha256'][name]
            self.assertEqual(row['sha256'], digest)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(selected['unavailable'], ['observe', 'apply', 'verify', 'recovery'])

    @contextlib.contextmanager
    def installed_checker_directory(self):
        """OS directory seam: selected and installed checkers share real fixture bytes.

        Normal trusted imports remain untouched; no checker validator is substituted.
        """
        opened = os.open
        root_info = ROOT.stat()
        def open_fixture(path, flags, *args, **kwargs):
            if path == 'scripts' and 'dir_fd' in kwargs:
                parent = os.fstat(kwargs['dir_fd'])
                if (parent.st_dev, parent.st_ino) == (root_info.st_dev, root_info.st_ino):
                    return opened(self.root / 'scripts', flags, *args)
            return opened(path, flags, *args, **kwargs)
        with patch('os.open', side_effect=open_fixture):
            yield

    def test_select_refuses_aggregate_decoded_material_over_eight_mib(self):
        self.file('scripts/compose-action-plan.py', b'#' * (8 * 1024 * 1024), 0o600)
        self.freeze_commit('c' * 40)
        with self.installed_checker_directory(), self.assertRaisesRegex(ValueError, 'material decoded byte limit'):
            self.select('decoded-overflow')
        self.assertFalse((self.root / 'decoded-overflow').exists())

    def test_select_encoded_material_cap_includes_final_canonical_overhead(self):
        names = ('infrastructure/contract/home-lab.yml', 'infrastructure/contract/schema.json',
                 'scripts/compose-deployment.py', 'scripts/compose-deployment-diff.py',
                 'scripts/compose-artifact.py', 'scripts/compose-model-inventory.py',
                 'scripts/compose-image-lock.py')
        other_encoded = sum(len(base64.b64encode(self.committed[name])) for name in names)
        size = ((8 * 1024 * 1024 - other_encoded) // 4) * 3
        self.assertEqual(other_encoded + len(base64.b64encode(b'#' * size)), 8 * 1024 * 1024)
        self.assertLess(size + sum(len(self.committed[name]) for name in names), 8 * 1024 * 1024)
        self.file('scripts/compose-action-plan.py', b'#' * size, 0o600)
        self.freeze_commit('c' * 40)
        with self.installed_checker_directory(), self.assertRaisesRegex(ValueError, 'material encoded byte limit'):
            self.select('encoded-overflow')
        self.assertFalse((self.root / 'encoded-overflow').exists())

    def test_select_freezes_checked_bytes_and_same_read_modes_before_output(self):
        name = 'scripts/compose-action-plan.py'
        sentinel = b"raise AssertionError('material must never execute')\n"
        self.file(name, sentinel, 0o700)
        self.freeze_commit('c' * 40)
        mkdir = os.mkdir
        changed = False
        def mutate_after_bookend(path, *args, **kwargs):
            nonlocal changed
            if path == 'frozen' and 'dir_fd' in kwargs:
                changed = True
                self.file(name, b'changed after checks\n', 0o644)
                self.file('infrastructure/contract/home-lab.yml', b'changed policy\n', 0o600)
            return mkdir(path, *args, **kwargs)
        with self.installed_checker_directory(), patch('os.mkdir', side_effect=mutate_after_bookend):
            selected = self.select('frozen')
        self.assertTrue(changed)
        path = self.root / 'frozen/execution-material.json'
        saved = path.read_bytes()
        rows = {row['path']: row for row in json.loads(saved)['members']}
        self.assertEqual(base64.b64decode(rows[name]['content_base64']), sentinel)
        self.assertEqual(rows[name]['mode'], '0700')
        contract = rows['infrastructure/contract/home-lab.yml']
        self.assertEqual(base64.b64decode(contract['content_base64']),
                         self.committed['infrastructure/contract/home-lab.yml'])
        self.assertEqual(contract['mode'], '0644')
        self.assertEqual(selected['checker_sha256'][name], hashlib.sha256(sentinel).hexdigest())
        self.file(name, b'later mutation\n', 0o755)
        self.assertEqual(path.read_bytes(), saved)

    def test_select_refuses_checker_bytes_or_modes_changed_before_bookend(self):
        original = self.git
        name = 'scripts/compose-action-plan.py'
        data = self.committed[name]
        for kind in ('bytes', 'mode'):
            changed = False
            def racing_git(root, args):
                nonlocal changed
                result = original(root, args)
                if args == ['show', 'a' * 40 + ':' + name]:
                    changed = True
                    self.file(name, data + b'\n# changed\n' if kind == 'bytes' else data,
                              0o600 if kind == 'mode' else 0o644)
                return result
            self.git = racing_git
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'source changed'):
                self.select('before-bookend-' + kind)
            self.assertTrue(changed)
            self.assertFalse((self.root / ('before-bookend-' + kind)).exists())
            self.file(name, data, 0o644)

    def test_select_missing_or_unsafe_fixed_material_refuses_without_fallback(self):
        names = ('infrastructure/contract/home-lab.yml', 'infrastructure/contract/schema.json',
                 'scripts/compose-deployment.py', 'scripts/compose-deployment-diff.py',
                 'scripts/compose-artifact.py', 'scripts/compose-action-plan.py',
                 'scripts/compose-model-inventory.py', 'scripts/compose-image-lock.py')
        for index, name in enumerate(names):
            path = self.root / name
            path.rename(self.root / ('retained-member-' + str(index)))
            with self.subTest(name=name, kind='missing'), self.assertRaises((ValueError, OSError)):
                self.select('missing-member-' + str(index))
            self.assertFalse((self.root / ('missing-member-' + str(index))).exists())
            self.file(name, self.committed[name], 0o666)
            with self.subTest(name=name, kind='mode'), self.assertRaisesRegex(ValueError, 'unsafe'):
                self.select('unsafe-member-' + str(index))
            self.assertFalse((self.root / ('unsafe-member-' + str(index))).exists())
            path.chmod(0o644)

    def test_select_sidecar_collision_and_symlink_refuse_retaining_partial_output(self):
        opened = os.open
        prior = self.file('prior-evidence', b'prior evidence must survive\n', 0o600)
        for kind in ('regular', 'symlink'):
            output = self.root / ('collision-' + kind)
            collided = False
            def collide(path, flags, *args, **kwargs):
                nonlocal collided
                if path == 'execution-material.json' and flags & os.O_CREAT:
                    collided = True
                    if kind == 'regular':
                        fd = opened(path, flags, *args, **kwargs)
                        with os.fdopen(fd, 'wb') as stream:
                            stream.write(b'prior evidence must survive\n')
                    else:
                        os.symlink(prior, path, dir_fd=kwargs['dir_fd'])
                return opened(path, flags, *args, **kwargs)
            with patch('os.open', side_effect=collide), self.assertRaises(FileExistsError):
                self.select(output.name)
            self.assertTrue(collided)
            self.assertEqual((output / 'execution-material.json').read_bytes(), prior.read_bytes())
            self.assertEqual(prior.stat().st_mode & 0o777, 0o600)
            self.assertTrue((output / 'selection.json').exists())
            with self.assertRaises(FileExistsError):
                self.select(output.name)
        linked = self.root / 'linked-output-parent'
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.select('linked-output-parent/no-output')
        self.assertFalse((self.root / 'no-output').exists())

    def test_plan_preserves_historical_selection_but_refuses_stale_self_checker(self):
        name = 'scripts/compose-deployment.py'
        self.file(name, self.committed[name] + b'\n# historical implementation identity\n')
        self.freeze_commit('c' * 40)
        with self.installed_checker_directory():
            old = self.select('old')
        self.file(name, (ROOT / name).read_bytes())
        self.freeze_commit('b' * 40)
        new = self.select('new')
        historical = {name: (self.root / 'old' / name).read_bytes()
                      for name in ('selection.json', 'contract.yml', 'execution-material.json')}
        with self.assertRaisesRegex(ValueError, 'checker identity incompatible'):
            self.plan(old, new, [], [], 'stale-self')
        self.assertFalse((self.root / 'stale-self').exists())
        for name, data in historical.items():
            self.assertEqual((self.root / 'old' / name).read_bytes(), data)

    def test_plan_ignores_absent_replaced_malicious_and_symlink_material(self):
        old = self.select('old')
        new = self.select('new')
        baseline = self.plan(old, new, [], [], 'with-material')
        for side in ('old', 'new'):
            (self.root / side / 'execution-material.json').rename(self.root / (side + '-material-retained'))
        absent = self.plan(old, new, [], [], 'absent-material')
        self.assertEqual(absent, baseline)
        for side in ('old', 'new'):
            self.file(side + '/execution-material.json',
                      b"raise AssertionError('sidecar is not an executable authority')\n", 0o600)
        self.assertEqual(self.plan(old, new, [], [], 'malicious-material'), baseline)
        for side in ('old', 'new'):
            path = self.root / side / 'execution-material.json'
            path.rename(self.root / (side + '-malicious-retained'))
            path.symlink_to(self.root / (side + '-malicious-retained'))
        self.assertEqual(self.plan(old, new, [], [], 'symlink-material'), baseline)
        for side in ('old', 'new'):
            self.file(side + '-malicious-retained', b'{"executable":true,"native_qualified":true,"approval":true}', 0o600)
        self.assertEqual(self.plan(old, new, [], [], 'forged-material'), baseline)
        self.assertFalse(baseline['executable'])
        self.assertFalse(baseline['process_adoption'])
        self.assertEqual(baseline['evidence_authority'], 'untrusted-review-input')

    def test_material_cannot_enable_loader_or_operational_commands(self):
        self.select()
        deployment = load('compose-deployment')
        for command in ('observe', 'apply', 'verify', 'recovery', 'validate-bundle', 'host-transaction', 'dispatch'):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()), \
                    patch('subprocess.Popen', side_effect=AssertionError('native effect')), \
                    patch('subprocess.run', side_effect=AssertionError('native effect')), \
                    self.assertRaises(SystemExit) as error:
                deployment.main([command, '--bundle', str(self.root / 'selection/execution-material.json')])
            self.assertEqual(error.exception.code, 2)

    def test_select_refuses_index_only_omission_of_optional_committed_directory_member(self):
        omitted = 'services/data/gluetun/a.sh'
        self.file(omitted, b'committed optional hook\n', 0o755)
        self.tracked.append(omitted)
        self.freeze_commit('c' * 40)
        self.tracked.remove(omitted)  # Index inventory differs; immutable C still contains both hooks.
        deployment = load('compose-deployment')
        queries = []
        def respond(args, kwargs):
            queries.append(args)
            return GitPipe(self.git(self.root, args))
        with self.assertRaisesRegex(ValueError, 'selected.*set|membership'):
            self.select_through_pipe(deployment, respond, 'index-omission')
        self.assertFalse((self.root / 'index-omission').exists())
        self.assertIn(['ls-files', '-z'], queries)
        self.assertFalse(any(q[0] == 'show' for q in queries))

    def test_select_refuses_index_only_added_selected_member(self):
        added = 'services/data/gluetun/index-only.sh'
        self.file(added, b'not in commit A\n', 0o755)
        self.tracked.append(added)
        deployment = load('compose-deployment')
        with self.assertRaisesRegex(ValueError, 'set|membership'):
            self.select_through_pipe(deployment, lambda args, kwargs: GitPipe(self.git(self.root, args)),
                                     'index-addition')
        self.assertFalse((self.root / 'index-addition').exists())

    def test_select_full_committed_set_and_legitimate_deletion_use_distinct_snapshots(self):
        removed = 'services/data/gluetun/a.sh'
        self.file(removed, b'committed then deleted\n', 0o755)
        self.tracked.append(removed)
        self.freeze_commit('c' * 40)
        deployment = load('compose-deployment')
        respond = lambda args, kwargs: GitPipe(self.git(self.root, args))
        old = self.select_through_pipe(deployment, respond, 'full-set')
        self.assertEqual({e['path'] for e in old['manifest']['entries']}, set(self.paths) | {removed})
        self.tracked.remove(removed)
        self.freeze_commit('b' * 40)
        new = self.select_through_pipe(deployment, respond, 'committed-deletion')
        self.assertEqual([e['path'] for e in new['manifest']['entries']], self.paths)
        self.assertEqual((old['source_commit'], new['source_commit']), ('c' * 40, 'b' * 40))
        self.assertIn(removed, self.commits['c' * 40])
        self.assertNotIn(removed, self.commits['b' * 40])
        self.assertFalse(old['executable'])
        self.assertFalse(new['executable'])

    def test_select_refuses_malformed_duplicate_and_overflow_tree_metadata(self):
        row = b'100644 blob ' + b'b' * 40 + b'\t'
        mutations = {
            'unterminated': lambda data: data[:-1],
            'empty-row': lambda data: data + b'\0',
            'duplicate': lambda data: data + data.split(b'\0')[0] + b'\0',
            'malformed': lambda data: data + b'not tree metadata\0',
            'unsafe-selected': lambda data: data + row + b'services/data/gluetun/../escape\0',
            'unsupported-selected-mode': lambda data: data.replace(b'100755 blob', b'120000 blob'),
            'inventory-overflow': lambda data: data + b''.join(
                row + ('unrelated-%04d' % n).encode() + b'\0' for n in range(4097)),
            'selected-overflow': lambda data: data + b''.join(
                row + ('services/data/gluetun/%04d.sh' % n).encode() + b'\0' for n in range(257)),
            'byte-overflow': lambda data: b'x' * (artifact.MAX_FILE_BYTES + 1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                deployment = load('compose-deployment')
                def respond(args, kwargs):
                    data = self.git(self.root, args)
                    return GitPipe(mutate(data) if args[0] == 'ls-tree' else data)
                with self.assertRaises(ValueError):
                    self.select_through_pipe(deployment, respond, 'tree-' + name)
                self.assertFalse((self.root / ('tree-' + name)).exists())

    def test_select_refuses_malformed_duplicate_and_overflow_index_metadata(self):
        for name, mutate in {
            'unterminated': lambda data: data[:-1],
            'empty-row': lambda data: data + b'\0',
            'duplicate': lambda data: data + data.split(b'\0')[0] + b'\0',
            'overflow': lambda data: data + b''.join(('unrelated-%04d' % n).encode() + b'\0'
                                                   for n in range(4097)),
        }.items():
            with self.subTest(name=name):
                deployment = load('compose-deployment')
                def respond(args, kwargs):
                    data = self.git(self.root, args)
                    return GitPipe(mutate(data) if args[0] == 'ls-files' else data)
                with self.assertRaises(ValueError):
                    self.select_through_pipe(deployment, respond, 'index-' + name)
                self.assertFalse((self.root / ('index-' + name)).exists())

    def test_select_refuses_unknown_committed_asset_even_if_index_omits_it(self):
        unknown = 'services/data/unknown.txt'
        self.file(unknown)
        self.tracked.append(unknown)
        self.freeze_commit('c' * 40)
        self.tracked.remove(unknown)
        deployment = load('compose-deployment')
        with self.assertRaisesRegex(ValueError, 'unselected'):
            self.select_through_pipe(deployment, lambda args, kwargs: GitPipe(self.git(self.root, args)),
                                     'unknown-committed')
        self.assertFalse((self.root / 'unknown-committed').exists())

    def test_select_reads_only_local_objects_and_admitted_bytes_without_filters(self):
        deployment = load('compose-deployment')
        self.tracked.append('unrelated.txt')
        self.file('unrelated.txt', b'never admit this file', 0o666)
        def respond(args, kwargs):
            self.assertNotEqual(args[0], 'diff', 'whole-worktree diff can execute conversion filters')
            for key, value in {'GIT_NO_LAZY_FETCH': '1', 'GIT_NO_REPLACE_OBJECTS': '1',
                               'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': ''}.items():
                self.assertEqual(kwargs['env'].get(key), value)
            return GitPipe(self.git(self.root, args))
        selected = self.select_through_pipe(deployment, respond, 'local-only')
        self.assertFalse(selected['executable'])
        self.assertNotIn('unrelated.txt', [e['path'] for e in selected['manifest']['entries']])

    def test_select_rejects_b_bytes_under_a_identity_despite_a_b_a_ref_bookends(self):
        deployment = load('compose-deployment')
        self.file('services/data/gluetun/gluetun_up.sh', b'committed B hook\n', 0o755)
        self.freeze_commit('b' * 40)
        self.head = 'a' * 40
        observed_refs = []
        def respond(args, kwargs):
            if args[0] == 'rev-parse':
                if len(observed_refs) == 2:
                    self.head = 'a' * 40
                observed_refs.append(self.head)
            if args[0] == 'ls-tree':
                self.head = 'b' * 40
            return GitPipe(self.git(self.root, args))
        with self.assertRaisesRegex(ValueError, 'exact committed source'):
            self.select_through_pipe(deployment, respond, 'aba')
        self.assertFalse((self.root / 'aba').exists())

    def test_select_rejects_b_modes_under_a_identity_despite_a_b_a_ref_bookends(self):
        deployment = load('compose-deployment')
        (self.root / 'services/data/gluetun/gluetun_up.sh').chmod(0o644)
        self.freeze_commit('b' * 40)
        self.head = 'a' * 40
        observed_refs = []
        def respond(args, kwargs):
            if args[0] == 'rev-parse':
                if len(observed_refs) == 2:
                    self.head = 'a' * 40
                observed_refs.append(self.head)
            if args[0] == 'ls-tree':
                self.head = 'b' * 40
            return GitPipe(self.git(self.root, args))
        with self.assertRaisesRegex(ValueError, 'committed executable mode'):
            self.select_through_pipe(deployment, respond, 'aba-modes')
        self.assertFalse((self.root / 'aba-modes').exists())

    def test_select_deadline_bounds_pipe_read_and_process_completion_and_reaps(self):
        for close_stdout in (False, True):
            with self.subTest(close_stdout=close_stdout):
                deployment = load('compose-deployment')
                process = StalledGitPipe(close_stdout)
                first_query = True
                first_clock = True
                monotonic = time.monotonic
                def clock():
                    nonlocal first_clock
                    now = monotonic()
                    if first_clock:
                        first_clock = False
                        return now - 14.95  # Spend 14.95s of the same deadline at the time seam.
                    return now
                def respond(args, kwargs):
                    nonlocal first_query
                    if first_query:
                        first_query = False
                        return process
                    return GitPipe(self.git(self.root, args))
                try:
                    with patch('time.monotonic', side_effect=clock), \
                            self.assertRaisesRegex(ValueError, 'Git query deadline'):
                        self.select_through_pipe(deployment, respond, 'stall-' + str(close_stdout))
                    self.assertTrue(process.killed)
                    self.assertTrue(process.reaped)
                    self.assertTrue(process.stdout.closed)
                    self.assertFalse(process.thread.is_alive())
                finally:
                    process.kill()
                    process.wait()
                    process.stdout.close()

    def test_select_git_pipe_byte_cap_is_enforced_and_reaped(self):
        deployment = load('compose-deployment')
        process = GitPipe(b'x' * (artifact.MAX_FILE_BYTES + 1))
        try:
            with self.assertRaisesRegex(ValueError, 'Git output byte limit'):
                self.select_through_pipe(deployment, lambda args, kwargs: process, 'overflow')
            self.assertTrue(process.stdout.closed)
        finally:
            process.stdout.close()
            process.wait()
        self.assertFalse(process.thread.is_alive())

    def test_select_missing_local_object_fails_offline(self):
        deployment = load('compose-deployment')
        def respond(args, kwargs):
            return GitPipe(b'', 1) if args[0] == 'show' else GitPipe(self.git(self.root, args))
        with self.assertRaisesRegex(ValueError, 'Git query failed'):
            self.select_through_pipe(deployment, respond, 'missing-local')
        self.assertFalse((self.root / 'missing-local').exists())

    def test_select_packages_only_declared_tracked_assets_preserving_legacy_hash_and_modes(self):
        self.file('services/data/gluetun/runtime.db', b'not tracked')
        selected = self.select()
        names = [e['path'] for e in selected['manifest']['entries']]
        self.assertEqual(names, self.paths)
        self.assertFalse(selected['executable'])
        self.assertEqual(selected['source_commit'], 'a' * 40)
        self.assertEqual(selected['manifest']['legacy_sha256'], artifact.artifact_hash(self.root, self.paths))
        copied = self.root / 'selection' / 'artifact'
        self.assertEqual(artifact.artifact_hash(copied, self.paths), selected['manifest']['legacy_sha256'])
        self.assertEqual((copied / 'services/data/gluetun/gluetun_up.sh').stat().st_mode & 0o777, 0o755)
        self.assertEqual((copied / 'secrets/production.sops.env').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.select()

    def plan(self, old, new, old_rows, new_rows, output='plan'):
        evidence = {'format': 'compose-consumer-review-v1',
                    'old_manifest_sha256': old['manifest']['sha256'],
                    'new_manifest_sha256': new['manifest']['sha256'],
                    'old': old_rows, 'new': new_rows}
        self.file(output + '-consumers.json', json.dumps(evidence).encode(), 0o600)
        deployment = load('compose-deployment')
        with patch('subprocess.Popen', side_effect=AssertionError('plan invoked external command')), \
                patch('subprocess.run', side_effect=AssertionError('plan invoked external command')), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            deployment.main(['plan', '--previous', str(self.root / 'old/selection.json'),
                             '--selection', str(self.root / 'new/selection.json'),
                             '--consumers', str(self.root / (output + '-consumers.json')),
                             '--output', str(self.root / output)])
        self.assertNotIn('example', stdout.getvalue())
        return json.loads((self.root / output / 'plan.json').read_bytes())

    def offline_fixture(self):
        old = self.select('old')
        new = self.select('new')
        self.offline_selections = (old, new)
        tool = {'name': 'compose', 'version': 'synthetic-1', 'binary_sha256': 'e' * 64}
        def generation(name, declarations, ids):
            model = {'project': 'fixture', 'services': declarations}
            return {'generation': name, 'manifest': old['manifest'],
                    'environment': {'generation': name + '-env', 'protected_sha256': 'f' * 64},
                    'model': model, 'model_sha256': self.digest(model),
                    'images': [{'service': service, 'declaration': reference, 'reference': reference,
                                'image_id': 'sha256:' + ids[service] * 64, 'platform': 'linux/amd64',
                                'repo_digests': [reference.split(':')[0] + '@sha256:' + ids[service] * 64],
                                'available': True, 'retained': None}
                               for service, reference in declarations.items()], 'override': {}}
        current = generation('current-1', {'app': 'registry/app:v1', 'peer': 'registry/peer:v1'},
                             {'app': '1', 'peer': '2'})
        candidate = generation('candidate-2', {'app': 'registry/app:v1', 'peer': 'registry/peer:v1'},
                               {'app': '1', 'peer': '2'})
        previous = generation('previous-0', {'archived': 'registry/archive:v0'}, {'archived': '9'})
        containers = []
        for service, cid, iid, running, pid in [('app', 'a', '1', True, 123), ('peer', 'b', '2', False, 0)]:
            containers.append({'id': cid * 64, 'name': 'exact_' + service + '.1', 'project': 'fixture',
                'service': service, 'image_id': 'sha256:' + iid * 64, 'image_reference': 'registry/' + service + ':v1',
                'state': 'running' if running else 'stopped', 'pid': pid,
                'started_at': '2026-01-01T00:00:00Z', 'restart_count': 2,
                'config_sha256': 'c' * 64, 'host_config_sha256': 'd' * 64,
                'mounts': [{'type': 'volume', 'source': 'actual-volume', 'target': '/data',
                            'resource_id': 'volume-identity', 'read_only': False}],
                'networks': [{'resource_id': '3' * 64, 'endpoint_id': cid * 64}]})
        runtime = {'generation_sha256': self.digest(current), 'tool_sha256': self.digest(tool),
                   'project': 'fixture', 'complete': True, 'container_ids': ['a' * 64, 'b' * 64],
                   'resource_ids': ['3' * 64, 'volume-identity'], 'containers': containers,
                   'resources': [{'kind': 'network', 'name': 'actual-network', 'id': '3' * 64},
                                 {'kind': 'volume', 'name': 'actual-volume', 'id': 'volume-identity'}]}
        return {'format': 'compose-offline-evidence-v1', 'project': 'fixture', 'tool': tool,
                'generations': {'current': current, 'candidate': candidate, 'previous': previous},
                'runtime': runtime, 'transition': None,
                'actions': {'generation_sha256': self.digest(candidate), 'tool_sha256': self.digest(tool),
                    'runtime_sha256': self.digest(runtime), 'grammar': 'synthetic-progress-v1',
                    'exit_code': 0, 'truncated': False, 'stdout': '', 'stderr': '',
                    'requested_roots': ['app'], 'mappings': [
                        {'kind': 'Container', 'name': 'exact_app.1', 'id': 'a' * 64, 'service': 'app'},
                        {'kind': 'Container', 'name': 'exact_peer.1', 'id': 'b' * 64, 'service': 'peer'},
                        {'kind': 'Network', 'name': 'actual-network', 'id': '3' * 64, 'service': None},
                        {'kind': 'Volume', 'name': 'actual-volume', 'id': 'volume-identity', 'service': None}]}}

    @staticmethod
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def offline_plan(self, value, output='offline', raw_evidence=None):
        old, new = self.offline_selections
        consumers = {'format': 'compose-consumer-review-v1',
                     'old_manifest_sha256': old['manifest']['sha256'],
                     'new_manifest_sha256': new['manifest']['sha256'], 'old': [], 'new': []}
        raw = json.dumps(consumers).encode()
        self.file(output + '-consumers.json', raw, 0o600)
        if 'bindings' not in value:
            value['bindings'] = {
                'previous_selection_sha256': hashlib.sha256((self.root / 'old/selection.json').read_bytes()).hexdigest(),
                'selection_sha256': hashlib.sha256((self.root / 'new/selection.json').read_bytes()).hexdigest(),
                'consumer_review_sha256': hashlib.sha256(raw).hexdigest(),
                'old_source_commit': old['source_commit'], 'new_source_commit': new['source_commit'],
                'old_manifest_sha256': old['manifest']['sha256'], 'new_manifest_sha256': new['manifest']['sha256'],
                'old_artifact_sha256': old['manifest']['legacy_sha256'], 'new_artifact_sha256': new['manifest']['legacy_sha256'],
                'old_contract_sha256': old['contract_sha256'], 'new_contract_sha256': new['contract_sha256']}
        self.file(output + '-evidence.json', json.dumps(value).encode() if raw_evidence is None else raw_evidence, 0o600)
        deployment = load('compose-deployment')
        with patch('subprocess.Popen', side_effect=AssertionError('offline review reached a process')), \
                patch('subprocess.run', side_effect=AssertionError('offline review reached a process')), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            deployment.main(['plan', '--previous', str(self.root / 'old/selection.json'),
                '--selection', str(self.root / 'new/selection.json'),
                '--consumers', str(self.root / (output + '-consumers.json')),
                '--evidence', str(self.root / (output + '-evidence.json')), '--output', str(self.root / output)])
        self.assertNotIn('SECRET', stdout.getvalue())
        return json.loads((self.root / output / 'plan.json').read_bytes())

    def test_offline_actions_keep_recreating_resources_and_induced_stopped_peer(self):
        value = self.offline_fixture()
        value['actions']['stdout'] = ('Container exact_app.1 Recreating\nContainer exact_app.1 Recreated\n'
            'Container exact_peer.1 Starting\nNetwork actual-network Created\nVolume actual-volume Created\n')
        report = self.offline_plan(value)
        review = report['offline_evidence']['actions']
        self.assertEqual([(r['kind'], r['action']) for r in review['records']],
                         [('Container', 'Recreate'), ('Container', 'Start'), ('Network', 'Create'), ('Volume', 'Create')])
        self.assertEqual(review['requested_roots'], ['app'])
        self.assertEqual(review['affected_services'], ['app', 'peer'])
        self.assertFalse(review['native_qualified'])
        self.assertFalse(report['executable'])
        self.assertFalse(report['process_adoption'])

    def test_offline_runtime_refuses_bogus_image_resource_before_output(self):
        value = self.offline_fixture()
        value['runtime']['resources'].append(
            {'kind': 'image', 'name': 'registry/app:v1', 'id': 'bogus-image-id'})
        value['runtime']['resource_ids'].append('bogus-image-id')
        self.rebind_offline(value)
        with self.assertRaisesRegex(ValueError, 'runtime resource'):
            self.offline_plan(value)
        self.assertFalse((self.root / 'offline').exists())

    def test_offline_runtime_refuses_generation_matching_image_resource_before_output(self):
        value = self.offline_fixture()
        value['runtime']['resources'].append(
            {'kind': 'image', 'name': 'registry/app:v1', 'id': 'sha256:' + '1' * 64})
        value['runtime']['resource_ids'].append('sha256:' + '1' * 64)
        self.rebind_offline(value)
        with self.assertRaisesRegex(ValueError, 'runtime resource'):
            self.offline_plan(value)
        self.assertFalse((self.root / 'offline').exists())

    def test_offline_runtime_keeps_full_stopped_process_mount_and_resource_identities(self):
        value = self.offline_fixture()
        report = self.offline_plan(value)
        runtime = report['offline_evidence']['runtime']
        self.assertEqual(runtime['containers'], value['runtime']['containers'])
        self.assertEqual(runtime['containers'][1]['id'], 'b' * 64)
        self.assertEqual(runtime['containers'][1]['state'], 'stopped')
        self.assertEqual(runtime['containers'][1]['pid'], 0)
        self.assertEqual(runtime['resources'], value['runtime']['resources'])
        self.assertEqual(runtime['containers'][0]['mounts'][0]['resource_id'], 'volume-identity')
        self.assertEqual(runtime['containers'][0]['networks'][0]['resource_id'], '3' * 64)
        self.assertFalse(report['offline_evidence']['native_qualified'])

    def rebind_offline(self, value):
        for generation in value['generations'].values():
            generation['model_sha256'] = self.digest(generation['model'])
        value['runtime']['generation_sha256'] = self.digest(value['generations']['current'])
        value['runtime']['tool_sha256'] = self.digest(value['tool'])
        value['actions']['generation_sha256'] = self.digest(value['generations']['candidate'])
        value['actions']['runtime_sha256'] = self.digest(value['runtime'])
        value['actions']['tool_sha256'] = self.digest(value['tool'])

    def test_offline_subset_hold_exposes_masked_update_and_independent_previous(self):
        value = self.offline_fixture()
        held = {'app': {'declaration': 'registry/app:v1', 'reference': 'registry/app:v1', 'image_id': 'sha256:' + '1' * 64}}
        value['generations']['current']['override'] = json.loads(json.dumps(held))
        value['generations']['candidate']['override'] = json.loads(json.dumps(held))
        value['generations']['candidate']['model']['services']['app'] = 'registry/app:v2'
        value['generations']['candidate']['images'][0]['declaration'] = 'registry/app:v2'
        self.rebind_offline(value)
        report = self.offline_plan(value)
        review = report['offline_evidence']['images']
        self.assertIn('hold-masks-declaration-change:app', review['blockers'])
        self.assertEqual(review['generations']['current']['override'], held)
        self.assertEqual(review['generations']['candidate']['override'], held)
        self.assertEqual(review['generations']['previous']['model']['services'], {'archived': 'registry/archive:v0'})
        self.assertEqual(review['generations']['previous']['images'][0]['image_id'], 'sha256:' + '9' * 64)
        change = review['changes'][0]
        self.assertTrue(change['declaration_changed'])
        self.assertFalse(change['effective_id_changed'])
        self.assertFalse(report['executable'])

    def test_offline_exact_subset_transition_preserves_unrelated_hold(self):
        value = self.offline_fixture()
        current, candidate = value['generations']['current'], value['generations']['candidate']
        current['override'] = {r['service']: {k: r[k] for k in ('declaration', 'reference', 'image_id')}
                               for r in current['images']}
        candidate['override'] = json.loads(json.dumps(current['override']))
        candidate['model']['services']['app'] = 'registry/app:v2'
        candidate['images'][0].update(declaration='registry/app:v2', reference='registry/app:v2',
                                      image_id='sha256:' + '4' * 64,
                                      repo_digests=['registry/app@sha256:' + '4' * 64])
        candidate['override']['app'] = {'declaration': 'registry/app:v2', 'reference': 'registry/app:v2',
                                         'image_id': 'sha256:' + '4' * 64}
        value['transition'] = {'status': 'proposed', 'old_override': current['override'],
                               'new_override': candidate['override'], 'services': [
                                   {'service': 'app', 'old': current['override']['app'], 'new': candidate['override']['app']}]}
        self.rebind_offline(value)
        report = self.offline_plan(value)
        review = report['offline_evidence']['images']
        self.assertEqual(review['transition'], value['transition'])
        self.assertEqual(review['generations']['candidate']['override']['peer'],
                         {'declaration': 'registry/peer:v1', 'reference': 'registry/peer:v1', 'image_id': 'sha256:' + '2' * 64})
        self.assertEqual([c['service'] for c in review['changes']], ['app'])
        self.assertIn('subset-transition-proposed-not-approved', review['blockers'])
        self.assertFalse(review['recovery_certified'])
        self.assertFalse(review['data_reversible'])
        self.assertFalse(report['executable'])

    def test_offline_action_mapping_cannot_alias_a_different_actual_container(self):
        value = self.offline_fixture()
        value['actions']['mappings'][0]['id'] = 'f' * 64
        value['actions']['stdout'] = 'Container exact_app.1 Recreating\n'
        with self.assertRaisesRegex(ValueError, 'mapping.*runtime|runtime.*mapping'):
            self.offline_plan(value)
        self.assertFalse((self.root / 'offline').exists())

    def test_plan_refuses_stale_new_helper_checker_identity_before_any_process(self):
        value = self.offline_fixture()
        new = self.offline_selections[1]
        new['checker_sha256']['scripts/compose-model-inventory.py'] = '0' * 64
        self.file('new/selection.json', json.dumps(new).encode(), 0o600)
        with self.assertRaisesRegex(ValueError, 'checker'):
            self.offline_plan(value)
        self.assertFalse((self.root / 'offline').exists())

    def test_offline_unknown_failed_truncated_and_empty_actions_never_qualify_native_noop(self):
        base = self.offline_fixture()
        cases = [({}, 'native-grammar-unqualified'),
                 ({'stdout': 'SECRET arbitrary native config/error\n'}, 'unknown-action-output'),
                 ({'stdout': '\n'}, 'unknown-action-output'),
                 ({'stdout': 'Container unmapped.2 Recreating\n'}, 'unmapped-or-unknown-action'),
                 ({'stdout': 'Volume actual-volume Exploding\n'}, 'unmapped-or-unknown-action'),
                 ({'exit_code': 1, 'stderr': 'SECRET'}, 'failed-truncated-or-error-action-output'),
                 ({'truncated': True}, 'failed-truncated-or-error-action-output'),
                 ({'grammar': 'installed-version-claim'}, 'unknown-action-grammar')]
        for index, (change, blocker) in enumerate(cases):
            with self.subTest(index=index):
                value = json.loads(json.dumps(base)); value['actions'].update(change)
                report = self.offline_plan(value, 'unqualified-' + str(index))
                self.assertIn(blocker, report['blockers'])
                self.assertEqual(report['status'], 'blocked')
                self.assertFalse(report['offline_evidence']['actions']['native_noop'])
                self.assertFalse(report['executable'])
                self.assertFalse(report['process_adoption'])
                self.assertNotIn('SECRET', json.dumps(report))
                self.assertNotIn('stdout', report['offline_evidence']['actions'])
                self.assertNotIn('stderr', report['offline_evidence']['actions'])

    def test_offline_all_container_image_and_preparation_effects_survive_review(self):
        value = self.offline_fixture()
        value['actions']['mappings'].extend([
            {'kind': 'Image', 'name': 'registry/app:v1', 'id': 'sha256:' + '1' * 64, 'service': None},
            {'kind': 'Preparation', 'name': 'saved-preparation', 'id': 'preparation-1', 'service': None}])
        value['actions']['stdout'] = ('Container exact_app.1 Creating\nContainer exact_app.1 Created\n'
            'Container exact_app.1 Recreating\nContainer exact_app.1 Starting\nContainer exact_app.1 Stopping\n'
            'Container exact_app.1 Removing\nNetwork actual-network Removing\nVolume actual-volume Removing\n'
            'Image registry/app:v1 Pulling\nImage registry/app:v1 Building\nImage registry/app:v1 Retagging\n'
            'Image registry/app:v1 Removing\nPreparation saved-preparation Preparing\n')
        report = self.offline_plan(value)
        rows = report['offline_evidence']['actions']['records']
        self.assertEqual([(r['kind'], r['action']) for r in rows], [
            ('Container', 'Create'), ('Container', 'Recreate'), ('Container', 'Remove'), ('Container', 'Start'),
            ('Container', 'Stop'), ('Image', 'Build'), ('Image', 'Pull'), ('Image', 'Remove'), ('Image', 'Retag'),
            ('Network', 'Remove'), ('Preparation', 'Prepare'), ('Volume', 'Remove')])
        self.assertIn('resource-or-preparation-effects-require-review', report['blockers'])
        self.assertFalse(report['executable'])

    def test_offline_duplicate_stopped_missing_and_aliased_runtime_identities_refuse(self):
        base = self.offline_fixture()
        def duplicate_service(v):
            v['runtime']['containers'][1]['service'] = 'app'
        def duplicate_id(v):
            v['runtime']['containers'][1]['id'] = 'a' * 64
        def duplicate_name(v):
            v['runtime']['containers'][1]['name'] = 'exact_app.1'
        def omit_stopped(v):
            v['runtime']['containers'].pop()
        def omit_stopped_and_id(v):
            v['runtime']['containers'].pop(); v['runtime']['container_ids'].pop()
        def duplicate_resource(v):
            v['runtime']['resources'].append(v['runtime']['resources'][0])
        def missing_resource(v):
            v['runtime']['resources'].pop()
        def wrong_mount(v):
            v['runtime']['containers'][0]['mounts'][0]['resource_id'] = 'unassociated'
        def wrong_network(v):
            v['runtime']['containers'][0]['networks'][0]['resource_id'] = '4' * 64
        cases = [duplicate_service, duplicate_id, duplicate_name, omit_stopped, omit_stopped_and_id,
                 duplicate_resource, missing_resource, wrong_mount, wrong_network,
                 lambda v: v['runtime'].update(complete=False),
                 lambda v: v['runtime']['containers'][0].update(id='a' * 12),
                 lambda v: v['runtime']['containers'][0].update(pid=0),
                 lambda v: v['runtime']['containers'][1].update(pid=123),
                 lambda v: v['runtime']['containers'][0].update(project='wrong'),
                 lambda v: v['runtime']['containers'][0].update(config_sha256='truncated'),
                 lambda v: v['runtime']['containers'][0].update(environment='SECRET'),
                 lambda v: v['runtime']['containers'][0].update(image_id='sha256:' + '5' * 64)]
        for index, mutate in enumerate(cases):
            with self.subTest(index=index):
                value = json.loads(json.dumps(base)); mutate(value); self.rebind_offline(value)
                with self.assertRaises(ValueError) as error:
                    self.offline_plan(value, 'invalid-runtime-' + str(index))
                self.assertNotIn('SECRET', str(error.exception))
                self.assertFalse((self.root / ('invalid-runtime-' + str(index))).exists())

    def test_offline_previous_requires_own_manifest_model_environment_images_and_subset(self):
        base = self.offline_fixture()
        cases = [lambda p, c: p.update(images=c['images']),
                 lambda p, c: p.update(override={'app': {'declaration': 'registry/app:v1',
                     'reference': 'registry/app:v1', 'image_id': 'sha256:' + '1' * 64}}),
                 lambda p, c: p.update(environment={}),
                 lambda p, c: p.update(manifest={}),
                 lambda p, c: p['images'].clear(),
                 lambda p, c: p['images'].append(p['images'][0]),
                 lambda p, c: p['images'][0].update(declaration='registry/app:v1'),
                 lambda p, c: p.update(generation=c['generation']),
                 lambda p, c: p['model'].update(environment='SECRET')]
        for index, mutate in enumerate(cases):
            with self.subTest(index=index):
                value = json.loads(json.dumps(base))
                mutate(value['generations']['previous'], value['generations']['current']); self.rebind_offline(value)
                with self.assertRaises(ValueError):
                    self.offline_plan(value, 'invalid-previous-' + str(index))
                self.assertFalse((self.root / ('invalid-previous-' + str(index))).exists())

    def test_offline_equal_recovery_content_still_retains_independent_generations(self):
        value = self.offline_fixture()
        previous = json.loads(json.dumps(value['generations']['current']))
        previous['generation'] = 'previous-independent'
        value['generations']['previous'] = previous
        self.rebind_offline(value)
        report = self.offline_plan(value)
        review = report['offline_evidence']['images']
        self.assertEqual(review['generations']['current']['environment'], review['generations']['previous']['environment'])
        self.assertEqual(review['generations']['current']['images'], review['generations']['previous']['images'])
        self.assertNotEqual(review['generation_sha256']['current'], review['generation_sha256']['previous'])
        self.assertFalse(review['recovery_certified'])

    def test_offline_missing_images_and_local_only_aliases_do_not_reach_legacy_preparation(self):
        base = self.offline_fixture()
        for index, retained in enumerate((False, True)):
            value = json.loads(json.dumps(base))
            for side in ('current', 'candidate'):
                generation = value['generations'][side]
                for row in generation['images']:
                    row.update(repo_digests=[], image_id='sha256:' + '1' * 64, available=False)
                    if retained:
                        row['retained'] = {k: row[k] for k in ('service', 'declaration', 'reference', 'image_id')}
                        row['retained']['generation'] = generation['generation']
            value['runtime']['containers'][1]['image_id'] = 'sha256:' + '1' * 64
            self.rebind_offline(value)
            report = self.offline_plan(value, 'local-only-' + str(index))
            review = report['offline_evidence']['images']
            self.assertIn('current:image-preparation-required:app', review['blockers'])
            self.assertIn('candidate:image-preparation-required:peer', review['blockers'])
            self.assertEqual('current:local-retention-provenance-required:app' in review['blockers'], not retained)
            self.assertEqual(review['changes'], [])
            self.assertFalse(report['executable'])

    def test_offline_reference_only_change_and_moving_tag_are_not_silent_convergence(self):
        base = self.offline_fixture()
        value = json.loads(json.dumps(base)); candidate = value['generations']['candidate']
        candidate['model']['services']['app'] = 'registry/app:v2'
        candidate['images'][0].update(declaration='registry/app:v2', reference='registry/app:v2')
        self.rebind_offline(value)
        report = self.offline_plan(value, 'reference-only')
        change = report['offline_evidence']['images']['changes'][0]
        self.assertTrue(change['reference_changed']); self.assertFalse(change['effective_id_changed'])
        self.assertIn('image-transition-review-required:app', report['blockers'])
        value = json.loads(json.dumps(base)); value['generations']['candidate']['images'][0]['image_id'] = 'sha256:' + '4' * 64
        self.rebind_offline(value)
        report = self.offline_plan(value, 'moving-tag')
        self.assertIn('moving-tag-or-implicit-refresh:app', report['blockers'])
        self.assertFalse(report['offline_evidence']['images']['changes'][0]['declaration_changed'])

    def test_offline_bound_sections_cannot_be_replaced_with_independent_hex_claims(self):
        base = self.offline_fixture()
        cases = [lambda v: v['runtime'].update(generation_sha256='0' * 64),
                 lambda v: v['runtime'].update(tool_sha256='0' * 64),
                 lambda v: v['actions'].update(generation_sha256='0' * 64),
                 lambda v: v['actions'].update(runtime_sha256='0' * 64),
                 lambda v: v['actions'].update(tool_sha256='0' * 64),
                 lambda v: v['generations']['previous'].update(model_sha256='0' * 64),
                 lambda v: v.update(bindings={}),
                 lambda v: v['generations']['candidate']['manifest'].update(sha256='0' * 64),
                 lambda v: v['tool'].update(native_qualified=True),
                 lambda v: v['generations']['previous']['images'][0].update(retained={'sha256': '0' * 64})]
        for index, mutate in enumerate(cases):
            with self.subTest(index=index):
                value = json.loads(json.dumps(base)); mutate(value)
                with self.assertRaises(ValueError):
                    self.offline_plan(value, 'invalid-binding-' + str(index))
                self.assertFalse((self.root / ('invalid-binding-' + str(index))).exists())

    def test_offline_malformed_duplicate_unknown_and_overflow_action_fields_refuse(self):
        base = self.offline_fixture()
        cases = [lambda a: a['mappings'].append(a['mappings'][0]),
                 lambda a: a['requested_roots'].append('app'),
                 lambda a: a['requested_roots'].append('unobserved'),
                 lambda a: a.update(stdout='x' * 65537),
                 lambda a: a.update(stdout='\n' * 2049),
                 lambda a: a.update(mappings=[a['mappings'][0]] * 1025),
                 lambda a: a.update(exit_code=True),
                 lambda a: a.update(truncated='false'),
                 lambda a: a.update(environment='SECRET'),
                 lambda a: a['mappings'][0].update(service='unobserved'),
                 lambda a: a['mappings'][0].update(name='SECRET\nraw')]
        for index, mutate in enumerate(cases):
            with self.subTest(index=index):
                value = json.loads(json.dumps(base)); mutate(value['actions'])
                with self.assertRaises(ValueError) as error:
                    self.offline_plan(value, 'invalid-actions-' + str(index))
                self.assertNotIn('SECRET', str(error.exception))
                self.assertFalse((self.root / ('invalid-actions-' + str(index))).exists())

    def test_offline_json_duplicate_keys_nonfinite_depth_and_byte_limits_refuse_redacted(self):
        value = self.offline_fixture()
        for index, raw in enumerate((b'{"SECRET":1,"SECRET":2}', b'{"SECRET":NaN}', b'{"SECRET":',
                                     b'{"SECRET":' + b'[' * 1100 + b'0' + b']' * 1100 + b'}',
                                     b' ' * (1024 * 1024 + 1))):
            with self.subTest(index=index), self.assertRaises(ValueError) as error:
                self.offline_plan(value, 'bad-json-' + str(index), raw_evidence=raw)
            self.assertNotIn('SECRET', str(error.exception))
            self.assertFalse((self.root / ('bad-json-' + str(index))).exists())

    def test_offline_review_uses_frozen_evidence_buffer_and_exclusive_private_output(self):
        value = self.offline_fixture()
        mkdir = os.mkdir
        changed = False
        def replace_after_read(path, *args, **kwargs):
            nonlocal changed
            if path == 'offline' and 'dir_fd' in kwargs:
                changed = True
                self.file('offline-evidence.json', b'{"SECRET":"replacement after read"}', 0o600)
            return mkdir(path, *args, **kwargs)
        with patch('os.mkdir', side_effect=replace_after_read):
            report = self.offline_plan(value)
        self.assertTrue(changed)
        expected = hashlib.sha256(json.dumps(value).encode()).hexdigest()
        self.assertEqual(report['bindings']['offline_evidence_sha256'], expected)
        self.assertNotIn('SECRET', json.dumps(report))
        saved = (self.root / 'offline/plan.json').read_bytes()
        self.assertEqual((self.root / 'offline').stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / 'offline/plan.json').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.offline_plan(value)
        self.assertEqual((self.root / 'offline/plan.json').read_bytes(), saved)

    def test_offline_changed_subset_without_exact_proposal_is_not_ignored_or_expanded(self):
        value = self.offline_fixture()
        current = value['generations']['current']; candidate = value['generations']['candidate']
        current['override'] = {'peer': {k: current['images'][1][k] for k in ('declaration', 'reference', 'image_id')}}
        self.rebind_offline(value)
        report = self.offline_plan(value)
        self.assertIn('subset-transition-proposal-required', report['blockers'])
        self.assertEqual(report['offline_evidence']['images']['generations']['current']['override'], current['override'])
        self.assertEqual(report['offline_evidence']['images']['generations']['candidate']['override'], {})
        self.assertFalse(report['executable'])
        value['transition'] = {'status': 'proposed', 'old_override': current['override'],
                               'new_override': candidate['override'], 'services': [
                                   {'service': 'peer', 'old': current['override']['peer'], 'new': current['override']['peer']}]}
        with self.assertRaisesRegex(ValueError, 'subset transition'):
            self.offline_plan(value, 'unrelated-hold-removal')

    def test_offline_requested_roots_do_not_hide_removed_current_service_actions(self):
        value = self.offline_fixture()
        candidate = value['generations']['candidate']
        del candidate['model']['services']['peer']; candidate['images'].pop()
        value['actions']['stdout'] = 'Container exact_peer.1 Stopping\nContainer exact_peer.1 Removing\n'
        self.rebind_offline(value)
        report = self.offline_plan(value)
        actions = report['offline_evidence']['actions']
        self.assertEqual(actions['requested_roots'], ['app'])
        self.assertEqual(actions['affected_services'], ['peer'])
        self.assertEqual([r['action'] for r in actions['records']], ['Remove', 'Stop'])
        self.assertEqual(len(report['offline_evidence']['runtime']['containers']), 2)
        self.assertFalse(report['executable'])

    def test_plan_refuses_old_checker_sets_and_select_binds_each_new_helper(self):
        value = self.offline_fixture()
        old = self.offline_selections[0]
        del old['checker_sha256']['scripts/compose-image-lock.py']
        self.file('old/selection.json', json.dumps(old).encode(), 0o600)
        with self.assertRaisesRegex(ValueError, 'selection'):
            self.offline_plan(value, 'stale-selection')
        for index, name in enumerate(('compose-action-plan.py', 'compose-image-lock.py', 'compose-model-inventory.py')):
            self.file('scripts/' + name, b'other frozen implementation\n')
            self.freeze_commit(str(index + 3) * 40)
            with self.assertRaisesRegex(ValueError, 'checker'):
                self.select('other-helper-' + str(index))
            self.file('scripts/' + name, (ROOT / 'scripts' / name).read_bytes())

    def test_offline_image_action_aliases_share_only_bound_effective_image_identity(self):
        value = self.offline_fixture()
        for side in ('current', 'candidate'):
            value['generations'][side]['images'][1]['image_id'] = 'sha256:' + '1' * 64
        value['runtime']['containers'][1]['image_id'] = 'sha256:' + '1' * 64
        value['actions']['mappings'].extend([
            {'kind': 'Image', 'name': 'registry/app:v1', 'id': 'sha256:' + '1' * 64, 'service': None},
            {'kind': 'Image', 'name': 'registry/peer:v1', 'id': 'sha256:' + '1' * 64, 'service': None}])
        value['actions']['stdout'] = 'Image registry/app:v1 Retagging\nImage registry/peer:v1 Pulling\n'
        self.rebind_offline(value)
        report = self.offline_plan(value)
        self.assertEqual([(r['name'], r['id']) for r in report['offline_evidence']['actions']['records']],
                         [('registry/app:v1', 'sha256:' + '1' * 64), ('registry/peer:v1', 'sha256:' + '1' * 64)])
        self.assertEqual([r['kind'] for r in report['offline_evidence']['runtime']['resources']],
                         ['network', 'volume'])
        self.assertFalse(report['offline_evidence']['native_qualified'])
        self.assertFalse(report['offline_evidence']['actions']['native_qualified'])
        self.assertFalse(report['executable'])
        self.assertFalse(report['process_adoption'])
        value['actions']['mappings'][-1]['id'] = 'sha256:' + '4' * 64
        with self.assertRaisesRegex(ValueError, 'mapping'):
            self.offline_plan(value, 'wrong-image-map')

    def test_plan_rejects_modified_policy_with_unchanged_contract_digest(self):
        self.policy['assets'][0]['disposition'] = 'retained-only'
        raw = json.dumps({'compose_deployment': self.policy}).encode()
        self.file('infrastructure/contract/home-lab.yml', raw)
        self.freeze_commit('c' * 40)
        old = self.select('old')
        (self.root / 'services/data/gluetun/gluetun_up.sh').chmod(0o644)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        for side, selected in [('old', old), ('new', new)]:
            selected['policy']['assets'][0]['disposition'] = 'compose-bind'
            self.file(side + '/selection.json', json.dumps(selected).encode(), 0o600)
        row = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun',
               'target': '/scripts', 'access': 'read-only'}
        with self.assertRaisesRegex(ValueError, 'contract policy'):
            self.plan(old, new, [row], [row], 'tampered-policy')

    def test_plan_rejects_swapped_contract_bytes(self):
        old = self.select('old')
        new = self.select('new')
        self.file('new/contract.yml', b'compose_deployment: {}\n', 0o600)
        with self.assertRaisesRegex(ValueError, 'contract identity'):
            self.plan(old, new, [], [], 'swapped-contract')

    def test_selection_retains_exact_contract_and_plan_refuses_missing_contract(self):
        old = self.select('old')
        new = self.select('new')
        contract = self.root / 'new/contract.yml'
        self.assertTrue(contract.exists(), 'selection must retain exact contract bytes')
        self.assertEqual(contract.read_bytes(), self.committed['infrastructure/contract/home-lab.yml'])
        self.assertEqual(contract.stat().st_mode & 0o777, 0o600)
        contract.rename(self.root / 'contract-retained.yml')
        with self.assertRaises(FileNotFoundError):
            self.plan(old, new, [], [], 'missing-contract')

    def test_plan_rejects_invalid_contract_even_with_matching_digest(self):
        old = self.select('old')
        new = self.select('new')
        for index, raw in enumerate((b'compose_deployment: {}\n',
                                    b'compose_deployment: {}\ncompose_deployment: {}\n',
                                    b'compose_deployment: [\n')):
            with self.subTest(index=index):
                self.file('new/contract.yml', raw, 0o600)
                new['contract_sha256'] = hashlib.sha256(raw).hexdigest()
                self.file('new/selection.json', json.dumps(new).encode(), 0o600)
                with self.assertRaises(ValueError):
                    self.plan(old, new, [], [], 'invalid-contract-' + str(index))

    def test_plan_reports_mode_change_as_review_only_not_process_adoption(self):
        old = self.select('old')
        (self.root / 'services/data/gluetun/gluetun_up.sh').chmod(0o644)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        row = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun',
               'target': '/scripts', 'access': 'read-only'}
        report = self.plan(old, new, [row], [row])
        self.assertFalse(report['executable'])
        self.assertEqual(report['status'], 'review-only')
        self.assertEqual(report['roots_requiring_native_evidence'], ['gluetun'])
        self.assertEqual(report['deltas'][0]['changes'], ['mode-changed'])
        self.assertFalse(report['process_adoption'])
        self.assertEqual(report['evidence_authority'], 'untrusted-review-input')
        self.assertNotIn('actions', report)

    def test_plan_rejects_missing_directory_consumers_not_prefix_matches(self):
        old = self.select('old')
        (self.root / 'services/data/gluetun/gluetun_up.sh').chmod(0o644)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        row = {'service': 'unrelated', 'kind': 'directory', 'source': 'services/data/gluetun-old',
               'target': '/scripts', 'access': 'read-only'}
        report = self.plan(old, new, [row], [row])
        self.assertIn('new:missing-consumer-source:services/data/gluetun-old', report['blockers'])
        self.assertEqual(report['roots_requiring_native_evidence'], [])

    def test_select_refuses_git_executable_mode_mismatch_even_if_diff_is_empty(self):
        original = self.git
        def mode_mismatch(root, args):
            if args[0] == 'ls-tree':
                return original(root, args).replace(b'100755 blob', b'100644 blob')
            return original(root, args)
        self.git = mode_mismatch
        with self.assertRaisesRegex(ValueError, 'mode'):
            self.select()

    def test_select_refuses_same_bytes_inode_replacement_during_git_binding(self):
        original = self.git
        replaced = False
        def racing_git(root, args):
            nonlocal replaced
            if args[0] == 'show' and not replaced:
                replaced = True
                path = self.root / 'services/data/gluetun/gluetun_up.sh'
                replacement = self.file('replacement', path.read_bytes(), 0o755)
                os.replace(replacement, path)
            return original(root, args)
        self.git = racing_git
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.select()

    def test_plan_blocks_same_and_nested_targets_per_service_and_side(self):
        old = self.select('old')
        (self.root / 'services/data/gluetun/gluetun_up.sh').chmod(0o644)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        directory = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun',
                     'target': '/scripts', 'access': 'read-only'}
        hook = {**directory, 'kind': 'file', 'source': 'services/data/gluetun/gluetun_up.sh'}
        for index, (target, service, ambiguous) in enumerate((
                ('/scripts', 'gluetun', True), ('/scripts/hook.sh', 'gluetun', True),
                ('/', 'gluetun', True), ('/scripts-old/hook.sh', 'gluetun', False),
                ('/scripts', 'other', False))):
            rows = [directory, {**hook, 'target': target, 'service': service}]
            report = self.plan(old, new, rows, rows, 'targets-' + str(index))
            for side in ('old', 'new'):
                self.assertEqual(any(b.startswith(side + ':ambiguous-target:gluetun:')
                                     for b in report['blockers']), ambiguous)
            self.assertEqual(len(report['deltas'][0]['consumers']), 4)

    def test_plan_keeps_same_source_at_distinct_nonoverlapping_targets(self):
        old = self.select('old')
        (self.root / 'services/data/gluetun/gluetun_up.sh').chmod(0o644)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        row = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun',
               'target': '/scripts', 'access': 'read-only'}
        rows = [row, {**row, 'target': '/scripts-old'}]
        report = self.plan(old, new, rows, rows, 'multiple-targets')
        self.assertEqual(report['status'], 'review-only')
        self.assertEqual({(r['side'], r['target']) for r in report['deltas'][0]['consumers']},
                         {('old', '/scripts'), ('old', '/scripts-old'),
                          ('new', '/scripts'), ('new', '/scripts-old')})

    def test_plan_rejects_missing_or_noncanonical_target_identity(self):
        old = self.select('old')
        new = self.select('new')
        row = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun',
               'access': 'read-only'}
        for index, target in enumerate((None, '', 'relative', '/../etc', '/scripts/./a',
                                        '/scripts//a', '/scripts/', '/' + 'a' * 240)):
            invalid = row if target is None else {**row, 'target': target}
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'consumer|target'):
                self.plan(old, new, [], [invalid], 'invalid-target-' + str(index))

    def test_conflicting_consumer_access_is_blocked_as_ambiguous(self):
        old = self.select('old')
        (self.root / 'services/data/gluetun/gluetun_up.sh').chmod(0o644)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        row = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun', 'target': '/scripts', 'access': 'read-only'}
        report = self.plan(old, new, [row], [row, {**row, 'access': 'writable'}])
        self.assertIn('new:ambiguous-consumer:gluetun:services/data/gluetun', report['blockers'])

    def test_directory_member_deletion_keeps_retained_directory_for_adoption_not_missing_source(self):
        retained = 'services/data/gluetun/retained.sh'
        self.file(retained, b'retained hook\n', 0o755)
        self.paths.append(retained)
        self.tracked.append(retained)
        self.freeze_commit('c' * 40)
        old = self.select('old')
        removed = 'services/data/gluetun/gluetun_up.sh'
        self.paths.remove(removed)
        self.tracked.remove(removed)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        row = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun',
               'target': '/scripts', 'access': 'read-only'}
        report = self.plan(old, new, [row], [row], 'member-deletion')
        self.assertEqual(report['status'], 'review-only')
        self.assertEqual(report['roots_requiring_native_evidence'], ['gluetun'])
        self.assertEqual(report['deltas'][0]['changes'], ['removed'])
        self.assertEqual(len(report['deltas'][0]['consumers']), 2)
        self.assertNotIn('removed-source-required-by-target', report['deltas'][0]['reasons'])

    def test_deletion_of_entire_required_directory_stays_blocked(self):
        old = self.select('old')
        removed = 'services/data/gluetun/gluetun_up.sh'
        self.paths.remove(removed)
        self.tracked.remove(removed)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        row = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun',
               'target': '/scripts', 'access': 'read-only'}
        report = self.plan(old, new, [row], [row], 'directory-deletion')
        self.assertIn('new:missing-consumer-source:services/data/gluetun', report['blockers'])
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['roots_requiring_native_evidence'], ['gluetun'])

    def test_plan_keeps_old_new_nested_file_directory_config_secret_union_and_deletion_hazard(self):
        old = self.select('old')
        hook = 'services/data/gluetun/gluetun_up.sh'
        added = 'services/data/gluetun/new.sh'
        self.paths.remove(hook)
        self.tracked.remove(hook)
        self.file(added, b'new reviewed hook\n', 0o755)
        self.paths.append(added)
        self.tracked.append(added)
        self.freeze_commit('b' * 40)
        new = self.select('new')
        def row(service, kind, source):
            return {'service': service, 'kind': kind, 'source': source, 'target': '/scripts', 'access': 'read-only'}
        old_rows = [row('old-file', 'file', hook), row('old-dir', 'directory', 'services/data'),
                    row('old-config', 'config', hook)]
        new_rows = [row('new-dir', 'directory', 'services/data/gluetun'), row('new-secret', 'secret', hook)]
        report = self.plan(old, new, old_rows, new_rows)
        removed = next(d for d in report['deltas'] if d['path'] == hook)
        self.assertEqual(removed['changes'], ['removed'])
        self.assertEqual({r['service'] for r in removed['consumers']},
                         {'old-file', 'old-dir', 'old-config', 'new-dir', 'new-secret'})
        self.assertIn('removed-source-required-by-target', removed['reasons'])
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(next(d for d in report['deltas'] if d['path'] == added)['changes'], ['added'])

    def test_no_change_is_not_native_evidence_or_process_adoption(self):
        old = self.select('old')
        new = self.select('new')
        report = self.plan(old, new, [], [])
        self.assertTrue(report['artifact_no_change'])
        self.assertFalse(report['process_adoption'])
        self.assertFalse(report['executable'])
        self.assertEqual(report['status'], 'review-only')

    def test_host_and_retained_changes_are_packaged_but_blocked_not_installed(self):
        declarations = [
            {'path': 'services/data/restic/excludes', 'kind': 'file', 'disposition': 'host-consumed',
             'host': {'consumer': 'restic', 'destination': '/etc/home-lab/restic/excludes', 'adoption': 'pending-review'}},
            {'path': 'services/data/wolf/wolf-input.conf', 'kind': 'file', 'disposition': 'host-consumed',
             'host': {'consumer': 'wolf', 'destination': '/etc/modules-load.d/wolf-input.conf', 'adoption': 'out-of-domain'}},
            {'path': 'services/data/backup-gpg-public.asc', 'kind': 'file', 'disposition': 'retained-only'}]
        self.policy['assets'].extend(declarations)
        self.file('infrastructure/contract/home-lab.yml', json.dumps({'compose_deployment': self.policy}).encode())
        for entry in declarations:
            self.file(entry['path'])
            self.paths.append(entry['path'])
            self.tracked.append(entry['path'])
        self.freeze_commit('c' * 40)
        old = self.select('old')
        for entry in declarations:
            self.file(entry['path'], b'changed\n')
        self.freeze_commit('b' * 40)
        new = self.select('new')
        report = self.plan(old, new, [], [])
        self.assertEqual(report['status'], 'blocked')
        self.assertIn('services/data/restic/excludes:host-consumer-pending-review', report['blockers'])
        self.assertIn('services/data/wolf/wolf-input.conf:host-consumer-out-of-domain', report['blockers'])
        self.assertIn('services/data/backup-gpg-public.asc:retained-only-change-requires-disposition', report['blockers'])
        self.assertNotIn('actions', report)

    def test_plan_rejects_unexpected_missing_symlink_and_changed_artifact_entries(self):
        old = self.select('old')
        new = self.select('new')
        tree = self.root / 'new/artifact'
        self.file('new/artifact/unexpected.txt')
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            self.plan(old, new, [], [], 'extra')
        # Retain the unexpected file outside the artifact; never clean failed attempts.
        (tree / 'unexpected.txt').rename(self.root / 'unexpected-retained.txt')
        hook = tree / 'services/data/gluetun/gluetun_up.sh'
        hook.rename(self.root / 'hook-retained.sh')
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.plan(old, new, [], [], 'missing')
        hook.symlink_to(self.root / 'hook-retained.sh')
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.plan(old, new, [], [], 'symlink')

    def test_plan_validates_manifest_and_review_evidence_fields_without_echoing_content(self):
        old = self.select('old')
        new = self.select('new')
        malformed = {'service': 'x', 'kind': 'directory', 'source': 'services/data/gluetun',
                     'target': '/scripts', 'access': 'read-only', 'environment': 'SECRET MUST NOT APPEAR'}
        with self.assertRaisesRegex(ValueError, 'invalid consumer'):
            self.plan(old, new, [], [malformed], 'bad-row')
        new['manifest']['entries'][0]['mode'] = '0777'
        self.file('new/selection.json', json.dumps(new).encode(), 0o600)
        with self.assertRaisesRegex(ValueError, 'manifest'):
            self.plan(old, new, [], [], 'bad-mode')

    def test_select_rejects_first_and_later_dot_components_in_contract_paths(self):
        for index, name in enumerate(('services/data/../x', 'services/data/./x',
                                      'services/data/a/../x', 'services/data/a/./x',
                                      'services/data/a/..', 'services/data/a/.')):
            self.policy['assets'][0]['path'] = name
            self.file('infrastructure/contract/home-lab.yml', json.dumps({'compose_deployment': self.policy}).encode())
            with self.subTest(path=name), self.assertRaisesRegex(ValueError, 'unsafe'):
                self.select('traversal-source-' + str(index))
        for index, destination in enumerate(('/../etc/x', '/./etc/x', '/etc/../x',
                                             '/etc/./x', '/etc/..', '/etc/.')):
            self.policy['assets'] = [{'path': 'services/data/example', 'kind': 'file',
                'disposition': 'host-consumed', 'host': {'consumer': 'example',
                'destination': destination, 'adoption': 'pending-review'}}]
            self.file('infrastructure/contract/home-lab.yml', json.dumps({'compose_deployment': self.policy}).encode())
            with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, 'host-consumer'):
                self.select('traversal-host-' + str(index))

    def test_select_refuses_unknown_tracked_asset_uncommitted_bytes_and_duplicate_policy(self):
        self.tracked.append('services/data/unknown.txt')
        with self.assertRaisesRegex(ValueError, 'unselected'):
            self.select('unknown')
        self.tracked.pop()
        self.file('services/data/gluetun/gluetun_up.sh', b'uncommitted', 0o755)
        with self.assertRaisesRegex(ValueError, 'committed source'):
            self.select('dirty')
        self.file('infrastructure/contract/home-lab.yml', b'compose_deployment: {}\ncompose_deployment: {}\n')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.select('duplicate')

    def test_mixed_mutable_and_unknown_consumers_stay_blocked(self):
        old = self.select('old')
        new = self.select('new')
        row = {'service': 'gluetun', 'kind': 'directory', 'source': 'services/data/gluetun', 'target': '/scripts', 'access': 'mixed-mutable'}
        report = self.plan(old, new, [row], [{**row, 'access': 'unknown'}])
        self.assertIn('old:consumer-mixed-mutable:gluetun', report['blockers'])
        self.assertIn('new:consumer-unknown:gluetun', report['blockers'])
        self.assertFalse(report['executable'])

    def test_observe_apply_verify_recovery_and_arbitrary_dispatch_are_unavailable(self):
        deployment = load('compose-deployment')
        for command in ('observe', 'apply', 'verify', 'recovery', '--task'):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()), \
                    patch('subprocess.Popen', side_effect=AssertionError('native effect')), \
                    self.assertRaises(SystemExit):
                deployment.main([command])

    def test_plan_refuses_nonprivate_implicit_directory_metadata(self):
        old = self.select('old')
        new = self.select('new')
        (self.root / 'new/artifact/services').chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'directory mode'):
            self.plan(old, new, [], [], 'wrong-directory-mode')

    def test_select_binds_the_checkers_actually_used_not_other_committed_checker_bytes(self):
        name = 'scripts/compose-deployment-diff.py'
        self.file(name, b'other committed implementation\n')
        self.freeze_commit('b' * 40)
        with self.assertRaisesRegex(ValueError, 'checker'):
            self.select('other-checker')

    def test_plan_refuses_extra_empty_directory_and_wrong_manifest_identity(self):
        old = self.select('old')
        new = self.select('new')
        extra = self.root / 'new/artifact/extra'
        extra.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            self.plan(old, new, [], [], 'extra-dir')
        extra.rename(self.root / 'extra-directory-retained')
        new['manifest']['sha256'] = '0' * 64
        self.file('new/selection.json', json.dumps(new).encode(), 0o600)
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.plan(old, new, [], [], 'bad-identity')

    def test_select_refuses_untracked_required_helper(self):
        self.tracked.remove('scripts/compose-deployment.py')
        with self.assertRaisesRegex(ValueError, 'committed source'):
            self.select('untracked-checker')


class LegacyCliTests(ArtifactCompatibilityTests):
    def test_legacy_artifact_list_hash_copy_and_no_git_hash_stay_compatible(self):
        paths = sorted(artifact.EXPLICIT_PATHS | {'services/data/hook.sh', 'services/apps.yml'})
        for name in paths:
            self.file(name, b'legacy\n', 0o755 if name.endswith('.sh') else 0o600)
        def git_run(argv, **kwargs):
            self.assertEqual(argv, artifact.GIT_PREFIX + ['ls-files', '-z'])
            return subprocess.CompletedProcess(argv, 0, b'\0'.join(p.encode() for p in paths) + b'\0')
        def cli(*args):
            with patch('sys.argv', ['compose-artifact.py', *args]), patch('subprocess.run', side_effect=git_run), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                artifact.main()
            return stdout.getvalue()
        self.assertEqual(cli('--root', str(self.root), 'list'), '\n'.join(paths) + '\n')
        source_hash = cli('--root', str(self.root), 'hash')
        copied = self.root / 'copied'
        self.assertEqual(cli('--root', str(self.root), 'copy', str(copied)), source_hash)
        self.assertEqual(cli('--root', str(copied), '--no-git', 'hash'), source_hash)
        self.assertEqual((copied / 'services/data/hook.sh').stat().st_mode & 0o777, 0o755)

    def test_legacy_diff_cli_keeps_canary_and_manual_only_results(self):
        diff = load('compose-deployment-diff')
        for name, value in {
            'desired': {'kind': 'desired', 'project_name': 'home-lab', 'services': {'app': {'image': 'new'}}},
            'runtime': {'kind': 'runtime', 'project_name': 'home-lab', 'services': {'app': {'image': 'old'}}},
            'actions': {'recreate_services': ['app'], 'forbidden_actions': []},
        }.items():
            self.file(name + '.json', json.dumps(value).encode())
        self.file('current/services/apps.yml', b'old')
        self.file('candidate/services/apps.yml', b'new')
        output = self.root / 'diff.json'
        argv = ['compose-deployment-diff.py']
        for name in ('desired', 'runtime', 'actions'):
            argv += ['--' + name, str(self.root / (name + '.json'))]
        argv += ['--candidate-root', str(self.root / 'candidate'), '--current-root', str(self.root / 'current'),
                 '--candidate-hash', 'new', '--deployed-hash', 'old', '--canary-service', 'app',
                 '--canary-path', 'services/apps.yml', '--output', str(output)]
        with patch('sys.argv', argv), patch('subprocess.run', side_effect=AssertionError('native effect')):
            diff.main()
        result = json.loads(output.read_bytes())
        self.assertTrue(result['canary_eligible'])
        self.assertFalse(result['artifact_only_eligible'])
        self.assertEqual(result['changed_paths'], ['services/apps.yml'])
        self.assertEqual(result['manual_only_paths'], [])
        self.assertEqual(result['image_services'], ['app'])


if __name__ == '__main__':
    unittest.main()
