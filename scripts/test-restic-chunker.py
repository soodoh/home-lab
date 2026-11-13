#!/usr/bin/env python3
"""Native Restic/rclone qualification on disposable Linux only; no cloud credentials."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'services/data/restic/policy.json').read_text())
LIMIT = 3 * 1024 * 1024


class NativeChunkerTest(unittest.TestCase):
    def test_interrupted_upload_is_not_published_and_can_retry(self):
        with tempfile.TemporaryDirectory(prefix='chunker-interruption-') as directory:
            work = Path(directory)
            config = work / 'rclone.conf'
            config.write_text(f'[proton-backup]\ntype = alias\nremote = {work / "cloud"}\n')
            config.chmod(0o600)
            source = work / 'payload'
            source.write_bytes(os.urandom(12 * 1024 * 1024))
            remote = POLICY['repositories']['proton']['path'].removeprefix('rclone:')
            remote = remote.replace('Backups/home-lab-restic', 'Backups/interruption')
            raw = work / 'cloud/Backups/interruption'
            env = {'RCLONE_CONFIG': str(config), 'HOME': str(work), 'PATH': '/usr/bin:/bin'}
            rclone = os.environ['RCLONE']
            with source.open('rb') as stream:
                child = subprocess.Popen([rclone, 'rcat', remote + 'payload', '--bwlimit', '1MiB',
                                          '--retries', '1', '--low-level-retries', '1'],
                                         stdin=stream, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, env=env)
                try:
                    deadline = time.monotonic() + 20
                    while not any(p.is_file() and p.stat().st_size == LIMIT for p in raw.rglob('*')):
                        self.assertIsNone(child.poll(), 'upload ended before the interruption point')
                        self.assertLess(time.monotonic(), deadline, 'no completed chunk observed')
                        time.sleep(0.05)
                    child.send_signal(signal.SIGTERM)
                    self.assertNotEqual(child.wait(timeout=10), 0)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait()
            self.assertFalse((raw / 'payload').exists(), 'incomplete object was published')
            subprocess.run([rclone, 'copyto', str(source), remote + 'payload'],
                           env=env, check=True, capture_output=True, timeout=60)
            readback = subprocess.run([rclone, 'cat', remote + 'payload'],
                                      env=env, check=True, capture_output=True, timeout=60)
            self.assertEqual(readback.stdout, source.read_bytes())
            self.assertLessEqual(max(p.stat().st_size for p in raw.rglob('*') if p.is_file()), LIMIT)
            subprocess.run([rclone, 'deletefile', remote + 'payload'],
                           env=env, check=True, capture_output=True, timeout=60)
            listing = subprocess.run([rclone, 'lsf', remote], env=env, check=True,
                                     capture_output=True, text=True, timeout=60)
            self.assertEqual(listing.stdout, '')

    def test_existing_repository_copy_restore_and_corruption_refusal(self):
        with tempfile.TemporaryDirectory(prefix='restic-chunker-') as directory:
            work = Path(directory)
            srv = work / 'srv'
            srv.mkdir()
            subprocess.run(['mount', '--bind', str(srv), '/srv'], check=True)
            try:
                self.exercise(work)
            finally:
                subprocess.run(['umount', '/srv'], check=True)

    def exercise(self, work):
        binaries = work / 'bin'
        binaries.mkdir()
        for name in ('restic', 'rclone'):
            source = Path(os.environ[name.upper()]).resolve()
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                             POLICY['tools'][name]['installed_sha256'])
            shutil.copyfile(source, binaries / name)
            (binaries / name).chmod(0o755)
        password = work / 'password'
        password.write_text('synthetic-native-chunker-password\n')
        password.chmod(0o600)
        config = work / 'rclone.conf'
        config.write_text(f'[proton-backup]\ntype = alias\nremote = {work / "cloud"}\n')
        config.chmod(0o600)
        environment = {
            'PATH': f'{binaries}:/usr/local/bin:/usr/bin:/bin',
            'HOME': str(work), 'LANG': 'C.UTF-8',
            'RESTIC_PASSWORD_FILE': str(password),
            'RESTIC_FROM_PASSWORD_FILE': str(password),
            'RESTIC_CACHE_DIR': str(work / 'cache'),
            'RCLONE_CONFIG': str(config),
        }
        local = str(work / 'local')
        direct = 'rclone:proton-backup:Backups/home-lab-restic'
        overlay = POLICY['repositories']['proton']['path']
        raw = work / 'cloud/Backups/home-lab-restic'

        def call(repository, *args):
            result = subprocess.run([str(binaries / 'restic'), '--repo', repository, *args],
                                    env=environment, text=True, capture_output=True, timeout=120)
            self.assertEqual(result.returncode, 0, f'{args[0]}: {result.stderr}')
            return result

        data = Path('/srv/home-lab-state/common')
        data.mkdir(parents=True)
        first = os.urandom(12 * 1024 * 1024)
        (data / 'first').write_bytes(first)
        policy_hash = hashlib.sha256(b'synthetic-policy').hexdigest()
        artifact_hash = hashlib.sha256(b'synthetic-artifact').hexdigest()
        tags = ['--tag', 'cadence=daily', '--tag', f'policy={policy_hash}',
                '--tag', f'artifact={artifact_hash}']
        call(local, 'init')
        call(local, 'backup', str(data), *tags)
        call(direct, 'init', '--copy-chunker-params', '--from-repo', local)
        call(direct, 'copy', '--from-repo', local)
        legacy = {p.relative_to(raw): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in raw.rglob('*') if p.is_file() and 'locks' not in p.parts}
        self.assertTrue(any((raw / name).stat().st_size > LIMIT for name in legacy))
        call(overlay, 'check', '--read-data')

        second = os.urandom(12 * 1024 * 1024)
        (data / 'second').write_bytes(second)
        call(local, 'backup', str(data), *tags)
        snapshots = json.loads(call(local, 'snapshots', '--json').stdout)
        latest = max(snapshots, key=lambda row: row['time'])
        call(overlay, 'copy', '--from-repo', local, latest['id'])
        new = [p for p in raw.rglob('*') if p.is_file() and p.relative_to(raw) not in legacy]
        self.assertTrue(new)
        self.assertLessEqual(max(p.stat().st_size for p in new), LIMIT,
                             'new physical uploads must fit a single Proton block')
        self.assertTrue(any('.rclone_chunk.' in p.name for p in new))
        for name, digest in legacy.items():
            self.assertEqual(hashlib.sha256((raw / name).read_bytes()).hexdigest(), digest)
        call(overlay, 'check', '--read-data')
        copied = json.loads(call(overlay, 'snapshots', '--json').stdout)
        match = [row for row in copied if row.get('original') == latest['id']]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0]['tree'], latest['tree'])
        self.assertEqual(set(match[0]['tags']), set(latest['tags']))
        before = {p.relative_to(raw) for p in (raw / 'data').rglob('*') if p.is_file()}
        call(overlay, 'copy', '--from-repo', local, latest['id'])
        self.assertEqual(before, {p.relative_to(raw) for p in (raw / 'data').rglob('*') if p.is_file()})

        # The public recovery interface must work without the producer's cache.
        shutil.rmtree(work / 'cache')
        parent = Path('/srv/home-lab-recovery')
        parent.mkdir(mode=0o700)
        target = parent / 'restic-chunker'
        target.mkdir(mode=0o700)
        recovery = {**environment,
                    'RECOVERY_TARGET': str(target),
                    'RECOVERY_RESTIC_REPOSITORY': overlay,
                    'RECOVERY_RESTIC_PASSWORD_FILE': str(password),
                    'RECOVERY_EXPECTED_RESTIC_REPOSITORY_ID': json.loads(call(overlay, 'cat', 'config').stdout)['id'],
                    'RECOVERY_EXPECTED_POLICY_SHA256': policy_hash,
                    'RECOVERY_EXPECTED_COMPOSE_ARTIFACT_SHA256': artifact_hash,
                    'RECOVERY_EXPECTED_RESTIC_SHA256': POLICY['tools']['restic']['installed_sha256'],
                    'RECOVERY_EXPECTED_RCLONE_SHA256': POLICY['tools']['rclone']['installed_sha256']}
        result = subprocess.run([str(ROOT / 'scripts/restore-critical-backup'),
                                 '--restic-snapshot-id', match[0]['id'], '--all', '--confirmed-empty-target'],
                                env=recovery, text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target / 'srv/home-lab-state/common/first').read_bytes(), first)
        self.assertEqual((target / 'srv/home-lab-state/common/second').read_bytes(), second)

        # Missing chunks must fail closed rather than disappear from listings.
        piece = next(p for p in new if '.rclone_chunk.' in p.name and '/data/' in str(p))
        held = piece.read_bytes()
        piece.unlink()
        damaged = subprocess.run([str(binaries / 'rclone'), 'lsf', overlay.removeprefix('rclone:'),
                                  '--recursive', '--retries', '1', '--low-level-retries', '1'],
                                 env=environment, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(damaged.returncode, 0, 'missing chunks were silently skipped')
        self.assertIn('chunk', damaged.stderr.lower())
        piece.write_bytes(held)
        call(overlay, 'check', '--read-data')
        # Native retention removes composite objects through the same overlay.
        call(overlay, 'forget', '--keep-last', '1', '--prune')
        call(overlay, 'check', '--read-data')
        self.assertEqual(len(json.loads(call(overlay, 'snapshots', '--json').stdout)), 1)


if __name__ == '__main__':
    if (sys.platform != 'linux' or os.geteuid() != 0
            or os.environ.get('RESTIC_CHUNKER_TEST_DISPOSABLE') != 'true'
            or Path('/etc/home-lab').exists()):
        raise SystemExit('Run only on explicitly disposable root Linux, never a managed host.')
    if len(sys.argv) == 1:
        raise SystemExit(subprocess.run(['unshare', '--mount', '--fork', '--propagation', 'private',
                                        sys.executable, __file__, os.readlink('/proc/self/ns/mnt')]).returncode)
    if len(sys.argv) != 2 or sys.argv[1] == os.readlink('/proc/self/ns/mnt'):
        raise SystemExit('Private mount namespace required.')
    sys.argv = sys.argv[:1]
    unittest.main()
