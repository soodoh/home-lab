#!/usr/bin/env python3
"""Offline fixed snapshot protocol, collector parity and real descriptor contention."""
import ast
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'infrastructure/host-lifecycle/proxmox/controller-observer-template.py'


def load():
    module = types.ModuleType('controller_observer')
    module.__file__ = str(SOURCE)
    source = SOURCE.read_text().replace("'@CONTROLLER_SPEC@'", repr(json.dumps({'observer_sha256': hashlib.sha256(b'observer').hexdigest(), 'collector_sha256': hashlib.sha256(b'collector').hexdigest()})))
    source = source.replace("@ACTIVATOR_SHA256@", hashlib.sha256(b"activator").hexdigest())
    exec(compile(source, str(SOURCE), 'exec'), module.__dict__)
    return module


class ControllerObserverTests(unittest.TestCase):
    def test_summary_functions_preserve_retained_protected_collector_semantics(self):
        old = ast.parse((ROOT / 'nix/proxmox/private-preparer-template.py').read_text())
        new = ast.parse((ROOT / 'infrastructure/host-lifecycle/proxmox/protected-collector-template.py').read_text())
        original = {n.name: ast.dump(n, include_attributes=False) for n in old.body if isinstance(n, ast.FunctionDef)}
        retained = {n.name: ast.dump(n, include_attributes=False) for n in new.body if isinstance(n, ast.FunctionDef)}
        self.assertGreater(len(retained), 20)
        for name, body in retained.items():
            self.assertEqual(body, original[name], name)
        self.assertNotIn('prepare', retained)
        self.assertNotIn('validate_plan', retained)
        self.assertNotIn('install_manifest', retained)
        source = (ROOT / 'infrastructure/host-lifecycle/proxmox/protected-collector-template.py').read_text()
        self.assertIn("sys.argv[1:] != [\"summary\"]", source)

    def test_fixed_invocation_rejects_every_non_nonce_or_legacy_verb(self):
        module = load()
        for raw in [b'', b'a' * 64, b'a' * 63 + b'\n', b'a' * 64 + b'\nextra', b'{"command":"apply"}\n']:
            with self.subTest(raw=raw), mock.patch.object(module.os, 'geteuid', return_value=0), \
                    mock.patch.object(module.sys, 'argv', ['helper', 'observe']), \
                    mock.patch.object(module.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(raw))), \
                    mock.patch.object(module, 'observe') as observe:
                with self.assertRaises(ValueError): module.main()
                observe.assert_not_called()
        for argv in [['helper'], ['helper', 'apply'], ['helper', 'observe', 'extra']]:
            with mock.patch.object(module.os, 'geteuid', return_value=0), mock.patch.object(module.sys, 'argv', argv):
                with self.assertRaises(ValueError): module.main()

    def test_nonce_installed_producer_host_key_and_scope_are_bound(self):
        module = load()
        def content(path, *_):
            if path.name == 'proxmox-ansible-deploy-activator': return b'activator'
            if path.name == 'proxmox-observer': return b'observer'
            if path.name == 'proxmox-protected-collector': return b'collector'
            if path.name == 'ssh_host_ed25519_key.pub': return b'ssh-ed25519 ' + base64.b64encode(b'synthetic-host-key') + b' fixture\n'
            return b'controller'
        result = types.SimpleNamespace(returncode=0, stderr=b'', stdout=b'{"fixture":true}\n')
        with mock.patch.object(module, 'acquire_locks', return_value=[]), mock.patch.object(module, 'read_fixed', side_effect=content), \
                mock.patch.object(module.subprocess, 'run', return_value=result) as run:
            observed = module.observe('a' * 64)
            self.assertEqual(observed['nonce'], 'a' * 64)
            self.assertEqual(observed['producer_sha256'], hashlib.sha256(b'controller').hexdigest())
            self.assertEqual(observed['host_key'], 'SHA256:' + base64.b64encode(hashlib.sha256(b'synthetic-host-key').digest()).decode().rstrip('='))
            self.assertEqual(observed['locks'], 'snapshot-exclusive-v1')
            self.assertEqual(observed['scope'], 'audit')
            self.assertEqual(run.call_args.args[0], ['/usr/local/libexec/home-lab/proxmox-observer', 'observe'])

    def test_changed_producer_fails_before_observer_runs(self):
        module = load()
        with mock.patch.object(module, 'acquire_locks', return_value=[]), mock.patch.object(module, 'read_fixed', return_value=b'wrong'), \
                mock.patch.object(module.subprocess, 'run') as run:
            with self.assertRaises(ValueError): module.observe('a' * 64)
            run.assert_not_called()

    def test_old_installed_activator_protocol_refuses_observation(self):
        module = load()
        def content(path, *_):
            return {'proxmox-observer': b'observer', 'proxmox-protected-collector': b'collector'}.get(path.name, b'old-activator')
        with mock.patch.object(module, 'acquire_locks', return_value=[]), mock.patch.object(module, 'read_fixed', side_effect=content), mock.patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'mutex participant mismatch'): module.observe('a' * 64)
            run.assert_not_called()

    def test_real_lock_contention_interruption_and_persistent_inode(self):
        module = load()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            lock = root / 'operation.lock'
            module.LOCKS = [lock]; module.APT_LOCKS = []; module.JOURNALS = []
            original_fstat = os.fstat
            def root_info(fd):
                info = original_fstat(fd)
                return types.SimpleNamespace(**{name: (0 if name in ("st_uid", "st_gid") else getattr(info, name)) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})
            with mock.patch.object(module, 'parent_fd', side_effect=lambda p: os.open(p.parent, os.O_RDONLY)), \
                    mock.patch.object(module.os, 'fstat', side_effect=root_info), \
                    mock.patch.object(module, 'fingerprint', side_effect=lambda i: (i.st_dev, i.st_ino, i.st_mode, i.st_nlink)):
                # Read-only observation cannot provision even a missing mutex.
                with self.assertRaises(FileNotFoundError): module.acquire_locks()
                self.assertFalse(lock.exists())
                lock.touch(mode=0o600)
                # Missing later mutex releases all earlier acquired descriptors.
                missing = root / 'missing.lock'; module.LOCKS = [lock, missing]
                with self.assertRaises(FileNotFoundError): module.acquire_locks()
                self.assertFalse(missing.exists())
                probe = os.open(lock, os.O_RDWR)
                try: fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally: os.close(probe)
                module.LOCKS = [lock]
                descriptors = module.acquire_locks()
                inode = lock.stat().st_ino
                with self.assertRaises(BlockingIOError): module.acquire_locks()
                for fd in descriptors: os.close(fd)
                # Owner journal presence is never mistaken for an unlocked file.
                journal = root / 'apply.lock'; journal.write_bytes(b'failed-session')
                module.JOURNALS = [journal]
                with self.assertRaises(ValueError): module.acquire_locks()
                self.assertEqual(journal.read_bytes(), b'failed-session')
                self.assertEqual(lock.stat().st_ino, inode)
                probe = os.open(lock, os.O_RDWR)
                try: fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally: os.close(probe)
                self.assertEqual(lock.stat().st_ino, inode)
                # Symlinks cannot be converted into locks or silently removed.
                module.JOURNALS = []; module.LOCKS = [root / 'alias']; (root / 'alias').symlink_to(lock)
                with self.assertRaises(OSError): module.acquire_locks()
                self.assertTrue((root / 'alias').is_symlink())

    def test_existing_protocol_paths_remain_distinct(self):
        module = load()
        self.assertIn(Path('/var/lib/home-lab/reconciliation/operation.lock'), module.LOCKS)
        self.assertIn(Path('/var/lib/iac-ansible-production.lock'), module.JOURNALS)
        self.assertIn(Path('/var/lib/home-lab/firewall-transaction/active.json'), module.JOURNALS)
        self.assertIn(Path('/var/lib/dpkg/lock-frontend'), module.APT_LOCKS)
        self.assertEqual(len(module.LOCKS), len(set(module.LOCKS)))
        self.assertEqual(set(module.LOCKS) & set(module.JOURNALS), set())


if __name__ == '__main__': unittest.main()
