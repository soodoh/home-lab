#!/usr/bin/env python3
"""Confined Linux/root descriptor, reboot-owner and installer failure fixtures.

Every native command is replaced before a transaction runs. Chroots contain only
synthetic files, never a host, workload, disk, repository state or credential.
"""
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
OBSERVER = ROOT / 'infrastructure/host-lifecycle/proxmox/controller-observer-template.py'
ACTIVATOR = ROOT / 'infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator'
INSTALLER = ROOT / 'infrastructure/proxmox-access/host/proxmox-controller-capability-transaction.py'


def module(source, name):
    result = types.ModuleType(name); result.__file__ = '/synthetic/' + name
    exec(compile(source, name, 'exec'), result.__dict__)
    return result


observer_source = OBSERVER.read_text().replace("'@CONTROLLER_SPEC@'", repr('{}'))
activator_source = ACTIVATOR.read_text().split('\ntry:\n    main()')[0]
installer_source = INSTALLER.read_text()
# Import all stdlib dependencies before entering an empty chroot.
module(observer_source, "preload_observer")
module(activator_source, "preload_activator")
module(installer_source, "preload_installer")


def seed(path, raw=b'', mode=0o600):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw); path.chmod(mode)
    return path


def available(path):
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def locked(path):
    try:
        available(path)
    except BlockingIOError:
        return True
    return False


def confined(function):
    """Run a full native fixture in a child chroot, never changing parent root."""
    def run(self):
        if sys.platform != 'linux' or os.geteuid() != 0:
            self.skipTest('native fixture requires disposable Linux/root')
        with tempfile.TemporaryDirectory(prefix='pve-fixture-') as root:
            pid = os.fork()
            if pid == 0:
                try:
                    os.chroot(root); os.chdir('/'); os.chmod('/', 0o755)
                    function(self)
                except BaseException:
                    import traceback
                    traceback.print_exc(); os._exit(1)
                os._exit(0)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0)
    return run


def descriptor_set():
    # Empty chroots have no /proc mount. Probe without opening/closing lock files.
    result = set()
    for fd in range(1024):
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
            result.add(fd)
        except OSError:
            pass
    return result


def terminated(function):
    pid = os.fork()
    if pid == 0:
        function()
        os._exit(1)  # The selected real syscall boundary must terminate the child.
    if os.waitpid(pid, 0)[1] != 73 << 8:
        raise AssertionError('child did not terminate at the selected boundary')


class NativeProtocolTests(unittest.TestCase):
    def setup_protocol(self):
        observer = module(observer_source, 'observer')
        for path in observer.LOCKS + observer.APT_LOCKS:
            seed(path)
        Path('/run/lock').chmod(0o1777)
        Path('/var/lib/home-lab/reconciliation').chmod(0o700)
        return observer

    @confined
    def test_preexisting_sticky_mutex_contention_and_partial_cleanup(self):
        observer = self.setup_protocol()
        before = {p: (p.stat().st_ino, p.read_bytes()) for p in observer.LOCKS + observer.APT_LOCKS}
        held = observer.acquire_locks()
        self.assertTrue(all(locked(p) for p in observer.LOCKS + observer.APT_LOCKS))
        with self.assertRaises(BlockingIOError): observer.acquire_locks()
        for fd in held: os.close(fd)
        # Contention after many acquisitions must release all earlier fds.
        fd = os.open(observer.LOCKS[-1], os.O_RDWR); fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            with self.assertRaises(BlockingIOError): observer.acquire_locks()
            for path in observer.LOCKS[:-1]: available(path)
        finally: os.close(fd)
        self.assertEqual(before, {p: (p.stat().st_ino, p.read_bytes()) for p in before})
        victim = observer.APT_LOCKS[-1]; victim.unlink()
        with self.assertRaises(FileNotFoundError): observer.acquire_locks()
        self.assertFalse(victim.exists())
        for path in observer.LOCKS: available(path)

    @confined
    def test_native_apt_posix_record_lock_exclusion_and_partial_cleanup(self):
        observer = self.setup_protocol()
        for victim in observer.APT_LOCKS:
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(ready_read); os.close(release_write)
                fd = os.open(victim, os.O_RDWR)
                # lockf uses POSIX F_SETLK whole-file write locking, compatible
                # with apt/dpkg; Linux flock alone does not conflict with it.
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.write(ready_write, b'1'); os.close(ready_write)
                os.read(release_read, 1); os.close(fd); os._exit(0)
            os.close(ready_write); os.close(release_read)
            try:
                self.assertEqual(os.read(ready_read, 1), b'1')
                available(victim)  # Prove a flock-only observer would miss it.
                with self.assertRaises(BlockingIOError): observer.acquire_locks()
                for path in observer.LOCKS: available(path)
                # Do not open/close APT files in this parent before the probe:
                # that would release leaked process-owned POSIX locks itself.
                # Probe earlier record locks from another process: record locks
                # are process-owned, so same-process reacquisition is not proof.
                probe = os.fork()
                if probe == 0:
                    try:
                        for path in observer.APT_LOCKS:
                            if path == victim: break
                            fd = os.open(path, os.O_RDWR)
                            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); os.close(fd)
                    except OSError:
                        os._exit(1)
                    os._exit(0)
                self.assertEqual(os.waitpid(probe, 0)[1], 0)
                for path in observer.APT_LOCKS: available(path)
            finally:
                os.close(ready_read); os.write(release_write, b'1'); os.close(release_write)
                self.assertEqual(os.waitpid(pid, 0)[1], 0)
        descriptors = observer.acquire_locks()
        try:
            # Conversely, a native POSIX holder must be excluded for the entire
            # observation descriptor lifetime, independently of flock.
            probe = os.fork()
            if probe == 0:
                for fd in descriptors: os.close(fd)
                for path in observer.APT_LOCKS:
                    fd = os.open(path, os.O_RDWR)
                    try:
                        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        os.close(fd); continue
                    os._exit(1)
                os._exit(0)
            self.assertEqual(os.waitpid(probe, 0)[1], 0)
        finally:
            for fd in descriptors: os.close(fd)

    @confined
    def test_unsafe_metadata_and_ancestors_never_repaired(self):
        observer = self.setup_protocol(); victim = observer.LOCKS[-1]
        for mode in (0o666, 0o644, 0o1600):
            victim.chmod(mode)
            with self.assertRaises(ValueError): observer.acquire_locks()
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), mode)
            available(observer.LOCKS[0])
        victim.chmod(0o600); os.chown(victim, 65534, 65534)
        with self.assertRaises(ValueError): observer.acquire_locks()
        os.chown(victim, 0, 0); alias = victim.with_name('hardlink'); os.link(victim, alias)
        with self.assertRaises(ValueError): observer.acquire_locks()
        alias.unlink(); victim.unlink(); os.symlink(observer.LOCKS[0], victim)
        with self.assertRaises(OSError): observer.acquire_locks()
        victim.unlink(); seed(victim)
        for parent, mode in ((Path('/run/lock'), 0o777), (Path('/run'), 0o1777), (Path('/var/lib'), 0o775)):
            previous = stat.S_IMODE(parent.stat().st_mode); parent.chmod(mode)
            with self.assertRaises(ValueError): observer.acquire_locks()
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), mode)
            parent.chmod(previous)
        Path('/run/lock').rename('/run/real-lock'); Path('/run/lock').symlink_to('/run/real-lock')
        with self.assertRaises(OSError): observer.acquire_locks()

    @confined
    def test_sticky_unprivileged_replacement_attacks(self):
        observer = self.setup_protocol(); victim = observer.LOCKS[-1]
        original = victim.stat().st_ino
        pid = os.fork()
        if pid == 0:
            os.setgid(65534); os.setuid(65534)
            try:
                os.unlink(victim)
            except PermissionError:
                os._exit(0)
            os._exit(1)
        self.assertEqual(os.waitpid(pid, 0)[1], 0)
        self.assertEqual(victim.stat().st_ino, original)
        victim.unlink()
        pid = os.fork()
        if pid == 0:
            os.setgid(65534); os.setuid(65534)
            fd = os.open(victim, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd); os._exit(0)
        self.assertEqual(os.waitpid(pid, 0)[1], 0)
        with self.assertRaises((PermissionError, ValueError)): observer.acquire_locks()
        self.assertEqual(victim.stat().st_uid, 65534)
        available(observer.LOCKS[0])

    @confined
    def test_retained_journals_and_path_replacement(self):
        observer = self.setup_protocol()
        for path in observer.JOURNALS:
            seed(path, b'foreign-retained-evidence')
            with self.assertRaises(ValueError): observer.acquire_locks()
            self.assertEqual(path.read_bytes(), b'foreign-retained-evidence')
            for mutex in observer.LOCKS: available(mutex)
            path.unlink()
        native_flock = fcntl.flock; victim = observer.LOCKS[-1]
        def replace_on_acquisition(fd, flags):
            native_flock(fd, flags)
            if os.fstat(fd).st_ino == victim.stat().st_ino:
                victim.rename(victim.with_name('retained-old-inode')); seed(victim)
        with patch.object(observer.fcntl, 'flock', side_effect=replace_on_acquisition):
            with self.assertRaises(ValueError): observer.acquire_locks()
        for mutex in observer.LOCKS: available(mutex)

    def setup_reboot(self):
        observer = self.setup_protocol(); activator = module(activator_source, 'activator')
        seed('/proc/sys/kernel/random/boot_id', b'fixture-before\n', 0o444)
        expected = {'boot_id': 'fixture-before', 'current_kernel': 'fixture-kernel-before', 'target_kernel': 'fixture-kernel-after'}
        activator.validate_reboot_plan = lambda *a, **k: expected
        activator.verify_repo = lambda *a: None
        # Exercise the dormant protocol below its explicit unqualified-VFIO gate;
        # a separate test proves production entry cannot bypass that blocker.
        activator.require_reboot_coordination = lambda: None
        activator.reboot_preconditions = lambda *a: None
        activator.reboot_health = lambda: None
        activator.os.uname = lambda: types.SimpleNamespace(release='fixture-kernel-after')
        return observer, activator, expected

    @confined
    def test_reboot_lifetime_queue_barrier_and_committed_removal_retry(self):
        observer, activator, expected = self.setup_reboot(); digest = 'a' * 64
        activator.reboot_operation({}, digest, 'prepare-reboot')
        events = []
        def native(argv, **kwargs):
            self.assertTrue(locked(activator.OPERATION_LOCK))
            self.assertTrue(locked(activator.BOOT_TRANSACTION_LOCK))
            journal = json.loads(activator.reboot_journal_path(digest).read_bytes())
            activator.validate_reboot_owner(journal, digest, expected)
            events.append(journal['status'])
            return types.SimpleNamespace(stdout='status: stopped')
        activator.native = native
        self.assertEqual(activator.reboot_operation({}, digest, 'apply-reboot')['reboot_transaction'], 'initiated')
        self.assertEqual(events, ['stopping-workload', 'stopping-workload', 'rebooting'])
        available(activator.OPERATION_LOCK)
        with self.assertRaises(ValueError): observer.acquire_locks()
        with self.assertRaises(ValueError): activator.boot_operation({}, 'b' * 64)
        with self.assertRaises(ValueError): activator.reboot_operation({}, digest, 'apply-reboot')
        seed('/proc/sys/kernel/random/boot_id', b'fixture-after\n', 0o444)
        real_release = activator.release_reboot_owner
        activator.release_reboot_owner = lambda *a: (_ for _ in ()).throw(OSError('injected after durable commit'))
        with self.assertRaises(OSError): activator.reboot_operation({}, digest, 'verify-reboot')
        self.assertTrue(activator.REBOOT_OWNER.exists())
        journal = json.loads(activator.reboot_journal_path(digest).read_bytes())
        self.assertEqual(journal['status'], 'committed')
        activator.release_reboot_owner = real_release
        health = []
        activator.reboot_health = lambda: health.append(True)
        activator.reboot_operation({}, digest, 'verify-reboot')
        self.assertEqual(health, [True]); self.assertFalse(activator.REBOOT_OWNER.exists())
        self.assertTrue(activator.reboot_journal_path(digest).exists())
        held = observer.acquire_locks()
        for fd in held: os.close(fd)

    @confined
    def test_reboot_failures_retain_owned_state_and_release_descriptors(self):
        observer, activator, _ = self.setup_reboot(); digest = 'b' * 64
        activator.reboot_operation({}, digest, 'prepare-reboot')
        activator.native = lambda *a, **k: (_ for _ in ()).throw(OSError('workload-stop timeout'))
        with self.assertRaises(OSError): activator.reboot_operation({}, digest, 'apply-reboot')
        self.assertTrue(activator.REBOOT_OWNER.exists())
        self.assertEqual(json.loads(activator.reboot_journal_path(digest).read_bytes())['status'], 'stopping-workload')
        for path in observer.LOCKS: available(path)
        with self.assertRaises(ValueError): observer.acquire_locks()
        # Neither foreign content nor an identical replacement inode is adopted.
        journal = json.loads(activator.reboot_journal_path(digest).read_bytes())
        raw = activator.REBOOT_OWNER.read_bytes()
        activator.REBOOT_OWNER.rename(activator.REBOOT_OWNER.with_name('retained-original'))
        seed(activator.REBOOT_OWNER, raw)
        with self.assertRaises(ValueError): activator.validate_reboot_owner(journal, digest, {'boot_id': 'fixture-before'})
        self.assertEqual(activator.REBOOT_OWNER.read_bytes(), raw)

    @confined
    def test_journal_fsync_order_and_workload_failure_boundaries(self):
        observer, activator, _ = self.setup_reboot(); digest = 'c' * 64
        events = []; real_fsync = os.fsync; real_replace = os.replace
        root = Path('/var/lib/home-lab/reboot-transactions')
        def sync(fd):
            info = os.fstat(fd)
            kind = 'directory' if stat.S_ISDIR(info.st_mode) else 'file'
            real_fsync(fd)
            events.append((kind, info.st_ino))
        def replace(*args, **kwargs):
            real_replace(*args, **kwargs); events.append(('replace', 0))
        before = descriptor_set()
        with patch.object(os, 'fsync', side_effect=sync), patch.object(os, 'replace', side_effect=replace):
            activator.reboot_operation({}, digest, 'prepare-reboot')
        journal_path = activator.reboot_journal_path(digest)
        self.assertLess(events.index(('directory', root.parent.stat().st_ino)), events.index(('file', journal_path.stat().st_ino)))
        self.assertEqual(events[-2:], [('file', journal_path.stat().st_ino), ('directory', root.stat().st_ino)])
        events.clear()
        def native(*args, **kwargs):
            self.assertEqual(events[-3:][0][0], 'file')
            self.assertEqual(events[-2:], [('replace', 0), ('directory', root.stat().st_ino)])
            return types.SimpleNamespace(stdout='status: stopped')
        activator.native = native
        with patch.object(os, 'fsync', side_effect=sync), patch.object(os, 'replace', side_effect=replace):
            activator.reboot_operation({}, digest, 'apply-reboot')
        seed('/proc/sys/kernel/random/boot_id', b'fixture-after\n', 0o444)
        # A real journal publication whose directory fsync fails must not release
        # the reboot owner, even though committed bytes are visible in page cache.
        replaced = []
        def record_replace(*args, **kwargs):
            real_replace(*args, **kwargs); replaced.append(True)
        def fail_sync(fd):
            if replaced and os.fstat(fd).st_ino == root.stat().st_ino:
                raise OSError('journal directory fsync failure')
            real_fsync(fd)
        with patch.object(os, 'replace', side_effect=record_replace), patch.object(os, 'fsync', side_effect=fail_sync):
            with self.assertRaises(OSError): activator.reboot_operation({}, digest, 'verify-reboot')
        self.assertTrue(activator.REBOOT_OWNER.exists())
        self.assertEqual(descriptor_set(), before)
        activator.reboot_operation({}, digest, 'verify-reboot')
        self.assertFalse(activator.REBOOT_OWNER.exists())

    @confined
    def test_actual_journal_creation_and_replacement_sync_failures(self):
        observer, activator, _ = self.setup_reboot(); before = descriptor_set()
        real_fsync = os.fsync; real_replace = os.replace
        root = Path('/var/lib/home-lab/reboot-transactions')
        # Newly mkdir'd transaction entry is not treated as durable on failure.
        def fail_parent(fd):
            if root.exists() and os.fstat(fd).st_ino == root.parent.stat().st_ino:
                raise OSError('transaction directory publication failed')
            real_fsync(fd)
        with patch.object(os, 'fsync', side_effect=fail_parent):
            with self.assertRaises(OSError): activator.reboot_journal_path('d' * 64)
        self.assertEqual(list(root.iterdir()), []); self.assertEqual(descriptor_set(), before)
        for index, boundary in enumerate(('file', 'directory')):
            digest = str(index + 1) * 64
            activator.reboot_operation({}, digest, 'prepare-reboot')
            calls = []; activator.native = lambda *a, **k: calls.append(a)
            replaced = []
            def record_replace(*args, **kwargs):
                real_replace(*args, **kwargs); replaced.append(True)
            def fail_sync(fd):
                info = os.fstat(fd)
                journal_file = any(p.stat().st_ino == info.st_ino for p in root.glob('.*.tmp'))
                if (boundary == 'file' and journal_file) or (boundary == 'directory' and replaced and info.st_ino == root.stat().st_ino):
                    raise OSError('actual journal fsync failure')
                real_fsync(fd)
            with patch.object(os, 'replace', side_effect=record_replace), patch.object(os, 'fsync', side_effect=fail_sync):
                with self.assertRaises(OSError): activator.reboot_operation({}, digest, 'apply-reboot')
            self.assertEqual(calls, []); self.assertTrue(activator.REBOOT_OWNER.exists())
            self.assertEqual(descriptor_set(), before)
            for mutex in observer.LOCKS: available(mutex)
            # Each scenario is synthetic isolated state, not a recovery operation.
            activator.REBOOT_OWNER.unlink()

    @confined
    def test_nested_transaction_directory_creation_is_durable_and_not_repaired(self):
        activator = module(activator_source, 'activator'); before = descriptor_set()
        Path('/var/lib').mkdir(parents=True)
        root = Path('/var/lib/synthetic-journals/transactions')
        real_fsync = os.fsync; synced = []
        def sync(fd):
            real_fsync(fd); synced.append(os.fstat(fd).st_ino)
        with patch.object(os, 'fsync', side_effect=sync): activator.journal_directory(root)
        self.assertEqual(synced, [root.parent.parent.stat().st_ino, root.parent.stat().st_ino])
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        root.chmod(0o755)
        with self.assertRaises((ValueError, SystemExit)): activator.journal_directory(root)
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
        self.assertEqual(descriptor_set(), before)

    @confined
    def test_exclusive_journal_sync_failure_and_unsafe_ancestry(self):
        observer, activator, _ = self.setup_reboot(); before = descriptor_set()
        root = activator.reboot_journal_path('a' * 64).parent
        real_fsync = os.fsync
        for boundary in ('file', 'directory'):
            target = root / (boundary + '.json'); file_synced = []
            def sync(fd):
                info = os.fstat(fd)
                if stat.S_ISREG(info.st_mode):
                    if boundary == 'file': raise OSError('exclusive file sync failed')
                    real_fsync(fd); file_synced.append(True); return
                if file_synced and info.st_ino == root.stat().st_ino:
                    raise OSError('exclusive directory sync failed')
                real_fsync(fd)
            with patch.object(os, 'fsync', side_effect=sync):
                with self.assertRaises(OSError): activator.save_package_journal(target, {'synthetic': True}, exclusive=True)
            self.assertTrue(target.exists())  # No invented retry of partial preparation.
            with self.assertRaises(FileExistsError): activator.save_package_journal(target, {}, exclusive=True)
            self.assertEqual(descriptor_set(), before)
        root.chmod(0o777)
        with self.assertRaises((ValueError, SystemExit)): activator.save_package_journal(root / 'unsafe.json', {}, exclusive=True)
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o777)
        root.chmod(0o700); root.rename(root.with_name('original'))
        root.symlink_to(root.with_name('original'))
        with self.assertRaises(OSError): activator.save_package_journal(root / 'unsafe.json', {}, exclusive=True)
        self.assertFalse((root / 'unsafe.json').exists()); self.assertEqual(descriptor_set(), before)

    @confined
    def test_scheduling_and_verification_failures_keep_barrier(self):
        observer, activator, _ = self.setup_reboot(); digest = 'd' * 64
        activator.reboot_operation({}, digest, 'prepare-reboot')
        def native(argv, **kwargs):
            if argv[0].endswith('systemctl'):
                raise OSError('ambiguous scheduling timeout')
            return types.SimpleNamespace(stdout='status: stopped')
        activator.native = native
        with self.assertRaises(OSError): activator.reboot_operation({}, digest, 'apply-reboot')
        journal = json.loads(activator.reboot_journal_path(digest).read_bytes())
        self.assertEqual(journal['status'], 'rebooting')
        available(activator.OPERATION_LOCK)
        with self.assertRaises(ValueError): activator.reboot_operation({}, digest, 'verify-reboot')
        seed('/proc/sys/kernel/random/boot_id', b'fixture-after\n', 0o444)
        activator.reboot_health = lambda: (_ for _ in ()).throw(ValueError('failed postboot health'))
        with self.assertRaises(ValueError): activator.reboot_operation({}, digest, 'verify-reboot')
        self.assertTrue(activator.REBOOT_OWNER.exists())
        with self.assertRaises(ValueError): observer.acquire_locks()

    @confined
    def test_deploy_dispatch_and_boot_partial_acquisition_are_serialized(self):
        observer, activator, _ = self.setup_reboot()
        victim = observer.LOCKS[-1]; victim.chmod(0o666)
        with self.assertRaises(ValueError): activator.acquire_boot_conflict_locks()
        for path in observer.LOCKS: available(path)
        victim.chmod(0o600)
        activator.read_bounded_stdin = lambda *a: {'operation': 'apply-package', 'plan_sha256': 'e' * 64}
        calls = []
        activator.dispatch = lambda request: calls.append(locked(activator.OPERATION_LOCK))
        activator.main(); self.assertEqual(calls, [True])
        held = observer.acquire_locks()
        try:
            with self.assertRaises(BlockingIOError): activator.main()
        finally:
            for fd in held: os.close(fd)
        seed(activator.REBOOT_OWNER, b'foreign-record')
        with self.assertRaises(ValueError): activator.main()
        self.assertEqual(calls, [True]); available(activator.OPERATION_LOCK)


    @confined
    def test_current_vfio_protocol_blocks_new_reboot_before_workload_commands(self):
        observer, activator, _ = self.setup_reboot(); digest = 'f' * 64
        activator.require_reboot_coordination = module(activator_source, 'gate').require_reboot_coordination
        activator.reboot_operation({}, digest, 'prepare-reboot')
        with patch.object(activator, 'native') as native:
            with self.assertRaisesRegex(ValueError, 'VFIO queued-reboot'):
                activator.reboot_operation({}, digest, 'apply-reboot')
            native.assert_not_called()
        self.assertFalse(activator.REBOOT_OWNER.exists())
        for mutex in observer.LOCKS: available(mutex)



class InstallerTests(unittest.TestCase):
    def test_current_vfio_protocol_blocks_streamed_install_before_any_mutation(self):
        installer = module(installer_source, 'gate_installer')
        with patch.object(installer, 'material') as material:
            for operation in ('apply', 'observe'):
                with self.assertRaisesRegex(ValueError, 'VFIO queued-reboot'):
                    installer.transaction({'operation': operation})
            material.assert_not_called()

    @confined
    def test_install_and_rollback_failure_ownership(self):
        fixture = NativeProtocolTests(); fixture.setup_protocol()
        installer = module(installer_source, 'installer'); installer.repository_prerequisites = lambda *a: None; installer.health = lambda *a: None; installer.require_vfio_coordination = lambda: None
        installer.account = lambda: None
        installer.native = lambda argv: b'{}\n'
        old = {}
        for path, mode in installer.TARGETS.items():
            if path != installer.CONTROLLER:
                seed(path, b'old-synthetic-helper', mode)
            old[str(path)] = None if path == installer.CONTROLLER else base64.b64encode(b'old-synthetic-helper').decode()
        raw_files = {p: b'new-synthetic-helper' for p in installer.TARGETS}
        raw_files[installer.CONTROLLER] = observer_source.encode()
        files = {str(p): base64.b64encode(raw).decode() for p, raw in raw_files.items()}
        payload = {'operation': 'apply', 'plan_sha256': 'd' * 64, 'files': files, 'before': old}
        self.assertEqual(installer.transaction({'operation': 'observe', 'files': files}), {'before': old})
        real_put = installer.put
        def fail_put(path, raw, mode, protocol, **kwargs):
            self.assertTrue(locked(Path('/var/lib/home-lab/reconciliation/operation.lock')))
            if path == installer.SUDO:
                raise OSError('sudo publication failure')
            real_put(path, raw, mode, protocol, **kwargs)
        installer.put = fail_put
        with self.assertRaises(OSError): installer.transaction(payload)
        self.assertFalse(installer.OWNER.exists())
        self.assertEqual(installer.transaction({'operation': 'observe', 'files': files})['before'], old)
        installer.put = real_put
        payload['plan_sha256'] = 'e' * 64
        def fail_restore(state, protocol):
            raise OSError('rollback injected failure')
        real_restore = installer.restore; installer.restore = fail_restore; installer.put = fail_put
        with self.assertRaises(OSError): installer.transaction(payload)
        self.assertTrue(installer.OWNER.exists())
        with self.assertRaises(ValueError): installer.transaction({'operation': 'observe', 'files': files})
        installer.put = real_put; installer.restore = real_restore
        payload['operation'] = 'rollback'
        owner_path = installer.OWNER / 'owner'; retained = installer.OWNER / 'retained-original'
        owner_raw = owner_path.read_bytes(); owner_path.rename(retained); seed(owner_path, owner_raw)
        with self.assertRaisesRegex(ValueError, 'identity replaced'): installer.transaction(payload)
        owner_path.unlink(); retained.rename(owner_path)
        helper = installer.BASE / 'proxmox-observer'; installed_raw = helper.read_bytes()
        seed(helper, b'foreign-installed-drift', 0o755)
        with self.assertRaisesRegex(ValueError, 'foreign installed bytes'): installer.transaction(payload)
        self.assertEqual(helper.read_bytes(), b'foreign-installed-drift')
        self.assertTrue(installer.OWNER.exists()); seed(helper, installed_raw, 0o755)
        self.assertEqual(installer.transaction(payload), {'status': 'rolled-back'})
        self.assertFalse(installer.OWNER.exists())
        payload.update(operation='apply', plan_sha256='f' * 64)
        self.assertEqual(installer.transaction(payload), {'status': 'candidate', 'observation': {}})
        self.assertTrue(installer.OWNER.exists())
        payload.update(operation='commit', observation_sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'audited candidate changed'): installer.transaction(payload)
        self.assertTrue(installer.OWNER.exists())
        payload['observation_sha256'] = installer.sha(b'{}\n')
        self.assertEqual(installer.transaction(payload), {'status': 'committed', 'live_acceptance': False})
        self.assertEqual(installer.transaction({'operation': 'observe', 'files': files})['before'], files)

    def setup_installer(self):
        observer = NativeProtocolTests().setup_protocol()
        installer = module(installer_source, 'installer')
        installer.repository_prerequisites = lambda *a: None
        installer.health = lambda *a: None
        installer.require_vfio_coordination = lambda: None
        installer.account = lambda: None
        installer.native = lambda argv: b'{}\n'
        old = {}
        for path, mode in installer.TARGETS.items():
            if path != installer.CONTROLLER:
                seed(path, b'old-synthetic-helper', mode)
            old[str(path)] = None if path == installer.CONTROLLER else base64.b64encode(b'old-synthetic-helper').decode()
        files = {str(p): base64.b64encode(observer_source.encode() if p == installer.CONTROLLER else b'new-synthetic-helper').decode() for p in installer.TARGETS}
        payload = {'operation': 'apply', 'plan_sha256': 'b' * 64, 'files': files, 'before': old}
        installer.transaction(payload)
        return observer, installer, payload

    @confined
    def test_terminated_temporary_publication_does_not_obstruct_exact_rollback(self):
        observer, installer, payload = self.setup_installer()
        payload['operation'] = 'rollback'; before = descriptor_set()
        real_fsync = os.fsync
        def child():
            def sync(fd):
                real_fsync(fd)
                info = os.fstat(fd)
                if any(p.stat().st_ino == info.st_ino for p in installer.TRANSACTIONS.glob('.*.tmp')):
                    os._exit(73)  # Abrupt death after temp fsync, before replace.
            with patch.object(os, 'fsync', side_effect=sync): installer.transaction(payload)
        terminated(child)
        leftovers = {p: (p.stat().st_ino, p.read_bytes()) for p in installer.TRANSACTIONS.glob('.*.tmp')}
        self.assertEqual(len(leftovers), 1)
        # A historical deterministic orphan is neither adopted nor deleted.
        orphan = seed(installer.TRANSACTIONS / ('.' + payload['plan_sha256'] + '.json.controller-capability.tmp'), b'foreign-orphan')
        for mutex in observer.LOCKS: available(mutex)
        self.assertEqual(installer.transaction(payload), {'status': 'rolled-back'})
        self.assertEqual(leftovers, {p: (p.stat().st_ino, p.read_bytes()) for p in leftovers})
        self.assertEqual(orphan.read_bytes(), b'foreign-orphan')
        self.assertFalse(installer.OWNER.exists()); self.assertEqual(descriptor_set(), before)

    @confined
    def test_terminal_detachment_child_exit_boundaries_and_exact_continuation(self):
        # Fresh child chroots per scenario keep terminal evidence independent.
        for operation in ('rollback', 'commit'):
            for boundary in ('terminal-replace', 'before-rename', 'after-rename', 'detached-parent-sync',
                             'before-unlink', 'after-unlink', 'empty-directory-sync',
                             'before-rmdir', 'after-rmdir', 'removed-parent-sync'):
                with tempfile.TemporaryDirectory(dir='/', prefix='scenario-') as root:
                    pid = os.fork()
                    if pid == 0:
                        try:
                            os.chroot(root); os.chdir('/'); os.chmod('/', 0o755)
                            self.terminal_scenario(operation, boundary)
                        except BaseException:
                            import traceback
                            traceback.print_exc(); os._exit(1)
                        os._exit(0)
                    self.assertEqual(os.waitpid(pid, 0)[1], 0, (operation, boundary))

    def terminal_scenario(self, operation, boundary):
        observer, installer, payload = self.setup_installer(); before = descriptor_set()
        payload.update(operation=operation, observation_sha256=installer.sha(b'{}\n'))
        state_path = installer.TRANSACTIONS / (payload['plan_sha256'] + '.json')
        state = json.loads(state_path.read_bytes())
        detached = installer.detached_owner(payload['plan_sha256'], state['owner_identity'])
        real_rename, real_unlink, real_rmdir, real_fsync, real_replace = os.rename, os.unlink, os.rmdir, os.fsync, os.replace
        def child():
            stage = []; terminal_sync = []
            def stop(label):
                if boundary == label:
                    self.assertTrue(terminal_sync)
                    os._exit(73)
            def replace(*args, **kwargs):
                real_replace(*args, **kwargs)
                if boundary == 'terminal-replace' and json.loads(state_path.read_bytes())['status'] in {'committed', 'rolled-back'}:
                    self.assertFalse(terminal_sync)
                    self.assertTrue(installer.OWNER.exists())
                    os._exit(73)  # Published, but not yet directory-fsynced.
            def rename(*args, **kwargs):
                self.assertEqual(json.loads(state_path.read_bytes())['status'], 'committed' if operation == 'commit' else 'rolled-back')
                self.assertTrue(terminal_sync)
                stop('before-rename'); real_rename(*args, **kwargs); stage.append('detached'); stop('after-rename')
            def unlink(name, *args, **kwargs):
                if name == 'owner':
                    self.assertIn('detached-parent-synced', stage)
                    stop('before-unlink'); real_unlink(name, *args, **kwargs); stage.append('empty'); stop('after-unlink')
                else:
                    real_unlink(name, *args, **kwargs)
            def rmdir(*args, **kwargs):
                stop('before-rmdir'); real_rmdir(*args, **kwargs); stage.append('removed'); stop('after-rmdir')
            def sync(fd):
                info = os.fstat(fd); real_fsync(fd)
                current = json.loads(state_path.read_bytes())
                if info.st_ino == installer.TRANSACTIONS.stat().st_ino and current['status'] in {'committed', 'rolled-back'}:
                    terminal_sync.append(True)
                if stage and info.st_ino == installer.OWNER.parent.stat().st_ino:
                    if stage[-1] == 'detached':
                        stage.append('detached-parent-synced'); stop('detached-parent-sync')
                    elif stage[-1] == 'removed': stop('removed-parent-sync')
                if stage and stage[-1] == 'empty' and info.st_ino == state['owner_identity'][1]: stop('empty-directory-sync')
            with patch.object(os, 'replace', side_effect=replace), patch.object(os, 'rename', side_effect=rename), patch.object(os, 'unlink', side_effect=unlink), patch.object(os, 'rmdir', side_effect=rmdir), patch.object(os, 'fsync', side_effect=sync):
                installer.transaction(payload)
        terminated(child)
        for mutex in observer.LOCKS: available(mutex)
        payload['operation'] = 'cleanup-committed' if operation == 'commit' else 'rollback'
        wrong = dict(payload, operation='rollback' if operation == 'commit' else 'cleanup-committed')
        with self.assertRaisesRegex(ValueError, 'terminal capability operation'): installer.transaction(wrong)
        # Same bytes at a foreign inode (active or detached) confer no authority.
        location = installer.OWNER if installer.OWNER.exists() else detached if detached.exists() else None
        if location is not None:
            retained = location.with_name('retained-original'); location.rename(retained)
            location.mkdir(mode=0o700)
            if (retained / 'owner').exists(): seed(location / 'owner', (retained / 'owner').read_bytes())
            with self.assertRaises(ValueError): installer.transaction(payload)
            if (location / 'owner').exists(): (location / 'owner').unlink()
            location.rmdir(); retained.rename(location)
        if location is not None and (location / 'owner').exists():
            record = location / 'owner'; raw = record.read_bytes()
            retained = location.with_name('retained-owner-record'); record.rename(retained)
            seed(record, raw)
            with self.assertRaisesRegex(ValueError, 'identity replaced'): installer.transaction(payload)
            self.assertEqual(record.read_bytes(), raw)
            record.unlink(); retained.rename(record)
        # A different later active owner must survive even exact old cleanup.
        if not installer.OWNER.exists():
            installer.OWNER.mkdir(mode=0o700)
            foreign = seed(installer.OWNER / 'owner', installer.owner_bytes('f' * 64))
            with self.assertRaises(ValueError): installer.transaction(payload)
            self.assertEqual(foreign.read_bytes(), installer.owner_bytes('f' * 64))
            foreign.unlink(); installer.OWNER.rmdir()
        installed = {p: p.read_bytes() if p.exists() else None for p in installer.TARGETS}
        # Terminal continuation must not call health, snapshot, restore or native.
        with patch.object(installer, 'restore', side_effect=AssertionError('restore after terminal')), patch.object(installer, 'native', side_effect=AssertionError('native after terminal')), patch.object(installer, 'health', side_effect=AssertionError('health after terminal')), patch.object(installer, 'snapshot', side_effect=AssertionError('snapshot after terminal')):
            result = installer.transaction(payload)
        self.assertEqual(result['status'], 'committed' if operation == 'commit' else 'rolled-back')
        self.assertFalse(installer.OWNER.exists()); self.assertFalse(detached.exists())
        self.assertEqual(installed, {p: p.read_bytes() if p.exists() else None for p in installer.TARGETS})
        self.assertEqual(descriptor_set(), before)
        installer.transaction(payload)  # Exact terminal-only idempotence, no apply.
        with self.assertRaises(ValueError): installer.transaction(dict(payload, operation='apply'))

    @confined
    def test_cleanup_committed_refuses_candidate_and_cleanup_errors_close_descriptors(self):
        observer, installer, payload = self.setup_installer(); before = descriptor_set()
        with self.assertRaisesRegex(ValueError, 'not committed'):
            installer.transaction(dict(payload, operation='cleanup-committed'))
        protocol = module(observer_source, 'observer').__dict__
        target = installer.TRANSACTIONS / 'synthetic.json'
        real_fsync = os.fsync
        def fail_sync(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode): raise OSError('file fsync failed')
            real_fsync(fd)
        # Even cleanup unlink failure must close the open file AND parent fd.
        with patch.object(os, 'fsync', side_effect=fail_sync), patch.object(os, 'unlink', side_effect=OSError('cleanup unlink failed')):
            with self.assertRaises(OSError): installer.put(target, b'fixture', 0o600, protocol)
        self.assertEqual(descriptor_set(), before)

    @confined
    def test_missing_mutex_foreign_owner_or_before_drift_prevents_install(self):
        observer = NativeProtocolTests().setup_protocol(); installer = module(installer_source, 'installer'); installer.repository_prerequisites = lambda *a: None; installer.health = lambda *a: None; installer.require_vfio_coordination = lambda: None
        files = {str(p): base64.b64encode(observer_source.encode() if p == installer.CONTROLLER else b'fixture').decode() for p in installer.TARGETS}
        installer.snapshot = lambda protocol: {'drift': True}
        payload = {'operation': 'apply', 'plan_sha256': 'a' * 64, 'files': files, 'before': {}}
        with self.assertRaises(ValueError): installer.transaction(payload)
        self.assertFalse(installer.OWNER.exists())
        victim = observer.LOCKS[-1]; victim.unlink()
        with self.assertRaises(FileNotFoundError): installer.transaction(payload)
        self.assertFalse(victim.exists()); available(observer.LOCKS[0])
        seed(victim); seed(observer.JOURNALS[0], b'foreign')
        with self.assertRaises(ValueError): installer.transaction(payload)
        self.assertEqual(observer.JOURNALS[0].read_bytes(), b'foreign')
        self.assertFalse(installer.OWNER.exists())


if __name__ == '__main__':
    unittest.main()
