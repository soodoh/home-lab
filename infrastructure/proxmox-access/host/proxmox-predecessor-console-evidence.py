#!/usr/bin/python3 -IBS
"""Fixed offline-developed console measurement slice; never admission authority."""
import fcntl
import hashlib
import json
import os
import re
import stat
import sys

FORMAT = 'home-lab-proxmox-predecessor-console-measurement-v1'
BLOCKERS = [
    'console-origin-unqualified', 'execution-unqualified',
    'independent-expected-profile-unapproved', 'host-binding-unqualified',
    'account-and-conventional-key-inventory-unobserved',
    'runtime-and-dependency-coverage-incomplete',
    'freshness-and-recovery-protocol-unapproved',
]
BASE = '/usr/local/libexec/home-lab/'
# Transaction TARGETS minus the NEW controller observer (not a predecessor).
# These are inspection constraints, NOT approved predecessor byte profiles.
PUBLIC = tuple((BASE + name, 0o755) for name in (
    'proxmox-observer', 'proxmox-protected-collector',
    'proxmox-package-candidate-observer', 'proxmox-ansible-plan-transport',
    'proxmox-ansible-deploy-activator',
    'proxmox-firewall-transaction', 'proxmox-firewall-transport',
)) + (('/etc/sudoers.d/ansible-plan', 0o440),
     ('/etc/sudoers.d/firewall-apply', 0o440))
RUNTIME = '/var/lib/home-lab/firewall-transaction'
RECONCILIATION = '/var/lib/home-lab/reconciliation'
OPERATION = RECONCILIATION + '/operation.lock'
BARRIERS = tuple(RECONCILIATION + '/' + name for name in (
    'apply.lock', 'owner.lock', 'nix.lock',
)) + ('/var/lib/iac-ansible-production.lock', RUNTIME + '/active.json')
# Firewall signing prerequisite: metadata only, O_PATH, never read or hashed.
SECRET = RUNTIME + '/attestation.key'
MAX_PUBLIC = 1024 * 1024
MAX_OUTPUT = 16384
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


class Refusal(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refusal(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def identity(info):
    # atime is deliberately excluded: ordinary bounded reads may update it.
    return tuple(getattr(info, field) for field in FIELDS)


def metadata(info):
    return {field[3:]: getattr(info, field) for field in FIELDS}


def terminal_identity():
    """Only this OS identity seam is substituted by positive console fixtures."""
    require(os.isatty(0), 'console-required')
    name = os.ttyname(0)
    info = os.fstat(0)
    named = os.stat(name, follow_symlinks=False)
    require(identity(info) == identity(named), 'console-required')
    require(os.tcgetpgrp(0) == os.getpgrp(), 'console-required')
    fd = os.open('/dev/tty', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(os.tcgetpgrp(fd) == os.getpgrp(), 'console-required')
    finally:
        os.close(fd)
    return name, info.st_mode, info.st_rdev


def startup():
    require(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
            'isolated-startup-required')
    require(sys.platform == 'linux' and os.getuid() == 0 and os.geteuid() == 0,
            'linux-root-required')
    require(sys.executable == '/usr/bin/python3', 'fixed-interpreter-required')
    require(not any(key.startswith(('SSH_', 'PYTHON')) for key in os.environ),
            'environment-refused')
    name, mode, device = terminal_identity()
    minor = os.minor(device)
    # Linux virtual consoles and the first four conventional 8250 serial TTYs.
    # No /dev/console alias, generic PTY, USB serial or WebShell approximation.
    expected = '/dev/tty' + str(minor) if 1 <= minor <= 63 else '/dev/ttyS' + str(minor - 64)
    require(stat.S_ISCHR(mode) and os.major(device) == 4 and
            1 <= minor <= 67 and name == expected, 'console-required')


class Snapshot:
    """Retained no-follow ancestry and file identities, under one existing flock.

    Not atomic against uncooperative privileged writers; no directory discovery.
    Metadata-only objects are pinned with O_PATH and cannot yield file bytes.
    """
    def __init__(self):
        self.fds = []
        self.dirs = {}
        self.files = []

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()

    def opened(self, path, flags, parent=None):
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        self.fds.append(fd)
        return fd

    def directory(self, path):
        if path in self.dirs:
            return self.dirs[path][0]
        if path == '/':
            parent, name = None, '/'
        else:
            parent_path, name = path.rsplit('/', 1)
            parent = self.directory(parent_path or '/')
        fd = self.opened(name, os.O_RDONLY | os.O_DIRECTORY, parent)
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                not info.st_mode & 0o022 and info.st_nlink >= 1, 'unsafe-directory')
        self.dirs[path] = (fd, info, parent, name)
        return fd

    def parent(self, path):
        parent, name = path.rsplit('/', 1)
        return self.directory(parent), name

    def barriers(self):
        for path in BARRIERS:
            parent, name = self.parent(path)
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            # EACCES/EIO/etc must propagate as refusal, not evidence of absence.
            raise Refusal('retained-owner')

    def pin(self, path, modes, limit, content=False, mutex=False):
        parent, name = self.parent(path)
        pin = self.opened(name, os.O_PATH, parent)
        info = os.fstat(pin)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes and
                0 <= info.st_size <= limit, 'unsafe-file')
        fd = pin
        if content or mutex:
            fd = self.opened(name, os.O_RDONLY | os.O_NONBLOCK, parent)
            require(identity(info) == identity(os.fstat(fd)), 'asset-changed')
        record = (fd, info, parent, name, content)
        self.files.append(record)
        self.check_file(record)
        if mutex:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.check_file(record)
        digest = self.digest(record) if content else None
        return record, digest

    def check_file(self, record):
        fd, before, parent, name, _ = record
        require(identity(before) == identity(os.fstat(fd)) ==
                identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                'asset-changed')

    def digest(self, record):
        fd, info, _, _, _ = record
        self.check_file(record)
        os.lseek(fd, 0, os.SEEK_SET)
        remaining = info.st_size
        digest = hashlib.sha256()
        while remaining:
            block = os.read(fd, min(65536, remaining))
            require(bool(block), 'asset-changed')
            digest.update(block)
            remaining -= len(block)
        require(not os.read(fd, 1), 'asset-changed')
        self.check_file(record)
        return digest.hexdigest()

    def recheck(self):
        for record in self.files:
            self.check_file(record)
        for fd, before, parent, name in self.dirs.values():
            require(identity(before) == identity(os.fstat(fd)) ==
                    identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'directory-changed')

    def collect(self):
        self.directory(RECONCILIATION)
        runtime = self.directory(RUNTIME)
        require(stat.S_IMODE(os.fstat(runtime).st_mode) == 0o700, 'unsafe-directory')
        lock, _ = self.pin(OPERATION, (0o600, 0o640), 4096, mutex=True)
        self.barriers()
        assets = []
        measurements = []
        for path, mode in PUBLIC:
            record, digest = self.pin(path, (mode,), MAX_PUBLIC, content=True)
            measurements.append((record, digest))
            assets.append({'path': path, 'metadata': metadata(record[1]), 'sha256': digest})
        secret, _ = self.pin(SECRET, (0o600,), 128)
        # Re-read exact public bytes, then all identities/ancestry/barriers, with
        # the operation descriptor still held. No claim of simultaneous sampling.
        for record, digest in measurements:
            require(self.digest(record) == digest, 'asset-changed')
        self.barriers()
        self.recheck()
        return {
            'public_assets': assets,
            'metadata_only': [{'path': SECRET, 'metadata': metadata(secret[1])},
                              {'path': OPERATION, 'metadata': metadata(lock[1])}],
            'runtime_directories': [
                {'path': path, 'metadata': metadata(self.dirs[path][1])}
                for path in (RECONCILIATION, RUNTIME)],
            'barriers_absent': list(BARRIERS),
            'coordination': 'existing-operation-flock-only-nonatomic',
        }


def main():
    result = {'format': FORMAT, 'authorized': False, 'admission_eligible': False,
              'origin': 'unqualified-console', 'blockers': BLOCKERS,
              'status': 'refused'}
    snapshot = Snapshot()
    code = 1
    try:
        require(len(sys.argv) == 3 and sys.argv[1] == '--challenge' and
                re.fullmatch('[0-9a-f]{64}', sys.argv[2]) is not None,
                'arguments-refused')
        startup()
        measured = snapshot.collect()
        result.update(measured)
        result.update(challenge=sys.argv[2], status='measured')
        require(len(canonical(result)) <= MAX_OUTPUT, 'output-bound')
        code = 0
    except (Refusal, OSError, ValueError):
        # No exception text, caller paths, argv or partial measurements on errors.
        result = {key: result[key] for key in (
            'format', 'authorized', 'admission_eligible', 'origin', 'blockers')}
        result.update(status='refused', error='inspection-refused')
    finally:
        snapshot.close()
    sys.stdout.buffer.write(canonical(result))
    return code


if __name__ == '__main__':
    sys.exit(main())
