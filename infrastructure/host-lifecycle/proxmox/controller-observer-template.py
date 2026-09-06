#!/usr/bin/python3
"""Fixed nonce-bound read-only snapshot; locks cover observation, not later owners."""
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SPEC = json.loads('@CONTROLLER_SPEC@')
ACTIVATOR_SHA256 = '@ACTIVATOR_SHA256@'
ENV = {"LC_ALL": "C.UTF-8", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
ROOT = Path('/var/lib/home-lab/reconciliation')
# Keep installed protocols: presence journals are not descriptor locks.
JOURNALS = [ROOT / name for name in ('apply.lock', 'owner.lock', 'nix.lock')]
JOURNALS += [Path('/var/lib/iac-ansible-production.lock'), Path('/var/lib/home-lab/firewall-transaction/active.json')]
LOCKS = [ROOT / 'operation.lock'] + [Path('/run/lock') / name for name in (
    'home-lab-vfio-recovery.lock', 'home-lab-backup.lock', 'home-lab-proxmox-low-risk.lock',
    'home-lab-proxmox-boot-configuration.lock', 'home-lab-proxmox-zfs-ownership.lock',
    'home-lab-proxmox-nfs-ownership.lock', 'home-lab-proxmox-network-ownership.lock',
    'home-lab-proxmox-tailscale-ownership.lock', 'home-lab-proxmox-package-ownership.lock',
    'home-lab-proxmox-package.lock', 'home-lab-proxmox-reboot.lock')]
APT_LOCKS = [Path(p) for p in ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock', '/var/lib/apt/lists/lock', '/var/cache/apt/archives/lock')]


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def parent_fd(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root_info = os.fstat(fd)
        if root_info.st_uid != 0 or root_info.st_gid != 0 or root_info.st_mode & 0o022:
            raise ValueError("unsafe root ancestor")
        walked = Path("/")
        for part in path.parts[1:-1]:
            walked /= part
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            # Only the canonical Linux lock directory may be writable. Sticky
            # root ownership protects existing root-owned entries, never creation.
            sticky_lock = walked == Path("/run/lock") and stat.S_IMODE(info.st_mode) == 0o1777
            if info.st_uid != 0 or info.st_gid != 0 or (info.st_mode & 0o022 and not sticky_lock):
                os.close(child)
                raise ValueError('unsafe parent')
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_fixed(path, limit, mode):
    parent = parent_fd(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != mode or before.st_size > limit:
                raise ValueError('unsafe producer input')
            raw = b''
            while len(raw) < before.st_size:
                chunk = os.read(fd, before.st_size - len(raw))
                if not chunk:
                    raise ValueError('short producer input')
                raw += chunk
            if fingerprint(before) != fingerprint(os.fstat(fd)) or fingerprint(before) != fingerprint(os.stat(path.name, dir_fd=parent, follow_symlinks=False)):
                raise ValueError('producer input changed')
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def acquire_descriptors():
    descriptors = []
    try:
        for path in LOCKS + APT_LOCKS:
            parent = parent_fd(path)
            try:
                # Separately reviewed provisioning owns mutex creation; the
                # capability installer also requires these files to preexist.
                fd = os.open(path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                descriptors.append(fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o600, 0o640):
                    raise ValueError('lock metadata differs')
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if fingerprint(info) != fingerprint(current):
                    raise ValueError("mutex pathname changed")
                if path in APT_LOCKS:
                    fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(parent)
        return descriptors
    except BaseException:
        for fd in descriptors:
            os.close(fd)
        raise


def acquire_locks():
    descriptors = acquire_descriptors()
    try:
        for path in JOURNALS:
            if os.path.lexists(path):
                raise ValueError('conflicting owner journal')
        return descriptors
    except BaseException:
        for fd in descriptors:
            os.close(fd)
        raise


def observe(nonce):
    descriptors = acquire_locks()
    try:
        paths = {'observer_sha256': Path('/usr/local/libexec/home-lab/proxmox-observer'),
                 'collector_sha256': Path('/usr/local/libexec/home-lab/proxmox-protected-collector')}
        for key, path in paths.items():
            if hashlib.sha256(read_fixed(path, 1024 * 1024, 0o755)).hexdigest() != SPEC[key]:
                raise ValueError('installed producer mismatch')
        if hashlib.sha256(read_fixed(Path('/usr/local/libexec/home-lab/proxmox-ansible-deploy-activator'), 1024 * 1024, 0o755)).hexdigest() != ACTIVATOR_SHA256:
            raise ValueError('installed mutex participant mismatch')
        key = read_fixed(Path('/etc/ssh') / 'ssh_host_ed25519_key.pub', 4096, 0o644).decode().split()
        if len(key) not in (2, 3) or key[0] != 'ssh-ed25519':
            raise ValueError('host key differs')
        host_key = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(key[1], validate=True)).digest()).decode().rstrip('=')
        result = subprocess.run([str(paths['observer_sha256']), 'observe'], input=b'', capture_output=True, env=ENV, timeout=180)
        if result.returncode or result.stderr or len(result.stdout) > 1024 * 1024:
            raise ValueError('observation failed')
        observation = json.loads(result.stdout)
        if canonical(observation) != result.stdout:
            raise ValueError('observation not canonical')
        return {'format': 'home-lab-proxmox-locked-observation-v1', 'nonce': nonce,
                'observed_at': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'host_key': host_key, 'scope': 'audit', 'locks': 'snapshot-exclusive-v1',
                'producer_sha256': hashlib.sha256(read_fixed(Path(__file__).absolute(), 1024 * 1024, 0o755)).hexdigest(),
                **SPEC, 'observation': observation}
    finally:
        for fd in descriptors:
            os.close(fd)


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ['observe']:
        raise ValueError('fixed invocation required')
    raw = sys.stdin.buffer.read(66)
    if not re.fullmatch(b'[0-9a-f]{64}\n', raw):
        raise ValueError('nonce required')
    sys.stdout.buffer.write(canonical(observe(raw.decode().strip())))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('locked Proxmox observation refused', file=sys.stderr)
        raise SystemExit(66)
