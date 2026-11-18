#!/usr/bin/env python3
"""Capture adapters for one full recovery set; no scheduling or admission engine.

Called only by the installed runner under its production/capture lock. Export
stdout, tokens and native errors never enter logs. Paths in policy are trusted
installed-controller inputs, not candidate application source.
"""
from __future__ import annotations

from contextlib import closing, contextmanager, nullcontext
import fcntl
import hashlib
import json
import http.client
import ipaddress
import os
from pathlib import Path
import re
import shutil
import sqlite3
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


class CaptureError(ValueError):
    pass


def retry(operation, attempts=3):
    for attempt in range(attempts):
        try:
            return operation()
        except (OSError, sqlite3.Error, CaptureError):
            if attempt + 1 == attempts:
                raise CaptureError('capture_phase_failed') from None
            time.sleep(2)


def command(argv, output=None):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output or subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=7200, check=False,
                                env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/var/empty', 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        raise CaptureError('capture_command') from None
    if result.returncode:
        raise CaptureError('capture_command')
    return result.stdout


def safe_source(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise CaptureError('source_path')
    for parent in (*path.parents, path):
        if parent.is_symlink():
            raise CaptureError('source_symlink')
    if not path.exists():
        raise CaptureError('source_missing')
    return path


def copy_paths(paths, target, excludes, online_sqlite=False, *, exclude=(), synchronize=False):
    for path in paths:
        safe_source(path)
    options = ['--exclude=' + str(path) for path in exclude]
    if online_sqlite:
        options.extend(['--exclude=*.db', '--exclude=*.db-wal', '--exclude=*.db-shm', '--exclude=*.db-journal'])
    if synchronize:
        options.extend(['--delete-delay', '--modify-window=-1'])
    command(['/usr/bin/rsync', '--archive', '--relative', '--numeric-ids', '--hard-links', '--acls', '--xattrs',
             '--exclude-from=' + str(excludes), *options, '--', *paths, str(target) + '/'])


def file_inventory(paths, *, exclude=()):
    """lstat only: never traverse links or inspect a file's private payload."""
    excluded = tuple(Path(path) for path in exclude)
    result = {}
    for source in paths:
        source = safe_source(source)
        pending = [source]
        while pending:
            path = pending.pop()
            if any(path == root or root in path.parents for root in excluded):
                continue
            info = path.lstat()
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise CaptureError('capture_special_file')
            result[str(path)] = (info.st_mode, info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid)
            if stat.S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
    return result


def database_fingerprints(names, inventory):
    """Private comparisons only: never log or persist database content digests.

    SQLite can fchown an existing WAL to its unchanged owner when opening it,
    advancing ctime without an application write. Compare actual bytes instead.
    """
    result = {}
    for name in sorted(names & inventory.keys()):
        metadata = inventory[name]
        with safe_source(name).open('rb') as stream:
            result[name] = (metadata[:4], metadata[6:], hashlib.file_digest(stream, 'sha256').digest())
    return result


def precopy(paths, target, excludes):
    """Seed private staging while writers are online; this is NOT recovery data."""
    before = file_inventory(paths)
    copy_paths(paths, target, excludes)
    return before


def finish_copy(paths, target, excludes, *, baseline):
    """After writer exclusion, invalidate changed seeds and synchronize natively.

    ctime/inode detect replacements and writes even if size/mtime were preserved.
    Only changed staged files are discarded; the final rsync owns deletion and
    metadata preservation. There are no hard links back to the production tree.
    """
    after = file_inventory(paths)
    for path, signature in after.items():
        if signature == baseline.get(path) or stat.S_ISDIR(signature[0]):
            continue
        destination = target / path.lstrip('/')
        # Resolve ancestors, not the leaf: a copied symlink is removed, not followed.
        if destination.is_symlink() or destination.is_file():
            safe_source(destination.parent)
            destination.unlink()
    copy_paths(paths, target, excludes, synchronize=True)


def stable_store(source, target):
    """Read small JSON/curl cookie stores without stopping their network writers."""
    source = safe_source(source)
    def capture():
        before = file_inventory([source])
        payloads = {}
        for name, signature in before.items():
            path = Path(name)
            if path == source:
                continue
            if path.parent != source or not stat.S_ISREG(signature[0]) or signature[3] > 16 * 1024 * 1024:
                raise CaptureError('online_store_type')
            raw = path.read_bytes()
            try:
                if path.suffix == '.json':
                    if not isinstance(json.loads(raw), (dict, list)):
                        raise ValueError
                elif path.suffix == '.cookies':
                    lines = raw.decode().splitlines()
                    header = False
                    for line in lines:
                        if line == '# Netscape HTTP Cookie File':
                            header = True
                            continue
                        if line.startswith('#HttpOnly_'):
                            line = line[len('#HttpOnly_'):]
                        elif not line or line.startswith('#'):
                            continue
                        fields = line.split('\t')
                        if not header or len(fields) != 7 or fields[1] not in {'TRUE', 'FALSE'} or fields[3] not in {'TRUE', 'FALSE'} or not fields[4].isdigit():
                            raise ValueError
                    if not header:
                        raise ValueError
                else:
                    raise ValueError
            except (ValueError, UnicodeError):
                raise CaptureError('online_store_invalid') from None
            payloads[path.name] = raw
        if not payloads or before != file_inventory([source]):
            raise CaptureError('online_source_changed')
        # Re-read bytes as well as metadata, including in-place writes on NFS.
        if any(raw != (source / name).read_bytes() for name, raw in payloads.items()):
            raise CaptureError('online_source_changed')
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        for old in target.iterdir():
            if old.name not in payloads:
                old.unlink()
        for name, raw in payloads.items():
            destination = target / name
            destination.write_bytes(raw)
            destination.chmod(0o600)
            if os.geteuid() == 0:
                info = (source / name).stat()
                os.chown(destination, info.st_uid, info.st_gid)
    retry(capture)


def mosquitto(step, target, excludes, *, container, running):
    """SIGUSR1 publishes Mosquitto's native persistence DB by atomic replacement."""
    persistence = Path(step['persistence'])
    if running:
        before = persistence.stat().st_ino if persistence.exists() else None
        command(['/usr/bin/docker', 'kill', '--signal', 'USR1', container])
        deadline = time.monotonic() + 30
        while True:
            if persistence.exists():
                safe_source(persistence)
                info = persistence.stat()
                if stat.S_ISREG(info.st_mode) and info.st_size and info.st_ino != before:
                    break
            if time.monotonic() >= deadline:
                raise CaptureError('mqtt_flush_timeout')
            time.sleep(.1)
    before = file_inventory(step['paths'])
    copy_paths(step['paths'], target, excludes, synchronize=True)
    if before != file_inventory(step['paths']):
        raise CaptureError('online_source_changed')


def online_tree(paths, target, excludes, *, sqlite_paths, json_roots=(), ephemeral=()):
    """Native SQLite snapshots plus companion files from a write-free interval.

    Before/after inode, size, mtime and ctime checks include the databases and
    WAL/journals, not the advisory SHM read-marks. Read-only WAL connections may
    rebuild a private wal-index and advance data_version without a real commit;
    that connection-local cache epoch is not an application-write detector.
    """
    before = file_inventory(paths, exclude=ephemeral)
    if any(stat.S_ISLNK(signature[0]) for signature in before.values()):
        raise CaptureError('online_source_symlink')
    if not sqlite_paths and not json_roots:
        raise CaptureError('online_capture_scope_missing')
    if any(root not in before or not stat.S_ISDIR(before[root][0]) for root in json_roots):
        raise CaptureError('online_json_root_missing')
    omitted = set()
    # Only declared application databases are converted. User uploads stay opaque.
    for name in sqlite_paths:
        if name not in before or not stat.S_ISREG(before[name][0]):
            raise CaptureError('online_sqlite_missing')
        with Path(name).open('rb') as stream:
            if stream.read(16) != b'SQLite format 3\x00':
                raise CaptureError('online_sqlite_format')
        omitted.update(name + suffix for suffix in ('', '-wal', '-shm', '-journal'))
    database_files = {name + suffix for name in sqlite_paths for suffix in ('', '-wal', '-journal')}
    before_databases = database_fingerprints(database_files, before)
    copy_paths(paths, target, excludes, exclude=sorted(omitted | set(ephemeral)), synchronize=True)
    for name in sqlite_paths:
        destination = target / name.lstrip('/')
        for suffix in ('-wal', '-shm', '-journal'):
            destination.with_name(destination.name + suffix).unlink(missing_ok=True)
        sqlite_backup(Path(name), destination)
        shutil.copystat(name, destination)
        if os.geteuid() == 0:
            info = Path(name).stat()
            os.chown(destination, info.st_uid, info.st_gid)
    after = file_inventory(paths, exclude=ephemeral)
    selected = lambda inventory: {name: value for name, value in inventory.items() if name not in omitted}
    if (selected(before) != selected(after) or
            before_databases != database_fingerprints(database_files, after)):
        raise CaptureError('online_source_changed')
    for name in before:
        path = Path(name)
        if str(path.parent) in json_roots and path.suffix == '.json' and stat.S_ISREG(before[name][0]):
            try:
                if not isinstance(json.loads((target / name.lstrip('/')).read_bytes()), (dict, list)):
                    raise ValueError
            except ValueError:
                raise CaptureError('online_json_invalid') from None


ZFS_BASE = Path('/mnt/storage')
ZFS_DATA_PATHS = ('media/nextcloud/data', 'media/books', 'media/audiobooks',
                  'media/tachidesk', 'media/caro-tachidesk', 'media/frigate/exports')
ZFS_PREFIX = 'home-lab-nextcloud-'
ZFS_EXPIRY = 72 * 3600
ZFS_BROKER_PORT = 2444


def zfs_spec(policy):
    spec = policy['capture']['zfs']
    if (set(spec) != {'dataset_guid', 'expiry_seconds', 'broker_ipv4'} or
            not re.fullmatch('[1-9][0-9]{0,19}', spec['dataset_guid']) or
            ipaddress.ip_address(spec['broker_ipv4']) not in ipaddress.ip_network('100.64.0.0/10') or
            spec['expiry_seconds'] != ZFS_EXPIRY):
        raise CaptureError('snapshot_policy')
    return spec


def zfs_call(spec, request):
    """One bounded RPC over WireGuard to the pinned peer IP; no DNS or SSH.

    The server socket is bound to tailscale0 and tailnet policy admits only the
    backup host. Closing the request half frames JSON; EOF frames the response.
    """
    raw = json.dumps(request).encode('utf-8')
    if len(raw) > 4096:
        raise CaptureError('snapshot_request_size')
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as stream:
            stream.settimeout(10)
            stream.connect((spec['broker_ipv4'], ZFS_BROKER_PORT))
            stream.sendall(raw)
            stream.shutdown(socket.SHUT_WR)
            deadline, response = time.monotonic() + 180, bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                stream.settimeout(remaining)
                part = stream.recv(min(4096, 65537 - len(response)))
                if not part:
                    break
                response.extend(part)
                if len(response) > 65536:
                    raise ValueError
        value = json.loads(response)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (OSError, ValueError):
        # A create may have succeeded: callers retain intent and never silently
        # repeat creation or fall back to a live-file backup.
        raise CaptureError('snapshot_remote_refused') from None


def zfs_record(spec, value, *, capture=None, owner=None):
    if (not isinstance(value, dict) or
            set(value) != {'capture', 'owner', 'guid', 'created', 'dataset_guid'} or
            not isinstance(value['capture'], str) or not re.fullmatch('[0-9a-f]{32}', value['capture']) or
            not isinstance(value['owner'], str) or not re.fullmatch('[0-9a-f]{64}', value['owner']) or
            not isinstance(value['guid'], str) or not re.fullmatch('[1-9][0-9]{0,19}', value['guid']) or
            type(value['created']) is not int or value['created'] <= 0 or
            value['dataset_guid'] != spec['dataset_guid'] or
            (capture is not None and value['capture'] != capture) or
            (owner is not None and value['owner'] != owner)):
        raise CaptureError('snapshot_identity')
    return value


def zfs_inventory(spec, require_admissible=False):
    value = zfs_call(spec, {'action': 'list'})
    if (set(value) != {'snapshots', 'pool_healthy', 'capture_admissible'} or not isinstance(value['snapshots'], list) or
            type(value['pool_healthy']) is not bool or type(value['capture_admissible']) is not bool):
        raise CaptureError('snapshot_inventory')
    if require_admissible and not value['capture_admissible']:
        raise CaptureError('snapshot_pool_not_admissible')
    records = [zfs_record(spec, row) for row in value['snapshots']]
    if len({row['capture'] for row in records}) != len(records):
        raise CaptureError('snapshot_inventory')
    return records


def zfs_paths():
    return [str(ZFS_BASE / root) for root in ZFS_DATA_PATHS]


def zfs_verify_scope(policy):
    declared = [path for step in policy['capture']['cold'] for path in step['paths']
                if Path(path).is_relative_to(ZFS_BASE)]
    if sorted(declared) != sorted(zfs_paths()):
        raise CaptureError('snapshot_policy_scope')
    if zfs_call(zfs_spec(policy), {'action': 'scope'}) != {'paths': list(ZFS_DATA_PATHS)}:
        raise CaptureError('snapshot_broker_scope')


def archive_path(stage, path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path == Path('/'):
        raise CaptureError('snapshot_path')
    return Path(stage) / 'files' / path.relative_to('/')


def empty_snapshot_target(stage, path, *, regular=False):
    target = archive_path(stage, path)
    base = safe_source(Path(stage) / 'files')
    parent = base
    for part in (target.parent if regular else target).relative_to(base).parts:
        parent = parent / part
        if parent.is_symlink():
            raise CaptureError('snapshot_target_type')
        parent.mkdir(mode=0o700, exist_ok=True)
    if regular:
        if not target.exists() and not target.is_symlink():
            with target.open('xb'):
                pass
        row = safe_source(target).lstat()
        if not stat.S_ISREG(row.st_mode) or row.st_nlink != 1:
            raise CaptureError('snapshot_target_type')
        if row.st_size:
            raise CaptureError('snapshot_target_not_empty')
    result = subprocess.run(['/usr/bin/mountpoint', '--quiet', '--', str(target)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
    if result.returncode != 32:
        raise CaptureError('snapshot_target_mount')
    if not regular and any(target.iterdir()):
        raise CaptureError('snapshot_target_not_empty')
    return target


def snapshot_mounts(stage):
    return [archive_path(stage, path) for path in zfs_paths()]


def snapshot_source(token, root):
    return '192.168.0.123:/storage/docker/.zfs/snapshot/' + ZFS_PREFIX + token + '/' + root


def require_private_mounts():
    if os.stat('/proc/self/ns/mnt').st_ino == os.stat('/proc/1/ns/mnt').st_ino:
        raise CaptureError('private_mount_namespace_required')


def verify_snapshot_mount(target, source, *, readonly=True):
    raw = command(['/usr/bin/findmnt', '--json', '--nofsroot', '--mountpoint', str(target),
                   '--output', 'SOURCE,FSTYPE,OPTIONS'])
    entries = json.loads(raw).get('filesystems', [])
    if len(entries) != 1 or entries[0]['source'] != source or entries[0]['fstype'] != 'nfs4':
        raise CaptureError('unknown_snapshot_mount')
    if readonly and 'ro' not in entries[0]['options'].split(','):
        raise CaptureError('snapshot_mount_not_readonly')


def zfs_mount(spec, record, stage):
    """Mount only the approved roots from one immutable source."""
    token = zfs_record(spec, record)['capture']
    require_private_mounts()
    for root, path in zip(ZFS_DATA_PATHS, zfs_paths()):
        target = empty_snapshot_target(stage, path)
        source = snapshot_source(token, root)
        command(['/usr/bin/mount', '-n', '-t', 'nfs4', '-o',
                 'ro,vers=4.2,proto=tcp,nosuid,nodev,noexec', source, str(target)])
        verify_snapshot_mount(target, source)


def zfs_verify_mounts(record, stage):
    for root, target in zip(ZFS_DATA_PATHS, snapshot_mounts(stage)):
        verify_snapshot_mount(target, snapshot_source(record['capture'], root))


def zfs_unmount(stage):
    mounted = []
    for root, target in zip(ZFS_DATA_PATHS, snapshot_mounts(stage)):
        if target.is_symlink():
            raise CaptureError('snapshot_target_type')
        if not target.exists():
            continue
        safe_source(target)
        result = subprocess.run(['/usr/bin/mountpoint', '--quiet', '--', str(target)],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
        if result.returncode == 0:
            mounted.append((root, target))
        elif result.returncode != 32:
            # util-linux mountpoint returns 32 for an ordinary non-mount path.
            raise CaptureError('snapshot_unmount_inspection')
    if not mounted:
        return
    require_private_mounts()
    state_path = safe_source(Path(stage) / 'zfs-source.json')
    token = json.loads(state_path.read_text())['capture']
    if not isinstance(token, str) or not re.fullmatch('[0-9a-f]{32}', token):
        raise CaptureError('snapshot_identity')
    for root, target in mounted:
        verify_snapshot_mount(target, snapshot_source(token, root), readonly=False)
    for _, target in reversed(mounted):
        command(['/usr/bin/umount', '--', str(target)])


STATE_BASE = Path('/srv/home-lab-state')


def state_snapshot_roots(policy):
    """Use exactly the cold paths declared beneath the state volume.

    In particular, do not bind the whole volume into the archive: it contains
    excluded database datadirs and already-captured online recovery artifacts.
    """
    paths = [Path(path) for step in policy['capture']['cold'] for path in step['paths']
             if Path(path).is_relative_to(STATE_BASE)]
    if (not paths or len(set(paths)) != len(paths) or
            any(path == STATE_BASE or '..' in path.parts or
                any(parent in paths for parent in path.parents) for path in paths)):
        raise CaptureError('state_snapshot_scope')
    return paths


def state_snapshot_exclusions(stage, policy_file):
    # Restic sees the archive paths rather than the originals seen by rsync.
    # The reviewed list uses only anchored paths and recursive glob patterns.
    result = []
    for line in Path(policy_file).read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        if line.startswith('/'):
            result.append(str(archive_path(stage, line)))
        elif line.startswith('**/'):
            result.append(line)
        else:
            raise CaptureError('snapshot_exclude_shape')
    return result


def verify_state_snapshot_mount(target, device_number, relative):
    raw = command(['/usr/bin/findmnt', '--json', '--mountpoint', str(target),
                   '--output', 'FSTYPE,OPTIONS,MAJ:MIN,FSROOT'])
    entries = json.loads(raw).get('filesystems', [])
    if (len(entries) != 1 or entries[0]['fstype'] != 'ext4' or
            entries[0]['maj:min'] != device_number or entries[0]['fsroot'] != str(relative) or
            not {'ro', 'nosuid', 'nodev', 'noexec'} <= set(entries[0]['options'].split(','))):
        raise CaptureError('state_snapshot_mount_identity')


def state_snapshot_mount(policy, device, snapshot_root, stage, *, capture=None):
    """Project cold trees from a verified snapshot partition without copying.

    The caller must own a private mount namespace and a read-only block
    attachment already verified against the storage producer's capture receipt.
    This function does not attach, freeze, or take a storage-host snapshot.
    The caller must unmount all projections before releasing the block source.
    """
    paths = state_snapshot_roots(policy)
    require_private_mounts()
    device = safe_source(device)
    metadata = device.stat()
    if not stat.S_ISBLK(metadata.st_mode):
        raise CaptureError('state_snapshot_device')
    device_number = f'{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}'
    if command(['/usr/sbin/blockdev', '--getro', str(device)]).strip() != b'1':
        raise CaptureError('state_snapshot_device_writable')
    # The UUID binds the filesystem to policy, not the snapshot to the capture:
    # a snapshot deliberately inherits the origin's UUID. The attacher checks
    # snapshot ownership and identity independently before this step.
    identities = [mount['identity'] for mount in policy['capture']['mounts'] if mount['path'] == str(STATE_BASE)]
    properties = command(['/usr/sbin/tune2fs', '-l', str(device)]).decode()
    fields = dict(line.split(':', 1) for line in properties.splitlines() if ':' in line)
    if (len(identities) != 1 or identities[0].get('fstype') != 'ext4' or
            fields.get('Filesystem UUID', '').strip() != identities[0].get('uuid')):
        raise CaptureError('state_snapshot_filesystem_identity')
    if (not fields.get('Filesystem features', '').split() or fields.get('Filesystem state', '').strip() != 'clean'
            or 'needs_recovery' in fields['Filesystem features'].split()):
        raise CaptureError('state_snapshot_requires_recovery')
    root = safe_source(snapshot_root)
    if any(root.iterdir()) or root.is_relative_to(stage):
        raise CaptureError('state_snapshot_root_not_private')
    targets = [empty_snapshot_target(stage, path) for path in paths]
    mounted = []
    try:
        command(['/usr/bin/mount', '-n', '-t', 'ext4', '-o',
                 'ro,noload,nosuid,nodev,noexec', str(device), str(root)])
        mounted.append(root)
        verify_state_snapshot_mount(root, device_number, Path('/'))
        for path, target in zip(paths, targets):
            relative = path.relative_to(STATE_BASE)
            source = safe_source(root / relative)
            if not source.is_dir() or source.stat().st_dev != root.stat().st_dev:
                raise CaptureError('state_snapshot_path')
            command(['/usr/bin/mount', '-n', '--bind', str(source), str(target)])
            mounted.append(target)
            verify_state_snapshot_mount(target, device_number, Path('/') / relative)
        mounted.extend(wolf_snapshot_mount(policy, root, stage, device_number, capture))
        return tuple(mounted)
    except BaseException:
        state_snapshot_unmount(mounted)
        raise


def state_snapshot_unmount(mounts):
    for target in reversed(mounts):
        command(['/usr/bin/umount', '--', str(target)])


STATE_NBD_PORT = 2445
STATE_NBD = '/dev/nbd15'
STATE_MAPPING = 'home-lab-restic-state'
STATE_LV_ID = r'[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{4}){5}-[A-Za-z0-9]{6}'


def state_snapshot_record(policy, value, capture, owner):
    if (not isinstance(value, dict) or set(value) != {'capture', 'owner', 'id', 'created', 'bytes'} or
            value['capture'] != capture or value['owner'] != owner or
            not re.fullmatch(STATE_LV_ID, str(value['id'])) or
            type(value['created']) is not int or value['created'] <= 0 or
            type(value['bytes']) is not int or value['bytes'] != policy['capture']['state_snapshot']['bytes']):
        raise CaptureError('state_snapshot_record')
    return value


def state_device_idle():
    sysfs = Path('/sys/class/block') / Path(STATE_NBD).name
    # An ambiguous previous attach is not ours to disconnect. Admit only an
    # unused, dedicated device with no holders, not an arbitrary kernel NBD.
    return (stat.S_ISBLK(Path(STATE_NBD).stat().st_mode) and not (sysfs / 'pid').exists() and
            (sysfs / 'size').read_text().strip() == '0' and not any((sysfs / 'holders').iterdir()))


def state_snapshot_preflight(policy, stage):
    require_private_mounts()
    state_snapshot_roots(policy)
    for name in ('qemu-nbd', 'nbd-client', 'sfdisk', 'e2fsck', 'dmsetup', 'prlimit', 'tune2fs'):
        if shutil.which(name, path='/usr/sbin:/usr/bin:/sbin:/bin') is None:
            raise CaptureError('state_snapshot_tools')
    if not state_device_idle() or state_attachment_path(stage).exists():
        raise CaptureError('state_snapshot_attachment_requires_inspection')
    result = zfs_call(zfs_spec(policy), {'action': 'state-list'})
    if result != {'snapshots': [], 'admissible': True}:
        raise CaptureError('state_snapshot_not_admissible')


def state_attachment_path(stage):
    return Path(stage).parent / 'state-attachment'


def state_partition(policy):
    geometry = policy['capture']['state_snapshot']
    table = json.loads(command(['/usr/sbin/sfdisk', '--json', STATE_NBD]))['partitiontable']
    partitions = table['partitions']
    sector = table['sectorsize']
    if (not isinstance(sector, int) or sector != 512 or table['label'] != 'gpt' or len(partitions) != 1 or
            int(command(['/usr/sbin/blockdev', '--getsize64', STATE_NBD])) != geometry['bytes']):
        raise CaptureError('state_snapshot_partition_table')
    partition = partitions[0]
    offset, size = partition['start'] * sector, partition['size'] * sector
    if (partition['uuid'].lower() != geometry['partition_uuid'] or offset != geometry['offset'] or
            size != geometry['partition_bytes'] or offset <= 0 or size <= 0 or offset + size > geometry['bytes']):
        raise CaptureError('state_snapshot_partition_identity')
    return offset, size


def replay_snapshot_journal(device):
    # -E journal_only must never target the live disk or remote read-only LV.
    # The caller owns the private COW partition. Do not auto-repair filesystem
    # errors; accept only successful replay or no replay needed.
    result = subprocess.run(['/usr/sbin/e2fsck', '-p', '-E', 'journal_only', device], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=120, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode not in {0, 1}:
        raise CaptureError('state_snapshot_replay_failed')
    command(['/usr/sbin/blockdev', '--setro', device])


@contextmanager
def state_snapshot_attached(policy, record, stage):
    """Attach one immutable export, replay only into a bounded scratch COW."""
    require_private_mounts()
    if not state_device_idle():
        raise CaptureError('state_snapshot_attachment_requires_inspection')
    scratch = state_attachment_path(stage)
    scratch.mkdir(mode=0o700)
    endpoint = scratch / 'nbd.sock'
    root = scratch / 'root'
    root.mkdir(mode=0o700)
    process, partition, attached, mounts = None, None, False, ()
    try:
        # A 1 GiB file-size limit is ample for journal replay and fails closed
        # on larger writes; qemu opens the remote backing export read-only.
        spec = zfs_spec(policy)
        options = ('driver=raw,file.driver=nbd,file.server.type=inet,file.server.host=' + spec['broker_ipv4'] +
                   ',file.server.port=' + str(STATE_NBD_PORT) + ',file.export=' + record['capture'])
        process = subprocess.Popen(['/usr/bin/prlimit', '--fsize=1073741824:1073741824', '--',
                                    '/usr/bin/qemu-nbd', '--snapshot', '--socket', str(endpoint), '--persistent',
                                    '--image-opts', options], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                                                  'LC_ALL': 'C', 'TMPDIR': str(scratch)})
        deadline = time.monotonic() + 20
        while not endpoint.is_socket():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise CaptureError('state_snapshot_export_unavailable')
            time.sleep(.1)
        # Mark attempt before attaching: failed or interrupted ioctl delivery
        # must retain scratch if the dedicated device still has an active peer.
        attached = True
        # Use netlink for a synchronous attachment. Legacy -L can return
        # before the background client has made the device readable.
        result = subprocess.run(['/usr/sbin/nbd-client', '-t', '15', '-u', str(endpoint), STATE_NBD],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise CaptureError('state_snapshot_attach_failed')
        offset, size = state_partition(policy)
        rdev = Path(STATE_NBD).stat().st_rdev
        table = f'0 {size // 512} linear {os.major(rdev)}:{os.minor(rdev)} {offset // 512}'
        command(['/usr/sbin/dmsetup', 'create', STATE_MAPPING, '--table', table])
        partition = STATE_MAPPING
        actual = command(['/usr/sbin/dmsetup', 'table', STATE_MAPPING]).decode().strip()
        if actual != table:
            raise CaptureError('state_snapshot_partition_device')
        identifier = command(['/usr/sbin/dmsetup', 'info', '-c', '--noheadings', '--separator', ':',
                              '-o', 'major,minor', STATE_MAPPING]).strip()
        if not re.fullmatch(rb'[0-9]+:[0-9]+', identifier):
            raise CaptureError('state_snapshot_partition_device')
        major, minor = map(int, identifier.split(b':'))
        # A private node avoids races with host device aliases and also works
        # before udev has populated the device mapper's /dev links.
        partition_device = scratch / 'partition'
        os.mknod(partition_device, stat.S_IFBLK | 0o600, os.makedev(major, minor))
        replay_snapshot_journal(str(partition_device))
        mounts = state_snapshot_mount(policy, partition_device, root, stage, capture=record['capture'])
        yield mounts, partition_device
    finally:
        # Failure to unmount/detach is an inspection gate, never permission
        # to disconnect a possibly active reader or destroy its remote LV.
        state_snapshot_unmount(mounts)
        if partition:
            if command(['/usr/sbin/dmsetup', 'table', STATE_MAPPING]).decode().strip() != table:
                raise CaptureError('state_snapshot_partition_device')
            command(['/usr/sbin/dmsetup', 'remove', STATE_MAPPING])
        if attached and not state_device_idle():
            sysfs = Path('/sys/class/block') / Path(STATE_NBD).name
            if any((sysfs / 'holders').iterdir()):
                raise CaptureError('state_snapshot_attachment_requires_inspection')
            command(['/usr/sbin/nbd-client', '-d', STATE_NBD])
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        deadline = time.monotonic() + 5
        while not state_device_idle():
            if time.monotonic() >= deadline:
                raise CaptureError('state_snapshot_attachment_requires_inspection')
            time.sleep(.1)
        if endpoint.is_socket():
            endpoint.unlink()
        (scratch / 'partition').unlink(missing_ok=True)
        root.rmdir()
        scratch.rmdir()


def sqlite_backup(source, target, *, reader=None):
    safe_source(source)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = target.with_name(target.name + '.partial')
    temporary.unlink(missing_ok=True)
    try:
        with (nullcontext(reader) if reader is not None else
              closing(sqlite3.connect('file:' + str(source) + '?mode=ro', uri=True, timeout=10))) as reader:
            with closing(sqlite3.connect(temporary)) as writer:
                deadline = time.monotonic() + 300
                def progress(*_):
                    if time.monotonic() > deadline:
                        raise CaptureError('sqlite_timeout')
                # Finish in one native step. Chunked reads can repeatedly restart
                # on a read-only WAL heap-index, even without application writes.
                reader.backup(writer, pages=-1, progress=progress)
                writer.execute('PRAGMA journal_mode=DELETE')
                if writer.execute('PRAGMA quick_check').fetchone() != ('ok',):
                    raise CaptureError('sqlite_integrity')
        os.chmod(temporary, 0o600)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def database_dump(spec, target):
    """Use native in-image clients; passwords are read inside the container."""
    if spec['engine'] == 'postgres':
        argv = ['sh', '-ec', 'exec pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB"']
    elif spec['engine'] == 'mariadb':
        # Pass a protected options file, not a password in argv/output. Container
        # /tmp is private; trap removes the file on both success and failure.
        # Quote option-file values and escape their native syntax, not shell
        # syntax. Command substitution matches the image's password-file reader
        # by stripping trailing newlines before encoding embedded control bytes.
        argv = ['sh', '-ec', 'umask 077; f=$(mktemp); trap \'rm -f "$f"\' EXIT; '
                'p=${MARIADB_ROOT_PASSWORD_FILE:-$MYSQL_ROOT_PASSWORD_FILE}; '
                r"""password=$(printf '%s' "$(cat "$p")" | """
                r"""sed ':a;$!{N;ba;};s/\\/\\\\/g;s/"/\\"/g;s/\n/\\n/g;s/\r/\\r/g;s/\t/\\t/g'); """
                'printf \'[client]\\nuser=root\\npassword="%s"\\n\' "$password" > "$f"; '
                'mariadb-dump --defaults-extra-file="$f" --single-transaction --quick '
                '--routines --events --triggers --hex-blob --default-character-set=utf8mb4 '
                '"${MARIADB_DATABASE:-$MYSQL_DATABASE}"']
    else:
        raise CaptureError('database_engine')
    with target.open('wb') as output:
        command(['/usr/bin/docker', 'exec', spec['container'], *argv], output)
        output.flush()
        os.fsync(output.fileno())
    if target.stat().st_size == 0:
        raise CaptureError('empty_dump')


def acme_store(source, target):
    """Capture a small native JSON store online without interrupting ingress."""
    source = safe_source(source)
    def capture():
        before = source.stat()
        raw = source.read_bytes()
        after = source.stat()
        if ((before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_ino, after.st_size, after.st_mtime_ns) or raw != source.read_bytes()):
            raise CaptureError('json_store_changed')
        try:
            value = json.loads(raw)
        except ValueError:
            raise CaptureError('json_store_invalid') from None
        if not isinstance(value, dict) or not value:
            raise CaptureError('json_store_invalid')
        accounts = [v for v in value.values() if isinstance(v, dict) and isinstance(v.get('Account'), dict)]
        if not accounts or any(not isinstance(v['Account'].get('PrivateKey'), str) or not v['Account']['PrivateKey'] for v in accounts):
            raise CaptureError('acme_account_key_missing')
        if any(not c.get('key') for v in accounts for c in v.get('Certificates', [])):
            raise CaptureError('acme_certificate_key_missing')
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(raw)
        target.chmod(0o600)
    retry(capture)


def cli_auth(source, target):
    """No service stop. Cooperate with Codex native per-file flock and validate."""
    source = safe_source(source)
    target.mkdir(parents=True, mode=0o700)
    def capture():
        for old in target.glob('*.json'):
            old.unlink()
        names = sorted(p.name for p in source.glob('*.json'))
        if not names:
            raise CaptureError('empty_auth_inventory')
        for name in names:
            path = safe_source(source / name)
            lock = path.with_name(name + '.lock')
            # Existing native locks only: do not alter the service directory.
            if lock.exists():
                safe_source(lock)
                metadata = lock.stat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise CaptureError('auth_lock_type')
                with lock.open('rb') as stream:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise CaptureError('auth_lock_timeout')
                            time.sleep(.05)
                    raw = path.read_bytes()
            else:
                raw = path.read_bytes()
                if raw != path.read_bytes():
                    raise CaptureError('auth_changed')
            try:
                value = json.loads(raw)
            except ValueError:
                raise CaptureError('auth_json') from None
            if not isinstance(value, dict) or not value:
                raise CaptureError('auth_json')
            destination = target / name
            destination.write_bytes(raw)
            destination.chmod(0o600)
        if names != sorted(p.name for p in source.glob('*.json')):
            raise CaptureError('auth_inventory_changed')
    retry(capture)


def jellyfin_endpoint():
    """Use the managed container's actual host binding, never an assumed listener."""
    raw = command(['/usr/bin/docker', 'inspect', '--format', '{{json .NetworkSettings.Ports}}', 'jellyfin'])
    try:
        bindings = json.loads(raw)['8096/tcp']
        if not isinstance(bindings, list) or len(bindings) != 1:
            raise ValueError
        host, port = bindings[0]['HostIp'], bindings[0]['HostPort']
        if not isinstance(host, str) or not isinstance(port, str):
            raise ValueError
        address, port = ipaddress.ip_address(host), int(port)
        if not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise CaptureError('jellyfin_port_binding') from None
    if address.is_unspecified:
        address = ipaddress.ip_address('127.0.0.1' if address.version == 4 else '::1')
    host = '[' + str(address) + ']' if address.version == 6 else str(address)
    return 'http://' + host + ':' + str(port)


def jellyfin(source, target):
    """Use existing server API key privately, never create a credential in backup."""
    source = safe_source(source)
    with closing(sqlite3.connect('file:' + str(source / 'data/jellyfin.db') + '?mode=ro', uri=True)) as db:
        row = db.execute('SELECT AccessToken FROM ApiKeys ORDER BY Id LIMIT 1').fetchone()
    if not row or not row[0]:
        raise CaptureError('jellyfin_backup_api_key_missing')
    before = set((source / 'data/backups').glob('*.zip'))
    request = urllib.request.Request(jellyfin_endpoint() + '/Backup/Create', method='POST',
        headers={'Authorization': 'MediaBrowser Token="' + urllib.parse.quote(row[0], safe='') + '"',
                 'Content-Type': 'application/json'},
        data=json.dumps({'Metadata': True, 'Subtitles': True, 'Trickplay': False}).encode())
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=1800) as response:
            if response.status != 200:
                raise CaptureError('jellyfin_backup')
            response.read(1024 * 1024)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        # Authentication refusals are known; other POST failures can be ambiguous.
        raise CaptureError('jellyfin_backup_auth' if status in {401, 403}
                           else 'jellyfin_backup_ambiguous') from None
    except OSError:
        # POST may have completed: do not blindly repeat it.
        raise CaptureError('jellyfin_backup_ambiguous') from None
    archives = set((source / 'data/backups').glob('*.zip')) - before
    if len(archives) != 1:
        raise CaptureError('jellyfin_backup_inventory')
    archive = safe_source(archives.pop())
    with zipfile.ZipFile(archive) as zipped:
        if zipped.testzip() is not None:
            raise CaptureError('jellyfin_backup_integrity')
    shutil.copyfile(archive, target)
    target.chmod(0o600)
    # Only our completed, copied archive is temporary; existing native backups stay.
    # The container's mount namespace remains writable while the capture service's
    # source tree stays read-only under ProtectSystem=strict. No shell or token argv.
    command(['/usr/bin/docker', 'exec', 'jellyfin', '/bin/rm', '--', '/config/data/backups/' + archive.name])


@contextmanager
def frozen_radio_copy(path, scratch):
    # Even after a clean stop, SQLite's WAL header may need a new shared-memory
    # index. Let SQLite recover only a small private copy of the frozen bytes.
    # Never use `immutable=1` to bypass normal WAL/rollback recovery checks.
    members = []
    total = 0
    for suffix in ('', '-wal', '-journal'):
        source = path.with_name(path.name + suffix)
        try:
            info = source.lstat()
        except FileNotFoundError:
            if suffix:
                continue
            raise
        if not stat.S_ISREG(info.st_mode):
            raise CaptureError('zha_backup_source_type')
        total += info.st_size
        if total > 64 * 1024**2:
            raise CaptureError('zha_backup_scratch_limit')
        members.append(source)
    with tempfile.TemporaryDirectory(prefix='.radio-check-', dir=scratch) as directory:
        for source in members:
            shutil.copyfile(safe_source(source), Path(directory) / source.name)
        yield Path(directory) / path.name


def radio_check(files, max_age, *, snapshot_scratch=None):
    """Validate native outputs without touching/resetting either radio."""
    now = time.time()
    nvm = Path(files) / 'srv/home-lab-state/zwave-data/backups/nvm'
    candidates = [p for p in nvm.glob('NVM_*') if p.is_file() and not p.is_symlink() and p.stat().st_size]
    if not candidates or not 0 <= now - max(p.stat().st_mtime for p in candidates) <= max_age:
        raise CaptureError('zwave_nvm_stale')
    path = Path(files) / 'srv/home-lab-state/hass-data/zigbee.db'
    selected = frozen_radio_copy(path, snapshot_scratch) if snapshot_scratch is not None else nullcontext(path)
    mode = 'rw' if snapshot_scratch is not None else 'ro'
    try:
        with selected as source, closing(sqlite3.connect(source.as_uri() + '?mode=' + mode, uri=True)) as db:
            names = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            tables = [n for n in names if re.fullmatch(r'network_backups_v[0-9]+', n)]
            if not tables:
                raise CaptureError('zha_backup_missing')
            table = max(tables, key=lambda n: int(n.rsplit('v', 1)[1]))
            from datetime import datetime
            timestamps = [datetime.fromisoformat(json.loads(r[0])['backup_time']).timestamp()
                          for r in db.execute('SELECT backup_json FROM ' + table)]
    except CaptureError:
        raise
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
        raise CaptureError('zha_backup_invalid') from None
    if not timestamps or not 0 <= now - max(timestamps) <= max_age:
        raise CaptureError('zha_backup_stale')


def wolf_idle(container):
    mounts = json.loads(command(['/usr/bin/docker', 'inspect', '--format', '{{json .Mounts}}', container]))
    locations = [Path(m['Source']) / 'wolf.sock' for m in mounts if m.get('Destination') == '/run/user/wolf']
    if len(locations) != 1 or not stat.S_ISSOCK(safe_source(locations[0]).stat().st_mode):
        raise CaptureError('wolf_management_socket')
    for kind in ('sessions', 'lobbies'):
        with closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as stream:
            stream.settimeout(10)
            stream.connect(str(locations[0]))
            with closing(http.client.HTTPConnection('localhost', timeout=10)) as connection:
                connection.sock = stream
                connection.request('GET', '/api/v1/' + kind)
                try:
                    response = connection.getresponse()
                    body = json.loads(response.read(1024 * 1024))
                except http.client.HTTPException:
                    raise CaptureError('wolf_api_response') from None
                if response.status != 200 or body.get('success') is not True or body.get(kind) != []:
                    raise CaptureError('wolf_not_idle')


WOLF_PREFIX_ROOTS = ('user.reg', 'userdef.reg', 'system.reg',
                     'drive_c/users/steamuser/Documents', 'drive_c/users/steamuser/Saved Games',
                     'drive_c/users/steamuser/AppData/Roaming', 'drive_c/users/steamuser/AppData/Local',
                     'drive_c/users/steamuser/AppData/LocalLow')
WOLF_SNAPSHOT_RECEIPT = 'wolf-pilot-source.json'


def wolf_pilot_binding(step):
    spec = step['wolf_pilot']
    if (not isinstance(spec, dict) or set(spec) - {'profile', 'app_id', 'snapshot'}
            or not {'profile', 'app_id'} <= spec.keys()
            or ('snapshot' in spec and spec['snapshot'] is not True)
            or not isinstance(spec['profile'], list) or len(spec['profile']) != 2
            or any(not isinstance(part, str) or part in {'.', '..'}
                   or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', part) for part in spec['profile'])
            or not isinstance(spec['app_id'], str) or not re.fullmatch(r'[1-9][0-9]{0,9}', spec['app_id'])
            or int(spec['app_id']) > 2**32 - 1):
        raise CaptureError('wolf_pilot_scope')
    profile = Path(step['wolf']) / 'profile-data' / Path(*spec['profile'])
    if not profile.is_absolute() or '..' in profile.parts:
        raise CaptureError('wolf_pilot_scope')
    legacy = tuple(profile / store / 'steamapps/compatdata' / spec['app_id']
                   for store in ('.steam/steam', '.local/share/Steam'))
    return legacy, STATE_BASE / 'wolf-pilot/compatdata' / spec['app_id']


def verify_wolf_pilot(policy, step):
    """Admit exactly one native read-only view over a retained legacy prefix."""
    require_private_mounts()
    choices, active = wolf_pilot_binding(step)
    try:
        legacy = safe_source(choices[0].resolve(strict=True))
        if legacy not in choices:
            raise CaptureError('wolf_pilot_scope')
        active = safe_source(active)
        if not legacy.is_dir() or not active.is_dir():
            raise CaptureError('wolf_pilot_scope')
        identities = [m['identity'] for m in policy['capture']['mounts'] if m['path'] == str(STATE_BASE)]
        if len(identities) != 1 or identities[0].get('fstype') != 'ext4' or not identities[0].get('uuid'):
            raise CaptureError('wolf_pilot_state_identity')
        raw = command(['/usr/bin/findmnt', '--list', '--json', '--output', 'TARGET,FSROOT,FSTYPE,UUID,OPTIONS'])
        mounts = json.loads(raw)['filesystems']
        base_rows = [m for m in mounts if m['target'] == str(STATE_BASE)]
        legacy_rows = [m for m in mounts if m['target'] == str(legacy)]
        uuid = identities[0]['uuid']
        if (len(base_rows) != 1 or base_rows[0]['fsroot'] != '/' or base_rows[0]['uuid'] != uuid
                or base_rows[0]['fstype'] != 'ext4'):
            raise CaptureError('wolf_pilot_state_identity')
        if (len(legacy_rows) != 1 or legacy_rows[0]['fsroot'] != '/' + str(active.relative_to(STATE_BASE))
                or legacy_rows[0]['uuid'] != uuid or legacy_rows[0]['fstype'] != 'ext4'
                or 'ro' not in legacy_rows[0]['options'].split(',')
                or not os.path.samestat(legacy.stat(), active.stat())):
            raise CaptureError('wolf_pilot_mount_identity')
        if any((target := Path(m['target'])).is_relative_to(active)
               or (target != legacy and target.is_relative_to(legacy))
               or (target != STATE_BASE and target.is_relative_to(STATE_BASE) and active.is_relative_to(target))
               for m in mounts):
            raise CaptureError('wolf_pilot_nested_mount')
        registry = safe_source(legacy / 'pfx/user.reg').lstat()
        if not stat.S_ISREG(registry.st_mode) or not registry.st_size:
            raise CaptureError('wolf_pilot_prefix_missing')
    except CaptureError:
        raise
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        raise CaptureError('wolf_pilot_mount_identity') from None
    return legacy, active


def wolf_snapshot_step(policy):
    steps = [s for s in policy['capture']['cold'] if isinstance(s.get('wolf_pilot'), dict)
             and s['wolf_pilot'].get('snapshot') is True]
    if len(steps) > 1 or (steps and (not steps[0].get('wolf') or not policy['capture'].get('state_snapshot')
                                    or not policy['capture'].get('zfs'))):
        raise CaptureError('wolf_pilot_snapshot_scope')
    return steps[0] if steps else None


def wolf_snapshot_members(prefix):
    """Only the exact registry files and user directories already selected for Wolf."""
    members = []
    for relative in WOLF_PREFIX_ROOTS:
        path = prefix / 'pfx' / relative
        try:
            row = path.lstat()
        except FileNotFoundError:
            continue
        regular = '/' not in relative
        if not (stat.S_ISREG(row.st_mode) if regular else stat.S_ISDIR(row.st_mode)):
            raise CaptureError('wolf_pilot_snapshot_member_type')
        if relative == 'user.reg' and not row.st_size:
            raise CaptureError('wolf_pilot_snapshot_members_missing')
        safe_source(path)
        members.append(relative)
    if 'user.reg' not in members:
        raise CaptureError('wolf_pilot_snapshot_members_missing')
    return members


def wolf_snapshot_selection(legacy, paths, mappings, capture):
    members = wolf_snapshot_members(legacy)
    roots = [legacy / 'pfx' / relative for relative in members]
    copied = []
    for value in paths:
        path = Path(value)
        if path.is_relative_to(legacy):
            if not any(path.is_relative_to(root) for root in roots):
                raise CaptureError('wolf_pilot_snapshot_unqualified_target')
        elif (any(root.is_relative_to(path) for root in roots)
              and not (path == legacy.parents[3] and path.name == 'share' and path.parent.name == '.local')):
            raise CaptureError('wolf_pilot_snapshot_overlapping_copy')
        else:
            copied.append(value)
    if not set(map(str, roots)) <= set(paths):
        raise CaptureError('wolf_pilot_snapshot_selection')
    for original, value in mappings.items():
        link = Path(original)
        # Resolve only ancestors: the final name can be a link whose target is
        # deliberately outside the pilot and therefore not qualified.
        location = link.parent.resolve() / link.name
        if location.is_relative_to(legacy) != Path(value['resolved']).is_relative_to(legacy):
            raise CaptureError('wolf_pilot_snapshot_cross_link')
    return copied, {'capture': capture, 'legacy': str(legacy), 'members': members}


def wolf_snapshot_mount(policy, root, stage, device_number, capture):
    step = wolf_snapshot_step(policy)
    if step is None:
        return ()
    require_private_mounts()
    choices, active = wolf_pilot_binding(step)
    try:
        receipt = safe_source(Path(stage) / WOLF_SNAPSHOT_RECEIPT)
        row = receipt.lstat()
        if (not stat.S_ISREG(row.st_mode) or row.st_uid != os.geteuid() or row.st_nlink != 1
                or stat.S_IMODE(row.st_mode) != 0o600 or not 0 < row.st_size <= 4096):
            raise CaptureError('wolf_pilot_snapshot_receipt')
        plan = json.loads(receipt.read_text())
        if (not isinstance(plan, dict) or set(plan) != {'capture', 'legacy', 'members'}
                or not re.fullmatch(r'[0-9a-f]{32}', capture or '') or plan['capture'] != capture
                or not isinstance(plan['legacy'], str) or str(Path(plan['legacy'])) != plan['legacy']
                or Path(plan['legacy']) not in choices):
            raise CaptureError('wolf_pilot_snapshot_receipt')
    except (OSError, ValueError, TypeError):
        raise CaptureError('wolf_pilot_snapshot_receipt') from None
    relative = active.relative_to(STATE_BASE)
    prefix = safe_source(root / relative)
    members = wolf_snapshot_members(prefix)
    if plan['members'] != members:
        raise CaptureError('wolf_pilot_snapshot_selection_mismatch')
    legacy = Path(plan['legacy'])
    mounted = []
    try:
        for member in members:
            source = prefix / 'pfx' / member
            if source.stat().st_dev != root.stat().st_dev:
                raise CaptureError('wolf_pilot_snapshot_source')
            target = empty_snapshot_target(stage, legacy / 'pfx' / member, regular='/' not in member)
            command(['/usr/bin/mount', '-n', '--bind', str(source), str(target)])
            mounted.append(target)
            verify_state_snapshot_mount(target, device_number, Path('/') / relative / 'pfx' / member)
        return tuple(mounted)
    except BaseException:
        state_snapshot_unmount(mounted)
        raise


def wolf_paths(base):
    """Selective host paths, not Steam installations or whole Proton prefixes.

    Save-bearing Proton user folders and registry files are preserved. Unknown
    symlinks resolve only inside the owned Wolf tree; external targets refuse.
    """
    base = safe_source(base)
    paths = [base / 'cfg']
    for profile in sorted((base / 'profile-data').glob('*/*')):
        if not profile.is_dir() or profile.is_symlink():
            raise CaptureError('wolf_profile_type')
        for relative in ('.config', '.local/share', 'ES-DE', '.steam/steam/userdata'):
            candidate = profile / relative
            if candidate.exists() or candidate.is_symlink():
                paths.append(candidate)
        compat = profile / '.steam/steam/steamapps/compatdata'
        for prefix in compat.glob('*/pfx'):
            for relative in WOLF_PREFIX_ROOTS:
                candidate = prefix / relative
                if candidate.exists() or candidate.is_symlink():
                    paths.append(candidate)
    # rsync preserves links but does not capture their targets. Inspect resolved
    # directories too, including targets discovered through other save links.
    resolved = set()
    scanned = set()
    links = {}
    pending = list(paths)
    while pending:
        path = pending.pop()
        # Wolf mounts each owned profile at /home/retro in the app container.
        # Absolute launcher/icon links must be translated, not mistaken for host
        # /home links or ignored. Other external mappings remain unqualified.
        try:
            if path.is_symlink() and Path(os.readlink(path)).is_relative_to('/home/retro'):
                relative = path.relative_to(base / 'profile-data')
                profile = base / 'profile-data' / relative.parts[0] / relative.parts[1]
                target = profile / Path(os.readlink(path)).relative_to('/home/retro')
                actual = target.resolve(strict=True)
                if actual.is_dir() and not any(actual.is_relative_to(p.resolve()) for p in paths if not p.is_symlink()):
                    raise CaptureError('wolf_unqualified_directory_target')
            else:
                actual = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise CaptureError('wolf_broken_save_target') from None
        if not actual.is_relative_to(base):
            raise CaptureError('wolf_external_save_target')
        resolved.add(str(actual))
        if actual != path:
            links[str(path)] = {'resolved': str(actual), 'target': os.readlink(path) if path.is_symlink() else str(actual)}
        if actual.is_dir():
            for current, dirs, names in os.walk(actual, followlinks=False):
                current = Path(current)
                if current in scanned:
                    dirs[:] = []
                    continue
                scanned.add(current)
                # Steam installations are bulk; explicit userdata/prefix paths
                # above own saves. Keep this exclusion after resolving aliases.
                if current.name == 'share' and current.parent.name == '.local':
                    dirs[:] = [d for d in dirs if d != 'Steam']
                for name in [*dirs, *names]:
                    child = current / name
                    if child.is_symlink():
                        pending.append(child)
    return sorted(resolved), links


def capacity_check(policy):
    paths = list(policy['capture']['live_files']) + [policy['capture']['cli_auth'], policy['capture']['jellyfin']]
    paths.extend(policy['capture']['estimate_paths'])
    paths.extend(policy['capture']['online_json'])
    paths.extend(policy['capture'].get('online_stores', []))
    for step in policy['capture'].get('online', []):
        paths.extend(step['paths'])
    snapshot_paths = set(zfs_paths()) if policy['capture'].get('zfs') else set()
    if policy['capture'].get('state_snapshot'):
        snapshot_paths.update(map(str, state_snapshot_roots(policy)))
    for step in policy['capture']['cold']:
        paths.extend(path for path in step['paths'] if path not in snapshot_paths)
        if step.get('wolf'):
            selected, _ = wolf_paths(step['wolf'])
            paths.extend(selected)
    # Native du does not follow links into bulk game installations. Conservative
    # bytes plus reserve must fit staging before any service is stopped.
    raw = command(['/usr/bin/du', '--summarize', '--total', '--apparent-size', '--block-size=1',
                   '--exclude-from=' + policy['runner']['exclude_file_path'], '--', *sorted(set(paths))])
    sizes = dict((line.split('\t', 1)[1], int(line.split('\t', 1)[0])) for line in raw.decode().splitlines())
    size = sizes['total']
    # Jellyfin first creates its native archive on its own filesystem. Budget
    # that temporary archive too; staging capacity alone is insufficient.
    jelly = policy['capture']['jellyfin']
    if shutil.disk_usage(jelly).free < sizes[jelly] * 2 + policy['capture']['reserve_bytes']:
        raise CaptureError('native_archive_capacity')
    parent = safe_source(Path(policy['capture']['stage']).parent)
    if shutil.disk_usage(parent).free < size * 2 + policy['capture']['reserve_bytes']:
        raise CaptureError('capture_capacity')


def fresh_stage(path, reserve):
    """Stable location simplifies snapshots/restore. Stale captures require review."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise CaptureError('previous_capture_requires_inspection')
    parent = safe_source(path.parent)
    if parent.stat().st_uid != os.geteuid() or parent.stat().st_mode & 0o022:
        raise CaptureError('capture_parent')
    if shutil.disk_usage(parent).free < reserve:
        raise CaptureError('capture_capacity')
    path.mkdir(mode=0o700)
    for child in ('files', 'databases', 'native'):
        (path / child).mkdir(mode=0o700)
    return path
