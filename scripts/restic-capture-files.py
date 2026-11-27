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
from typing import NamedTuple
import urllib.error
import urllib.parse
import urllib.request
import zipfile


class CaptureError(ValueError):
    pass


ONLINE_SOURCE_RETRY_DELAYS = (2, 4, 8, 12, 16)


def retry(operation, attempts=3):
    """Retry transient capture operations, with progressive backoff on live file churn."""
    base_attempts = max(1, attempts)
    churn_limit = 1 if attempts <= 1 else max(base_attempts, len(ONLINE_SOURCE_RETRY_DELAYS) + 1)
    churn_failures = 0
    non_churn_failures = 0
    while True:
        try:
            return operation()
        except (OSError, sqlite3.Error, CaptureError) as error:
            is_source_churn = isinstance(error, CaptureError) and str(error) == 'online_source_changed'
            if is_source_churn:
                churn_failures += 1
                if churn_failures >= churn_limit:
                    raise CaptureError('capture_phase_failed') from None
                delay = ONLINE_SOURCE_RETRY_DELAYS[min(churn_failures - 1, len(ONLINE_SOURCE_RETRY_DELAYS) - 1)]
            else:
                non_churn_failures += 1
                if non_churn_failures >= base_attempts:
                    raise CaptureError('capture_phase_failed') from None
                delay = 2
            time.sleep(delay)


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


def copy_paths(paths, target, excludes, online_sqlite=False, *, exclude=(), synchronize=False, checksum=False):
    for path in paths:
        safe_source(path)
    options = ['--exclude=' + str(path) for path in exclude]
    if online_sqlite:
        options.extend(['--exclude=*.db', '--exclude=*.db-wal', '--exclude=*.db-shm', '--exclude=*.db-journal'])
    if synchronize:
        options.extend(['--delete-delay', '--modify-window=-1'])
    if checksum:
        options.append('--checksum')
    command(['/usr/bin/rsync', '--archive', '--relative', '--numeric-ids', '--hard-links', '--acls', '--xattrs',
             '--exclude-from=' + str(excludes), *options, '--', *paths, str(target) + '/'])


def _glob_to_regex(pattern):
    parts = ['^']
    index = 0
    while index < len(pattern):
        if pattern[index:index + 3] == '**/' and (index == 0 or pattern[index - 1] == '/'):
            parts.append('(?:.*/)?')
            while pattern[index:index + 3] == '**/':
                index += 3
        elif pattern[index:index + 2] == '**':
            parts.append('.*')
            index += 2
        elif pattern[index] == '*':
            parts.append('[^/]*')
            index += 1
        elif pattern[index] == '?':
            parts.append('[^/]')
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return ''.join(parts)


class ExcludeRule(NamedTuple):
    pattern: re.Pattern[str]
    child_pattern: re.Pattern[str] | None = None


def _iter_policy_exclude_lines(policy_file):
    for line in Path(policy_file).read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        if (not (line.startswith('/') or line.startswith('**/'))
                or line.endswith('/')
                or '//' in line
                or '***' in line
                or '**/**' in line
                or any(char in line for char in ('[', ']', '\\'))):
            raise CaptureError('snapshot_exclude_shape')
        if line.endswith('/**'):
            base = line[:-3]
            if not base or base == '**' or base.endswith('/') or base.endswith('/**'):
                raise CaptureError('snapshot_exclude_shape')
        yield line


def load_policy_excludes(policy_file, *, paths=None):
    source_strings = tuple(str(Path(path)) for path in paths) if paths is not None else None
    patterns = []
    for line in _iter_policy_exclude_lines(policy_file):
        is_subtree = line.endswith('/**')
        raw = line[:-3] if is_subtree else line
        if source_strings is not None and raw.startswith('/'):
            prefix = re.split(r'[*?]', raw, maxsplit=1)[0]
            if not any(source.startswith(prefix) or prefix.startswith(source) for source in source_strings):
                continue
        if is_subtree:
            base_regex = _glob_to_regex(raw)
            rule = ExcludeRule(
                re.compile(base_regex + r'\Z', re.DOTALL),
                re.compile(base_regex + r'/.*\Z', re.DOTALL),
            )
        else:
            rule = ExcludeRule(re.compile(_glob_to_regex(raw) + r'\Z', re.DOTALL))
        patterns.append(rule)
    return tuple(patterns)


def _path_excluded(path, excluded, policy_excludes):
    text = str(path)
    if any(path == root or root in path.parents for root in excluded):
        return True
    return any(
        (rule.child_pattern is None and rule.pattern.match(text))
        or (rule.child_pattern is not None and rule.child_pattern.match(text))
        for rule in policy_excludes
    )


def file_inventory(paths, *, exclude=(), excludes_file=None):
    """lstat only: never traverse links or inspect a file's private payload."""
    excluded = tuple(Path(path) for path in exclude)
    resolved = [safe_source(source) for source in paths]
    policy_excludes = load_policy_excludes(excludes_file, paths=resolved) if excludes_file is not None else ()
    result = {}
    for source in resolved:
        # Match rsync --relative, which evaluates non-subtree excludes against ancestor dirs too.
        if any(rule.child_pattern is None and rule.pattern.match(str(parent))
               for parent in source.parents for rule in policy_excludes):
            continue
        pending = [source]
        while pending:
            path = pending.pop()
            text = str(path)
            if _path_excluded(path, excluded, policy_excludes):
                continue
            try:
                info = path.lstat()
            except FileNotFoundError:
                if path != source:
                    raise CaptureError('online_source_changed') from None
                raise
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise CaptureError('capture_special_file')
            if stat.S_ISDIR(info.st_mode):
                if any(rule.child_pattern is not None and rule.pattern.match(text) for rule in policy_excludes):
                    # rsync `dir/**` copies `dir` itself while excluding children:
                    # verify type/identity without failing on child-churn timestamps.
                    result[text] = (info.st_mode, info.st_dev, info.st_ino, None, None, None, info.st_uid, info.st_gid)
                    continue
                try:
                    pending.extend(path.iterdir())
                except FileNotFoundError:
                    if path != source:
                        raise CaptureError('online_source_changed') from None
                    raise
            result[text] = (info.st_mode, info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid)
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
    before = file_inventory(paths, excludes_file=excludes)
    copy_paths(paths, target, excludes)
    return before


def finish_copy(paths, target, excludes, *, baseline):
    """After writer exclusion, invalidate changed seeds and synchronize natively.

    ctime/inode detect replacements and writes even if size/mtime were preserved.
    Only changed staged files are discarded; the final rsync owns deletion and
    metadata preservation. There are no hard links back to the production tree.
    """
    after = file_inventory(paths, excludes_file=excludes)
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
    before = file_inventory(step['paths'], excludes_file=excludes)
    copy_paths(step['paths'], target, excludes, synchronize=True)
    if before != file_inventory(step['paths'], excludes_file=excludes):
        raise CaptureError('online_source_changed')


def online_tree(paths, target, excludes, *, sqlite_paths, json_roots=(), ephemeral=()):
    """Native SQLite snapshots plus companion files from a write-free interval.

    Before/after inode, size, mtime and ctime checks include the databases and
    WAL/journals, not the advisory SHM read-marks. Read-only WAL connections may
    rebuild a private wal-index and advance data_version without a real commit;
    that connection-local cache epoch is not an application-write detector.
    """
    before = file_inventory(paths, exclude=ephemeral, excludes_file=excludes)
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
    after = file_inventory(paths, exclude=ephemeral, excludes_file=excludes)
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
ZFS_DATA_PATHS = ('media/nextcloud/data', 'media/frigate/exports', 'media/uchiyomi/downloads')
ZFS_PREFIX = 'home-lab-nextcloud-'
ZFS_EXPIRY = 72 * 3600
ZFS_BROKER_PORT = 2444


def _validate_online_paths(online_paths, *, base, key_error, path_error):
    if (not isinstance(online_paths, dict) or
            any(not isinstance(k, str) or not k or not isinstance(v, str) or not v
                for k, v in online_paths.items())):
        raise CaptureError(key_error)
    if (any(str(Path(v)) != v or '..' in Path(v).parts or not Path(v).is_relative_to(base) or Path(v) == base
            for v in online_paths.values()) or
            len(set(online_paths.values())) != len(online_paths)):
        raise CaptureError(path_error)
    return online_paths


def _validate_zfs_online_paths(online_paths):
    return _validate_online_paths(
        online_paths, base=ZFS_BASE, key_error='snapshot_policy', path_error='snapshot_policy',
    )


def zfs_spec(policy):
    spec = policy['capture']['zfs']
    if (not isinstance(spec, dict) or
            set(spec) - {'online_paths'} != {'dataset_guid', 'expiry_seconds', 'broker_ipv4'} or
            not re.fullmatch('[1-9][0-9]{0,19}', spec['dataset_guid']) or
            ipaddress.ip_address(spec['broker_ipv4']) not in ipaddress.ip_network('100.64.0.0/10') or
            spec['expiry_seconds'] != ZFS_EXPIRY):
        raise CaptureError('snapshot_policy')
    if 'online_paths' in spec:
        _validate_zfs_online_paths(spec['online_paths'])
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


def zfs_verify_broker_scope(policy):
    if zfs_call(zfs_spec(policy), {'action': 'scope'}) != {'paths': list(ZFS_DATA_PATHS)}:
        raise CaptureError('snapshot_broker_scope')


def archive_path(stage, path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path == Path('/'):
        raise CaptureError('snapshot_path')
    return Path(stage) / 'files' / path.relative_to('/')


def empty_snapshot_target(stage, path):
    target = archive_path(stage, path)
    parent = safe_source(Path(stage) / 'files')
    for part in target.relative_to(parent).parts:
        parent = parent / part
        if parent.is_symlink():
            raise CaptureError('snapshot_target_type')
        parent.mkdir(mode=0o700, exist_ok=True)
    result = subprocess.run(['/usr/bin/mountpoint', '--quiet', '--', str(target)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
    if result.returncode != 32:
        raise CaptureError('snapshot_target_mount')
    if any(target.iterdir()):
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


def state_snapshot_roots(shared_paths, online_paths):
    """Select only declared application trees, not the whole state volume."""
    paths = [Path(path) for path in shared_paths if Path(path).is_relative_to(STATE_BASE)]
    paths.extend(map(Path, online_paths))
    if (not paths or len(set(paths)) != len(paths) or
            any(not path.is_relative_to(STATE_BASE) or path == STATE_BASE or '..' in path.parts or
                any(parent in paths for parent in path.parents) for path in paths)):
        raise CaptureError('state_snapshot_scope')
    return paths


def state_snapshot_exclusions(stage, policy_file):
    # Restic sees the archive paths rather than the originals seen by rsync.
    # The reviewed list uses only anchored paths and recursive glob patterns.
    result = []
    for line in _iter_policy_exclude_lines(policy_file):
        if line.startswith('/'):
            result.append(str(archive_path(stage, line)))
        else:
            result.append(line)
    return result


def verify_state_snapshot_mount(target, device_number, relative):
    raw = command(['/usr/bin/findmnt', '--json', '--mountpoint', str(target),
                   '--output', 'FSTYPE,OPTIONS,MAJ:MIN,FSROOT'])
    entries = json.loads(raw).get('filesystems', [])
    if (len(entries) != 1 or entries[0]['fstype'] != 'ext4' or
            entries[0]['maj:min'] != device_number or entries[0]['fsroot'] != str(relative) or
            not {'ro', 'nosuid', 'nodev', 'noexec'} <= set(entries[0]['options'].split(','))):
        raise CaptureError('state_snapshot_mount_identity')


def state_snapshot_mount(policy, device, snapshot_root, stage, paths):
    """Project the selected trees from a verified snapshot partition without copying.

    The caller must own a private mount namespace and a read-only block
    attachment already verified against the storage producer's capture receipt.
    This function does not attach, freeze, or take a storage-host snapshot.
    The caller must unmount all projections before releasing the block source.
    """
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
def state_snapshot_attached(policy, record, stage, paths):
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
        mounts = state_snapshot_mount(policy, partition_device, root, stage, paths)
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


MARIADB_CLIENT_PROLOGUE = (
    'umask 077; f=$(mktemp); trap \'rm -f "$f"\' EXIT; '
    'trap \'rm -f "$f"; exit 130\' INT; '
    'trap \'rm -f "$f"; exit 143\' TERM; '
    'trap \'rm -f "$f"; exit 129\' HUP; '
    'p=${MARIADB_ROOT_PASSWORD_FILE:-$MYSQL_ROOT_PASSWORD_FILE}; '
    r"""password=$(printf '%s' "$(cat "$p")" | """
    r"""sed ':a;$!{N;ba;};s/\\/\\\\/g;s/"/\\"/g;s/\n/\\n/g;s/\r/\\r/g;s/\t/\\t/g'); """
    'printf \'[client]\\nuser=root\\npassword="%s"\\n\' "$password" > "$f"; '
)


NEXTCLOUD_WRITE_FD_TARGET_RE = re.compile(
    r'^(?:/var/www/html/(?:data|config|custom_apps|themes)/|/(?:tmp|var/tmp)/(?:php|oc_tmp_))'
)
NEXTCLOUD_LOG_FD_RE = re.compile(r'^/var/www/html/data/nextcloud\.log(?:\.[0-9]+)?(?: \(deleted\))?\Z')
FDINFO_FLAGS_RE = re.compile(r'^flags:\s*([0-7]+)\s*$', re.MULTILINE)


NEXTCLOUD_CRON_PROBE = (
    'busybox pidof php >/dev/null 2>&1; rc=$?; '
    '[ "$rc" -eq 0 ] && exit 10; '
    '[ "$rc" -eq 1 ] && exit 0; '
    'exit 2'
)


NEXTCLOUD_WEB_STATUS_PROBE = (
    "$ch = curl_init('http://127.0.0.1/status.php');"
    " if ($ch === false) exit(2);"
    " curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 5,"
    " CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => false]);"
    " $body = curl_exec($ch);"
    " if ($body === false || curl_getinfo($ch, CURLINFO_HTTP_CODE) !== 200) exit(1);"
    " echo $body;"
)


def _run_probe(argv, *, timeout=30):
    try:
        return subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False,
            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/var/empty', 'LC_ALL': 'C', 'TZ': 'UTC'},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CaptureError('capture_command') from None


def nextcloud_web_status(container):
    result = _run_probe(['/usr/bin/docker', 'exec', '--user', 'www-data', container,
                         'php', '-r', NEXTCLOUD_WEB_STATUS_PROBE], timeout=30)
    if result.returncode != 0:
        raise CaptureError('nextcloud_web_status')
    try:
        value = json.loads(result.stdout)
    except ValueError as error:
        raise CaptureError('nextcloud_web_status') from error
    if not isinstance(value, dict):
        raise CaptureError('nextcloud_web_status')
    return value


def nextcloud_cron_busy(container):
    result = _run_probe(['/usr/bin/docker', 'exec', container,
                         'busybox', 'sh', '-c', NEXTCLOUD_CRON_PROBE], timeout=30)
    if result.returncode == 10:
        return True
    if result.returncode == 0:
        return False
    raise CaptureError('nextcloud_drain_check')


def _container_host_pids(container):
    result = _run_probe(['/usr/bin/docker', 'top', container, '-eo', 'pid'], timeout=30)
    if result.returncode != 0:
        raise CaptureError('nextcloud_drain_check')
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(lines) < 2 or lines[0] != 'PID' or any(not (line.isascii() and line.isdigit()) or int(line) <= 0 for line in lines[1:]):
        raise CaptureError('nextcloud_drain_check')
    return [int(line) for line in lines[1:]]


def nextcloud_write_fds_busy(container, *, proc_root=Path('/proc')):
    """Inspect container worker FDs from host /proc so root has CAP_SYS_PTRACE.

    Inside a default-capability container, root cannot read www-data Apache
    worker /proc/<pid>/fd entries without CAP_SYS_PTRACE. Failing closed on
    PermissionError prevents silent false-idle results.
    """
    pids = _container_host_pids(container)
    for pid in pids:
        pid_dir = proc_root / str(pid)
        try:
            entries = list((pid_dir / 'fd').iterdir())
        except PermissionError:
            raise CaptureError('nextcloud_drain_check') from None
        except (FileNotFoundError, ProcessLookupError):
            return True
        except OSError:
            raise CaptureError('nextcloud_drain_check') from None
        for entry in entries:
            try:
                target = os.readlink(entry)
            except PermissionError:
                raise CaptureError('nextcloud_drain_check') from None
            except (FileNotFoundError, ProcessLookupError):
                continue
            except OSError:
                raise CaptureError('nextcloud_drain_check') from None
            if not NEXTCLOUD_WRITE_FD_TARGET_RE.match(target) or NEXTCLOUD_LOG_FD_RE.match(target):
                continue
            try:
                info = (pid_dir / 'fdinfo' / entry.name).read_text(encoding='utf-8', errors='replace')
            except PermissionError:
                raise CaptureError('nextcloud_drain_check') from None
            except (FileNotFoundError, ProcessLookupError):
                return True
            except OSError:
                raise CaptureError('nextcloud_drain_check') from None
            match = FDINFO_FLAGS_RE.search(info)
            if match is None or (int(match.group(1), 8) & 3) != 0:
                return True
    return False


def mariadb_idle(container):
    """Return True when no active query or open InnoDB transaction touches the DB."""
    argv = ['sh', '-ec', MARIADB_CLIENT_PROLOGUE +
            'mariadb --defaults-extra-file="$f" --connect-timeout=10 -N -B "${MARIADB_DATABASE:-$MYSQL_DATABASE}" -e '
            '"SET STATEMENT max_statement_time=15 FOR '
            'SELECT (SELECT COUNT(*) FROM information_schema.PROCESSLIST '
            'WHERE COALESCE(USER, \'\') != \'system user\' '
            'AND COALESCE(COMMAND, \'\') NOT IN (\'Sleep\', \'Daemon\') '
            'AND ID != CONNECTION_ID()) + '
            '(SELECT COUNT(*) FROM information_schema.INNODB_TRX WHERE trx_mysql_thread_id != CONNECTION_ID())"']
    result = _run_probe(['/usr/bin/docker', 'exec', container, *argv], timeout=30)
    if result.returncode != 0:
        raise CaptureError('mariadb_drain_check')
    raw = result.stdout.strip()
    if not (raw.isascii() and raw.isdigit()):
        raise CaptureError('mariadb_drain_check')
    return int(raw) == 0


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
        argv = ['sh', '-ec', MARIADB_CLIENT_PROLOGUE +
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


def online_postgres(paths, files, excludes, *, spec, target, verified=None):
    """Pair a native PostgreSQL dump with a stable local companion-file tree."""
    if not paths or spec['engine'] != 'postgres':
        raise CaptureError('online_postgres_scope')
    before = {path: file_inventory([path], excludes_file=excludes) for path in paths}
    # Reconcile each root independently. On a retry, skip roots whose inventory
    # is unchanged since a previously verified clean copy, and enable --checksum
    # only for roots that already have unverified staged content.
    for path in paths:
        staged_path = files / str(Path(path)).lstrip('/')
        is_staged = staged_path.exists() or staged_path.is_symlink()
        if verified is not None and is_staged and verified.get(path) == before[path]:
            continue
        if verified is not None:
            verified.pop(path, None)
        copy_paths([path], files, excludes, synchronize=True, checksum=is_staged)
    database_dump(spec, target)
    changed = False
    for path in paths:
        if before[path] == file_inventory([path], excludes_file=excludes):
            if verified is not None:
                verified[path] = before[path]
        else:
            changed = True
            if verified is not None:
                verified.pop(path, None)
    if changed:
        raise CaptureError('online_source_changed')


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


def frozen_zwave_store_check(store):
    """Reject torn in-place writes to the Z-Wave store before publishing a capture."""
    store = safe_source(store)
    settings = store / 'settings.json'
    try:
        for path in {settings, *store.glob('*.json'), *store.glob('*.jsonl')}:
            item = path.lstat()
            if not stat.S_ISREG(item.st_mode) or item.st_size > 64 * 1024**2:
                raise ValueError
            with path.open('rb') as stream:
                if path.suffix == '.jsonl':
                    if any(not line.endswith(b'\n') or not isinstance(json.loads(line), dict)
                           for line in stream if line.strip()):
                        raise ValueError
                else:
                    value = json.load(stream)
                    if not isinstance(value, (dict, list)):
                        raise ValueError
                    if path == settings and (not isinstance(value, dict) or not isinstance(value.get('zwave'), dict)):
                        raise ValueError
    except (OSError, ValueError):
        raise CaptureError('zwave_store_invalid') from None


def radio_check(files, max_age, *, snapshot_scratch=None):
    """Validate native outputs without touching/resetting either radio."""
    now = time.time()
    store = Path(files) / 'srv/home-lab-state/zwave-data'
    nvm = store / 'backups/nvm'
    candidates = [p for p in nvm.glob('NVM_*') if p.is_file() and not p.is_symlink() and p.stat().st_size]
    if not candidates or not 0 <= now - max(p.stat().st_mtime for p in candidates) <= max_age:
        raise CaptureError('zwave_nvm_stale')
    if snapshot_scratch is not None:
        frozen_zwave_store_check(store)
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


GAMES_BASE = Path('/mnt/games')


def live_games_roots(paths):
    if not isinstance(paths, list) or any(not isinstance(p, str) or str(Path(p)) != p for p in paths):
        raise CaptureError('live_games_scope')
    roots = [Path(p) for p in paths]
    if (len(set(roots)) != len(roots) or any(
            not p.is_relative_to(GAMES_BASE) or p == GAMES_BASE or p.is_relative_to(GAMES_BASE / 'restic')
            or p.is_relative_to(GAMES_BASE / 'home-lab-backup') or '..' in p.parts
            or any(parent in roots for parent in p.parents) for p in roots)):
        raise CaptureError('live_games_scope')
    return roots


def verify_live_games_sources(roots):
    games = GAMES_BASE
    if roots:
        device = safe_source(games).stat().st_dev
        mounts = json.loads(command(['/usr/bin/findmnt', '--json', '--list', '--output', 'TARGET']))['filesystems']
        for root in roots:
            if (not safe_source(root).is_dir() or root.stat().st_dev != device
                    or any((target := Path(row['target'])) != games and target.is_relative_to(games)
                           and (target.is_relative_to(root) or root.is_relative_to(target)) for row in mounts)):
                raise CaptureError('live_games_mount_identity')


@contextmanager
def live_games_mounted(roots, stage):
    require_private_mounts()
    verify_live_games_sources(roots)
    mounted = []
    try:
        for source in roots:
            target = empty_snapshot_target(stage, source)
            command(['/usr/bin/mount', '-n', '--bind', str(source), str(target)])
            mounted.append(target)
            command(['/usr/bin/mount', '-n', '-o', 'remount,bind,ro,nosuid,nodev,noexec', str(target)])
            options = command(['/usr/bin/findmnt', '--noheadings', '--mountpoint', str(target),
                               '--output', 'OPTIONS']).decode().strip().split(',')
            if not {'ro', 'nosuid', 'nodev', 'noexec'} <= set(options) or not os.path.samestat(source.stat(), target.stat()):
                raise CaptureError('live_games_mount_identity')
        yield
    finally:
        state_snapshot_unmount(mounted)


class CaptureSources(NamedTuple):
    zfs: list[str]
    state: list[Path]
    live_games: list[Path]


def _validate_state_online_paths(online_paths):
    return _validate_online_paths(
        online_paths,
        base=STATE_BASE,
        key_error='state_snapshot_online_services',
        path_error='state_snapshot_scope',
    )


def _parse_snapshot_settings(settings):
    zfs_setting = settings.get('zfs')
    if zfs_setting is not None and (not isinstance(zfs_setting, (dict, bool)) or (isinstance(zfs_setting, dict) and not zfs_setting)):
        raise CaptureError('snapshot_policy')
    zfs_online = {}
    if isinstance(zfs_setting, dict) and 'online_paths' in zfs_setting:
        zfs_online = _validate_zfs_online_paths(zfs_setting['online_paths'])
    state_setting = settings.get('state_snapshot')
    if state_setting is not None and (not isinstance(state_setting, dict) or not state_setting):
        raise CaptureError('state_snapshot_scope')
    state_online = _validate_state_online_paths(state_setting.get('online_paths', {})) if state_setting else {}
    return zfs_setting, zfs_online, state_setting, state_online


def _build_capture_sources(settings, *, shared_paths, zfs_setting, zfs_online, state_setting, state_online):
    zfs, state = [], []
    if zfs_setting:
        # Use the native adapter's fixed mount order, not policy ordering.
        zfs = zfs_paths()
        declared = [path for path in (*shared_paths, *zfs_online.values())
                    if Path(path).is_relative_to(ZFS_BASE)]
        if sorted(declared) != sorted(zfs):
            raise CaptureError('snapshot_policy_scope')
    if state_setting:
        if not zfs:
            raise CaptureError('state_snapshot_requires_shared_capture')
        state = state_snapshot_roots(shared_paths, state_online.values())
    return CaptureSources(zfs, state, live_games_roots(settings.get('live_games_paths', [])))


def capture_sources(settings):
    """Select archive mounts from reviewed policy, also usable on a ready retry."""
    cold = settings.get('cold', [])
    if not isinstance(cold, list) or any(not isinstance(step, dict) or not _valid_path_list(step.get('paths')) for step in cold):
        raise CaptureError('capture_stop_scope')
    maintenance = settings.get('maintenance', [])
    if not isinstance(maintenance, list) or any(not isinstance(step, dict) or not _valid_path_list(step.get('paths')) for step in maintenance):
        raise CaptureError('maintenance_capture_scope')
    shared_paths = [path for step in (*cold, *maintenance) for path in step['paths']]
    zfs_setting, zfs_online, state_setting, state_online = _parse_snapshot_settings(settings)
    return _build_capture_sources(
        settings,
        shared_paths=shared_paths,
        zfs_setting=zfs_setting,
        zfs_online=zfs_online,
        state_setting=state_setting,
        state_online=state_online,
    )


class CapturePlan(NamedTuple):
    sources: CaptureSources
    pause_services: list[str]
    maintenance: list[dict]
    precopy: list[str]
    paused_copy: list[str]
    cold_dumps: list[dict]
    maintenance_dumps: list[dict]
    cold_names: list[str]
    maintenance_names: list[str]
    state_names: list[str]
    zfs_names: list[str]
    online: list[dict]
    online_stores: list[str]
    live_files: list[str]
    online_json: list[str]
    cli_auth: str
    jellyfin: str
    capacity_paths: list[str]

    @property
    def databases(self):
        return (
            [dump for step in self.online for dump in step.get('databases', [])]
            + self.maintenance_dumps
            + self.cold_dumps
        )


CONTAINER_NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')


def _valid_database_spec(dump, engine):
    return (isinstance(dump, dict) and dump.get('engine') == engine
            and isinstance(dump.get('container'), str) and CONTAINER_NAME.fullmatch(dump['container']) is not None
            and isinstance(dump.get('name'), str) and bool(dump['name'])
            and '/' not in dump['name'] and dump['name'] not in {'.', '..'})


def _valid_path_list(paths):
    return isinstance(paths, list) and bool(paths) and all(isinstance(path, str) and bool(path) for path in paths)


def _valid_service_list(services):
    return (isinstance(services, list) and bool(services)
            and all(isinstance(service, str) and bool(service) for service in services)
            and len(set(services)) == len(services))


NEXTCLOUD_MAINTENANCE_SERVICES = frozenset({'nextcloud', 'nextcloud-cron'})


def _validate_maintenance_steps(maintenance, declared, stopped):
    if not isinstance(maintenance, list):
        raise CaptureError('maintenance_capture_scope')
    names, maintenance_services = [], set()
    for step in maintenance:
        if not isinstance(step, dict):
            raise CaptureError('maintenance_capture_scope')
        services = step.get('services', [])
        databases = step.get('databases', [])
        if (step.get('native') != 'nextcloud' or step.get('name') != 'nextcloud'
                or step['name'] in names or not _valid_service_list(services)
                or not set(services) <= declared or set(services) & stopped
                or 'nextcloud' not in services or not set(services) <= NEXTCLOUD_MAINTENANCE_SERVICES
                or ('nextcloud-cron' in declared and 'nextcloud-cron' not in services)
                or not _valid_path_list(step.get('paths'))
                or not isinstance(databases, list) or len(databases) != 1
                or any(not _valid_database_spec(dump, 'mariadb') for dump in databases)):
            raise CaptureError('maintenance_capture_scope')
        names.append(step['name'])
        maintenance_services.update(services)
    return names, maintenance_services


def _validate_cold_steps(cold):
    if not isinstance(cold, list):
        raise CaptureError('capture_stop_scope')
    names, selected = [], []
    for step in cold:
        if not isinstance(step, dict):
            raise CaptureError('capture_stop_scope')
        services = step.get('services')
        databases = step.get('databases', [])
        if (not isinstance(step.get('name'), str) or not step['name']
                or not _valid_service_list(services)
                or not _valid_path_list(step.get('paths'))
                or not isinstance(databases, list)
                or any(not isinstance(dump, dict) or dump.get('engine') not in {'postgres', 'mariadb'}
                       or not _valid_database_spec(dump, dump['engine']) for dump in databases)):
            raise CaptureError('capture_stop_scope')
        names.append(step['name'])
        selected.extend(services)
    return names, selected


def _validate_online_steps(online, declared, exclusive_services):
    if not isinstance(online, list):
        raise CaptureError('online_capture_scope')
    names = []
    for step in online:
        if not isinstance(step, dict):
            raise CaptureError('online_capture_scope')
        native = step.get('native')
        if native == 'postgres':
            services = step.get('services')
            databases = step.get('databases')
            if (not isinstance(step.get('name'), str) or not step['name']
                    or not _valid_service_list(services)
                    or not set(services) <= declared or set(services) & exclusive_services
                    or not isinstance(databases, list) or len(databases) != 1
                    or not _valid_database_spec(databases[0], 'postgres')
                    or not _valid_path_list(step.get('paths'))):
                raise CaptureError('online_postgres_scope')
        elif native == 'mosquitto':
            service = step.get('service')
            if not isinstance(service, str) or service not in declared or service in exclusive_services:
                raise CaptureError('online_mosquitto_scope')
        elif 'native' in step:
            raise CaptureError('unknown_native_capture')
        if native != 'postgres' and 'databases' in step:
            raise CaptureError('online_capture_scope')
        if (not isinstance(step.get('name'), str) or not step['name'] or step['name'] in names
                or not _valid_path_list(step.get('paths'))):
            raise CaptureError('online_capture_scope')
        names.append(step['name'])
    return names


def capture_plan(policy, declared):
    """Resolve one fresh capture's source selection before doing capture I/O."""
    settings = policy['capture']
    cold = settings.get('cold', [])
    maintenance = settings.get('maintenance', [])
    online = settings.get('online', [])
    cold_names, selected = _validate_cold_steps(cold)
    pause = policy['stop_groups']['applications']
    stopped = set(pause + policy['stop_groups']['databases'])
    if len(pause) != len(selected) or len(set(selected)) != len(selected) or set(pause) != set(selected):
        raise CaptureError('capture_stop_scope')
    if not set(pause) <= declared:
        raise CaptureError('capture_service_missing')
    maintenance_names, maintenance_services = _validate_maintenance_steps(maintenance, declared, stopped)
    exclusive_services = stopped | maintenance_services
    zfs_setting, zfs_online, state_setting, state_online = _parse_snapshot_settings(settings)
    if not state_online.keys() <= declared or state_online.keys() & exclusive_services:
        raise CaptureError('state_snapshot_online_services')
    if not zfs_online.keys() <= declared or zfs_online.keys() & exclusive_services:
        raise CaptureError('zfs_snapshot_online_services')
    online_names = _validate_online_steps(online, declared, exclusive_services)
    cold_paths = [path for step in cold for path in step['paths']]
    maintenance_paths = [path for step in maintenance for path in step['paths']]
    sources = _build_capture_sources(
        settings,
        shared_paths=[*cold_paths, *maintenance_paths],
        zfs_setting=zfs_setting,
        zfs_online=zfs_online,
        state_setting=state_setting,
        state_online=state_online,
    )
    snapshot = {*sources.zfs, *map(str, sources.state)}
    precopy, paused_copy = [], []
    for step in (*cold, *maintenance):
        for path in step['paths']:
            if path not in snapshot:
                (precopy if step.get('precopy') else paused_copy).append(path)
    online_stores = settings.get('online_stores', [])
    live_files, online_json = settings['live_files'], settings['online_json']
    cli_auth, jellyfin = settings['cli_auth'], settings['jellyfin']
    online_paths = [path for step in online for path in step['paths']]
    online_paths.extend((*online_stores, *live_files, *online_json, cli_auth))
    live_games = list(map(str, sources.live_games))
    # A stage path cannot be owned by both a copy and a mount, or written by
    # multiple capture steps. Jellyfin's parent and SQL estimate-only roots
    # are budgets, not file writers; auxiliary Jellyfin exports are deliberate.
    archive_paths = [
        *cold_paths, *maintenance_paths,
        *state_online.values(), *zfs_online.values(), *online_paths, *live_games,
    ]
    roots = set(map(Path, archive_paths))
    if len(roots) != len(archive_paths) or any(
            path.anchor != '/' or path == Path('/') or '..' in path.parts or roots.intersection(path.parents)
            for path in roots) or any(str(Path(path)) != path for path in archive_paths):
        raise CaptureError('capture_path_scope')
    capacity_paths = sorted({*precopy, *paused_copy, *online_paths, *settings.get('estimate_paths', []),
                             jellyfin, *live_games})
    plan = CapturePlan(
        sources=sources, pause_services=pause, maintenance=maintenance, precopy=precopy, paused_copy=paused_copy,
        cold_dumps=[dump for step in cold for dump in step.get('databases', [])],
        maintenance_dumps=[dump for step in maintenance for dump in step.get('databases', [])],
        cold_names=cold_names, maintenance_names=maintenance_names,
        state_names=list(state_online), zfs_names=list(zfs_online), online=online,
        online_stores=online_stores, live_files=live_files, online_json=online_json,
        cli_auth=cli_auth, jellyfin=jellyfin, capacity_paths=capacity_paths,
    )
    step_names = [*cold_names, *maintenance_names, *online_names]
    snapshot_names = state_online.keys() | zfs_online.keys()
    if (len(step_names) != len(set(step_names))
            or set(step_names) & (snapshot_names | {'online'})
            or 'online' in snapshot_names):
        raise CaptureError('capture_name_scope')
    database_names = [dump['name'] for dump in plan.databases]
    if len(database_names) != len(set(database_names)):
        raise CaptureError('capture_database_scope')
    return plan


def capacity_check(plan, stage, reserve, excludes):
    verify_live_games_sources(plan.sources.live_games)
    # Native du does not follow links into bulk game installations. Conservative
    # bytes plus reserve must fit staging before any service is stopped.
    raw = command(['/usr/bin/du', '--summarize', '--total', '--apparent-size', '--block-size=1',
                   '--exclude-from=' + str(excludes), '--', *plan.capacity_paths])
    sizes = dict((line.split('\t', 1)[1], int(line.split('\t', 1)[0])) for line in raw.decode().splitlines())
    # Jellyfin first creates its native archive on its own filesystem. Budget
    # that temporary archive too; staging capacity alone is insufficient.
    if shutil.disk_usage(plan.jellyfin).free < sizes[plan.jellyfin] * 2 + reserve:
        raise CaptureError('native_archive_capacity')
    if shutil.disk_usage(safe_source(stage.parent)).free < sizes['total'] * 2 + reserve:
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
