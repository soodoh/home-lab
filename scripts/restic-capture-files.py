#!/usr/bin/env python3
"""Capture adapters for one full recovery set; no scheduling or admission engine.

Called only by the installed runner under its production/capture lock. Export
stdout, tokens and native errors never enter logs. Paths in policy are trusted
installed-controller inputs, not candidate application source.
"""
from __future__ import annotations

from contextlib import closing
import fcntl
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


def copy_paths(paths, target, excludes, online_sqlite=False):
    for path in paths:
        safe_source(path)
    options = []
    if online_sqlite:
        options = ['--exclude=*.db', '--exclude=*.db-wal', '--exclude=*.db-shm', '--exclude=*.db-journal']
    command(['/usr/bin/rsync', '--archive', '--relative', '--numeric-ids', '--hard-links', '--acls', '--xattrs',
             '--exclude-from=' + str(excludes), *options, '--', *paths, str(target) + '/'])


ZFS_DATA_PATH = '/mnt/storage/media/nextcloud/data'
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


def zfs_mount(spec, record, stage):
    """Expose only Nextcloud at its original archive path in a private namespace."""
    record = zfs_record(spec, record)
    if os.stat('/proc/self/ns/mnt').st_ino == os.stat('/proc/1/ns/mnt').st_ino:
        raise CaptureError('private_mount_namespace_required')
    # The parent export does not expose snapshot filesystems. The restricted
    # storage-host adapter publishes only this immutable Nextcloud subtree.
    source = '192.168.0.123:/storage/docker/.zfs/snapshot/' + ZFS_PREFIX + record['capture'] + '/media/nextcloud/data'
    target = Path(stage) / 'files' / ZFS_DATA_PATH.lstrip('/')
    # Parent creation must never traverse an archive/source-controlled link.
    parent = Path(stage) / 'files'
    safe_source(parent)
    for part in Path(ZFS_DATA_PATH).parts[1:]:
        parent = parent / part
        if parent.is_symlink():
            raise CaptureError('snapshot_target_type')
        parent.mkdir(mode=0o700, exist_ok=True)
        safe_source(parent)
    if any(target.iterdir()):
        raise CaptureError('snapshot_target_not_empty')
    command(['/usr/bin/mount', '-n', '-t', 'nfs4', '-o',
             'ro,vers=4.2,proto=tcp,nosuid,nodev,noexec', source, str(target)])
    raw = command(['/usr/bin/findmnt', '--json', '--nofsroot', '--mountpoint', str(target), '--output', 'SOURCE,FSTYPE,OPTIONS'])
    entries = json.loads(raw).get('filesystems', [])
    if (len(entries) != 1 or entries[0]['source'] != source or entries[0]['fstype'] != 'nfs4' or
            'ro' not in entries[0]['options'].split(',')):
        raise CaptureError('snapshot_mount_not_readonly')


def zfs_unmount(stage):
    target = Path(stage) / 'files' / ZFS_DATA_PATH.lstrip('/')
    if target.is_symlink():
        raise CaptureError('snapshot_target_type')
    if not target.exists():
        return
    result = subprocess.run(['/usr/bin/mountpoint', '--quiet', '--', str(target)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
    if result.returncode == 0:
        if os.stat('/proc/self/ns/mnt').st_ino == os.stat('/proc/1/ns/mnt').st_ino:
            raise CaptureError('private_mount_namespace_required')
        state_path = safe_source(Path(stage) / 'zfs-source.json')
        token = json.loads(state_path.read_text())['capture']
        if not isinstance(token, str) or not re.fullmatch('[0-9a-f]{32}', token):
            raise CaptureError('snapshot_identity')
        raw = command(['/usr/bin/findmnt', '--json', '--nofsroot', '--mountpoint', str(target), '--output', 'SOURCE,FSTYPE'])
        entries = json.loads(raw).get('filesystems', [])
        expected = '192.168.0.123:/storage/docker/.zfs/snapshot/' + ZFS_PREFIX + token + '/media/nextcloud/data'
        if len(entries) != 1 or entries[0]['source'] != expected or entries[0]['fstype'] != 'nfs4':
            raise CaptureError('unknown_snapshot_mount')
        command(['/usr/bin/umount', '--', str(target)])
    elif result.returncode != 32:
        # util-linux mountpoint returns 32 for an ordinary non-mount path.
        raise CaptureError('snapshot_unmount_inspection')


def sqlite_backup(source, target):
    safe_source(source)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = target.with_name(target.name + '.partial')
    temporary.unlink(missing_ok=True)
    try:
        with closing(sqlite3.connect('file:' + str(source) + '?mode=ro', uri=True, timeout=10)) as reader:
            with closing(sqlite3.connect(temporary)) as writer:
                deadline = time.monotonic() + 300
                def progress(*_):
                    if time.monotonic() > deadline:
                        raise CaptureError('sqlite_timeout')
                reader.backup(writer, pages=256, progress=progress)
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


def radio_check(files, max_age):
    """Validate native outputs without touching/resetting either radio."""
    now = time.time()
    nvm = Path(files) / 'srv/home-lab-state/zwave-data/backups/nvm'
    candidates = [p for p in nvm.glob('NVM_*') if p.is_file() and not p.is_symlink() and p.stat().st_size]
    if not candidates or not 0 <= now - max(p.stat().st_mtime for p in candidates) <= max_age:
        raise CaptureError('zwave_nvm_stale')
    path = Path(files) / 'srv/home-lab-state/hass-data/zigbee.db'
    with closing(sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True)) as db:
        names = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        import re
        tables = [n for n in names if re.fullmatch(r'network_backups_v[0-9]+', n)]
        if not tables:
            raise CaptureError('zha_backup_missing')
        table = max(tables, key=lambda n: int(n.rsplit('v', 1)[1]))
        from datetime import datetime
        timestamps = [datetime.fromisoformat(json.loads(r[0])['backup_time']).timestamp()
                      for r in db.execute('SELECT backup_json FROM ' + table)]
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
            for relative in ('user.reg', 'userdef.reg', 'system.reg',
                             'drive_c/users/steamuser/Documents', 'drive_c/users/steamuser/Saved Games',
                             'drive_c/users/steamuser/AppData/Roaming', 'drive_c/users/steamuser/AppData/Local',
                             'drive_c/users/steamuser/AppData/LocalLow'):
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
    for step in policy['capture']['cold']:
        paths.extend(step['paths'])
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
