"""Fixed-origin LVM-thin authority used under the storage broker's native lock."""
import json
import math
import re
import subprocess
import time

VG = 'pve'
ORIGIN = 'vm-100-disk-1'
POOL = 'data'
PREFIX = 'home-lab-state-'
EXPIRY = 72 * 3600
MAX_POOL_PERCENT = 75
MIN_HEADROOM = 32 * 1024**3
LV_ID = r'[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{4}){5}-[A-Za-z0-9]{6}'


def native(*args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=30, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise ValueError('state_snapshot_native_refused')
    return result.stdout


def volumes():
    result = native('/usr/sbin/lvs', '--reportformat', 'json', '--units', 'b', '--nosuffix',
                    '--config', 'report { time_format="%s" }', '-o',
                    'lv_name,lv_uuid,lv_size,origin,origin_uuid,pool_lv,lv_attr,lv_time,lv_tags,data_percent,metadata_percent', VG)
    rows = json.loads(result)['report'][0]['lv']
    by_name = {row['lv_name']: row for row in rows}
    if len(by_name) != len(rows):
        raise ValueError('state_snapshot_volume_inventory')
    return by_name


def verify_origin(rows, spec):
    if set(spec) != {'origin_uuid', 'pool_uuid', 'bytes'} or type(spec['bytes']) is not int or spec['bytes'] <= 0:
        raise ValueError('state_snapshot_configuration')
    origin, pool = rows[ORIGIN], rows[POOL]
    if (origin['lv_uuid'] != spec['origin_uuid'] or origin['pool_lv'] != POOL or origin['origin'] or
            origin['lv_attr'][:2] != 'Vw' or origin['lv_attr'][4] != 'a' or
            int(origin['lv_size']) != spec['bytes'] or pool['lv_uuid'] != spec['pool_uuid'] or
            pool['lv_attr'][:2] != 'tw' or pool['lv_attr'][4] != 'a'):
        raise ValueError('state_snapshot_origin_identity')
    return pool


def admitted(pool):
    data, metadata = float(pool['data_percent']), float(pool['metadata_percent'])
    size = int(pool['lv_size'])
    return (all(math.isfinite(value) and 0 <= value < MAX_POOL_PERCENT for value in (data, metadata))
            and size * (100 - data) / 100 >= MIN_HEADROOM and pool['lv_attr'][8:10] == '--')


def record(row, spec):
    capture = row['lv_name'].removeprefix(PREFIX)
    tags = row['lv_tags'].split(',')
    owners = [tag.removeprefix('homelab-owner-') for tag in tags if tag.startswith('homelab-owner-')]
    if (not re.fullmatch('[0-9a-f]{32}', capture) or len(owners) != 1 or
            not re.fullmatch('[0-9a-f]{64}', owners[0]) or set(tags) != {'homelab-backup-state', 'homelab-owner-' + owners[0]} or
            row['origin'] != ORIGIN or row['origin_uuid'] != spec['origin_uuid'] or row['pool_lv'] != POOL or
            row['lv_attr'][:2] != 'Vr' or not re.fullmatch(LV_ID, row['lv_uuid']) or
            int(row['lv_size']) != spec['bytes']):
        raise ValueError('state_snapshot_unowned')
    return {'capture': capture, 'owner': owners[0], 'id': row['lv_uuid'],
            'created': int(row['lv_time']), 'bytes': int(row['lv_size'])}


def execute(request, spec):
    action = request['action']
    fields = {'action'} if action == 'state-list' else {'action', 'capture', 'owner'}
    if action in {'state-ready', 'state-complete', 'state-abandon'}:
        fields.add('id')
    if (set(request) != fields or action not in {'state-list', 'state-create', 'state-inspect', 'state-ready', 'state-complete', 'state-abandon'} or
            ('capture' in fields and (not re.fullmatch('[0-9a-f]{32}', str(request['capture'])) or
                                     not re.fullmatch('[0-9a-f]{64}', str(request['owner'])))) or
            ('id' in fields and not re.fullmatch(LV_ID, str(request['id'])))):
        raise ValueError('state_snapshot_request')
    rows = volumes()
    pool = verify_origin(rows, spec)
    known = {name: record(row, spec) for name, row in rows.items() if name.startswith(PREFIX)}
    if action == 'state-list':
        return {'snapshots': list(known.values()), 'admissible': admitted(pool)}
    token, owner = request['capture'], request['owner']
    name = PREFIX + token
    lv = VG + '/' + name
    socket = 'home-lab-state-snapshot@' + token + '.socket'
    service = socket.removesuffix('.socket') + '.service'
    if name not in known:
        if action == 'state-complete':
            # Idempotent only when neither the LV nor a listener is present.
            for unit in (socket, service):
                state = native('/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', unit).strip()
                if state not in {'inactive', 'failed'}:
                    raise ValueError('state_snapshot_listener_retained')
            return {'deleted': True}
        if action != 'state-create':
            raise ValueError('state_snapshot_missing')
        if known or not admitted(pool):
            raise ValueError('state_snapshot_not_admissible')
        native('/usr/sbin/lvcreate', '--snapshot', '--permission', 'r', '--addtag', 'homelab-backup-state',
               '--addtag', 'homelab-owner-' + owner, '-n', name, VG + '/' + ORIGIN)
        known[name] = record(volumes()[name], spec)
    value = known[name]
    if value['owner'] != owner or ('id' in fields and request['id'] != value['id']):
        raise ValueError('state_snapshot_replaced')
    if action == 'state-ready':
        if not admitted(pool) or time.time() - value['created'] >= EXPIRY:
            raise ValueError('state_snapshot_not_admissible')
        native('/usr/sbin/lvchange', '--activate', 'y', '--ignoreactivationskip', lv)
        if native('/usr/sbin/blockdev', '--getro', '/dev/' + lv).strip() != '1':
            raise ValueError('state_snapshot_not_readonly')
        native('/usr/bin/systemctl', 'start', socket)
    elif action in {'state-complete', 'state-abandon'}:
        if action == 'state-abandon' and time.time() - value['created'] < EXPIRY:
            raise ValueError('state_snapshot_not_expired')
        native('/usr/bin/systemctl', 'stop', socket)
        native('/usr/bin/systemctl', 'stop', service)
        # Inspect again before removing. Do not force or auto-adopt another LV.
        if record(volumes()[name], spec) != value:
            raise ValueError('state_snapshot_replaced')
        native('/usr/sbin/lvremove', '--yes', lv)
        return {'deleted': True}
    return value
