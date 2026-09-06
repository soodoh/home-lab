#!/usr/bin/python3
"""Attended, streamed exact capability transaction; never an account sudo helper."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import stat
import secrets
import subprocess
import sys

BASE = Path('/usr/local/libexec/home-lab')
CONTROLLER = BASE / 'proxmox-controller-observer'
SUDO = Path('/etc/sudoers.d/ansible-plan')
TARGETS = {BASE / name: 0o755 for name in (
    'proxmox-observer', 'proxmox-protected-collector', 'proxmox-controller-observer',
    'proxmox-package-candidate-observer', 'proxmox-ansible-plan-transport',
    'proxmox-ansible-deploy-activator')}
TARGETS[SUDO] = 0o440
OWNER = Path('/var/lib/iac-ansible-production.lock')
TRANSACTIONS = Path('/var/lib/home-lab/controller-observer-capability')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'}


def require_vfio_coordination():
    raise ValueError('installation blocked: VFIO queued-reboot ownership protocol is unqualified')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def native(argv):
    result = subprocess.run(argv, input=b'', capture_output=True, env=ENV, timeout=180)
    if result.returncode or result.stderr or len(result.stdout) > 1024 * 1024:
        raise ValueError('capability prerequisite command failed')
    return result.stdout


def material(payload):
    if set(payload['files']) != {str(p) for p in TARGETS}:
        raise ValueError('fixed capability targets differ')
    files = {Path(p): base64.b64decode(raw, validate=True) for p, raw in payload['files'].items()}
    if any(len(raw) > 1024 * 1024 for raw in files.values()):
        raise ValueError('capability file exceeds bound')
    # The controller rebuilds these bytes from the clean reviewed revision.
    protocol = {'__name__': 'capability_protocol', '__file__': str(CONTROLLER)}
    exec(compile(files[CONTROLLER], str(CONTROLLER), 'exec'), protocol)
    return files, protocol


def metadata(path, protocol):
    try:
        raw = protocol['read_fixed'](path, 1024 * 1024, TARGETS.get(path, 0o600))
    except FileNotFoundError:
        return None
    return base64.b64encode(raw).decode()


def account():
    user = pwd.getpwnam('ansible-plan')
    groups = sorted(grp.getgrgid(g).gr_name for g in os.getgrouplist(user.pw_name, user.pw_gid))
    fields = native(('/usr/bin/passwd', '--status', 'ansible-plan')).decode().split()
    if user.pw_dir != '/home/ansible-plan' or user.pw_shell != str(BASE / 'proxmox-ansible-plan-transport') or groups != ['ansible-plan'] or len(fields) < 2 or fields[1] not in {'L', 'LK'}:
        raise ValueError('fixed plan account differs')
    for path in (Path('/home/ansible-plan/.ssh/authorized_keys'), Path('/home/ansible-plan/.ssh/authorized_keys2')):
        if os.path.lexists(path):
            raise ValueError('conventional plan key remains')


def repository_prerequisites(payload, protocol):
    commit = payload['commit']
    if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('capability commit differs')
    for ref in ('HEAD', 'origin/main'):
        if native(('/usr/bin/git', '-C', '/root/home-lab', 'rev-parse', ref)).decode().strip() != commit:
            raise ValueError('installed repository revision differs')
    if native(('/usr/bin/git', '-C', '/root/home-lab', 'status', '--porcelain=v1', '--untracked-files=all')):
        raise ValueError('installed repository is not clean')
    required = {
        'infrastructure/contract/home-lab.yml', 'infrastructure/contract/schema.json',
        'ansible/inventory/proxmox-production.yml', 'scripts/controller/proxmox-controller-observer-capability.py',
        'ansible/inventory/production.yml',
        'infrastructure/proxmox-access/host/proxmox-controller-capability-transaction.py',
    }
    if set(payload['bindings']) != required:
        raise ValueError('capability source binding set differs')
    for relative, expected in payload['bindings'].items():
        raw = protocol['read_fixed'](Path('/root/home-lab') / relative, 1024 * 1024, 0o644)
        if sha(raw) != expected:
            raise ValueError('installed repository source bytes differ')
    for name in ('proxmox-ansible-deploy-activator', 'proxmox-ansible-plan-transport'):
        raw = protocol['read_fixed'](Path('/root/home-lab/infrastructure/proxmox-access/host') / name, 1024 * 1024, 0o755)
        if base64.b64encode(raw).decode() != payload['files'][str(BASE / name)]:
            raise ValueError('installed repository helper bytes differ')


def snapshot(protocol):
    account()
    paths = {str(p): metadata(p, protocol) for p in TARGETS}
    if any(raw is None for p, raw in paths.items() if p != str(CONTROLLER)):
        raise ValueError('installed predecessor prerequisite missing')
    # No private values are returned: these are fixed public helper/sudo bytes.
    native(('/usr/sbin/visudo', '--check'))
    observation()
    return paths


def observation():
    raw = native((str(BASE / 'proxmox-observer'), 'observe'))
    if raw != canonical(json.loads(raw)):
        raise ValueError('installed observer is not canonical')
    return json.loads(raw)


def health(files):
    source = files[BASE / 'proxmox-ansible-deploy-activator'].decode()
    if source.count('\ntry:\n    main()') != 1:
        raise ValueError('fixed activator source differs')
    namespace = {'__name__': 'capability_health', '__file__': str(BASE / 'proxmox-ansible-deploy-activator')}
    exec(compile(source.split('\ntry:\n    main()')[0], 'capability_health', 'exec'), namespace)
    namespace['reboot_health']()


def put(path, raw, mode, protocol, exclusive=False):
    temporary = path.name if exclusive else '.' + path.name + '.' + secrets.token_hex(16) + '.controller-capability.tmp'
    parent = protocol['parent_fd'](path)
    fd = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        os.fchmod(fd, mode); os.fchown(fd, 0, 0)
        with os.fdopen(os.dup(fd), 'wb') as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        if path == SUDO and not exclusive:
            native(('/usr/sbin/visudo', '--check', '--file=' + str(path.parent / temporary)))
        if not exclusive:
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            if fd is not None:
                try:
                    if not exclusive:
                        try:
                            named = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                        except FileNotFoundError:
                            named = None
                        opened = os.fstat(fd)
                        if named is not None and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino):
                            os.unlink(temporary, dir_fd=parent); os.fsync(parent)
                finally:
                    os.close(fd)
        finally:
            os.close(parent)


def trusted_directory(path, protocol):
    parent = protocol['parent_fd'](path)
    try:
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent); os.fsync(parent)
        except FileExistsError:
            pass
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('transaction directory differs')
    finally:
        os.close(parent)


def owner_bytes(plan):
    return canonical({'format': 'home-lab-controller-capability-owner-v1', 'plan_sha256': plan})


def owner_matches(plan, protocol, identity=None, directory=OWNER):
    parent = protocol['parent_fd'](directory / 'owner')
    try:
        info = os.fstat(parent)
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('capability owner directory differs')
    finally:
        os.close(parent)
    owner_info = os.stat(directory / 'owner', follow_symlinks=False)
    observed_identity = [info.st_dev, info.st_ino, owner_info.st_dev, owner_info.st_ino]
    if identity is not None and observed_identity != identity:
        raise ValueError('capability owner identity replaced')
    if protocol['read_fixed'](directory / 'owner', 4096, 0o600) != owner_bytes(plan):
        raise ValueError('foreign capability owner retained')
    return observed_identity


def reject_journals(protocol, plan=None):
    for path in protocol['JOURNALS']:
        if not os.path.lexists(path):
            continue
        if path != OWNER or plan is None:
            raise ValueError('conflicting retained owner')
        owner_matches(plan, protocol)


def detached_owner(plan, identity):
    return OWNER.with_name(OWNER.name + '.terminal-' + plan + '-' + sha(canonical(identity)))


def release_owner(plan, protocol, identity):
    # Only a durable terminal journal grants this cleanup authority. The shared
    # descriptors serialize cooperating privileged writers, including later owners.
    detached = detached_owner(plan, identity)
    parent = protocol['parent_fd'](OWNER)
    try:
        if os.path.lexists(OWNER):
            owner_matches(plan, protocol, identity)
            if os.path.lexists(detached) or set(os.listdir(OWNER)) != {'owner'}:
                raise ValueError('unexpected terminal owner evidence')
            # Detach the whole exact directory, never leave an empty active barrier.
            os.rename(OWNER.name, detached.name, src_dir_fd=parent, dst_dir_fd=parent)
        # Persist detachment before deleting its identity record, even on an
        # explicitly authorized continuation after interruption at rename/fsync.
        os.fsync(parent)
        if not os.path.lexists(detached):
            return
        directory = protocol['parent_fd'](detached / 'owner')
        try:
            info = os.fstat(directory)
            if [info.st_dev, info.st_ino] != identity[:2] or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('detached capability owner identity replaced')
            entries = set(os.listdir(directory))
            if entries == {'owner'}:
                owner_matches(plan, protocol, identity, detached)
                os.unlink('owner', dir_fd=directory)
            elif entries:
                raise ValueError('foreign detached capability owner retained')
            # An empty directory is removable only at the journal-bound inode.
            os.fsync(directory)
            named = os.stat(detached.name, dir_fd=parent, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('detached capability owner identity replaced')
            os.rmdir(detached.name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(directory)
    finally:
        os.close(parent)


def restore(state, protocol):
    # Revoke sudo before restoring producers/transport. Never overwrite drift.
    for path in (SUDO, *(p for p in TARGETS if p != SUDO)):
        current = metadata(path, protocol)
        before, after = state['before'][str(path)], state['after'][str(path)]
        if current not in (before, after):
            raise ValueError('rollback refuses foreign installed bytes')
        if current == before:
            continue
        if before is None:
            parent = protocol['parent_fd'](path)
            try:
                os.unlink(path.name, dir_fd=parent); os.fsync(parent)
            finally:
                os.close(parent)
        else:
            put(path, base64.b64decode(before, validate=True), TARGETS[path], protocol)
    if snapshot(protocol) != state['before']:
        raise ValueError('rollback postcondition differs')


def transaction(payload):
    if payload.get('operation') in {'observe', 'apply'}:
        require_vfio_coordination()
    files, protocol = material(payload)
    descriptors = protocol['acquire_descriptors']()
    try:
        repository_prerequisites(payload, protocol)
        operation = payload['operation']
        if operation == 'observe':
            reject_journals(protocol)
            health(files)
            return {'before': snapshot(protocol)}
        plan = payload['plan_sha256']
        if len(plan) != 64 or any(c not in '0123456789abcdef' for c in plan):
            raise ValueError('transaction identity differs')
        state_path = TRANSACTIONS / (plan + '.json')
        if operation in {'rollback', 'commit', 'cleanup-committed'}:
            # Retried rollback is explicitly approved against the original saved
            # before/after bytes, not permission to resume a failed installation.
            reject_journals(protocol, plan)
            state_raw = protocol['read_fixed'](state_path, 8 * 1024 * 1024, 0o600)
            state = json.loads(state_raw)
            if canonical(state) != state_raw or set(state) != {'format', 'plan_sha256', 'before', 'after', 'status', 'owner_identity'} or state['format'] != 'home-lab-controller-capability-journal-v1':
                raise ValueError('capability journal format differs')
            if state.get('plan_sha256') != plan or state.get('before') != payload['before'] or state.get('after') != payload['files'] or state.get('status') not in {'prepared', 'installing', 'candidate', 'rollback-failed', 'committed', 'rolled-back'}:
                raise ValueError('rollback ownership/bindings differ')
            identity = state['owner_identity']
            if not isinstance(identity, list) or len(identity) != 4 or any(type(n) is not int or n < 0 for n in identity):
                raise ValueError('capability owner identity differs')
            terminal = {'committed': 'cleanup-committed', 'rolled-back': 'rollback'}
            if state['status'] in terminal:
                if operation != terminal[state['status']]:
                    raise ValueError('terminal capability operation differs')
                # A process may have died after journal rename but before its
                # directory fsync. Re-publish terminal evidence durably first.
                put(state_path, canonical(state), 0o600, protocol)
                release_owner(plan, protocol, identity)
                return {'status': state['status'], **({'live_acceptance': False} if operation == 'cleanup-committed' else {})}
            if operation == 'cleanup-committed':
                raise ValueError('capability journal is not committed')
            owner_matches(plan, protocol, identity)
            if operation == 'commit':
                health(files)
                if state['status'] != 'candidate' or snapshot(protocol) != payload['files'] or sha(canonical(observation())) != payload.get('observation_sha256'):
                    raise ValueError('audited candidate changed or is not commit-ready')
                state['status'] = 'committed'; put(state_path, canonical(state), 0o600, protocol)
                release_owner(plan, protocol, state['owner_identity'])
                return {'status': 'committed', 'live_acceptance': False}
            restore(state, protocol)
            state['status'] = 'rolled-back'; put(state_path, canonical(state), 0o600, protocol)
            release_owner(plan, protocol, state['owner_identity'])
            return {'status': 'rolled-back'}
        if operation != 'apply':
            raise ValueError('fixed transaction operation required')
        reject_journals(protocol)
        health(files)
        if snapshot(protocol) != payload['before']:
            raise ValueError('capability before-state changed')
        trusted_directory(TRANSACTIONS, protocol)
        if os.path.lexists(state_path):
            raise ValueError('transaction retained; new plan or exact rollback required')
        # Exclusive owner publication and durable rollback precede all mutation.
        os.mkdir(OWNER, 0o700)
        put(OWNER / 'owner', owner_bytes(plan), 0o600, protocol, exclusive=True)
        parent = protocol['parent_fd'](OWNER)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        state = {'format': 'home-lab-controller-capability-journal-v1', 'plan_sha256': plan, 'before': payload['before'], 'after': payload['files'], 'status': 'prepared',
                 'owner_identity': owner_matches(plan, protocol)}
        put(state_path, canonical(state), 0o600, protocol, exclusive=True)
        try:
            state['status'] = 'installing'; put(state_path, canonical(state), 0o600, protocol)
            for path, raw in files.items():
                if path != SUDO:
                    put(path, raw, TARGETS[path], protocol)
            put(SUDO, files[SUDO], TARGETS[SUDO], protocol)
            if snapshot(protocol) != payload['files']:
                raise ValueError('installed capability postcondition differs')
            state['status'] = 'candidate'; put(state_path, canonical(state), 0o600, protocol)
            observed = observation()
        except Exception:
            try:
                restore(state, protocol)
                state['status'] = 'rolled-back'; put(state_path, canonical(state), 0o600, protocol)
            except Exception:
                state['status'] = 'rollback-failed'; put(state_path, canonical(state), 0o600, protocol)
                raise
            release_owner(plan, protocol, state['owner_identity'])
            raise
        # Retained owner spans the controller's independent exact parity audit.
        return {'status': 'candidate', 'observation': observed}
    finally:
        for fd in descriptors:
            os.close(fd)


def main():
    if os.geteuid() != 0 or sys.argv[1:]:
        raise ValueError('attended fixed transaction invocation required')
    raw = sys.stdin.buffer.read(12 * 1024 * 1024 + 1)
    if len(raw) > 12 * 1024 * 1024:
        raise ValueError('transaction input exceeds bound')
    sys.stdout.buffer.write(canonical(transaction(json.loads(raw))))


if __name__ == '__main__':
    main()
