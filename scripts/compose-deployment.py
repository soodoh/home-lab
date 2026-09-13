#!/usr/bin/env python3
"""Offline Compose selection and review only; no observation or effect authority."""
from argparse import ArgumentParser
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


artifact = module('compose-artifact')
CONTRACT = 'infrastructure/contract/home-lab.yml'
CHECKERS = ('infrastructure/contract/schema.json', 'scripts/compose-deployment.py',
            'scripts/compose-deployment-diff.py', 'scripts/compose-artifact.py',
            'scripts/compose-action-plan.py', 'scripts/compose-model-inventory.py',
            'scripts/compose-image-lock.py')


def yaml_object(raw):
    try:
        import yaml
    except ImportError as exc:
        raise ValueError('PyYAML required in the explicitly selected Python interpreter') from exc

    class UniqueLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=True)
                if not isinstance(key, str) or key in result:
                    raise ValueError('duplicate or invalid YAML key')
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    if len(raw) > 1024 * 1024:
        raise ValueError('policy byte limit exceeded')
    try:
        depth = 0
        for count, event in enumerate(yaml.parse(raw)):
            if isinstance(event, yaml.AliasEvent) or count > 50000:
                raise ValueError('YAML aliases or node overflow unsupported')
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            if isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if depth > 32:
                raise ValueError('YAML depth overflow')
        value = yaml.load(raw, Loader=UniqueLoader)
    except yaml.YAMLError as exc:
        raise ValueError('malformed YAML (contents suppressed)') from exc
    if not isinstance(value, dict):
        raise ValueError('YAML object required')
    return value


def git_read(root, args):
    # Fixed callers below issue only local, non-mutating Git queries.
    deadline = time.monotonic() + 15
    process = subprocess.Popen(artifact.GIT_PREFIX + args, cwd=root, env=artifact.GIT_ENV,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise ValueError('Git query deadline exceeded')
        return seconds

    try:
        chunks = []
        count = 0
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as reader:
            reader.register(process.stdout, selectors.EVENT_READ)
            while True:
                if not reader.select(remaining()):
                    raise ValueError('Git query deadline exceeded')
                chunk = os.read(process.stdout.fileno(), min(65536, artifact.MAX_FILE_BYTES + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                if count > artifact.MAX_FILE_BYTES:
                    raise ValueError('Git output byte limit exceeded')
                chunks.append(chunk)
        try:
            status = process.wait(timeout=remaining())
        except subprocess.TimeoutExpired as exc:
            raise ValueError('Git query deadline exceeded') from exc
        remaining()
        if status != 0:
            raise ValueError('committed-source Git query failed')
        return b''.join(chunks)
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
        process.wait()


def metadata_rows(raw):
    # Both local inventories are bounded, NUL-terminated records, never worktree content.
    if len(raw) > artifact.MAX_FILE_BYTES:
        raise ValueError('Git metadata byte limit exceeded')
    if not raw or not raw.endswith(b'\0'):
        raise ValueError('malformed Git metadata framing')
    rows = raw[:-1].split(b'\0')
    if len(rows) > 4096 or any(not row for row in rows):
        raise ValueError('empty or excessive Git metadata rows')
    return rows


def freeze_execution_material(bindings, modes, commit, selection_bytes):
    """Fixed checked closure as immutable data, not authenticated executable buffers."""
    if sum(len(bindings[name]) for name in (CONTRACT, *CHECKERS)) > 8 * 1024 * 1024:
        raise ValueError('execution material decoded byte limit exceeded')
    members = []
    for name in sorted((CONTRACT, *CHECKERS)):
        data = bindings[name]
        members.append({'path': name, 'type': 'file',
                        'kind': 'python' if name.startswith('scripts/') else 'policy',
                        'mode': f'{modes[name]:04o}', 'size': len(data),
                        'sha256': hashlib.sha256(data).hexdigest(),
                        'content_base64': base64.b64encode(data).decode('ascii')})
    frozen = artifact.canonical({
        'format': 'compose-execution-material-v1', 'executable': False,
        'authority': 'untrusted-local-source-only', 'source_commit': commit,
        'selection_sha256': hashlib.sha256(selection_bytes).hexdigest(), 'members': members,
    }) + b'\n'
    if len(frozen) > 8 * 1024 * 1024:
        raise ValueError('execution material encoded byte limit exceeded')
    return frozen


def select(root, source, trust, output, git):
    if source != 'HEAD':
        raise ValueError('only exact committed HEAD selection is supported')
    commit = git(root, ['rev-parse', '--verify', 'HEAD^{commit}']).decode().strip()
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('invalid committed source')
    if git(root, ['rev-parse', '--verify', 'refs/remotes/origin/main']).decode().strip() != commit:
        raise ValueError('source differs from local origin/main; no publication proof implied')
    # No worktree-content Git commands: they may run attribute conversion filters.
    # Only the explicitly admitted bytes below are checked; unrelated cleanliness is not claimed.
    binding_identities = artifact.source_identities(root, [CONTRACT, *CHECKERS])
    raw_contract, contract_mode = artifact.bounded_read(root / CONTRACT, 1024 * 1024)
    contract = yaml_object(raw_contract)
    policy = artifact.validate_policy(contract.get('compose_deployment'))
    # Enumerate the captured local tree independently of the mutable index. Filtering
    # this query by index-selected names would hide committed optional member deletions.
    committed_entries = {}
    for row in metadata_rows(git(root, ['ls-tree', '-rz', commit])):
        match = re.fullmatch(rb'(100644|100755|120000|160000) (blob|commit) [0-9a-f]{40}\t([^\0]+)', row)
        if match is None or (match[1] == b'160000') != (match[2] == b'commit'):
            raise ValueError('unsupported committed source metadata')
        name = match[3].decode()
        if name in committed_entries:
            raise ValueError('duplicate committed metadata path')
        committed_entries[name] = match[1]
    paths = artifact.strict_selected_paths(list(committed_entries), policy)
    tracked = [row.decode() for row in metadata_rows(git(root, ['ls-files', '-z']))]
    if artifact.strict_selected_paths(tracked, policy) != paths:
        raise ValueError('selected membership set differs from captured commit')
    identities = artifact.source_identities(root, paths)
    manifest, buffers = artifact.strict_snapshot(root, paths)
    includes = yaml_object(buffers['docker-compose.yml'])
    if (set(includes) != {'include'} or not isinstance(includes['include'], list)
            or sorted(includes['include']) != sorted('./' + p for p in artifact.STACK_PATHS)):
        raise ValueError('unsupported Compose include selection')
    bindings = {CONTRACT: raw_contract}
    binding_modes = {CONTRACT: contract_mode}
    for name in CHECKERS:
        bindings[name], binding_modes[name] = artifact.bounded_read(root / name)
        executing_bytes, _ = artifact.bounded_read(Path(__file__).absolute().parents[1] / name)
        if executing_bytes != bindings[name]:
            raise ValueError('selected checker differs from the offline implementation in use')
    source_buffers = {**buffers, **bindings}
    source_modes = {**{e['path']: int(e['mode'], 8) for e in manifest['entries']}, **binding_modes}
    for name, data in source_buffers.items():
        committed_mode = committed_entries.get(name)
        if committed_mode not in (b'100644', b'100755'):
            raise ValueError('unsupported or missing committed source mode/type')
        if bool(source_modes[name] & 0o111) != (committed_mode == b'100755'):
            raise ValueError('committed executable mode differs')
        if name not in tracked or git(root, ['show', commit + ':' + name]) != data:
            raise ValueError('selected bytes are not the exact committed source')
    trust_bytes, _ = artifact.bounded_read(trust, 65536)
    if not trust_bytes:
        raise ValueError('empty trust input')
    # Bookend selected disk bytes/modes and source ref; never normalize Git 100644 to disk 0644.
    after, _ = artifact.strict_snapshot(root, paths)
    if (after != manifest or artifact.source_identities(root, paths) != identities
            or artifact.source_identities(root, [CONTRACT, *CHECKERS]) != binding_identities
            or git(root, ['rev-parse', '--verify', 'HEAD^{commit}']).decode().strip() != commit):
        raise ValueError('source changed during selection')
    selection = {
        'format': 'compose-offline-selection-v1', 'executable': False,
        'source_commit': commit, 'source_ref': source, 'publication': 'local-ref-only',
        'contract_sha256': hashlib.sha256(raw_contract).hexdigest(),
        'checker_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in bindings.items() if name != CONTRACT},
        'trust_sha256': hashlib.sha256(trust_bytes).hexdigest(),
        'policy': policy, 'manifest': manifest,
        'unavailable': ['observe', 'apply', 'verify', 'recovery'],
    }
    selection_bytes = artifact.canonical(selection) + b'\n'
    material_bytes = freeze_execution_material(bindings, binding_modes, commit, selection_bytes)
    # Per-operation collision/no-follow checks do not pin regular directories for
    # the transaction lifetime. Stronger output-directory pinning is deferred.
    artifact.exclusive_directory(output)
    artifact.strict_copy(output / 'artifact', manifest, buffers)
    artifact.verify_tree(output / 'artifact', manifest)
    artifact.exclusive_file(output / 'contract.yml', raw_contract)
    artifact.exclusive_file(output / 'selection.json', selection_bytes)
    artifact.exclusive_file(output / 'execution-material.json', material_bytes)
    return selection


def json_object(path):
    raw, _ = artifact.bounded_read(path, 1024 * 1024)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result

    try:
        result = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError('invalid JSON constant')))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('malformed JSON (contents suppressed)') from exc
    if not isinstance(result, dict):
        raise ValueError('JSON object required')
    return result, hashlib.sha256(raw).hexdigest()


def selection_input(path):
    value, identity = json_object(path)
    if (set(value) != {'format', 'executable', 'source_commit', 'source_ref', 'publication',
                       'contract_sha256', 'checker_sha256', 'trust_sha256', 'policy', 'manifest', 'unavailable'}
            or value['format'] != 'compose-offline-selection-v1' or value['executable'] is not False
            or value['source_ref'] != 'HEAD' or value['publication'] != 'local-ref-only'
            or value['unavailable'] != ['observe', 'apply', 'verify', 'recovery']
            or not isinstance(value['source_commit'], str)
            or not re.fullmatch('[0-9a-f]{40}', value['source_commit'])
            or not isinstance(value['checker_sha256'], dict) or set(value['checker_sha256']) != set(CHECKERS)):
        raise ValueError('invalid offline selection')
    for digest in [value['contract_sha256'], value['trust_sha256'], *value['checker_sha256'].values()]:
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('invalid selection identity')
    for name in CHECKERS:
        checker, _ = artifact.bounded_read(Path(__file__).absolute().parents[1] / name)
        if hashlib.sha256(checker).hexdigest() != value['checker_sha256'][name]:
            raise ValueError('offline selection checker identity incompatible with implementation')
    artifact.validate_manifest(value['manifest'])
    artifact.validate_policy(value['policy'])
    raw_contract, _ = artifact.bounded_read(path.parent / 'contract.yml', 1024 * 1024)
    if hashlib.sha256(raw_contract).hexdigest() != value['contract_sha256']:
        raise ValueError('contract identity mismatch')
    policy = artifact.validate_policy(yaml_object(raw_contract).get('compose_deployment'))
    if policy != value['policy']:
        raise ValueError('contract policy mismatch')
    # Internal byte binding only; these local claims do not authenticate source or native evidence.
    value['policy'] = policy
    names = [e['path'] for e in value['manifest']['entries']]
    if artifact.strict_selected_paths(names, value['policy']) != names:
        raise ValueError('unselected manifest path')
    artifact.verify_tree(path.parent / 'artifact', value['manifest'])
    return value, identity


def plan(previous, selection, consumers, output, offline_evidence=None):
    old, old_identity = selection_input(previous)
    new, new_identity = selection_input(selection)
    evidence, evidence_identity = json_object(consumers)
    diff = module('compose-deployment-diff')
    result = diff.review_plan(old['manifest'], new['manifest'], evidence, old['policy'], new['policy'])
    result['bindings'] = {
        'previous_selection_sha256': old_identity, 'selection_sha256': new_identity,
        'consumer_review_sha256': evidence_identity,
        'old_source_commit': old['source_commit'], 'new_source_commit': new['source_commit'],
        'old_manifest_sha256': old['manifest']['sha256'], 'new_manifest_sha256': new['manifest']['sha256'],
        'old_artifact_sha256': old['manifest']['legacy_sha256'], 'new_artifact_sha256': new['manifest']['legacy_sha256'],
        'old_contract_sha256': old['contract_sha256'], 'new_contract_sha256': new['contract_sha256'],
    }
    if offline_evidence is not None:
        supplied, supplied_identity = json_object(offline_evidence)
        result['offline_evidence'] = diff.review_offline_evidence(supplied, result['bindings'], old['manifest'], new['manifest'])
        result['bindings']['offline_evidence_sha256'] = supplied_identity
        result['blockers'] = sorted(set(result['blockers']) | set(result['offline_evidence']['blockers']))
        result['status'] = 'blocked'
    artifact.exclusive_directory(output)
    artifact.exclusive_file(output / 'plan.json', artifact.canonical(result) + b'\n')
    return result


def main(argv=None, *, git=None):
    parser = ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    choose = commands.add_parser('select')
    choose.add_argument('--source', required=True, choices=['HEAD'])
    choose.add_argument('--root', type=Path, default=Path.cwd())
    choose.add_argument('--known-hosts', type=Path, required=True)
    choose.add_argument('--output', type=Path, required=True)
    review = commands.add_parser('plan', help='untrusted local consumer review, never an executable plan')
    review.add_argument('--previous', type=Path, required=True)
    review.add_argument('--selection', type=Path, required=True)
    review.add_argument('--consumers', type=Path, required=True)
    review.add_argument('--output', type=Path, required=True)
    review.add_argument('--evidence', type=Path, help='bounded synthetic/untrusted action/runtime/image review; never native qualification')
    args = parser.parse_args(argv)
    if args.command == 'select':
        result = select(args.root.absolute(), args.source, args.known_hosts.absolute(), args.output.absolute(), git or git_read)
    else:
        result = plan(args.previous.absolute(), args.selection.absolute(), args.consumers.absolute(), args.output.absolute(),
                      args.evidence.absolute() if args.evidence is not None else None)
    print(json.dumps({'format': result['format'], 'executable': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError):
        # Never echo raw source, policy values, secrets or native errors.
        print('blocked: invalid offline input or unavailable capability; retain partial output', file=sys.stderr)
        raise SystemExit(2)
