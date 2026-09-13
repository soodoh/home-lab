#!/usr/bin/env python3
"""Combine secret-free Compose inventories and dry-run actions into a deploy plan."""

from argparse import ArgumentParser
import json
import importlib.util
import re
from pathlib import Path


def load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("plan input must be a JSON object")
    return value


def review_plan(old: dict, new: dict, evidence: dict, old_policy: dict, new_policy: dict) -> dict:
    """Pure offline reducer. The legacy CLI below remains an operational compatibility lane.

    Supplied mount rows are sanitized review claims, NOT authenticated native captures.
    Roots are questions for a later collector, never dependency closure or effect argv.
    """
    spec = importlib.util.spec_from_file_location('compose_artifact_review', Path(__file__).with_name('compose-artifact.py'))
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    artifact.validate_manifest(old)
    artifact.validate_manifest(new)
    artifact.validate_policy(old_policy)
    artifact.validate_policy(new_policy)
    if (not isinstance(evidence, dict)
            or set(evidence) != {'format', 'old_manifest_sha256', 'new_manifest_sha256', 'old', 'new'}
            or evidence['format'] != 'compose-consumer-review-v1'
            or evidence['old_manifest_sha256'] != old['sha256']
            or evidence['new_manifest_sha256'] != new['sha256']):
        raise ValueError('invalid review consumer bindings')
    rows = []
    blockers = set()
    manifests = {'old': {e['path']: e for e in old['entries']},
                 'new': {e['path']: e for e in new['entries']}}
    for side in ('old', 'new'):
        values = evidence[side]
        if not isinstance(values, list) or len(values) > 1024:
            raise ValueError('invalid consumer count')
        seen = set()
        sources = set()
        targets = {}
        for row in values:
            if (not isinstance(row, dict) or set(row) != {'service', 'kind', 'source', 'target', 'access'}
                    or not isinstance(row['service'], str)
                    or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', row['service'])
                    or row['kind'] not in ('file', 'directory', 'config', 'secret')
                    or row['access'] not in ('read-only', 'writable', 'mixed-mutable', 'unknown')):
                raise ValueError('invalid consumer row')
            artifact.strict_path(row['source'])
            target = row['target']
            if (not isinstance(target, str) or not 1 <= len(target) <= 240
                    or not re.fullmatch(r'/(?:[A-Za-z0-9_. -]+(?:/[A-Za-z0-9_. -]+)*)?', target)
                    or any(part in ('.', '..') for part in target.split('/'))):
                raise ValueError('invalid consumer target')
            # Conservative ambiguity only, not an implementation of Compose mount resolution.
            for earlier in targets.setdefault(row['service'], []):
                if (target == earlier or target.startswith(earlier.rstrip('/') + '/')
                        or earlier.startswith(target.rstrip('/') + '/')):
                    pair = ':'.join(sorted((earlier, target)))
                    blockers.add(side + ':ambiguous-target:' + row['service'] + ':' + pair)
            targets[row['service']].append(target)
            identity = artifact.canonical(row)
            if identity in seen:
                raise ValueError('duplicate consumer row')
            seen.add(identity)
            source_identity = (row['service'], row['source'], target)
            if source_identity in sources:
                blockers.add(side + ':ambiguous-consumer:' + row['service'] + ':' + row['source'])
            sources.add(source_identity)
            if row['access'] in ('mixed-mutable', 'unknown'):
                blockers.add(side + ':consumer-' + row['access'] + ':' + row['service'])
            present = (any(name.startswith(row['source'] + '/') for name in manifests[side])
                       if row['kind'] == 'directory' else row['source'] in manifests[side])
            if not present:
                blockers.add(side + ':missing-consumer-source:' + row['source'])
            rows.append({'side': side, **row})
    deltas = []
    roots = set()
    for name in sorted(manifests['old'].keys() | manifests['new'].keys()):
        before, after = manifests['old'].get(name), manifests['new'].get(name)
        changes = []
        if before is None:
            changes.append('added')
        elif after is None:
            changes.append('removed')
        else:
            if before['sha256'] != after['sha256'] or before['size'] != after['size']:
                changes.append('byte-changed')
            if before['mode'] != after['mode']:
                changes.append('mode-changed')
        if not changes:
            continue
        consumers = [row for row in rows if name == row['source'] or
                     (row['kind'] == 'directory' and name.startswith(row['source'] + '/'))]
        reasons = {'pending-native-actions-and-adoption'}
        roots.update(row['service'] for row in consumers)
        if after is None and any(
                row['side'] == 'new' and (row['kind'] != 'directory' or not any(
                    path.startswith(row['source'] + '/') for path in manifests['new']))
                for row in consumers):
            reasons.add('removed-source-required-by-target')
            blockers.add(name + ':removed-source-required-by-target')
        for side, policy in (('old', old_policy), ('new', new_policy)):
            if name not in manifests[side]:
                continue
            asset = artifact.asset_policy(name, policy)
            if asset is not None and asset['disposition'] == 'host-consumed':
                host = asset['host']
                reasons.add('host-consumer-' + host['adoption'])
                blockers.add(name + ':host-consumer-' + host['adoption'])
                consumers.append({'side': side, 'kind': 'host', **host})
            elif asset is not None and asset['disposition'] == 'retained-only':
                reasons.add('retained-only-change-requires-disposition')
                blockers.add(name + ':retained-only-change-requires-disposition')
            elif name.startswith('services/data/') and (asset is None or not consumers):
                blockers.add(name + ':unknown-consumer-or-policy')
                reasons.add('unknown-consumer-or-policy')
        if name.startswith('secrets/'):
            blockers.add(name + ':separate-secret-lifecycle-required')
            reasons.add('separate-secret-lifecycle-required')
        if name.startswith('scripts/'):
            reasons.add('execution-helper-code-review-required')
        if any(row.get('access') == 'writable' for row in consumers):
            reasons.add('writable-source-mutation-evidence-required')
        deltas.append({'path': name, 'changes': changes, 'consumers': consumers, 'reasons': sorted(reasons)})
    if old_policy != new_policy:
        blockers.add('consumer-policy-change-requires-review')
    return {'format': 'compose-offline-plan-v1', 'status': 'blocked' if blockers else 'review-only',
            'executable': False, 'process_adoption': False, 'evidence_authority': 'untrusted-review-input',
            'artifact_no_change': not deltas, 'deltas': deltas, 'blockers': sorted(blockers),
            'roots_requiring_native_evidence': sorted(roots),
            'pending': ['admitted-native-evidence', 'image-and-runtime-identities', 'lifecycle-and-recovery-support'],
            'unavailable': ['observe', 'apply', 'verify', 'recovery']}


def review_offline_evidence(value: dict, bindings: dict, old: dict, new: dict) -> dict:
    """Reduce saved synthetic claims only; never dispatch the compatibility CLIs.

    --evidence is compose-offline-evidence-v1 with exact selection/consumer bindings,
    project/tool, three independent generations, runtime, actions and optional transition.
    Digests bind supplied content to itself, NOT source/host authority or native grammar.
    """
    import hashlib
    def digest(item):
        return hashlib.sha256(json.dumps(item, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    def helper(name):
        spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    if (not isinstance(value, dict) or set(value) != {'format', 'bindings', 'project', 'tool',
            'generations', 'runtime', 'actions', 'transition'}
            or value['format'] != 'compose-offline-evidence-v1' or value['bindings'] != bindings
            or not isinstance(value['project'], str) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', value['project'])):
        raise ValueError('invalid offline evidence bindings')
    tool = value['tool']
    if (not isinstance(tool, dict) or set(tool) != {'name', 'version', 'binary_sha256'}
            or tool['name'] != 'compose' or not isinstance(tool['version'], str)
            or not re.fullmatch('[A-Za-z0-9_.-]{1,64}', tool['version'])
            or not isinstance(tool['binary_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', tool['binary_sha256'])):
        raise ValueError('invalid unqualified tool identity')
    generations = value['generations']
    if not isinstance(generations, dict) or set(generations) != {'current', 'candidate', 'previous'}:
        raise ValueError('independent image generations required')
    images = helper('compose-image-lock').review_generations(generations, value['project'], old, new, value['transition'])
    runtime = helper('compose-model-inventory').review_runtime(value['runtime'], generations['current'],
                                                              value['project'], digest(tool))
    actions = helper('compose-action-plan').review_actions(value['actions'], generations['candidate'],
                                                          runtime, digest(tool))
    return {'native_qualified': False, 'evidence_authority': 'untrusted-review-input',
            'runtime': runtime, 'actions': actions, 'images': images,
            'blockers': sorted(set(actions['blockers']) | set(images['blockers']))}


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument("--desired", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--actions", required=True, type=Path)
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--current-root", required=True, type=Path)
    parser.add_argument("--candidate-hash", required=True)
    parser.add_argument("--deployed-hash", required=True)
    parser.add_argument("--canary-service", required=True)
    parser.add_argument("--canary-path", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    desired = load_object(args.desired)
    runtime = load_object(args.runtime)
    actions = load_object(args.actions)
    if desired.get("kind") != "desired" or runtime.get("kind") != "runtime":
        raise SystemExit("inventory kinds are invalid")
    if desired.get("project_name") != runtime.get("project_name"):
        raise SystemExit("inventory project names differ")
    desired_services = desired.get("services")
    runtime_services = runtime.get("services")
    recreate_services = actions.get("recreate_services")
    forbidden_actions = actions.get("forbidden_actions")
    if not isinstance(desired_services, dict) or not isinstance(runtime_services, dict):
        raise SystemExit("inventory services are invalid")
    if not isinstance(recreate_services, list) or not isinstance(forbidden_actions, list):
        raise SystemExit("action plan is invalid")

    desired_names = set(desired_services)
    runtime_names = set(runtime_services)
    image_services = []
    stateful_services = []
    for service_name in sorted(desired_names & runtime_names):
        desired_service = desired_services[service_name]
        runtime_service = runtime_services[service_name]
        if not isinstance(desired_service, dict) or not isinstance(runtime_service, dict):
            raise SystemExit("service inventory entry is invalid")
        if desired_service.get("image") != runtime_service.get("image"):
            image_services.append(service_name)
        volumes = desired_service.get("volumes")
        if service_name in recreate_services and isinstance(volumes, list) and volumes:
            stateful_services.append(service_name)

    candidate_paths = {
        path.relative_to(args.candidate_root).as_posix(): path.read_bytes()
        for path in args.candidate_root.rglob("*")
        if path.is_file()
    }
    current_paths = {
        path.relative_to(args.current_root).as_posix(): path.read_bytes()
        for path in args.current_root.rglob("*")
        if path.is_file()
    }
    changed_paths = sorted(
        path
        for path in set(candidate_paths) | set(current_paths)
        if candidate_paths.get(path) != current_paths.get(path)
    )

    canary_eligible = (
        args.candidate_hash != args.deployed_hash
        and image_services == [args.canary_service]
        and sorted(set(recreate_services)) == [args.canary_service]
        and not stateful_services
        and not forbidden_actions
        and desired_names == runtime_names
        and changed_paths == [args.canary_path]
    )
    artifact_only_eligible = (
        args.candidate_hash != args.deployed_hash
        and not recreate_services
        and not image_services
        and not forbidden_actions
        and desired_names == runtime_names
        and bool(changed_paths)
        and all(path.startswith("scripts/") for path in changed_paths)
    )

    report = {
        "candidate_hash": args.candidate_hash,
        "deployed_hash": args.deployed_hash,
        "has_changes": args.candidate_hash != args.deployed_hash,
        "recreate_services": sorted(set(recreate_services)),
        "image_services": image_services,
        "stateful_recreate_services": stateful_services,
        "missing_runtime_services": sorted(desired_names - runtime_names),
        "unexpected_runtime_services": sorted(runtime_names - desired_names),
        "forbidden_actions": forbidden_actions,
        "changed_paths": changed_paths,
        "manual_only_paths": [
            path for path in changed_paths if path.startswith("services/data/")
        ],
        "canary_service": args.canary_service,
        "canary_path": args.canary_path,
        "canary_eligible": canary_eligible,
        "artifact_only_eligible": artifact_only_eligible,
    }
    args.output.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)


if __name__ == "__main__":
    main()
