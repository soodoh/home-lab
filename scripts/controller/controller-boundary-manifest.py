#!/usr/bin/env python3
"""Validate declared non-secret boundary inputs, not live IAM policy authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

LIMIT = 16384
ACCOUNT = '658271954302'
PARTITION = 'aws'
VARIABLES = {
    'TF_VAR_controller_plan_permissions_boundary_arn': 'plan_policy_arn',
    'TF_VAR_controller_apply_permissions_boundary_arn': 'apply_policy_arn',
}
OWNED_POLICIES = {f'arn:aws:iam::{ACCOUNT}:policy/home-lab-opentofu-state-{role}'
                  for role in ('plan', 'apply')}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                      parse_constant=lambda _: require(False, 'non-finite JSON value'))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'unexpected object keys or type')


def document(value):
    keys(value, ('version', 'account_id', 'partition', 'plan_policy_arn', 'apply_policy_arn', 'provenance'))
    require(type(value['version']) is int and value['version'] == 1, 'unsupported version')
    require(value['account_id'] == ACCOUNT and value['partition'] == PARTITION, 'account or partition mismatch')
    for field in VARIABLES.values():
        arn = value[field]
        require(type(arn) is str and len(arn) <= 1024 and re.fullmatch(
            rf'arn:aws:iam::{ACCOUNT}:policy/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+', arn),
            'expected same-account managed-policy ARN')
        parts = arn.split(':policy/', 1)[1].split('/')
        require(all(part not in ('.', '..') for part in parts)
                and len(parts[-1]) <= 128 and len('/'.join(parts[:-1])) <= 510, 'invalid policy path or name')
        require(arn not in OWNED_POLICIES, 'boundary must not be a controller-owned state policy')
    require(value['plan_policy_arn'] != value['apply_policy_arn'], 'boundary policies must be distinct')
    provenance = value['provenance']
    keys(provenance, ('review_reference', 'plan_policy_sha256', 'apply_policy_sha256'))
    reference = provenance['review_reference']
    require(type(reference) is str and re.fullmatch(r'[\x20-\x7e]{1,256}', reference)
            and reference == reference.strip(), 'invalid provenance review reference')
    for field in ('plan_policy_sha256', 'apply_policy_sha256'):
        require(type(provenance[field]) is str and re.fullmatch(r'[0-9a-f]{64}', provenance[field]),
                'invalid declared policy SHA-256')
    return value


def load(path):
    path = Path(path)
    require(path.is_absolute(), 'manifest path must be explicit and absolute')
    # Open without following the final symlink or blocking on a special file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                and not metadata.st_mode & 0o022, 'manifest must be an owned regular file, not group/world writable')
        raw = stream.read(LIMIT + 1)
    require(0 < len(raw) <= LIMIT, 'manifest size exceeds bounds or is empty')
    value = document(decode(raw))
    for variable, field in VARIABLES.items():
        require(variable not in os.environ or os.environ[variable] == value[field],
                'conflicting boundary TF_VAR override')
    # Do not parse CLI/HCL fragments. Fixed root -var arguments take precedence over
    # auto tfvars; injected CLI arguments are refused rather than interpreted.
    require(not any(v for k, v in os.environ.items() if k == 'TF_CLI_ARGS' or k.startswith('TF_CLI_ARGS_')),
            'TF_CLI_ARGS overrides are not accepted with boundary inputs')
    return {'path': str(path.resolve(strict=True)), 'sha256': hashlib.sha256(raw).hexdigest(), 'document': value}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('action', choices=('load', 'verify'))
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--binding')
    parser.add_argument('--saved-plan')
    args = parser.parse_args()
    try:
        binding = load(args.manifest)
        if args.action == 'load':
            require(args.binding is None and args.saved_plan is None, 'load does not accept verification options')
            print(binding['document']['plan_policy_arn'], binding['document']['apply_policy_arn'],
                  canonical(binding), sep='\t')
        else:
            require(args.binding is not None, 'accepted binding is required')
            require(canonical(decode(args.binding.encode())) == canonical(binding),
                    'accepted manifest content or provenance changed')
            if args.saved_plan is not None:
                saved = decode(Path(args.saved_plan).read_bytes())
                require(type(saved) is dict and canonical(saved.get('controller_boundary_manifest')) == canonical(binding),
                        'saved plan boundary manifest is missing or changed')
    except (OSError, ValueError, RecursionError) as error:
        print(f'controller_boundary_manifest=failed reason={error}', file=sys.stderr)
        return 66
    return 0


if __name__ == '__main__':
    sys.exit(main())
