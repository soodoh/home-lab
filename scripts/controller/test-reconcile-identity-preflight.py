#!/usr/bin/env python3
"""Real verify/apply-tailnet dispatch with synthetic plans, never live endpoints.

Only source-listed files are copied. The inspector, boundary admission, manifest
checks, descriptor lock and policy/recap parsers are real; operational tools are
closed fixture implementations. No credentials or configuration are inherited.
"""
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ROOTS = ('aws-foundation', 'proxmox', 'omada', 'tailscale', 'authentik')
SENTINEL = 'SYNTHETIC-RAW-PLAN-VALUE-DO-NOT-DISPLAY'
PLAN_ARN = 'arn:aws:iam::658271954302:policy/fixture/plan'
APPLY_ARN = 'arn:aws:iam::658271954302:policy/fixture/apply'
SOURCES = (
    'scripts/reconcile-infrastructure', 'scripts/inspect-tofu-plan',
    'infrastructure/policy/inspect-plan.py',
    'scripts/controller/controller-boundaries.sh',
    'scripts/controller/controller-boundary-manifest.py',
    'scripts/controller/controller-apply-lock.py', 'scripts/controller/controller_lock.py',
    'scripts/controller/tailscale-policy.py', 'scripts/controller/parse-ansible-recap.py',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(actions=None, kind='aws_iam_role'):
    return {'address': kind + '.fixture', 'type': kind, 'mode': 'managed',
            'change': {'actions': actions or ['no-op'],
                       'before': {'policy': SENTINEL}, 'after': {'policy': SENTINEL}}}


def noop():
    return {'complete': True, 'errored': False, 'resource_changes': [identity()]}


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o700)


# One closed mock executable implements only the operations reached by these
# public paths. Unknown commands fail, and none delegates to an operational tool.
MOCK = r'''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
base = pathlib.Path(os.environ['FIXTURE_BASE'])
repo = base / 'repo'
with (base / 'events').open('a') as stream:
    stream.write(json.dumps([name, args]) + '\n')
def refuse():
    raise SystemExit('unexpected fixture endpoint: ' + name)
def emit(value):
    print(json.dumps(value))
if name == 'git':
    if args == ['rev-parse', 'HEAD']: print('0' * 40)
    elif args != ['status', '--porcelain', '--untracked-files=all']: refuse()
elif name == 'node':
    if args == ['scripts/controller/check-vm-100-authority.js', '--require-ordinary-mutation']: pass
    elif args[:1] == ['scripts/controller/proxmox-check-evidence.js'] and args[1] in ('collect', 'verify', 'recheck'): emit({'verified': True})
    elif args == ['--input-type=module', '-'] and os.environ.get('EXPRESSION') == 'backups.legacy_offen.retirement.state': print('retired')
    else: refuse()
elif name == 'tofu':
    root = args.pop(0).removeprefix('-chdir=infrastructure/tofu/')
    if root not in ('aws-foundation', 'proxmox', 'omada', 'tailscale', 'authentik'): refuse()
    operation = args.pop(0)
    scenario = json.loads((base / 'scenario.json').read_text())
    if operation == 'init':
        (base / (root + '.ready')).touch()
    elif operation == 'plan':
        assert (base / (root + '.ready')).exists()
        expected = ['-var=controller_plan_permissions_boundary_arn=' + os.environ['TF_VAR_controller_plan_permissions_boundary_arn'],
                    '-var=controller_apply_permissions_boundary_arn=' + os.environ['TF_VAR_controller_apply_permissions_boundary_arn']]
        if root == 'omada': expected = ['-var=omada_export_path=' + str(repo / '.local/omada/export.json')]
        elif root != 'aws-foundation': expected = []
        assert [arg for arg in args if arg.startswith('-var=')] == expected
        selected = scenario if root == scenario['root'] else {'plan': {'complete': True, 'resource_changes': []}, 'exit': 0}
        outputs = [arg[5:] for arg in args if arg.startswith('-out=')]
        if outputs:
            assert len(outputs) == 1
            target = pathlib.Path(outputs[0])
            assert target.is_relative_to(base / 'tmp') and not target.is_relative_to(repo / '.reconcile')
            assert target.parent.stat().st_mode & 0o777 == 0o700
            target.write_bytes(b'FRESH\n' + json.dumps(selected).encode())
            assert target.stat().st_mode & 0o777 == 0o600
        print('SYNTHETIC-RAW-PLAN-VALUE-DO-NOT-DISPLAY')
        raise SystemExit(selected['exit'])
    elif operation == 'show':
        assert args[0] == '-json' and (base / (root + '.ready')).exists()
        raw = pathlib.Path(args[1]).read_bytes()
        marker, payload = raw.split(b'\n', 1)
        value = json.loads(payload)
        if marker == b'FRESH':
            print('SYNTHETIC-RAW-PLAN-VALUE-DO-NOT-DISPLAY', file=sys.stderr)
            if value.get('show_fail'): raise SystemExit(43)
            if value.get('malformed'): print('{'); raise SystemExit(0)
            emit(value['plan'])
        else:
            assert marker == b'SAVED'
            emit(value)
    elif operation == 'apply':
        assert root == 'tailscale'
        assert pathlib.Path(args[-1]) == repo / '.reconcile/plans/reviewed/tailscale.tfplan'
        assert pathlib.Path(args[-1]).read_bytes().startswith(b'SAVED\n')
    elif operation == 'state' and args == ['pull'] and root == 'tailscale':
        emit({'resources': [{'type': 'terraform_data', 'name': 'tailscale_policy', 'instances': [
            {'attributes': {'input': {'value': {'policy_json': (base / 'live-policy').read_text()}}}}]}]})
    else: refuse()
elif name == 'ansible-inventory':
    assert args[-1] == '--list'
    emit({'_meta': {'hostvars': {'docker-host-production': {}, 'proxmox-host-production': {}}}})
elif name == 'ansible-playbook':
    assert '--check' in args and '--diff' in args
    assert args[2] in ('playbooks/audit.yml', 'playbooks/proxmox-access-cutover-plan.yml')
    host = 'docker-host-production' if args[2] == 'playbooks/audit.yml' else 'proxmox-host-production'
    print(host + ' : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0')
elif name == 'curl':
    if args[-1] == 'https://api.tailscale.com/api/v2/oauth/token':
        assert '--data-binary' in args
        emit({'access_token': 'synthetic-token'})
    elif '-D' in args:
        pathlib.Path(args[args.index('-D') + 1]).write_text('ETag: "fixture-etag"\r\n')
        pathlib.Path(args[args.index('-o') + 1]).write_text((base / 'live-policy').read_text())
    elif '--data-binary' in args and '-o' in args:
        payload = pathlib.Path(args[args.index('--data-binary') + 1][1:]).read_text()
        if '-X' in args:
            assert args[args.index('-X') + 1] == 'POST'
            assert 'If-Match: "fixture-etag"' in args
            (base / 'live-policy').write_text(payload)
        else: assert any(arg.endswith('/acl/validate') for arg in args)
        pathlib.Path(args[args.index('-o') + 1]).write_text('{}')
    else: refuse()
else: refuse()
'''


class IdentityPreflightDispatchTests(unittest.TestCase):
    dispatches = 0

    @classmethod
    def tearDownClass(cls):
        print(f'Synthetic public dispatches: {cls.dispatches}; no live endpoints.')

    def dispatch(self, action, scenario):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repo = base / 'repo'
            for relative in SOURCES:
                destination = repo / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            for source in (ROOT / 'infrastructure/policy/allow').glob('*.txt'):
                destination = repo / 'infrastructure/policy/allow' / source.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            (repo / 'ansible').mkdir()
            (repo / '.reconcile').mkdir(mode=0o700)
            plans = repo / '.reconcile/plans/reviewed'
            plans.mkdir(parents=True, mode=0o700)
            home = base / 'home'; home.mkdir(mode=0o700)
            temporary = base / 'tmp'; temporary.mkdir(mode=0o700)
            binaries = base / 'bin'; binaries.mkdir()
            python = shlex.quote(sys.executable)
            executable(binaries / 'python3', f'#!/bin/sh\nexec {python} -I -B -S "$@"\n')
            jq = shutil.which('jq')
            self.assertIsNotNone(jq, 'jq is required; no installation or fallback')
            executable(binaries / 'jq', f'#!/bin/sh\nexec {shlex.quote(jq)} "$@"\n')
            for name in ('git', 'node', 'tofu', 'ansible', 'ansible-playbook', 'ansible-inventory',
                         'curl', 'go', 'aws', 'ssh', 'docker', 'nix'):
                executable(binaries / name, '#!/usr/bin/env python3\n' + MOCK)
            executable(repo / 'scripts/compose-artifact.py', "print('a' * 64)\n")
            boundary = base / 'boundaries.json'
            document = {'version': 1, 'account_id': '658271954302', 'partition': 'aws',
                        'plan_policy_arn': PLAN_ARN, 'apply_policy_arn': APPLY_ARN,
                        'provenance': {'review_reference': 'synthetic-only',
                                       'plan_policy_sha256': 'a' * 64, 'apply_policy_sha256': 'b' * 64}}
            boundary.write_text(json.dumps(document)); boundary.chmod(0o600)
            before = '{"grants":[]}\n'
            after = '{"grants":[],"tagOwners":{}}\n'
            (base / 'live-policy').write_text(before)
            records = []
            for root in ROOTS:
                value = noop()
                if root == 'tailscale':
                    value['resource_changes'] = [{'address': 'terraform_data.tailscale_policy[0]',
                        'type': 'terraform_data', 'mode': 'managed', 'change': {'actions': ['update'],
                        'before': {'input': {'policy_json': before}}, 'after': {'input': {'policy_json': after}}}}]
                saved = plans / (root + '.tfplan')
                saved.write_bytes(b'SAVED\n' + json.dumps(value).encode()); saved.chmod(0o600)
                records.append({'root': root, 'file': saved.name, 'sha256': digest(saved.read_bytes()),
                    'changed': root == 'tailscale',
                    'tailscale_policy_before_sha256': digest(before.encode()) if root == 'tailscale' else '',
                    'tailscale_policy_after_sha256': digest(after.encode()) if root == 'tailscale' else '',
                    'tailscale_policy_etag': '"fixture-etag"' if root == 'tailscale' else ''})
            manifest = plans / 'manifest.json'
            manifest.write_text(json.dumps({'version': 6, 'commit': '0' * 40, 'phase': 'steady',
                'stage': 'converge', 'backend_bucket': 'synthetic-state-bucket',
                'controller_boundary_manifest': {'path': str(boundary), 'sha256': digest(boundary.read_bytes()), 'document': document},
                'compose_artifact_sha256': 'a' * 64, 'ansible_extra_vars_file_sha256': '',
                'recovery_backup_identity_sha256': '', 'recovery_expectations_sha256': '',
                'offen_retirement_operation': '', 'plans': records,
                'proxmox_host_check': {'file': '.reconcile/plans/' + 'f' * 64 + '.check.json', 'sha256': 'f' * 64}}))
            manifest.chmod(0o600)
            preserved = [*plans.iterdir(), boundary, *(repo / 'infrastructure/policy/allow').glob('*.txt')]
            original = {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in preserved}
            (base / 'scenario.json').write_text(json.dumps({'root': 'aws-foundation', 'exit': 0, **scenario}))
            env = {'HOME': str(home), 'TMPDIR': str(temporary), 'PATH': f'{binaries}:/usr/bin:/bin',
                   'FIXTURE_BASE': str(base), 'TF_BACKEND_BUCKET': 'synthetic-state-bucket', 'AWS_REGION': 'us-east-1',
                   'TF_VAR_omada_enable_management': 'true', 'TF_VAR_authentik_enable_management': 'true',
                   'TF_VAR_tailscale_enable_management': 'true',
                   'TAILSCALE_OAUTH_CLIENT_ID': 'synthetic-client', 'TAILSCALE_OAUTH_CLIENT_SECRET': 'synthetic-secret',
                   'RECONCILE_REVIEWED_MANIFEST_SHA256': digest(manifest.read_bytes())}
            type(self).dispatches += 1
            result = subprocess.run(['/bin/bash', str(repo / 'scripts/reconcile-infrastructure'), action,
                '--plan-dir', str(plans), '--boundary-manifest', str(boundary)], cwd=repo, env=env,
                capture_output=True, text=True, timeout=30)
            events = [json.loads(line) for line in (base / 'events').read_text().splitlines()]
            self.assertEqual(original, {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in preserved})
            self.assertNotIn(SENTINEL, result.stdout + result.stderr)
            self.assertNotIn('Traceback', result.stdout + result.stderr)
            for log in plans.glob('*.log'):
                self.assertNotIn('Traceback', log.read_text(), log.name)
                self.assertNotIn('unexpected fixture endpoint', log.read_text(), log.name)
            self.assertEqual(list(temporary.iterdir()), [], 'temporary plans/decoded JSON must be removed even on refusal')
            return result, events

    def check_case(self, scenario, denied=True, diagnostic='fresh plan inspection failed'):
        for action in ('verify', 'apply-tailnet'):
            with self.subTest(action=action, scenario=scenario):
                result, events = self.dispatch(action, scenario)
                applies = [args for name, args in events if name == 'tofu' and 'apply' in args]
                fresh = [args for name, args in events if name == 'tofu' and 'plan' in args]
                self.assertTrue(fresh, result.stderr)
                if denied:
                    self.assertNotIn('unexpected fixture endpoint', result.stdout + result.stderr)
                    self.assertNotEqual(result.returncode, 0, 'unchecked fresh plan admitted by ' + action)
                    self.assertEqual(applies, [], 'fresh refusal must exclude downstream saved-plan apply')
                    self.assertFalse(any(name in ('curl', 'ansible-playbook') for name, _ in events))
                    self.assertIn(diagnostic, result.stderr)
                    if diagnostic == 'fresh plan inspection failed':
                        self.assertIn('owner intervention required', result.stderr)
                        self.assertTrue(any(name == 'tofu' and 'show' in args and '/tmp/' in args[-1]
                                            for name, args in events), 'fresh plan must reach the real inspector wrapper')
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(len(applies), int(action == 'apply-tailnet'))
                    self.assertTrue(any(name == 'ansible-playbook' for name, _ in events))
                    # Every successful fresh plan must actually be decoded, not
                    # merely inspected via argv/source assertions.
                    fresh_shows = [args for name, args in events if name == 'tofu' and 'show' in args and '/tmp/' in args[-1]]
                    self.assertEqual(len(fresh_shows), len(fresh))

    def test_valid_fresh_noop_passes_both_dispatches(self):
        self.check_case({'plan': noop()}, denied=False)

    def test_identity_drift_plus_noop_exit_zero_blocks_both_dispatches(self):
        plan = noop(); plan['resource_drift'] = [identity(['update'])]
        self.check_case({'plan': plan})

    def test_incomplete_blocks_both_dispatches(self):
        plan = noop(); plan['complete'] = False
        self.check_case({'plan': plan})

    def test_errored_blocks_both_dispatches(self):
        plan = noop(); plan['errored'] = True
        self.check_case({'plan': plan})

    def test_malformed_envelope_blocks_both_dispatches(self):
        self.check_case({'plan': {'resource_drift': {}}})

    def test_deferred_identity_blocks_both_dispatches(self):
        plan = noop(); plan['deferred_changes'] = [{'resource_change': identity(), 'reason': 'unknown'}]
        self.check_case({'plan': plan})

    def test_managed_oidc_noop_blocks_both_dispatches(self):
        plan = noop(); plan['resource_changes'] = [identity(kind='aws_iam_openid_connect_provider')]
        self.check_case({'plan': plan})

    def test_identity_mutation_blocks_both_dispatches(self):
        plan = noop(); plan['resource_changes'] = [identity(['update'], 'aws_rolesanywhere_profile')]
        self.check_case({'plan': plan, 'exit': 2})

    def test_malformed_json_blocks_both_dispatches(self):
        self.check_case({'plan': noop(), 'malformed': True})

    def test_show_failure_blocks_both_dispatches(self):
        self.check_case({'plan': noop(), 'show_fail': True})

    def test_plan_failure_blocks_both_dispatches(self):
        self.check_case({'plan': noop(), 'exit': 42}, diagnostic='verification planning failed')

    def test_ordinary_nonconvergence_still_blocks_both_dispatches(self):
        self.check_case({'plan': {'resource_changes': []}, 'exit': 2}, diagnostic='root is not converged')

    def test_nonfoundation_root_is_also_inspected(self):
        plan = noop(); plan['resource_drift'] = [identity(['update'])]
        self.check_case({'plan': plan, 'root': 'proxmox'})


if __name__ == '__main__':
    unittest.main()
