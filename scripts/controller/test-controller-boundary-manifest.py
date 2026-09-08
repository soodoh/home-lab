#!/usr/bin/env python3
"""Offline subprocess contracts; every provider/credential endpoint is synthetic."""
import copy
import hashlib
import json
import os
from pathlib import Path
import pty
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/controller/controller-boundary-manifest.py'
PYTHON = [sys.executable, '-B', '-E', '-s', '-S']
PLAN = 'arn:aws:iam::658271954302:policy/fixture/plan'
APPLY = 'arn:aws:iam::658271954302:policy/fixture/apply'
PLAN_VAR = 'TF_VAR_controller_plan_permissions_boundary_arn'
APPLY_VAR = 'TF_VAR_controller_apply_permissions_boundary_arn'


def fixture_document():
    return {'version': 1, 'account_id': '658271954302', 'partition': 'aws',
            'plan_policy_arn': PLAN, 'apply_policy_arn': APPLY,
            'provenance': {'review_reference': 'synthetic-review-only',
                           'plan_policy_sha256': 'a' * 64, 'apply_policy_sha256': 'b' * 64}}


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o700)


class BoundaryManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.home = self.base / 'home'; self.home.mkdir(mode=0o700)
        self.bin = self.base / 'bin'; self.bin.mkdir()
        executable(self.bin / 'python3', '#!/bin/sh\nexec ' + ' '.join(PYTHON) + ' "$@"\n')
        self.env = {'HOME': str(self.home), 'PATH': f'{self.bin}:/usr/bin:/bin'}
        self.path = self.base / 'boundaries.json'
        self.write_document(fixture_document())

    def write_document(self, value):
        self.path.write_text(json.dumps(value) + '\n')
        self.path.chmod(0o600)

    def run_helper(self, *args, env=None):
        return subprocess.run([*PYTHON, str(HELPER), *args], env=env or self.env,
                              text=True, capture_output=True, timeout=10)

    def load(self, env=None):
        return self.run_helper('load', '--manifest', str(self.path), env=env)

    def binding(self):
        result = self.load()
        self.assertEqual(result.returncode, 0, result.stderr)
        plan, apply, binding = result.stdout.rstrip('\n').split('\t')
        self.assertEqual((plan, apply), (PLAN, APPLY))
        return json.loads(binding)

    def test_valid_pair_binds_exact_bytes_path_and_declared_provenance(self):
        binding = self.binding()
        self.assertEqual(binding, {'path': str(self.path.resolve()),
                                  'sha256': hashlib.sha256(self.path.read_bytes()).hexdigest(),
                                  'document': fixture_document()})

    def test_required_path_and_strict_bounded_json(self):
        self.assertNotEqual(self.run_helper('load').returncode, 0)
        for raw in ('null', '[]', '{}', '{', '"text"', '{"version":1,"version":1}',
                    json.dumps(fixture_document()).replace('"review_reference":', '"review_reference":"duplicate", "review_reference":'),
                    ' ' * 16385, '\ufeff' + json.dumps(fixture_document())):
            with self.subTest(raw=raw[:60]):
                self.path.write_text(raw)
                self.assertNotEqual(self.load().returncode, 0)

    def test_rejects_unknown_keys_types_accounts_partitions_and_aliasing(self):
        mutations = [lambda d: d.update(extra=True), lambda d: d.update(version=True),
                     lambda d: d.update(version=2), lambda d: d.update(account_id=658271954302),
                     lambda d: d.update(account_id='000000000000'), lambda d: d.update(partition='aws-cn'),
                     lambda d: d.pop('plan_policy_arn'), lambda d: d.update(apply_policy_arn=PLAN),
                     lambda d: d.update(plan_policy_arn=None), lambda d: d.update(provenance=[]),
                     lambda d: d['provenance'].update(extra='unknown'),
                     lambda d: d['provenance'].update(review_reference=''),
                     lambda d: d['provenance'].update(review_reference='x\ny'),
                     lambda d: d['provenance'].update(plan_policy_sha256='A' * 64)]
        for mutate in mutations:
            value = fixture_document(); mutate(value); self.write_document(value)
            self.assertNotEqual(self.load().returncode, 0, value)
        for arn in ('arn:aws:iam::aws:policy/ReadOnlyAccess', PLAN.replace('658271954302', '000000000000'),
                    PLAN.replace(':aws:', ':aws-us-gov:'), PLAN.replace(':policy/', ':role/'),
                    PLAN + '\n', PLAN + ' ', PLAN + '*', PLAN.replace('/fixture/plan', '//plan'),
                    PLAN.replace('/fixture/plan', '/fixture/../plan'), PLAN.replace('/fixture/plan', '/fixture/'),
                    'arn:aws:iam::658271954302:policy/home-lab-opentofu-state-plan',
                    'arn:aws:iam::658271954302:policy/home-lab-opentofu-state-apply'):
            value = fixture_document(); value['plan_policy_arn'] = arn; self.write_document(value)
            self.assertNotEqual(self.load().returncode, 0, arn)

    def test_missing_symlink_nonregular_and_writable_manifest_fail(self):
        self.path.unlink()
        self.assertNotEqual(self.load().returncode, 0)
        self.path.mkdir()
        self.assertNotEqual(self.load().returncode, 0)
        self.path.rmdir()
        target = self.base / 'target'; target.write_text(json.dumps(fixture_document()))
        self.path.symlink_to(target)
        self.assertNotEqual(self.load().returncode, 0)
        self.path.unlink(); self.write_document(fixture_document()); self.path.chmod(0o666)
        self.assertNotEqual(self.load().returncode, 0)

    def test_inherited_overrides_and_cli_injection_are_rejected(self):
        for key in (PLAN_VAR, APPLY_VAR):
            for value in ('', 'wrong', APPLY if key == PLAN_VAR else PLAN):
                self.assertNotEqual(self.load({**self.env, key: value}).returncode, 0)
        self.assertEqual(self.load({**self.env, PLAN_VAR: PLAN, APPLY_VAR: APPLY}).returncode, 0)
        for key in ('TF_CLI_ARGS', 'TF_CLI_ARGS_plan', 'TF_CLI_ARGS_apply', 'TF_CLI_ARGS_init'):
            self.assertNotEqual(self.load({**self.env, key: '-var=controller_plan_permissions_boundary_arn=wrong'}).returncode, 0)

    def test_saved_binding_rejects_bytes_provenance_path_pair_and_legacy_changes(self):
        binding = self.binding()
        saved = self.base / 'saved.json'
        saved.write_text(json.dumps({'controller_boundary_manifest': binding}))
        args = ('verify', '--manifest', str(self.path), '--binding', json.dumps(binding), '--saved-plan', str(saved))
        self.assertEqual(self.run_helper(*args).returncode, 0)
        for mutate in (lambda d: d.update(plan_policy_arn=PLAN + '-new'),
                       lambda d: d['provenance'].update(review_reference='new-review')):
            d = fixture_document(); mutate(d); self.write_document(d)
            self.assertNotEqual(self.run_helper(*args).returncode, 0)
        self.write_document(fixture_document()); self.path.write_text(self.path.read_text() + ' ')
        self.assertNotEqual(self.run_helper(*args).returncode, 0)
        self.write_document(fixture_document())
        other = self.base / 'same-bytes.json'; shutil.copyfile(self.path, other)
        self.assertNotEqual(self.run_helper('verify', '--manifest', str(other), '--binding', json.dumps(binding)).returncode, 0)
        for value in ({}, {'controller_boundary_manifest': {**binding, 'sha256': 'f' * 64}}):
            saved.write_text(json.dumps(value)); self.assertNotEqual(self.run_helper(*args).returncode, 0)

    def fixture_repo(self):
        repo = self.base / 'repo'; (repo / 'scripts/controller').mkdir(parents=True)
        for name in ('local-controller', 'reconcile-infrastructure',
                     'controller/controller-boundary-manifest.py', 'controller/controller-boundaries.sh'):
            source = ROOT / 'scripts' / name
            if source.exists(): shutil.copyfile(source, repo / 'scripts' / name)
        self.events = self.base / 'events'
        self.env['FIXTURE_EVENTS'] = str(self.events)
        executable(self.bin / 'git', '#!/bin/sh\ncase "$1" in rev-parse) printf "%040d\\n" 0;; status) exit 0;; *) exit 98;; esac\n')
        for name in ('tofu', 'aws', 'node', 'nix', 'curl', 'docker', 'ansible', 'ansible-playbook', 'go', 'jq', 'shellcheck', 'ansible-lint'):
            executable(self.bin / name, f'#!/bin/sh\nprintf "{name}:%s\\n" "$*" >>"$FIXTURE_EVENTS"\nexit 91\n')
        return repo

    def test_public_paths_fail_before_any_external_endpoint_when_missing_or_conflicted(self):
        repo = self.fixture_repo()
        for script, actions in (('local-controller', ('plan', 'apply', 'apply-tailnet')),
                                ('reconcile-infrastructure', ('validate', 'plan', 'apply', 'apply-tailnet', 'verify'))):
            for action in actions:
                command = ['/bin/bash', str(repo / 'scripts' / script), action]
                if script == 'local-controller': command += ['steady', '--generation', 'fixture']
                for options, env in (([], self.env),
                                     (['--boundary-manifest', str(self.path)], {**self.env, PLAN_VAR: 'wrong'})):
                    with self.subTest(script=script, action=action, options=options):
                        result = subprocess.run(command + options, env=env, text=True, capture_output=True, timeout=10)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('boundary', result.stderr.lower(), result.stderr)
                        self.assertFalse(self.events.exists(), self.events.read_text() if self.events.exists() else '')

    def test_configured_credential_conflict_fails_before_tls_or_provider(self):
        repo = self.fixture_repo()
        config = self.base / 'config'; config.mkdir(mode=0o700)
        creds = config / 'plan-credentials.json'; creds.write_text(json.dumps({PLAN_VAR: 'wrong'})); creds.chmod(0o600)
        executable(repo / 'scripts/prepare-provider-ca-bundle', '#!/bin/sh\necho tls >>"$FIXTURE_EVENTS"\nexit 91\n')
        result = subprocess.run(['/bin/bash', str(repo / 'scripts/local-controller'), 'plan', 'steady',
                                 '--generation', 'fixture', '--config-dir', str(config),
                                 '--boundary-manifest', str(self.path)], env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('boundary', result.stderr.lower())
        self.assertFalse(self.events.exists())

    def test_apply_config_conflicts_preserve_confirmation_order_and_block_capability_use(self):
        repo = self.fixture_repo()
        config = self.base / 'config'; config.mkdir(mode=0o700)
        creds = config / 'apply-credentials.json'
        creds.write_text(json.dumps({APPLY_VAR: 'synthetic-conflict-not-a-secret'})); creds.chmod(0o600)
        plan_dir = repo / '.reconcile/plans' / ('0' * 40) / 'steady/fixture'
        plan_dir.mkdir(parents=True)
        saved = plan_dir / 'manifest.json'
        saved.write_text(json.dumps({'version': 6, 'commit': '0' * 40, 'phase': 'steady',
                                     'stage': 'converge', 'plans': [],
                                     'controller_boundary_manifest': self.binding()}))
        bundle = repo / '.local/provider-ca/bundle.pem'; bundle.parent.mkdir(parents=True)
        bundle.write_text('synthetic-not-a-certificate'); bundle.chmod(0o600)
        executable(self.bin / 'node', '#!/bin/sh\nprintf "node:%s\\n" "$*" >>"$FIXTURE_EVENTS"\nexit 0\n')
        # Deliberately narrow fixture responses, not a real jq/host verifier.
        executable(self.bin / 'jq', '#!/bin/sh\ncase "$*" in\n'
                   '  "-r .stage "*) echo converge;;\n'
                   '  "-r .plans[] "*) exit 0;;\n'
                   '  "-e --arg commit "*) exit 0;;\n'
                   '  *) echo unexpected-fixture-jq >&2; exit 98;;\nesac\n')
        executable(repo / 'scripts/reconcile-infrastructure',
                   '#!/bin/sh\n[ "$1" = validate ] || exit 98\n'
                   f'[ "${PLAN_VAR}" = "{PLAN}" ] && [ "${APPLY_VAR}" = "{APPLY}" ] || exit 98\n'
                   'printf "reconcile:%s\\n" "$*" >>"$FIXTURE_EVENTS"\n')
        for name in ('prepare-provider-ca-bundle', 'prepare-authentik-plan-input', 'prepare-omada-plan-input'):
            executable(repo / 'scripts' / name,
                       '#!/bin/sh\necho forbidden-capability-use >>"$FIXTURE_EVENTS"\nexit 98\n')
        for action in ('apply', 'apply-tailnet'):
            if self.events.exists(): self.events.unlink()
            command = ['/bin/bash', str(repo / 'scripts/local-controller'), action, 'steady',
                       '--generation', 'fixture', '--config-dir', str(config),
                       '--boundary-manifest', str(self.path)]
            # A noninteractive attempt must stop at confirmation without reading
            # the conflicting mutation-config fixture.
            result = subprocess.run(command, env=self.env, text=True, capture_output=True, timeout=10)
            self.assertIn('interactive_confirmation_required', result.stderr)
            self.assertNotIn('conflicting boundary', result.stderr)
            self.assertIn('reconcile:validate --boundary-manifest', self.events.read_text())
            self.events.unlink()
            master, slave = pty.openpty()
            try:
                process = subprocess.Popen(command, env=self.env, stdin=slave,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                confirmation = 'apply-reviewed-' + ('tailnet-' if action == 'apply-tailnet' else '') + 'steady-converge\n'
                os.write(master, confirmation.encode())
                stdout, stderr = process.communicate(timeout=10)
            finally:
                os.close(master); os.close(slave)
            self.assertEqual(process.returncode, 66, stderr)
            self.assertIn('Ready to apply operation=steady', stdout)
            self.assertIn('conflicting boundary TF_VAR override', stderr)
            self.assertNotIn('synthetic-conflict-not-a-secret', stdout + stderr)
            events = self.events.read_text()
            self.assertIn('reconcile:validate --boundary-manifest', events)
            self.assertNotIn('forbidden-capability-use', events)
            self.assertNotIn('reconcile:apply', events)

    def test_saved_pair_drift_blocks_public_apply_before_validation(self):
        repo = self.fixture_repo()
        executable(self.bin / 'node', '#!/bin/sh\nexit 0\n')
        plan_dir = repo / '.reconcile/plans' / ('0' * 40) / 'steady/fixture'
        plan_dir.mkdir(parents=True)
        (plan_dir / 'manifest.json').write_text(json.dumps({'controller_boundary_manifest': self.binding()}))
        changed = fixture_document(); changed['provenance']['review_reference'] = 'changed-after-plan'
        self.write_document(changed)
        for action in ('apply', 'apply-tailnet'):
            result = subprocess.run(['/bin/bash', str(repo / 'scripts/local-controller'), action, 'steady',
                                     '--generation', 'fixture', '--boundary-manifest', str(self.path)],
                                    env=self.env, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 66, result.stderr)
            self.assertIn('saved plan boundary manifest is missing or changed', result.stderr)
            self.assertFalse(self.events.exists())

    def test_backend_and_recheck_seams_reject_changed_input_before_tools(self):
        repo = self.fixture_repo()
        source = (ROOT / 'scripts/reconcile-infrastructure').read_text()
        definitions = ''
        for name in ('backend_init', 'verify_all', 'tailnet_only_preflight'):
            definitions += name + '() {' + source.split(name + '() {', 1)[1].split('\n}\n', 1)[0] + '\n}\n'
        saved = self.base / 'manifest.json'
        saved.write_text(json.dumps({'controller_boundary_manifest': self.binding()}))
        for call in ('backend_init aws-foundation', 'verify_all', 'tailnet_only_preflight'):
            self.write_document(fixture_document())
            shell = ('set -euo pipefail\nrepo_root=' + str(repo) + '\n'
                     'source "$repo_root/scripts/controller/controller-boundaries.sh"\n'
                     'boundary_manifest=' + str(self.path) + '\nplan_dir=' + str(self.base) + '\n'
                     'initialize_controller_boundaries\n' + definitions + '\n'
                     'printf " " >>"$boundary_manifest"\n' + call + '\n')
            result = subprocess.run(['/bin/bash', '-c', shell], env=self.env, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 66, result.stderr)
            self.assertIn('accepted manifest content or provenance changed', result.stderr)
            self.assertFalse(self.events.exists())

    def test_foundation_fixed_cli_pair_used_by_all_plan_recheck_paths(self):
        source = (ROOT / 'scripts/reconcile-infrastructure').read_text()
        start = source.index('root_plan_args() {'); end = source.index('\nplan_all() {', start)
        shell = ('set -euo pipefail\nrepo_root=' + str(ROOT) + '\n'
                 'source "$repo_root/scripts/controller/controller-boundaries.sh"\n'
                 'boundary_manifest=' + str(self.path) + '\ninitialize_controller_boundaries\n'
                 + source[start:end] + '\nroot_plan_args aws-foundation\n')
        result = subprocess.run(['/bin/bash', '-c', shell], env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(b'\0')[:-1],
                         [f'-var=controller_plan_permissions_boundary_arn={PLAN}'.encode(),
                          f'-var=controller_apply_permissions_boundary_arn={APPLY}'.encode()])
        plan = source.split('plan_all() {', 1)[1].split('\n}\n', 1)[0]
        fresh = source.split('verify_fresh_root_noop() (', 1)[1].split('\n)\n', 1)[0]
        for section in (plan, fresh):
            self.assertIn('(root_plan_args "$root")', section)
        for function in ('verify_all', 'tailnet_only_preflight'):
            section = source.split(function + '() {', 1)[1].split('\n}\n', 1)[0]
            self.assertIn('verify_fresh_root_noop "$root"', section)
        self.assertIn('verify_controller_boundaries', source.split('backend_init() {', 1)[1].split('\n}', 1)[0])


if __name__ == '__main__':
    unittest.main()
