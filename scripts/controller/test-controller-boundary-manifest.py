#!/usr/bin/env python3
"""Offline subprocess contracts; every provider/credential endpoint is synthetic."""
import copy
import hashlib
import json
import os
from pathlib import Path
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



if __name__ == '__main__':
    unittest.main()
