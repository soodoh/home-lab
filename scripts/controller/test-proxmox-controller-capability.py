#!/usr/bin/env python3
"""Offline source/artifact/authority coherence and retained legacy-owner guards."""
import ast
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    path = ROOT / 'scripts/controller' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


capability = load('proxmox-controller-observer-capability')


class ControllerCapabilityTests(unittest.TestCase):
    def test_admission_uses_captured_bindings_and_exact_private_receipts(self):
        access, now = self.access_fixture()
        backup = {'format': 'home-lab-proxmox-reboot-backup-attestation-v1', 'commit': 'a'*40,
                  'authorized': False, 'automatic_reboot': False, 'evidence': {
                      'accepted_mtime_epoch': int(now.timestamp()) - 60, 'pending_records': 0, 'proton_copy_records': 1,
                      'local_service': {'result': 'success'}, 'proton_service': {'result': 'success'}}}
        class Clock(capability.dt.datetime):
            @classmethod
            def now(cls, tz=None): return now
        bound = {'infrastructure/contract/home-lab.yml': 'b'*64, 'ansible/inventory/production.yml': 'c'*64}
        with patch.object(capability.dt, 'datetime', Clock), patch.object(capability, 'read', side_effect=AssertionError('must use captured source bindings')):
            def admit(candidate, bindings=bound):
                raws = capability.canonical(access), capability.canonical(candidate)
                with patch.object(capability, 'private', side_effect=[(access, raws[0]), (candidate, raws[1])]):
                    return capability.admission(Path('/not-read-access'), Path('/not-read-backup'), 'a'*40, bindings)
            self.assertEqual(admit(backup), {'access_sha256': capability.sha(capability.canonical(access)),
                                            'backup_sha256': capability.sha(capability.canonical(backup))})
            for key in bound:
                with self.subTest(binding=key), self.assertRaisesRegex(ValueError, 'source/host binding'):
                    admit(backup, {**bound, key: 'f'*64})
            for field, replacement in (('accepted_mtime_epoch', True), ('accepted_mtime_epoch', int(now.timestamp()) + 1),
                                       ('accepted_mtime_epoch', int(now.timestamp()) - 86401), ('pending_records', False),
                                       ('proton_copy_records', True), ('local_service', None), ('proton_service', {'result': 'failed'})):
                wrong = copy.deepcopy(backup); wrong['evidence'][field] = replacement
                with self.subTest(backup_field=field), self.assertRaises(ValueError): admit(wrong)
        tree = ast.parse(capability.HOST.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'repository_prerequisites')
        required = next(node.value for node in function.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'required' for target in node.targets))
        self.assertEqual(set(capability.bindings()), ast.literal_eval(required))

    def test_cleanup_committed_is_separately_confirmed_without_apply_or_audit(self):
        transaction = capability.read(capability.HOST, 0o644)
        bound = capability.bindings()
        now = capability.dt.datetime.now(capability.dt.timezone.utc)
        proof = {'access_sha256': 'b'*64, 'backup_sha256': 'c'*64}
        value = {'format': capability.FORMAT, 'commit': 'a'*40, 'bindings': bound,
                 'files': {}, 'before': {}, 'prerequisites': proof, 'host_key_fingerprint': capability.FINGERPRINT,
                 'authorized': False, 'automatic_apply': False, 'created_at': now.isoformat(),
                 'expires_at': (now + capability.dt.timedelta(minutes=30)).isoformat()}
        raw = capability.canonical(value); digest = capability.sha(raw)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            args = types.SimpleNamespace(command='cleanup-committed', plan=directory / (digest + '.json'),
                                         artifact=directory / 'artifact', access=directory / 'access', backup=directory / 'backup')
            with patch.object(capability, 'ROOT', directory), patch.object(capability, 'clean_commit', return_value='a'*40), \
                    patch.object(capability, 'bindings', return_value=bound), patch.object(capability, 'sources', return_value={}), \
                    patch.object(capability, 'admission', return_value=proof), patch.object(capability, 'private', return_value=(value, raw)), \
                    patch.object(capability, 'acquire_transfer_lock', side_effect=lambda path: os.open(path, os.O_CREAT | os.O_RDWR, 0o600)), \
                    patch.object(capability, 'require_vfio_coordination', side_effect=AssertionError('must not strand terminal cleanup')), \
                    patch.object(capability, 'remote', return_value={'status': 'committed', 'live_acceptance': False}) as remote, \
                    patch.object(capability.subprocess, 'run') as command:
                with patch.dict(os.environ, {'PROXMOX_CONTROLLER_OBSERVER_CAPABILITY_CONFIRMED': 'apply-proxmox-controller-observer-capability-' + digest}):
                    with self.assertRaisesRegex(ValueError, 'exact separate confirmation'): capability.execute(args)
                remote.assert_not_called()
                with patch.dict(os.environ, {'PROXMOX_CONTROLLER_OBSERVER_CAPABILITY_CONFIRMED': 'cleanup-committed-proxmox-controller-observer-capability-' + digest}):
                    self.assertEqual(capability.execute(args), {'status': 'committed', 'live_acceptance': False, 'plan_sha256': digest})
                remote.assert_called_once_with({'operation': 'cleanup-committed', 'plan_sha256': digest, 'files': {}, 'before': {}},
                                               'a'*40, bound, transaction)
                command.assert_not_called()

    def access_fixture(self):
        now = capability.dt.datetime(2026, 9, 6, 12, 0, tzinfo=capability.dt.timezone.utc)
        value = {'format': 'home-lab-proxmox-access-evidence-v1', 'draft_sha256': 'd'*64,
                 'commit': 'a'*40, 'contract_sha256': 'b'*64, 'inventory_sha256': 'c'*64,
                 'host_key_fingerprint': capability.FINGERPRINT, 'created_at': '2026-09-06T11:55:00Z',
                 'console_attested_at': '2026-09-06T11:56:00Z', 'expires_at': '2026-09-06T12:25:00Z',
                 'proofs': {'strict_host_key': True,
                    'plan_observer': {'positive': True, 'injection_rejected': True, 'observation_sha256': 'e'*64},
                    'deploy_transport': {'positive': True, 'injection_rejected': True, 'marker_plan_sha256': 'e'*64},
                    'firewall_transport': {'positive': True, 'injection_rejected': True, 'inspect_sha256': 'e'*64},
                    'human_session': {'positive': True},
                    'console': {'attested': True, 'method': 'physical-console-bootstrap-install-and-verify'},
                    'tailnet_policy': {'tests_present': True, 'live_plan_noop': True, 'expected_retirement_drift': False,
                                      'controller_plan_stdout_sha256': 'e'*64},
                    'root_keys': {'records': [], 'attributed': dict(capability.ACCESS_ATTRIBUTIONS),
                                  'attributed_count': 0, 'total_count': 0, 'unresolved': [], 'complete': True}}}
        return value, now

    def test_complete_access_schema_bindings_times_and_negative_proofs(self):
        value, now = self.access_fixture()
        def validate(candidate, raw=None):
            capability.validate_access(candidate, capability.canonical(candidate) if raw is None else raw,
                                       'a'*40, 'b'*64, 'c'*64, now)
        validate(value)
        for key in value:
            wrong = copy.deepcopy(value); del wrong[key]
            with self.subTest(missing=key), self.assertRaises(ValueError): validate(wrong)
        changes = [
            (('format',), 'home-lab-proxmox-access-evidence-draft-v1'), (('extra',), True),
            (('commit',), 'f'*40), (('contract_sha256',), 'f'*64), (('inventory_sha256',), 'f'*64),
            (('host_key_fingerprint',), 'wrong-host'), (('draft_sha256',), True),
            (('expires_at',), '2099-01-01T00:00:00Z'), (('expires_at',), '2026-09-06T12:26:00Z'),
            (('created_at',), '2026-09-06T12:01:00Z'), (('console_attested_at',), '2026-09-06T11:54:59Z'),
            (('console_attested_at',), '2026-09-06T12:00:01Z'), (('created_at',), '2026-09-06T11:55:00'),
            (('proofs', 'strict_host_key'), 1), (('proofs', 'human_session', 'positive'), 1),
            (('proofs', 'console', 'method'), 'self-declared'), (('proofs', 'root_keys', 'complete'), False),
            (('proofs', 'root_keys', 'total_count'), True), (('proofs', 'root_keys', 'attributed_count'), 1),
            (('proofs', 'root_keys', 'attributed'), {}), (('proofs', 'root_keys', 'unresolved'), ['unknown']),
            (('proofs', 'tailnet_policy', 'expected_retirement_drift'), True),
            (('proofs', 'tailnet_policy', 'live_plan_noop'), False),
            (('proofs', 'tailnet_policy', 'controller_plan_stdout_sha256'), 'bad'),
        ]
        for name, hash_field in (('plan_observer', 'observation_sha256'), ('deploy_transport', 'marker_plan_sha256'),
                                 ('firewall_transport', 'inspect_sha256')):
            changes.extend([(('proofs', name, 'positive'), False), (('proofs', name, 'injection_rejected'), False),
                            (('proofs', name, hash_field), 'bad')])
        for path, replacement in changes:
            wrong = copy.deepcopy(value); item = wrong
            for key in path[:-1]: item = item[key]
            item[path[-1]] = replacement
            with self.subTest(path=path, value=replacement), self.assertRaises(ValueError): validate(wrong)
        for name in value['proofs']:
            wrong = copy.deepcopy(value); del wrong['proofs'][name]
            with self.subTest(missing_proof=name), self.assertRaises(ValueError): validate(wrong)
        with self.assertRaises(ValueError):
            capability.validate_access(value, capability.canonical(value), 'a'*40, 'b'*64, 'c'*64,
                                       now + capability.dt.timedelta(hours=1))
        with self.assertRaises(ValueError): validate(value, capability.canonical(value) + b' ')
        with self.assertRaises(ValueError): validate(value, b' ' * 262145)
        record = {'bits': 256, 'fingerprint': next(iter(capability.ACCESS_ATTRIBUTIONS)), 'comment': 'fixture', 'type': 'ED25519'}
        known = copy.deepcopy(value)
        known['proofs']['root_keys'].update(records=[record], total_count=1, attributed_count=1)
        validate(known)
        for field, replacement in (('bits', True), ('bits', 1), ('fingerprint', 'unknown'), ('type', 'unknown'), ('comment', 123)):
            wrong = copy.deepcopy(known); wrong['proofs']['root_keys']['records'][0][field] = replacement
            with self.subTest(record_field=field), self.assertRaises(ValueError): validate(wrong)
        known['proofs']['root_keys'].update(records=[record, record], total_count=2, attributed_count=2)
        with self.assertRaises(ValueError): validate(known)

    def test_admission_rejects_old_incomplete_indefinite_receipt(self):
        access = {'format': 'home-lab-proxmox-access-evidence-v1', 'commit': 'a'*40,
                  'expires_at': '2099-01-01T00:00:00Z', 'proofs': {'console': {'attested': True},
                    **{name: {'positive': True} for name in ('plan_observer', 'deploy_transport', 'human_session')}}}
        with patch.object(capability, 'private', side_effect=[(access, capability.canonical(access)), ({}, b'{}\n')]), \
                patch.object(capability, 'read', return_value=b'synthetic source'):
            with self.assertRaisesRegex(ValueError, 'access evidence schema'):
                capability.admission(Path('/not-read-access'), Path('/not-read-backup'), 'a'*40,
                    {'infrastructure/contract/home-lab.yml': 'b'*64, 'ansible/inventory/production.yml': 'c'*64})

    def test_remote_phases_never_replace_approved_revision_or_transaction(self):
        commit = 'a' * 40
        transaction = b"# exact reviewed transaction\n"
        key = 'infrastructure/proxmox-access/host/proxmox-controller-capability-transaction.py'
        expected = {key: capability.sha(transaction)}
        state = {'commit': commit, 'bindings': dict(expected), 'transaction': transaction}
        receipt = types.SimpleNamespace(returncode=0, stderr=b'', stdout=capability.canonical({'status': 'fixture'}))
        with patch.object(capability, 'clean_commit', side_effect=lambda: state['commit']), \
                patch.object(capability, 'bindings', side_effect=lambda: state['bindings']), \
                patch.object(capability, 'read', side_effect=lambda *a: state['transaction']), \
                patch.object(capability, 'ssh', return_value=('synthetic-ssh',)) as ssh, \
                patch.object(capability.subprocess, 'run', return_value=receipt) as run:
            for operation in ('observe', 'apply', 'commit', 'rollback', 'cleanup-committed'):
                payload = {'operation': operation, 'plan_sha256': 'b' * 64}
                self.assertEqual(capability.remote(payload, commit, expected, transaction), {'status': 'fixture'})
                sent = json.loads(run.call_args.kwargs['input'])
                self.assertEqual((sent['commit'], sent['bindings']), (commit, expected))
                self.assertIn(capability.shlex.quote(transaction.decode()), run.call_args.args[0][-1])
                for field, changed in (('commit', 'c' * 40), ('bindings', {key: 'd' * 64}), ('transaction', b'changed code')):
                    previous = state[field]; state[field] = changed
                    ssh.reset_mock(); run.reset_mock()
                    with self.subTest(operation=operation, changed=field), self.assertRaisesRegex(ValueError, 'approved capability source changed'):
                        capability.remote(payload, commit, expected, transaction)
                    ssh.assert_not_called(); run.assert_not_called()
                    state[field] = previous
            # A source change after the final check cannot substitute streamed
            # bytes or approved identities, even if the dispatch setup races.
            def racing_ssh():
                state['transaction'] = b'unreviewed replacement'
                return ('synthetic-ssh',)
            ssh.side_effect = racing_ssh
            capability.remote({'operation': 'commit'}, commit, expected, transaction)
            self.assertIn(capability.shlex.quote(transaction.decode()), run.call_args.args[0][-1])
            self.assertNotIn('unreviewed replacement', run.call_args.args[0][-1])

    def test_current_vfio_protocol_blocks_controller_install_before_host_contact(self):
        with patch.object(capability, 'remote') as remote, patch.object(capability, 'clean_commit') as clean:
            for command in ('plan', 'apply'):
                with self.assertRaisesRegex(ValueError, 'VFIO queued-reboot'):
                    capability.execute(types.SimpleNamespace(command=command))
            remote.assert_not_called(); clean.assert_not_called()

    def test_consumer_integration_is_hard_prerequisite_not_waiver(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); directory = root / 'infrastructure/maintenance/host'; directory.mkdir(parents=True)
            for name in ('maintenance-read-only-observer', 'package-candidate-observer'):
                (directory / name).write_text('retained=[]\n')
            with patch.object(capability, 'ROOT', root), self.assertRaisesRegex(ValueError, 'installation blocked'):
                capability.consumer_gate()

    def test_source_rebuild_exact_sudo_transport_and_installed_participant_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'artifact'
            result = subprocess.run(('node', str(ROOT / 'scripts/controller/build-proxmox-ansible-observer.js'), '--output-dir', str(artifact)), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Consumer migration is separately tested and deliberately blocked in
            # this snapshot; this isolated builder test does not grant admission.
            with patch.object(capability, 'consumer_gate'):
                files = capability.sources(artifact)
                self.assertEqual(base64.b64decode(files['/etc/sudoers.d/ansible-plan']), capability.RULE.encode())
                producer = base64.b64decode(files[capability.BASE + 'proxmox-controller-observer'])
                activator = base64.b64decode(files[capability.BASE + 'proxmox-ansible-deploy-activator'])
                self.assertIn(capability.sha(activator).encode(), producer)
                transport = base64.b64decode(files[capability.BASE + 'proxmox-ansible-plan-transport'])
                self.assertIn(b'observe-controller)', transport)
                self.assertIn(b'exec /usr/bin/sudo -n -- /usr/local/libexec/home-lab/proxmox-controller-observer observe', transport)
                (artifact / 'proxmox-controller-observer').write_bytes(b'changed-source')
                with self.assertRaisesRegex(ValueError, 'artifact/source bytes differ'):
                    capability.sources(artifact)

    def test_legacy_installers_cannot_reopen_unserialized_or_incomplete_authority(self):
        for name, args in (('proxmox-package-observer-capability', (Path('/nonexistent-plan'), Path('/nonexistent-artifact'))),
                           ('proxmox-plan-capability', (Path('/nonexistent-plan'),))):
            old = load(name)
            with patch.object(old.subprocess, 'run') as run:
                with self.assertRaisesRegex(SystemExit, 'legacy installer disabled'):
                    old.apply(*args)
                run.assert_not_called()

    def test_descriptor_ancestry_validation_is_identical_in_both_participants(self):
        sources = [ROOT / 'infrastructure/host-lifecycle/proxmox/controller-observer-template.py',
                   ROOT / 'infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator']
        definitions = []
        for path in sources:
            tree = ast.parse(path.read_text())
            definitions.append({n.name: ast.dump(n, include_attributes=False) for n in tree.body if isinstance(n, ast.FunctionDef)})
        for name in ('parent_fd', 'fingerprint'):
            self.assertEqual(definitions[0][name], definitions[1][name])

    def test_retained_nix_ordinary_initializing_and_terminal_paths_reject_reboot_owner(self):
        source = (ROOT / 'nix/proxmox/activator-template.py').read_text(); tree = ast.parse(source)
        selected = {'read_lock', 'require_lock', 'reconcile_initializing', 'reconcile_terminal_release',
                    'lock_matches_ownership', 'commit', 'rollback'}
        namespace = {'json': json, 'stat': __import__('stat'), 'LOCK_PATH': Path('/synthetic/apply.lock')}
        def exact(value, keys, label):
            if set(value) != keys:
                raise ValueError('legacy exact shape rejects reboot owner')
        owner = {'format': 'home-lab-proxmox-reboot-owner-v1', 'operation': 'apply-reboot',
                 'plan_sha256': 'a' * 64, 'boot_id': 'synthetic-before', 'token': 'b' * 64}
        namespace.update(exact=exact, canonical=capability.canonical,
                         read_fixed_file=lambda *a: (capability.canonical(owner), types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o100600)),
                         validate_common=lambda *a: None, validate_envelope_shape=lambda *a: None,
                         self_sha256=lambda: 'synthetic-legacy', completed_retry=lambda *a: None)
        def prohibited(*a):
            self.fail('legacy path reached mutation/removal for reboot record')
        namespace.update(release_fixed_lock=prohibited, save_journal=prohibited, read_manifest=prohibited)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in selected:
                exec(compile(ast.Module(body=[node], type_ignores=[]), 'retained-nix-fixture', 'exec'), namespace)
        for operation in ('commit', 'rollback'):
            namespace['read_journal'] = lambda *a: {'state': 'applying'}
            with self.assertRaisesRegex(ValueError, 'legacy exact shape'):
                namespace[operation]({'planSha256': 'c' * 64})
        for status in ('committed-release-pending', 'recovered-release-pending'):
            with self.assertRaisesRegex(ValueError, 'legacy exact shape'):
                namespace['reconcile_terminal_release']({'state': status, 'ownership': {}})
        with self.assertRaisesRegex(ValueError, 'legacy exact shape'):
            namespace['reconcile_initializing']({'state': 'initializing', 'ownership': {'activatorSha256': 'synthetic-legacy'}})
        # Current Ansible and firewall share the descriptor and this exact retained
        # pathname; no legacy source is modified to interpret the reboot format.
        ansible = (ROOT / 'ansible/roles/apply_lock/tasks/main.yml').read_text()
        self.assertIn('test ! -e "$competing_lock"', ansible)
        self.assertIn('/var/lib/home-lab/reconciliation/apply.lock', ansible)
        firewall = (ROOT / 'infrastructure/proxmox-firewall/host/proxmox-firewall-transaction.py').read_text()
        self.assertIn('MUTEX = Path("/var/lib/home-lab/reconciliation/operation.lock")', firewall)
        self.assertIn('NIX_LOCK = Path("/var/lib/home-lab/reconciliation/apply.lock")', firewall)


if __name__ == '__main__': unittest.main()
