#!/usr/bin/env python3
"""Exercise the actual reboot pool-admission tasks with synthetic native observations.

No host operations, disk reads or reboot module run in this fixture.
"""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parent.parent


def pool():
    mirrors = {}
    for index in range(2):
        leaves = {f'/dev/disk/by-id/fixture-{index}-{n}': {
            'vdev_type': 'disk', 'guid': str(100 + index * 10 + n), 'state': 'ONLINE',
        } for n in range(2)}
        mirrors[f'mirror-{index}'] = {
            'vdev_type': 'mirror', 'class': 'normal', 'guid': str(index + 10),
            'state': 'ONLINE', 'vdevs': leaves,
        }
    return {'name': 'storage', 'pool_guid': '1234', 'state': 'ONLINE', 'error_count': '0',
            'scan_stats': {'state': 'FINISHED', 'errors': '1'},
            'vdevs': {'storage': {'vdev_type': 'root', 'vdevs': mirrors}}}


def leaf(value, mirror=0, member=0):
    return list(value['vdevs']['storage']['vdevs'][f'mirror-{mirror}']['vdevs'].values())[member]


def admission(value, *, acknowledged=False, phase='before'):
    return {'ansible.builtin.include_role': {'name': 'proxmox_reboot', 'tasks_from': 'pool-admission'},
            'vars': {'proxmox_reboot_pool': value, 'proxmox_reboot_pool_readonly': 'off',
                     'proxmox_reboot_degraded_confirmed': acknowledged,
                     'proxmox_reboot_pool_phase': phase}}


class PoolAdmission(unittest.TestCase):
    def run_case(self, before, after=None, *, acknowledged=False, accepted=True, readonly='off'):
        with tempfile.TemporaryDirectory(prefix='proxmox-reboot-test-') as directory:
            work = Path(directory)
            first = admission(before, acknowledged=acknowledged)
            first['vars']['proxmox_reboot_pool_readonly'] = readonly
            tasks = [first]
            if after is not None:
                tasks += [{'ansible.builtin.set_fact': {
                    'proxmox_reboot_pool_baseline': '{{ proxmox_reboot_pool_snapshot }}'}},
                    admission(after, acknowledged=acknowledged, phase='after')]
            plays = [{'hosts': 'localhost', 'gather_facts': False, 'tasks': tasks}]
            path = work / 'fixture.yml'
            path.write_text(yaml.safe_dump(plays, sort_keys=False))
            env = os.environ | {
                'ANSIBLE_CONFIG': str(ROOT / 'ansible/ansible.cfg'),
                'ANSIBLE_ROLES_PATH': str(ROOT / 'ansible/roles'),
                'ANSIBLE_LOCAL_TEMP': str(work / 'local'),
                'ANSIBLE_REMOTE_TEMP': str(work / 'remote'),
                'PYTHONDONTWRITEBYTECODE': '1',
            }
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(path)],
                                    env=env, capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)

    def test_online_and_unchanged_degraded_and_recovered_are_admitted(self):
        healthy = pool()
        self.run_case(healthy, copy.deepcopy(healthy))
        degraded = pool()
        degraded['state'] = 'DEGRADED'
        leaf(degraded)['state'] = 'FAULTED'
        # A historical scan error is not a current known-data error.
        self.run_case(degraded, copy.deepcopy(degraded), acknowledged=True)
        self.run_case(degraded, healthy, acknowledged=True)

    def test_default_refuses_degraded_and_acknowledgment_is_not_a_blanket_waiver(self):
        degraded = pool()
        degraded['state'] = 'DEGRADED'
        leaf(degraded)['state'] = 'FAULTED'
        self.run_case(degraded, accepted=False)
        for state in ['FAULTED', 'SUSPENDED', 'UNAVAIL', 'OFFLINE', 'UNKNOWN']:
            with self.subTest(state=state):
                bad = pool()
                bad['state'] = state
                self.run_case(bad, acknowledged=True, accepted=False)
        self.run_case(pool(), readonly='on', accepted=False)
        bad = pool()
        bad['error_count'] = '1'
        self.run_case(bad, acknowledged=True, accepted=False)

    def test_active_or_unknown_scan_and_unsupported_topology_refuse(self):
        for scan in ['SCANNING', 'PAUSED', 'UNKNOWN']:
            bad = pool()
            bad['scan_stats']['state'] = scan
            self.run_case(bad, accepted=False)
        bad = pool()
        bad['vdevs']['storage']['vdevs']['mirror-0']['vdev_type'] = 'raidz'
        self.run_case(bad, accepted=False)
        bad = pool()
        leaf(bad)['state'] = 'FAULTED'
        leaf(bad, member=1)['state'] = 'UNAVAIL'
        self.run_case(bad, acknowledged=True, accepted=False)
        bad = pool()
        del bad['error_count']
        self.run_case(bad, accepted=False)
        # An ONLINE summary cannot conceal a failed leaf without acknowledgment.
        bad = pool()
        leaf(bad)['state'] = 'FAULTED'
        self.run_case(bad, accepted=False)
        bad = pool()
        leaf(bad, member=1)['guid'] = leaf(bad)['guid']
        self.run_case(bad, accepted=False)

    def test_post_reboot_refuses_lost_survivor_even_with_same_pool_health(self):
        before = pool()
        before['state'] = 'DEGRADED'
        leaf(before)['state'] = 'FAULTED'
        after = copy.deepcopy(before)
        leaf(after, mirror=1)['state'] = 'FAULTED'
        self.run_case(before, after, acknowledged=True, accepted=False)
        # Merely trading a failed member for a formerly healthy member is not recovery.
        after = copy.deepcopy(before)
        leaf(after)['state'] = 'ONLINE'
        leaf(after, member=1)['state'] = 'FAULTED'
        self.run_case(before, after, acknowledged=True, accepted=False)

    def test_post_reboot_refuses_identity_membership_and_online_regression(self):
        for mutation in ['pool_guid', 'membership', 'health', 'data_error']:
            before = pool()
            after = copy.deepcopy(before)
            if mutation == 'pool_guid':
                after['pool_guid'] = '5678'
            elif mutation == 'membership':
                leaf(after)['guid'] = '9999'
            elif mutation == 'health':
                after['state'] = 'DEGRADED'
                leaf(after)['state'] = 'FAULTED'
            else:
                after['error_count'] = '1'
            self.run_case(before, after, acknowledged=True, accepted=False)


if __name__ == '__main__':
    unittest.main()
