#!/usr/bin/env python3
"""Storage authority behavior with a disposable native-command fixture."""
import copy
import runpy
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ENGINE = runpy.run_path(str(Path(__file__).with_name('state-backup-snapshot.py')))


class Authority(unittest.TestCase):
    token = 'a' * 32
    owner = 'b' * 64
    lv_id = 'aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg'
    name = 'home-lab-state-' + token
    size = 128 * 1024**3

    def setUp(self):
        self.spec = {'origin_uuid': 'observed-origin', 'pool_uuid': 'observed-pool', 'bytes': self.size}
        self.rows = {
            'vm-100-disk-1': {'lv_uuid': 'observed-origin', 'lv_size': str(self.size), 'origin': '',
                             'pool_lv': 'data', 'lv_attr': 'Vwi-aotz--'},
            'data': {'lv_uuid': 'observed-pool', 'lv_attr': 'twi-aotz--', 'lv_size': str(700 * 1024**3),
                     'data_percent': '25', 'metadata_percent': '1'},
        }
        self.calls = []
        self.busy = False
        self.execute = ENGINE['execute']
        overrides = patch.dict(self.execute.__globals__, {'volumes': lambda: copy.deepcopy(self.rows),
                                                        'native': self.native})
        overrides.start()
        self.addCleanup(overrides.stop)

    def native(self, *args):
        self.calls.append(args)
        if args[0] == '/usr/sbin/lvcreate':
            self.rows[self.name] = {'lv_name': self.name, 'lv_uuid': self.lv_id, 'lv_attr': 'Vri---tz-k',
                                    'lv_size': str(self.size), 'lv_time': str(int(time.time())),
                                    'lv_tags': 'homelab-backup-state,homelab-owner-' + self.owner,
                                    'origin_uuid': 'observed-origin', 'origin': 'vm-100-disk-1', 'pool_lv': 'data'}
        if args[0] == '/usr/sbin/blockdev':
            return '1\n'
        if args[:2] == ('/usr/bin/systemctl', 'show'):
            return 'inactive\n'
        if args[0] == '/usr/sbin/lvremove':
            if self.busy:
                raise ValueError('busy')
            del self.rows[self.name]
        return ''

    def request(self, action, **values):
        return self.execute({'action': action, 'capture': self.token, 'owner': self.owner, **values}, self.spec)

    def test_create_ready_and_exact_completion(self):
        self.assertEqual(self.execute({'action': 'state-list'}, self.spec), {'snapshots': [], 'admissible': True})
        created = self.request('state-create')
        self.assertEqual(created, self.request('state-create'))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][:5], ('/usr/sbin/lvcreate', '--snapshot', '--permission', 'r', '--addtag'))
        self.assertEqual(self.calls[0][-1], 'pve/vm-100-disk-1')
        self.assertEqual(created, self.request('state-ready', id=self.lv_id))
        self.assertEqual(self.calls[-1], ('/usr/bin/systemctl', 'start', f'home-lab-state-snapshot@{self.token}.socket'))
        self.assertEqual(self.request('state-complete', id=self.lv_id), {'deleted': True})
        self.assertEqual(self.calls[-1], ('/usr/sbin/lvremove', '--yes', 'pve/' + self.name))
        self.assertEqual(self.request('state-complete', id=self.lv_id), {'deleted': True})

    def test_untrusted_arguments_and_changed_origin_refuse_before_native_mutation(self):
        for params in ({'volume': 'pve/root'}, {'capture': '/etc/passwd'}, {'owner': 'f' * 64 + ' /dev/'}, {'force': True}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.request('state-create', **params)
        self.rows['vm-100-disk-1']['lv_uuid'] = 'replaced'
        with self.assertRaisesRegex(ValueError, 'origin_identity'):
            self.request('state-create')
        self.assertEqual(self.calls, [])

    def test_live_pool_pressure_refuses_new_capture(self):
        self.rows['data']['data_percent'] = '80'
        self.assertFalse(self.execute({'action': 'state-list'}, self.spec)['admissible'])
        with self.assertRaisesRegex(ValueError, 'not_admissible'):
            self.request('state-create')
        self.assertEqual(self.calls, [])

    def test_wrong_snapshot_id_or_unexpired_abandon_never_closes_listener(self):
        self.request('state-create')
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'replaced'):
            self.request('state-complete', id=self.lv_id.replace('aaaaaa', 'hhhhhh'))
        with self.assertRaisesRegex(ValueError, 'not_expired'):
            self.request('state-abandon', id=self.lv_id)
        self.assertEqual(self.calls, [])
        self.assertIn(self.name, self.rows)

    def test_busy_snapshot_is_not_force_removed(self):
        self.request('state-create')
        self.busy = True
        with self.assertRaisesRegex(ValueError, 'busy'):
            self.request('state-complete', id=self.lv_id)
        self.assertIn(self.name, self.rows)
        self.assertEqual(self.calls[-1], ('/usr/sbin/lvremove', '--yes', 'pve/' + self.name))


if __name__ == '__main__':
    unittest.main()
