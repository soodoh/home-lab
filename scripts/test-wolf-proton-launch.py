#!/usr/bin/env python3
"""Exercise the launch gate with a synthetic vendor launcher; no Steam needed."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parent / 'wolf-proton-launch'
# The fake setup writes a readiness marker *before* it reaches vendor dispatch.
VENDOR = b'''import os
class Session:
    def run(self):
        with open('dispatch', 'w') as output:
            output.write('game')
with open('prefix-ready', 'w') as marker:
    marker.write('ready')
Session().run()
'''
HELPER = b'''import os
from pathlib import Path

def relative(value):
    return value.split('/')

def open_storage(opened, state, games):
    fd = os.open('.', os.O_RDONLY)
    opened.callback(os.close, fd)
    return fd, 1, fd, 2

def descend(opened, payload, relative_install, mount):
    if os.environ.get('MISSING_MOUNT'):
        raise OSError('synthetic missing installation mount')
    return payload

def prepare(*args):
    assert Path('prefix-ready').read_text() == 'ready'
    assert not Path('dispatch').exists()
    if os.environ.get('CONFLICT'):
        raise OSError('synthetic conflicting install link')
    Path('checked').touch()
'''


class WolfProtonLaunch(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux':
            self.skipTest('requires Linux')
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.work = Path(work.name)
        previous = Path.cwd()
        os.chdir(self.work)
        self.addCleanup(os.chdir, previous)
        self.launch = runpy.run_path(str(SOURCE))['launch']
        self.globals = self.launch.__globals__
        self.policy = dict(proton='/reviewed/proton', compatdata='/compat', games='/games',
                           app_id='117', link='Program Files/WolfFixture', install='title')
        self.environment = dict(SteamAppId='117', SteamGameId='117', STEAM_COMPAT_DATA_PATH='/compat/117',
                                STEAM_COMPAT_INSTALL_PATH='/games/title')

    def run_launch(self, verb='waitforexitandrun', vendor=VENDOR, **env):
        artifacts = {'proton': vendor, 'wolf-proton-launch.json': json.dumps(self.policy).encode(),
                     'prepare-wolf-proton-install': HELPER}
        isolated = SimpleNamespace(platform='linux', flags=SimpleNamespace(isolated=True),
                                   argv=[str(SOURCE), verb, 'cmd.exe'], path=[])
        with (mock.patch.dict(self.globals, {'readonly_bytes': lambda path, _: artifacts[path.name],
                                           'sys': isolated, 'UPSTREAM_SHA256': hashlib.sha256(VENDOR).hexdigest()}),
              mock.patch.object(os, 'geteuid', return_value=1000),
              mock.patch.dict(os.environ, {**self.environment, **env}, clear=True),
              contextlib.redirect_stdout(io.StringIO()) as output):
            self.launch()
        return output.getvalue()

    def test_post_setup_pre_dispatch(self):
        self.assertEqual(self.run_launch(), 'wolf_proton_launch=handoff_verified\n')
        self.assertTrue(Path('checked').is_file())
        self.assertEqual(Path('dispatch').read_text(), 'game')

    def test_conflict_never_dispatches(self):
        with self.assertRaisesRegex(OSError, 'conflicting install link'):
            self.run_launch(CONFLICT='1')
        self.assertTrue(Path('prefix-ready').is_file())
        self.assertFalse(Path('dispatch').exists())

    def test_unqualified_inputs_refused_before_prefix_mutation(self):
        for args, expected in [(dict(verb='run'), 'unsupported_launch_verb'),
                               (dict(verb='runinprefix'), 'unsupported_launch_verb'),
                               (dict(vendor=VENDOR + b'\n'), 'unreviewed_proton_launcher'),
                               (dict(SteamAppId='118'), 'unexpected_title_binding'),
                               (dict(MISSING_MOUNT='1'), 'missing installation mount')]:
            with self.subTest(reason=expected), self.assertRaisesRegex((ValueError, OSError), expected):
                self.run_launch(**args)
            self.assertFalse(Path('prefix-ready').exists())
            self.assertFalse(Path('dispatch').exists())


if __name__ == '__main__':
    unittest.main()
