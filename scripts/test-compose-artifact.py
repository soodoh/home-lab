#!/usr/bin/env python3
"""Local artifact and diff CLI compatibility; no Docker, secrets or hosts."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

artifact = load('compose-artifact')

class ComposeArtifactCompatibilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def file(self, name, data, mode=0o600):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def test_legacy_artifact_list_hash_copy_and_no_git_hash_stay_compatible(self):
        paths = sorted(artifact.EXPLICIT_PATHS | {'services/data/hook.sh', 'services/apps.yml'})
        for name in paths:
            self.file(name, b'legacy\n', 0o755 if name.endswith('.sh') else 0o600)
        def git_run(argv, **kwargs):
            self.assertEqual(argv, artifact.GIT_PREFIX + ['ls-files', '-z'])
            return subprocess.CompletedProcess(argv, 0, b'\0'.join(p.encode() for p in paths) + b'\0')
        def cli(*args):
            with patch('sys.argv', ['compose-artifact.py', *args]), patch('subprocess.run', side_effect=git_run), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                artifact.main()
            return stdout.getvalue()
        self.assertEqual(cli('--root', str(self.root), 'list'), '\n'.join(paths) + '\n')
        source_hash = cli('--root', str(self.root), 'hash')
        copied = self.root / 'copied'
        self.assertEqual(cli('--root', str(self.root), 'copy', str(copied)), source_hash)
        self.assertEqual(cli('--root', str(copied), '--no-git', 'hash'), source_hash)
        self.assertEqual((copied / 'services/data/hook.sh').stat().st_mode & 0o777, 0o755)

    def test_compare_reports_exact_selected_path_changes(self):
        paths = sorted(artifact.EXPLICIT_PATHS | {'services/apps.yml'})
        left = self.root / 'left'
        right = self.root / 'right'
        for root in (left, right):
            for name in paths:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'same\n')
        (right / 'services/apps.yml').write_bytes(b'changed\n')
        extra = right / 'services/data/new.conf'
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_bytes(b'new\n')
        self.assertEqual(
            artifact.changed_paths(left, right),
            ['services/apps.yml', 'services/data/new.conf'],
        )

    def test_legacy_diff_cli_keeps_canary_and_manual_only_results(self):
        diff = load('compose-deployment-diff')
        for name, value in {
            'desired': {'kind': 'desired', 'project_name': 'home-lab', 'services': {'app': {'image': 'new'}}},
            'runtime': {'kind': 'runtime', 'project_name': 'home-lab', 'services': {'app': {'image': 'old'}}},
            'actions': {'recreate_services': ['app'], 'forbidden_actions': []},
        }.items():
            self.file(name + '.json', json.dumps(value).encode())
        self.file('current/services/apps.yml', b'old')
        self.file('candidate/services/apps.yml', b'new')
        output = self.root / 'diff.json'
        argv = ['compose-deployment-diff.py']
        for name in ('desired', 'runtime', 'actions'):
            argv += ['--' + name, str(self.root / (name + '.json'))]
        argv += ['--candidate-root', str(self.root / 'candidate'), '--current-root', str(self.root / 'current'),
                 '--candidate-hash', 'new', '--deployed-hash', 'old', '--canary-service', 'app',
                 '--canary-path', 'services/apps.yml', '--output', str(output)]
        with patch('sys.argv', argv), patch('subprocess.run', side_effect=AssertionError('native effect')):
            diff.main()
        result = json.loads(output.read_bytes())
        self.assertTrue(result['canary_eligible'])
        self.assertFalse(result['artifact_only_eligible'])
        self.assertEqual(result['changed_paths'], ['services/apps.yml'])
        self.assertEqual(result['manual_only_paths'], [])
        self.assertEqual(result['image_services'], ['app'])


if __name__ == '__main__':
    unittest.main()
