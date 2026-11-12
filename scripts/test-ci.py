#!/usr/bin/env python3
"""Exercise cached native tool admission; gate behavior lives in JavaScript tests."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('sha256sum') and shutil.which('jq'),
                     'requires Linux tool-verification commands')
class CachedToolAdmission(unittest.TestCase):
    def test_cache_hit_still_requires_exact_installed_checksum(self):
        action = yaml.safe_load((ROOT / '.github/actions/setup-restic/action.yml').read_text())
        verify = next(step for step in action['runs']['steps'] if step.get('id') == 'verify')
        self.assertNotIn('if', verify)
        with tempfile.TemporaryDirectory(prefix='ci-tool-verification-') as directory:
            root = Path(directory); tool = root / 'home-lab-restic-tool/restic'
            tool.parent.mkdir(mode=0o700); tool.write_bytes(b'synthetic admitted tool')
            policy = root / 'services/data/restic/policy.json'; policy.parent.mkdir(parents=True)
            policy.write_text(json.dumps({'tools': {'restic': {'installed_sha256': hashlib.sha256(tool.read_bytes()).hexdigest()}}}))
            output = root / 'output'
            env = {**os.environ, 'RUNNER_TEMP': str(root), 'GITHUB_OUTPUT': str(output)}
            for changed in (False, True):
                if changed:
                    tool.write_bytes(b'synthetic altered cache'); output.unlink()
                result = subprocess.run(['bash', '-eu', '-o', 'pipefail', '-c', verify['run']], cwd=root,
                                        env=env, capture_output=True, timeout=5)
                self.assertEqual(result.returncode == 0, not changed)
                self.assertEqual(output.exists(), not changed)


if __name__ == '__main__':
    unittest.main()
