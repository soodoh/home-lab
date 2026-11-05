#!/usr/bin/env python3
"""Exercise the production pre-pull task through Ansible without a Docker daemon."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


def nested_tasks(tasks):
    for task in tasks:
        yield task
        for section in ("block", "rescue", "always"):
            yield from nested_tasks(task.get(section, []))


class ImagePullTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="compose-image-pull-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        # Execute the actual task, replacing only external registry/Docker I/O.
        tasks = yaml.safe_load((ROOT / "ansible/roles/compose_native/tasks/deploy.yml").read_text())
        pulls = [task for task in nested_tasks(tasks) if "community.docker.docker_compose_v2_pull" in task]
        self.assertEqual(len(pulls), 1)
        self.pull = deepcopy(pulls[0])
        self.pull["delay"] = 0  # Preserve retry behavior without wall-clock waits.
        plugins = self.work / "collections/ansible_collections/community/docker/plugins"
        (plugins / "action").mkdir(parents=True)
        (plugins / "modules").mkdir()
        (plugins / "modules/docker_compose_v2_pull.py").write_text("# Fixture action handles external I/O.\n")
        (plugins / "action/docker_compose_v2_pull.py").write_text('''from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        work = Path(task_vars['fixture_work'])
        attempts = work / 'attempts'
        count = int(attempts.read_text()) + 1 if attempts.exists() else 1
        attempts.write_text(str(count))
        if count <= task_vars['fixture_failures']:
            return {'failed': True, 'msg': 'synthetic registry throttling',
                    'stderr': 'SYNTHETIC_PRIVATE_REGISTRY_ERROR'}
        return {'changed': True}
''')

    def run_pull(self, failures):
        playbook = self.work / "pull.yml"
        playbook.write_text(yaml.safe_dump([{
            "name": "Exercise bounded pre-pull before publication", "hosts": "localhost",
            "gather_facts": False, "vars": {
                "ansible_connection": "local", "ansible_become": False,
                "fixture_work": str(self.work), "fixture_failures": failures,
                "compose_native_automated": True, "compose_native_source_changed": True,
                "compose_native_incoming_source": {"path": str(self.work / "incoming")},
                "compose_native_project_name": "fixture", "compose_native_files": ["compose.yml"],
                "compose_native_runtime_env_path": str(self.work / "synthetic.env"),
                "compose_native_home": str(self.work),
            }, "tasks": [self.pull, {
                "name": "Record that publication was reached", "ansible.builtin.copy": {
                    "dest": str(self.work / "published"), "content": "synthetic", "mode": "0600",
                },
            }],
        }], sort_keys=False))
        env = os.environ | {
            "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"),
            "ANSIBLE_COLLECTIONS_PATH": str(self.work / "collections"),
            "ANSIBLE_LOCAL_TEMP": str(self.work / "ansible"),
            "ANSIBLE_REMOTE_TEMP": str(self.work / "remote"),
            "TMPDIR": str(self.work), "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)],
            env=env, text=True, capture_output=True, timeout=60, check=False,
        )
        self.assertNotIn("SYNTHETIC_PRIVATE_REGISTRY_ERROR", result.stdout + result.stderr)
        return result

    def test_transient_failure_retries_before_publication(self):
        result = self.run_pull(1)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.work / "attempts").read_text(), "2")
        self.assertTrue((self.work / "published").exists())

    def test_persistent_failure_is_bounded_and_never_publishes(self):
        result = self.run_pull(99)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.work / "attempts").read_text(), "4")
        self.assertFalse((self.work / "published").exists())

    def test_success_does_not_repeat_the_pull(self):
        result = self.run_pull(0)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.work / "attempts").read_text(), "1")


if __name__ == "__main__":
    unittest.main()
