#!/usr/bin/env python3
"""Qualify pinned application shutdown and native persistence with synthetic data.

Opt in with BACKUP_CONTAINER_TESTS=true. Uses only uniquely named, labelled
containers; no production mounts, host ports, credentials, or shared networks.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]


def docker(*args, timeout=240):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError('native Docker fixture operation failed: ' + args[0] + '\n' + result.stderr[-2000:])
    return result.stdout.strip()


@unittest.skipUnless(os.environ.get('BACKUP_CONTAINER_TESTS') == 'true', 'requires explicit disposable Docker admission')
class Containers(unittest.TestCase):
    @contextmanager
    def container(self, service, *, environment=None, command=(), entrypoint=None, files=()):
        name = 'home-lab-backup-fixture-' + uuid.uuid4().hex
        args = ['create', '--name', name, '--platform', 'linux/amd64', '--network', 'none', '--memory', '1g', '--cpus', '2',
                '--label', 'home-lab.backup-fixture=true']
        if service.get('init'):
            args.append('--init')
        for key, option in [('stop_signal', '--stop-signal'), ('user', '--user')]:
            if service.get(key):
                args.extend([option, service[key]])
        entrypoint = entrypoint or service.get('entrypoint')
        prefix = []
        if entrypoint:
            entrypoint = [entrypoint] if isinstance(entrypoint, str) else entrypoint
            args.extend(['--entrypoint', entrypoint[0]])
            prefix = entrypoint[1:]
        for key, value in (environment or {}).items():
            args.extend(['--env', key + '=' + value])
        args.extend([service['image'], *prefix, *(command or service.get('command', []))])
        docker(*args)
        try:
            for source, destination in files:
                docker('cp', str(source), name + ':' + destination)
            yield name
        finally:
            docker('rm', '--force', '--volumes', name)

    def ready(self, name, probe):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            state = json.loads(docker('inspect', '--format', '{{json .State}}', name))
            self.assertTrue(state['Running'], 'synthetic application exited before readiness')
            result = subprocess.run(['docker', 'exec', name, *probe], capture_output=True, timeout=10)
            if result.returncode == 0:
                return
            time.sleep(1)
        self.fail('synthetic application did not become ready')

    def graceful_restart(self, service, environment, probe, *, entrypoint=None, files=()):
        with self.container(service, environment=environment, entrypoint=entrypoint, files=files) as name:
            docker('start', name)
            self.ready(name, probe)
            for _ in range(2):
                docker('stop', '--timeout', '10', name, timeout=20)
                state = json.loads(docker('inspect', '--format', '{{json .State}}', name))
                self.assertFalse(state['OOMKilled'])
                self.assertNotEqual(state['ExitCode'], 137, 'shutdown required SIGKILL instead of a graceful exit')
                docker('start', name)
                self.ready(name, probe)

    def test_nextcloud_cron_exits_without_inheriting_apache_stop_signal(self):
        # Resolve the real Compose anchor/entrypoint rather than a fixture image.
        service = yaml.safe_load((ROOT / 'services/nextcloud.yml').read_text())['services']['nextcloud-cron']
        self.graceful_restart(service, {}, ['busybox', 'pidof', 'busybox'], entrypoint=service['entrypoint'])

    def test_openfit_exits_gracefully_and_reopens_its_database(self):
        service = yaml.safe_load((ROOT / 'services/openfit.yml').read_text())['services']['openfit']
        self.graceful_restart(service, {
            'BETTER_AUTH_BASE_URL': 'http://localhost:3000',
            'BETTER_AUTH_SECRET': 'synthetic-test-secret-' * 3,
            'SKIP_EXERCISE_IMAGE_DOWNLOADS': 'true',
        }, ['wget', '-T', '2', '-q', '--spider', 'http://localhost:3000/'],
            files=[(ROOT / 'services/data/openfit/start.mjs', '/opt/home-lab-openfit-start.mjs')])

    def test_openfit_refuses_unknown_shutdown_handlers_even_when_native_errors_are_trapped(self):
        service = yaml.safe_load((ROOT / 'services/openfit.yml').read_text())['services']['openfit']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            native = root / 'unknown-runtime.mjs'
            native.write_text("process.on('uncaughtException', () => {});\n"
                              "process.on('unhandledRejection', () => {});\n"
                              "process.on('SIGTERM', () => {});\n"
                              "setInterval(() => {}, 1000);\n")
            with self.container(service, environment={'SKIP_EXERCISE_IMAGE_DOWNLOADS': 'true'}, files=[
                (ROOT / 'services/data/openfit/start.mjs', '/opt/home-lab-openfit-start.mjs'),
                (native, '/app/.output/server/index.mjs'),
            ]) as name:
                docker('start', name)
                deadline = time.monotonic() + 15
                while True:
                    state = json.loads(docker('inspect', '--format', '{{json .State}}', name))
                    if not state['Running']:
                        break
                    self.assertLess(time.monotonic(), deadline, 'unknown shutdown interface was not refused')
                    time.sleep(.1)
                self.assertEqual(state['ExitCode'], 1)

    def test_mindwtr_exits_gracefully_and_reopens_its_store(self):
        service = yaml.safe_load((ROOT / 'services/apps.yml').read_text())['services']['mindwtr-cloud']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            tokens = root / 'tokens'
            tokens.write_text('synthetic-backup-fixture-token-only')
            tokens.chmod(0o400)
            self.graceful_restart(service, {
                'MINDWTR_CLOUD_AUTH_TOKENS_FILE': '/tmp/fixture-tokens',
                'MINDWTR_CLOUD_DATA_DIR': '/app/cloud_data',
            }, ['curl', '--max-time', '2', '-fsS', 'http://localhost:8787/ready'],
                files=[(tokens, '/tmp/fixture-tokens')])

    def test_mosquitto_online_flush_restores_retained_messages_without_stopping_source(self):
        service = yaml.safe_load((ROOT / 'services/hass.yml').read_text())['services']['mosquitto']
        # Native file-format qualification; all payloads/credentials are synthetic.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            config = root / 'mosquitto.conf'
            config.write_text('user root\nlistener 1883\nallow_anonymous true\npersistence true\n'
                              'persistence_location /tmp/\nautosave_interval 0\n')
            service = {**service, 'user': '0'}
            with self.container(service, command=['mosquitto', '-c', '/tmp/fixture.conf']) as source:
                docker('cp', str(config), source + ':/tmp/fixture.conf')
                docker('start', source)
                self.ready(source, ['mosquitto_pub', '-h', '127.0.0.1', '-t', 'backup/fixture', '-m', 'saved', '-r'])
                docker('kill', '--signal', 'USR1', source)
                deadline = time.monotonic() + 10
                while True:
                    result = subprocess.run(['docker', 'exec', source, 'test', '-s', '/tmp/mosquitto.db'], capture_output=True)
                    if result.returncode == 0:
                        break
                    self.assertLess(time.monotonic(), deadline, 'native persistence flush did not finish')
                    time.sleep(.1)
                docker('cp', source + ':/tmp/mosquitto.db', str(root / 'mosquitto.db'))
                with self.container(service, command=['mosquitto', '-c', '/tmp/fixture.conf']) as restored:
                    docker('cp', str(config), restored + ':/tmp/fixture.conf')
                    docker('cp', str(root / 'mosquitto.db'), restored + ':/tmp/mosquitto.db')
                    docker('start', restored)
                    self.ready(restored, ['mosquitto_sub', '-h', '127.0.0.1', '-t', 'backup/fixture', '-C', '1', '-W', '2'])
                    self.assertEqual(docker('exec', restored, 'mosquitto_sub', '-h', '127.0.0.1', '-t', 'backup/fixture',
                                            '-C', '1', '-W', '2'), 'saved')
                self.assertEqual(docker('inspect', '--format', '{{.State.Running}}', source), 'true')


if __name__ == '__main__':
    unittest.main()
