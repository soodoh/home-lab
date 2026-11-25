#!/usr/bin/env python3
"""Exercise the Ansible role against the pinned BookOrbit admin API contract."""

import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BookOrbitApi(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, payload=None):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def handle_request(self):
        if self.headers.get('X-Api-Key') != 'bok_fixture':
            return self.reply(401)
        method = self.command
        parts = self.path.removeprefix('/api/v1/').split('/')
        if parts == ['auth', 'me']:
            return self.reply(200, {'authenticationMethod': 'api_key', 'isSuperuser': False, 'permissions': ['manage_app_settings']})
        if parts == ['admin', 'download-clients', 'validate']:
            return self.reply(403 if self.server.read_only else 400)
        if parts[0] != 'admin':
            return self.reply(404)
        _, collection, *suffix = parts
        if method != 'GET':
            self.server.writes.append((method, collection, suffix))
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or '{}')
        if collection == 'book-request-automation':
            if method == 'PUT':
                self.server.automation.update(body)
            return self.reply(200, self.server.automation)
        if collection not in self.server.records:
            return self.reply(404)
        records = self.server.records[collection]
        list_key, discriminator, password_key = {
            'request-indexer-managers': ('managers', 'type', 'credential'),
            'download-clients': ('clients', 'adapterType', 'password'),
        }[collection]
        if method == 'GET' and not suffix:
            rows = [{key: val for key, val in row.items() if key != password_key} for row in records.values()]
            return self.reply(200, {list_key: rows, 'encryptionConfigured': True})
        if method == 'POST' and not suffix and discriminator in body:
            if any(row.get('name') == body.get('name') for row in records.values()):
                return self.reply(409)
            record_id = max(records, default=0) + 1
            records[record_id] = dict(body, id=record_id)
            return self.reply(201, {'id': record_id})
        if not suffix or not suffix[0].isdigit() or int(suffix[0]) not in records:
            return self.reply(404)
        record = records[int(suffix[0])]
        if method == 'PUT' and len(suffix) == 1 and discriminator not in body:
            record.update(body)
            return self.reply(200, {'id': record['id']})
        if method == 'POST' and suffix[1:] == ['test']:
            return self.reply(200, {'success': record[password_key] == self.server.current[record[discriminator]]})
        if method == 'POST' and suffix[1:] == ['sync'] and collection == 'request-indexer-managers':
            return self.reply(200, {'manager': {'id': record['id']}})
        return self.reply(404)

    do_GET = do_POST = do_PUT = handle_request


class Convergence(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory(prefix='bookorbit-ansible-test-')
        self.addCleanup(workspace.cleanup)
        self.work = Path(workspace.name)
        server = self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), BookOrbitApi)
        self.addCleanup(server.server_close)
        server.read_only = False
        server.records = {'request-indexer-managers': {42: {'name': 'Unrelated', 'id': 42}}, 'download-clients': {}}
        server.automation = {'autoGrabEnabled': True, 'unrelated': 'keep'}
        server.writes = []
        server.current = {name: name * 8 for name in ('prowlarr', 'qbittorrent', 'sabnzbd')}
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.play = self.work / 'test.yml'
        self.play.write_text('''---
- hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.include_role:
        name: bookorbit
        tasks_from: preflight
    - ansible.builtin.include_role:
        name: bookorbit
        tasks_from: connections
''')

    def run_playbook(self, *args, succeeds=True):
        variables = self.work / 'vars.json'
        variables.write_text(json.dumps({
            'bookorbit_api_url': f'http://127.0.0.1:{self.server.server_port}/api/v1',
            'bookorbit_production': {
                'BOOKORBIT_CONVERGENCE_API_KEY': 'bok_fixture',
                'BOOKORBIT_REQUEST_ENCRYPTION_KEY': 'b' * 64,
                'PROWLARR_API_KEY': self.server.current['prowlarr'],
            },
            'bookorbit_download_clients': {
                'qbittorrent_username': 'fixture',
                'qbittorrent_password': self.server.current['qbittorrent'],
                'sabnzbd_api_key': self.server.current['sabnzbd'],
            },
        }))
        result = subprocess.run(
            ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(self.play), '-e', f'@{variables}', *args],
            cwd=ROOT, text=True, capture_output=True, check=False, timeout=90,
            env=dict(os.environ, ANSIBLE_CONFIG=str(ROOT / 'ansible/ansible.cfg'), ANSIBLE_LOCAL_TEMP=str(self.work / 'ansible')),
        )
        for secret in ('bok_fixture', *self.server.current.values()):
            self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)

    def test_rotation_updates_only_managed_rows_and_keeps_ids(self):
        self.run_playbook()
        self.assertEqual(self.server.automation, {'autoGrabEnabled': False, 'unrelated': 'keep'})
        clients = self.server.records['download-clients']
        self.assertTrue(clients[1]['enabled'])
        self.assertFalse(clients[2]['enabled'])
        for row, medium in zip(clients.values(), ('qbittorrent', 'sabnzbd'), strict=True):
            self.assertEqual(row['category'], 'bookorbit')
            self.assertFalse(row['useHardlinks'])
            self.assertFalse(row['removeCompletedDownloads'])
            self.assertEqual(row['pathMappings'][0]['localPath'], f'/acquisition/{medium}')
        self.server.current = {name: 'rotated-' + secret for name, secret in self.server.current.items()}
        self.server.writes.clear()
        self.run_playbook()
        managers = self.server.records['request-indexer-managers']
        self.assertFalse(managers[43]['syncNewIndexers'])
        self.assertEqual(managers[43]['credential'], self.server.current['prowlarr'])
        self.assertEqual(managers[42], {'id': 42, 'name': 'Unrelated'})
        self.assertEqual(set(clients), {1, 2})
        self.assertEqual(clients[1]['password'], self.server.current['qbittorrent'])
        self.assertEqual(clients[2]['password'], self.server.current['sabnzbd'])
        privileged = [write for write in self.server.writes if len(write[2]) <= 1]
        self.assertEqual(privileged, [
            ('PUT', 'request-indexer-managers', ['43']),
            ('PUT', 'download-clients', ['1']),
            ('PUT', 'download-clients', ['2']),
        ])

    def test_preview_does_not_modify_app_and_read_only_token_refuses_early(self):
        self.run_playbook('--check')
        self.assertFalse(self.server.writes)
        self.server.read_only = True
        self.run_playbook(succeeds=False)
        self.assertFalse(self.server.writes)


if __name__ == '__main__':
    unittest.main()
