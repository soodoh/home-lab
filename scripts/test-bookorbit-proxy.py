#!/usr/bin/env python3
"""Exercise the real acquisition proxy with synthetic services on two bridges."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = '''
import functools
import http.server
from pathlib import Path
import threading

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.do_GET()

servers = []
for directory in Path('/fixture').iterdir():
    if not directory.is_dir():
        continue
    handler = functools.partial(Handler, directory=directory)
    server = http.server.ThreadingHTTPServer(('', int(directory.name)), handler)
    servers.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait(180)
'''


class AcquisitionProxy(unittest.TestCase):
    def test_only_the_intended_routes_and_interfaces_are_reachable(self):
        with tempfile.TemporaryDirectory(prefix='bookorbit-proxy-test-') as workspace:
            work = Path(workspace)
            model = yaml.safe_load((ROOT / 'services/bookorbit.yml').read_text())
            proxy = model['services']['bookorbit-acquisition']
            proxy.pop('container_name')
            for volume in proxy['volumes']:
                volume['source'] = str(ROOT / 'services' / volume['source'])
            network = 'bookorbit-acquisition'
            routes = {
                '9696': ('api/v1/system/status', 'api/v1/indexer/5/newznab', 'api/v1/indexer/5/download', '5/download', 'api/v1/config/host'),
                '8081': ('api/v2/app/version', 'api/v2/torrents/info', 'api/v2/app/preferences', 'api/v2/torrents/add'),
                '8080': ('api',),
                '1122': ('unrelated',),
            }
            for port, paths in routes.items():
                for url_path in paths:
                    file = work / port / url_path
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text(f'{port} synthetic origin')
            work.chmod(0o755)  # Docker must traverse only this synthetic data directory.
            model = {
                'services': {
                    network: proxy,
                    'gluetun': {
                        'image': 'python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90',
                        'networks': ['arr_network'], 'command': ['python', '-c', ORIGIN],
                        'volumes': [f'{work}:/fixture:ro'],
                    },
                    'client': {
                        'image': proxy['image'], 'networks': [network, 'bookorbit-egress'],
                        'entrypoint': ['/bin/sh', '-ec', 'sleep 180'],
                    },
                },
                'networks': {network: model['networks'][network], 'arr_network': {}, 'bookorbit-egress': {}},
            }
            model_file = work / 'compose.json'
            model_file.write_text(json.dumps(model))
            compose = ['docker', 'compose', '--project-name', f'bookorbit-proxy-{work.name.split("-")[-1].lower()}', '-f', str(model_file)]

            def call(*args, check=True):
                result = subprocess.run(compose + list(args), text=True, capture_output=True, timeout=120, check=False)
                if check:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result

            def request(service, url, *, post=False):
                method = ['--post-data=fixture'] if post else []
                return call('exec', '-T', service, 'busybox', 'wget', '-T', '5', '-S', '-O', '-', *method, url, check=False)

            try:
                started = call('up', '-d', '--wait', '--wait-timeout', '45', check=False)
                if started.returncode:
                    logs = call('logs', '--no-color', check=False)
                    self.fail(started.stderr + logs.stdout + logs.stderr)
                proxy_url = f'http://{network}'
                for port, url_path in [
                    ('9696', 'api/v1/system/status'), ('9696', 'api/v1/indexer/5/newznab?t=search'),
                    ('9696', 'api/v1/indexer/5/download'), ('9696', '5/download'),
                    ('8081', 'api/v2/app/version'), ('8081', 'api/v2/torrents/info?category=bookorbit'),
                    ('8080', 'api?mode=version'), ('8080', 'api?mode=get_config&section=categories'),
                ]:
                    with self.subTest(route=f'{port}/{url_path}'):
                        reply = request('client', f'{proxy_url}:{port}/{url_path}')
                        self.assertEqual(reply.stdout, f'{port} synthetic origin', reply.stderr)
                for port, path in [('8081', 'api/v2/torrents/add'), ('8080', 'api?mode=addfile')]:
                    reply = request('client', f'{proxy_url}:{port}/{path}', post=True)
                    self.assertEqual(reply.stdout, f'{port} synthetic origin', reply.stderr)
                    self.assertIn('404 Not Found', request('client', f'{proxy_url}:{port}/{path}').stderr)
                for port, url_path in [
                    ('9696', 'api/v1/config/host'), ('8081', 'api/v2/app/preferences'),
                    ('8080', 'api?mode=set_config'), ('8080', 'api?mode=get_config&section=misc'),
                ]:
                    with self.subTest(denied=f'{port}/{url_path}'):
                        reply = request('client', f'{proxy_url}:{port}/{url_path}')
                        self.assertIn('404 Not Found', reply.stderr)
                gluetun_ip = call('exec', '-T', 'gluetun', 'hostname', '-i').stdout.strip()
                for source, url in [
                    ('client', 'http://gluetun:1122/unrelated'),
                    ('client', f'http://{gluetun_ip}:1122/unrelated'),
                    ('client', f'{proxy_url}:1122/unrelated'),
                    ('gluetun', f'{proxy_url}:8081/api/v2/app/version'),
                ]:
                    self.assertNotEqual(request(source, url).returncode, 0, f'{source} reached {url}')
            finally:
                call('down', '-v', '--remove-orphans')


if __name__ == '__main__':
    unittest.main()
