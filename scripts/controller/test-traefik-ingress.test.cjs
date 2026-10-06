const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const yaml = require('js-yaml');

const readYaml = (path) => yaml.load(fs.readFileSync(path, 'utf8'));
const staticConfig = readYaml('services/data/traefik/traefik.yml');
const dynamic = readYaml('services/data/traefik/routes.yml').http;
const compose = readYaml('services/infra.yml');
const forwards = JSON.parse(fs.readFileSync('infrastructure/tofu/omada/desired.json', 'utf8')).port_forwards;
const recovery = JSON.parse(fs.readFileSync('recovery/groups.json', 'utf8')).groups.infrastructure;

const authentikHosts = [
  'auth', 'caromanga', 'comics', 'ddns', 'frigate', 'openfit',
  'prowlarr', 'qb', 'radarr-4k', 'radarr', 'sabnzbd',
  'seerr', 'shelfmark', 'sonarr', 'gost',
];
const directHosts = {
  hass: 'hass', vaultwarden: 'vaultwarden', watch: 'jellyfin', books: 'books',
  nextcloud: 'nextcloud', todo: 'mindwtr-app', 'todo-api': 'mindwtr-cloud',
  'todo-auth': 'authentik', karaoke: 'karaoke',
};

test('the public host allowlist routes to the intended private backends', () => {
  const expected = Object.fromEntries([
    ...authentikHosts.map((host) => [host, 'authentik']),
    ...Object.entries(directHosts),
  ]);
  assert.deepEqual(Object.keys(dynamic.routers).sort(), Object.keys(expected).sort());
  assert.ok(!Object.values(dynamic.routers).some(({ rule }) => /omada\.diloreto\.com|proxmox\.diloreto\.com|zwave\.diloreto\.com|ts-control\.diloreto\.com|sonarr-4k\.diloreto\.com/.test(rule)));
  for (const [host, service] of Object.entries(expected)) {
    const route = dynamic.routers[host];
    if (host !== 'todo-api' && host !== 'todo-auth') {
      assert.equal(route.rule, `Host(\`${host}.diloreto.com\`)`);
    }
    assert.deepEqual(route.entryPoints, ['websecure']);
    assert.equal(route.service, service);
    assert.deepEqual(route.middlewares, host === 'todo' ? ['mindwtr-web-auth'] : undefined);
    assert.ok(dynamic.services[service].loadBalancer.servers[0].url.startsWith('http://'));
  }
  assert.equal(dynamic.services.authentik.loadBalancer.servers[0].url, 'http://authentik-server:9000');
  assert.equal(dynamic.services.hass.loadBalancer.servers[0].url, 'http://172.23.0.1:8123');
  assert.equal(dynamic.services.books.loadBalancer.servers[0].url, 'http://grimmory:6060');
});

test('Mindwtr web requires Authentik; sync API and calendar feeds keep native credentials', () => {
  const host = 'Host(`todo.diloreto.com`)';
  assert.equal(dynamic.routers.todo.rule, host);
  assert.equal(dynamic.routers['todo-api'].rule, `${host} && (Path(\`/v1\`) || PathPrefix(\`/v1/\`))`);
  assert.equal(dynamic.routers['todo-auth'].rule, `${host} && PathPrefix(\`/outpost.goauthentik.io/\`)`);
  assert.ok(dynamic.routers['todo-auth'].priority > dynamic.routers['todo-api'].priority);
  assert.equal(dynamic.routers['todo-api'].middlewares, undefined);
  assert.equal(dynamic.routers['todo-auth'].middlewares, undefined);
  assert.deepEqual(dynamic.middlewares['mindwtr-web-auth'], {
    forwardAuth: {
      address: 'http://authentik-server:9000/outpost.goauthentik.io/auth/traefik',
      trustForwardHeader: false,
      authRequestHeaders: ['Cookie'],
    },
  });
  assert.equal(dynamic.services['mindwtr-app'].loadBalancer.servers[0].url, 'http://mindwtr-app:5173');
  assert.equal(dynamic.services['mindwtr-cloud'].loadBalancer.servers[0].url, 'http://mindwtr-cloud:8787');
});

test('redirects, certificates, HTTP/3, and uniform HSTS preserve ingress policy', () => {
  const entries = staticConfig.entryPoints;
  assert.equal(entries.web.address, ':80');
  assert.equal(entries.web.http.redirections.entryPoint.to, 'websecure');
  assert.equal(entries.web.http.redirections.entryPoint.scheme, 'https');
  assert.equal(entries.web.http.redirections.entryPoint.permanent, true);
  assert.equal(entries.websecure.address, ':443');
  assert.deepEqual(entries.websecure.http3, {});
  assert.deepEqual(entries.websecure.http.middlewares, ['hsts@file']);
  assert.deepEqual(dynamic.middlewares.hsts, { headers: { stsSeconds: 15552000 } });
  assert.equal(entries.websecure.http.tls.certResolver, 'letsencrypt');
  assert.equal(staticConfig.certificatesResolvers.letsencrypt.acme.httpChallenge.entryPoint, 'web');
  assert.equal(staticConfig.certificatesResolvers.letsencrypt.acme.storage, '/data/acme.json');
  assert.equal(staticConfig.providers.file.filename, '/etc/traefik/routes.yml');
  assert.equal(staticConfig.providers.docker, undefined);
});

test('NAT, Compose, trusted proxy, and certificate persistence agree', () => {
  const service = compose.services.traefik;
  assert.deepEqual(service.ports, ['18080:80/tcp', '18443:443/tcp', '18443:443/udp']);
  assert.equal(service.networks.proxy.ipv4_address, '172.23.0.250');
  assert.ok(service.volumes.includes('/srv/home-lab-state/traefik-data:/data'));
  assert.ok(service.volumes.includes('./data/traefik/traefik.yml:/etc/traefik/traefik.yml:ro'));
  assert.ok(service.volumes.includes('./data/traefik/routes.yml:/etc/traefik/routes.yml:ro'));
  assert.ok(!service.volumes.some((volume) => volume.includes('docker.sock')));
  const byExternalPort = Object.fromEntries(Object.values(forwards).map((rule) => [rule.external_port, rule]));
  assert.deepEqual(Object.keys(byExternalPort).sort(), ['443', '80']);
  assert.equal(byExternalPort['80'].forward_port, '18080');
  assert.equal(byExternalPort['443'].forward_port, '18443');
  assert.equal(byExternalPort['443'].protocol, 'tcp_udp');
  assert.ok(recovery.services.includes('traefik'));
  assert.ok(!recovery.paths.includes('/srv/home-lab-state/traefik-data'));
  assert.ok(!fs.readFileSync('services/data/restic/files-from', 'utf8').split('\n').includes('/srv/home-lab-state/traefik-data'));
});
