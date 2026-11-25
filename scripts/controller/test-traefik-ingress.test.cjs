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
  'auth', 'caromanga', 'ddns', 'frigate', 'openfit',
  'prowlarr', 'qb', 'radarr', 'sabnzbd',
  'seerr', 'shelfmark', 'sonarr', 'gost',
];
const directHosts = {
  hass: 'hass', vaultwarden: 'vaultwarden', watch: 'jellyfin', books: 'books',
  nextcloud: 'nextcloud', todo: 'mindwtr-app', 'todo-api': 'mindwtr-cloud',
  'todo-auth': 'authentik', karaoke: 'karaoke', comics: 'uchiyomi',
};

test('the public host allowlist routes to the intended private backends', () => {
  const expected = Object.fromEntries([
    ...authentikHosts.map((host) => [host, 'authentik']),
    ...Object.entries(directHosts),
  ]);
  assert.deepEqual(Object.keys(dynamic.routers).sort(), [...Object.keys(expected), 'books-deny-local-auth'].sort());
  assert.ok(!Object.values(dynamic.routers).some(({ rule }) => /omada\.diloreto\.com|proxmox\.diloreto\.com|zwave\.diloreto\.com|ts-control\.diloreto\.com|sonarr-4k\.diloreto\.com/.test(rule)));
  for (const [host, service] of Object.entries(expected)) {
    const route = dynamic.routers[host];
    if (!['todo-api', 'todo-auth'].includes(host)) {
      assert.equal(route.rule, `Host(\`${host}.diloreto.com\`)`);
    }
    assert.deepEqual(route.entryPoints, ['websecure']);
    assert.equal(route.service, service);
    const middlewares = host === 'todo' ? ['mindwtr-web-auth'] : undefined;
    assert.deepEqual(route.middlewares, middlewares);
    assert.ok(dynamic.services[service].loadBalancer.servers[0].url.startsWith('http://'));
  }
  assert.equal(dynamic.services.authentik.loadBalancer.servers[0].url, 'http://authentik-server:9000');
  assert.equal(dynamic.services.hass.loadBalancer.servers[0].url, 'http://172.23.0.1:8123');
  assert.equal(dynamic.services.books.loadBalancer.servers[0].url, 'http://bookorbit:3000');
  assert.equal(dynamic.services.uchiyomi.loadBalancer.servers[0].url, 'http://gluetun:3000');
});

test('Books isolates the backend and denies local auth without blocking the OIDC callback or Kobo', () => {
  const model = readYaml('services/bookorbit.yml');
  const app = model.services.bookorbit;
  assert.equal(app.environment.APP_URL, 'https://books.diloreto.com');
  assert.equal(app.environment.DISABLE_LOCAL_AUTH, 'true');
  assert.equal(app.ports, undefined);
  assert.deepEqual(app.networks.sort(), ['bookorbit-db', 'bookorbit-egress', 'bookorbit-ingress']);
  assert.deepEqual(model.networks['bookorbit-ingress'], { internal: true });
  assert.deepEqual(Object.keys(compose.services.traefik.networks).sort(), ['bookorbit-ingress', 'proxy']);
  const guard = dynamic.routers['books-deny-local-auth'];
  assert.equal(guard.service, 'noop@internal');
  assert.deepEqual(guard.entryPoints, ['websecure']);
  assert.ok(guard.priority > dynamic.routers.books.rule.length);
  const patterns = [...guard.rule.matchAll(/PathRegexp\(`([^`]+)`\)/g)]
    .map(([, p]) => new RegExp(p.replace(/^\(\?i\)/, ''), 'i'));
  for (const path of ['/api/v1/auth/setup', '/api/v1/auth/login', '/api/v1/auth/register',
    '/api/v1/users', '/api/v1/users/shared', '/api/v1/users/42/reset-password',
    '/api/v1/auth/magic-links/token', '/api/v1/users%252fshared']) {
    assert.ok(patterns.some(pattern => pattern.test(path)), path);
  }
  for (const path of ['/oauth2-callback', '/api/v1/auth/oidc/authentik/start',
    '/api/v1/kobo/example/v1/library/sync', '/api/v1/auth/login-options']) {
    assert.ok(!patterns.some(pattern => pattern.test(path)), path);
  }
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
