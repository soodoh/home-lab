const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const yaml = require('js-yaml');

const readYaml = (path) => yaml.load(fs.readFileSync(path, 'utf8'));
const staticConfig = readYaml('services/data/traefik-tailnet/traefik.yml');
const routes = readYaml('services/data/traefik-tailnet/routes.yml').http;
const publicConfig = readYaml('services/data/traefik/traefik.yml');
const publicRoutes = readYaml('services/data/traefik/routes.yml').http;
const ingressIp = JSON.parse(fs.readFileSync('infrastructure/tofu/aws-foundation/tail-ingress.auto.tfvars.json', 'utf8')).tail_ingress_ipv4;

test('private TLS is bound to the reviewed tailnet address with its own DNS-01 store', () => {
  assert.deepEqual(Object.keys(staticConfig.entryPoints), ['tailnet']);
  assert.equal(staticConfig.entryPoints.tailnet.address, `${ingressIp}:443/tcp`);
  assert.equal(staticConfig.entryPoints.tailnet.http.tls.certResolver, 'tailnet');
  assert.equal(staticConfig.certificatesResolvers.tailnet.acme.dnsChallenge.provider, 'route53');
  assert.equal(staticConfig.certificatesResolvers.tailnet.acme.storage, '/data/acme.json');
  assert.equal(staticConfig.providers.file.filename, '/etc/traefik/routes.yml');
  assert.equal(staticConfig.providers.docker, undefined);
  assert.equal(publicConfig.certificatesResolvers.letsencrypt.acme.httpChallenge.entryPoint, 'web');
  assert.equal(staticConfig.certificatesResolvers.tailnet.acme.httpChallenge, undefined);
});

test('the private router allowlist has no catch-all backend or public routes', () => {
  const expected = { omada: 'omada', llm: 'cli-proxy-api' };
  assert.deepEqual(Object.keys(routes.routers).sort(), Object.keys(expected).sort());
  for (const [name, service] of Object.entries(expected)) {
    const router = routes.routers[name];
    assert.equal(router.rule, `Host(\`${name}.ts.diloreto.com\`)`);
    assert.deepEqual(router.entryPoints, ['tailnet']);
    assert.equal(router.service, service);
    assert.deepEqual(router.tls, { certResolver: 'tailnet', domains: [{ main: '*.ts.diloreto.com' }] });
  }
  assert.ok(Object.values(publicRoutes.routers).every(({ rule }) => !rule.includes('ts.diloreto.com')));
  assert.equal(publicConfig.providers.file.filename, '/etc/traefik/routes.yml');
});

test('the sole backend TLS exception is encrypted Omada loopback', () => {
  assert.deepEqual(Object.keys(routes.services).sort(), ['cli-proxy-api', 'omada']);
  assert.deepEqual(Object.keys(routes.serversTransports), ['omada-loopback']);
  assert.equal(routes.services.omada.loadBalancer.serversTransport, 'omada-loopback');
  assert.equal(routes.services.omada.loadBalancer.servers[0].url, 'https://127.0.0.1:8043');
  assert.deepEqual(routes.serversTransports['omada-loopback'], {
    insecureSkipVerify: true, disableHTTP2: true,
  });
  assert.equal(routes.services['cli-proxy-api'].loadBalancer.servers[0].url, 'http://127.0.0.1:8317');
  assert.equal(routes.services['cli-proxy-api'].loadBalancer.serversTransport, undefined);
});
