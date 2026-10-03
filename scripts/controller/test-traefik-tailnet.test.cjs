const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { X509Certificate } = require('node:crypto');
const yaml = require('js-yaml');

const readYaml = (path) => yaml.load(fs.readFileSync(path, 'utf8'));
const staticConfig = readYaml('services/data/traefik-tailnet/traefik.yml');
const routes = readYaml('services/data/traefik-tailnet/routes.yml').http;
const publicConfig = readYaml('services/data/traefik/traefik.yml');
const publicRoutes = readYaml('services/data/traefik/routes.yml').http;
const infra = readYaml('services/infra.yml');
const recovery = JSON.parse(fs.readFileSync('recovery/groups.json', 'utf8')).groups.infrastructure;
const ingressIp = JSON.parse(fs.readFileSync('infrastructure/tofu/aws-foundation/tail-ingress.auto.tfvars.json', 'utf8')).tail_ingress_ipv4;

test('private TLS is bound to the reviewed tailnet address with its own production DNS-01 store', () => {
  assert.deepEqual(Object.keys(staticConfig.entryPoints), ['tailnet']);
  assert.equal(staticConfig.entryPoints.tailnet.address, ':443/tcp');
  assert.equal(staticConfig.entryPoints.tailnet.http.tls.certResolver, 'tailnet');
  assert.equal(staticConfig.certificatesResolvers.tailnet.acme.dnsChallenge.provider, 'route53');
  assert.equal(staticConfig.certificatesResolvers.tailnet.acme.storage, '/data/acme.json');
  assert.equal(staticConfig.certificatesResolvers.tailnet.acme.caServer, undefined);
  assert.equal(staticConfig.providers.file.filename, '/etc/traefik/routes.yml');
  assert.equal(staticConfig.providers.docker, undefined);
  assert.equal(publicConfig.certificatesResolvers.letsencrypt.acme.httpChallenge.entryPoint, 'web');
  assert.equal(staticConfig.certificatesResolvers.tailnet.acme.httpChallenge, undefined);
});

test('private Compose ingress publishes only tailnet TCP on a bridge', () => {
  const privateIngress = infra.services['traefik-tailnet'];
  assert.equal(privateIngress.network_mode, undefined);
  assert.deepEqual(privateIngress.ports, [`${ingressIp}:443:443/tcp`]);
  assert.deepEqual(privateIngress.networks, ['proxy', 'omada-backend']);
  assert.deepEqual(infra.services.omada.networks, ['omada-backend']);
  assert.ok(Object.entries(infra.services).every(([name, service]) => {
    const networks = Array.isArray(service.networks) ? service.networks : Object.keys(service.networks || {});
    return ['omada', 'traefik-tailnet'].includes(name) || !networks.includes('omada-backend');
  }));
  assert.deepEqual(infra.networks['omada-backend'], {});
  assert.equal(privateIngress.image, infra.services.traefik.image);
  assert.ok(privateIngress.volumes.includes('/srv/home-lab-state/traefik-tailnet-data:/data'));
  assert.ok(privateIngress.volumes.includes('./data/traefik-tailnet/traefik.yml:/etc/traefik/traefik.yml:ro'));
  assert.ok(privateIngress.volumes.includes('./data/traefik-tailnet/routes.yml:/etc/traefik/routes.yml:ro'));
  assert.ok(privateIngress.volumes.includes('./data/traefik-tailnet/omada.pem:/etc/traefik/omada.pem:ro'));
  assert.ok(!privateIngress.volumes.some((volume) => volume.includes('docker.sock')));
  assert.equal(privateIngress.environment.AWS_ACCESS_KEY_ID, undefined);
  assert.equal(privateIngress.environment.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(privateIngress.environment.AWS_SHARED_CREDENTIALS_FILE, '/run/secrets/traefik_tailnet_aws_credentials');
  assert.deepEqual(privateIngress.secrets, ['traefik_tailnet_aws_credentials']);
  assert.equal(privateIngress.environment.AWS_HOSTED_ZONE_ID, 'Z07741203I5VR48TBSMSA');
  assert.equal(privateIngress.environment.AWS_REGION, 'us-east-1');
  for (const [name, service] of Object.entries(infra.services)) {
    if (name === 'traefik-tailnet') continue;
    assert.equal(service.environment?.AWS_ACCESS_KEY_ID, undefined);
    assert.equal(service.environment?.AWS_SECRET_ACCESS_KEY, undefined);
    assert.equal(service.environment?.AWS_SHARED_CREDENTIALS_FILE, undefined);
  }
  assert.deepEqual(infra.services.traefik.ports, ['18080:80/tcp', '18443:443/tcp', '18443:443/udp']);
  assert.ok(recovery.services.includes('traefik-tailnet'));
  assert.ok(!recovery.paths.includes('/srv/home-lab-state/traefik-tailnet-data'));
});

test('the private router allowlist has no catch-all backend or public routes', () => {
  const expected = { omada: 'omada', llm: 'cli-proxy-api', proxmox: 'proxmox', zwave: 'authentik', grimmory: 'grimmory' };
  const apiRoutes = { 'sonarr-api': 'v3', 'radarr-api': 'v3', 'radarr-4k-api': 'v3', 'prowlarr-api': 'v1' };
  assert.deepEqual(Object.keys(routes.routers).sort(), [...Object.keys(expected), ...Object.keys(apiRoutes)].sort());
  for (const [name, service] of Object.entries(expected)) {
    const router = routes.routers[name];
    assert.equal(router.rule, `Host(\`${name}.ts.diloreto.com\`)`);
    assert.deepEqual(router.entryPoints, ['tailnet']);
    assert.equal(router.service, service);
    assert.deepEqual(router.tls, { certResolver: 'tailnet', domains: [{ main: '*.ts.diloreto.com' }] });
  }
  for (const [name, version] of Object.entries(apiRoutes)) {
    const router = routes.routers[name];
    const host = name.slice(0, -4);
    assert.equal(router.rule, `Host(\`${host}.ts.diloreto.com\`) && (Path(\`/api/${version}\`) || PathPrefix(\`/api/${version}/\`))`);
    assert.deepEqual(router.entryPoints, ['tailnet']);
    assert.equal(router.service, name);
    assert.deepEqual(router.tls, { certResolver: 'tailnet', domains: [{ main: '*.ts.diloreto.com' }] });
  }
  assert.ok(Object.values(publicRoutes.routers).every(({ rule }) => !rule.includes('ts.diloreto.com')));
  assert.equal(publicConfig.providers.file.filename, '/etc/traefik/routes.yml');
});

test('Omada uses a pinned trusted certificate on its dedicated bridge', () => {
  const transport = routes.serversTransports['omada-backend'];
  const cert = new X509Certificate(fs.readFileSync('services/data/traefik-tailnet/omada.pem'));
  assert.deepEqual(Object.keys(routes.services).sort(), [
    'authentik', 'cli-proxy-api', 'grimmory', 'omada', 'proxmox', 'sonarr-api', 'radarr-api', 'radarr-4k-api', 'prowlarr-api',
  ].sort());
  assert.deepEqual(Object.keys(routes.serversTransports).sort(), ['omada-backend', 'proxmox-lan']);
  assert.equal(routes.services.omada.loadBalancer.serversTransport, 'omada-backend');
  assert.equal(routes.services.omada.loadBalancer.servers[0].url, 'https://omada:8043');
  assert.deepEqual(transport, {
    rootCAs: ['/etc/traefik/omada.pem'], serverName: 'Omada', disableHTTP2: true,
  });
  assert.ok(cert.checkHost(transport.serverName));
  assert.ok(cert.verify(cert.publicKey));
  assert.equal(cert.fingerprint256, 'BA:98:A1:D1:F1:88:B9:82:B8:1F:1E:D0:BC:C1:64:35:5E:FB:92:2B:F8:40:B5:6D:1A:2C:51:F0:AF:42:89:56');
  assert.ok(Date.parse(cert.validTo) > Date.now());
  assert.equal(routes.services['cli-proxy-api'].loadBalancer.servers[0].url, 'http://cli-proxy-api:8317');
  assert.equal(routes.services['cli-proxy-api'].loadBalancer.serversTransport, undefined);
  assert.deepEqual(routes.serversTransports['proxmox-lan'], { insecureSkipVerify: true });
  assert.equal(routes.services.proxmox.loadBalancer.serversTransport, 'proxmox-lan');
  assert.equal(routes.services.proxmox.loadBalancer.servers[0].url, 'https://192.168.0.123:8006');
  assert.equal(routes.services.authentik.loadBalancer.servers[0].url, 'http://authentik-server:9000');
  assert.equal(routes.services.authentik.loadBalancer.serversTransport, undefined);
  assert.ok(readYaml('services/servarr.yml').services.gluetun.networks.includes('proxy'));
  for (const [name, port] of Object.entries({ 'sonarr-api': 8989, 'radarr-api': 7878, 'radarr-4k-api': 7879, 'prowlarr-api': 9696 })) {
    assert.equal(routes.services[name].loadBalancer.servers[0].url, `http://gluetun:${port}`);
    assert.equal(routes.services[name].loadBalancer.serversTransport, undefined);
  }
  const authentik = readYaml('services/authentik.yml').services['authentik-server'];
  assert.equal(authentik.ports, undefined);
  assert.ok(authentik.networks.includes('proxy'));
  const zwave = readYaml('services/hass.yml').services.zwave;
  assert.deepEqual(zwave.ports, ['127.0.0.1:3000:3000']);
  assert.deepEqual(zwave.networks, ['hass', 'proxy']);
  const cli = readYaml('services/cli-proxy-api.yml').services['cli-proxy-api'];
  assert.ok(cli.networks.includes('proxy'));
});
