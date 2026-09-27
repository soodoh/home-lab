const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const yaml = require('js-yaml');

const gost = yaml.load(fs.readFileSync('services/data/gost/tailscale-control.yml', 'utf8'));
const infra = yaml.load(fs.readFileSync('services/infra.yml', 'utf8'));
const publicRoutes = yaml.load(fs.readFileSync('services/data/traefik/routes.yml', 'utf8')).http;
const privateRoutes = yaml.load(fs.readFileSync('services/data/traefik-tailnet/routes.yml', 'utf8')).http;

test('authenticated relay has only control-plane and private subdomain HTTPS destinations', () => {
  assert.deepEqual(gost.bypasses, [{
    name: 'tailscale-control-destinations',
    whitelist: true,
    matchers: [
      'tailscale.com:80', 'tailscale.com:443',
      '*.tailscale.com:80', '*.tailscale.com:443',
      '*.ts.diloreto.com:443',
    ],
  }]);
  assert.equal(gost.services[0].bypass, 'tailscale-control-destinations');
  assert.equal(gost.services[0].listener.type, 'ws');
  assert.deepEqual(infra.services['tailscale-control-proxy'].dns, ['100.100.100.100', '1.1.1.1']);
  assert.equal(infra.services['tailscale-control-proxy'].ports, undefined);
  assert.equal(publicRoutes.routers.gost.service, 'authentik');
  assert.equal(privateRoutes.routers.llm.rule, 'Host(`llm.ts.diloreto.com`)');
  assert.equal(privateRoutes.routers.omada.rule, 'Host(`omada.ts.diloreto.com`)');
});
