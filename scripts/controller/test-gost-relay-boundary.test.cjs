const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const yaml = require('js-yaml');

const gost = yaml.load(fs.readFileSync('services/data/gost/tailscale-control.yml', 'utf8'));
const infra = yaml.load(fs.readFileSync('services/infra.yml', 'utf8'));
const publicRoutes = yaml.load(fs.readFileSync('services/data/traefik/routes.yml', 'utf8')).http;
const privateRoutes = yaml.load(fs.readFileSync('services/data/traefik-tailnet/routes.yml', 'utf8')).http;

test('authenticated GOST relay allows all destinations behind Authentik without a host port', () => {
  assert.equal(gost.bypasses, undefined);
  assert.equal(gost.services.length, 1);
  assert.equal(gost.services[0].name, 'tailscale-control-proxy');
  assert.equal(gost.services[0].bypass, undefined);
  assert.equal(gost.services[0].handler.type, 'http');
  assert.equal(gost.services[0].listener.type, 'ws');
  assert.equal(gost.services[0].listener.metadata.path, '/tailscale-control');
  assert.deepEqual(infra.services['tailscale-control-proxy'].dns, ['100.100.100.100', '1.1.1.1']);
  assert.equal(infra.services['tailscale-control-proxy'].ports, undefined);
  assert.equal(publicRoutes.routers.gost.service, 'authentik');
  assert.equal(privateRoutes.routers.llm.rule, 'Host(`llm.ts.diloreto.com`)');
  assert.equal(privateRoutes.routers.omada.rule, 'Host(`omada.ts.diloreto.com`)');
});
