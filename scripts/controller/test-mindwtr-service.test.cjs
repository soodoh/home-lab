const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const yaml = require('js-yaml');

const compose = yaml.load(fs.readFileSync('services/apps.yml', 'utf8')).services;
const policy = JSON.parse(fs.readFileSync('services/data/restic/policy.json', 'utf8'));
const recovery = JSON.parse(fs.readFileSync('recovery/groups.json', 'utf8')).groups.applications;
const paths = fs.readFileSync('services/data/restic/files-from', 'utf8').trim().split('\n');
const encrypted = yaml.load(fs.readFileSync('secrets/production.sops.yaml', 'utf8'));

test('Mindwtr runs a pinned, token-authenticated cloud without publishing a host port', () => {
  const cloud = compose['mindwtr-cloud'];
  const app = compose['mindwtr-app'];
  for (const service of [cloud, app]) {
    assert.match(service.image, /@sha256:[0-9a-f]{64}$/);
    assert.deepEqual(service.networks, ['proxy']);
    assert.equal(service.ports, undefined);
  }
  assert.equal(cloud.environment.MINDWTR_CLOUD_AUTH_TOKENS, '$MINDWTR_CLOUD_AUTH_TOKENS');
  assert.equal(cloud.environment.MINDWTR_CLOUD_CORS_ORIGIN, 'https://todo.diloreto.com');
  assert.equal(cloud.environment.MINDWTR_CLOUD_DATA_DIR, '/data');
  assert.deepEqual(cloud.volumes, [{
    type: 'bind', source: '/srv/home-lab-state/mindwtr-data', target: '/data',
    bind: { create_host_path: false },
  }]);
  assert.deepEqual(app.depends_on, { 'mindwtr-cloud': { condition: 'service_healthy' } });
  assert.match(encrypted.MINDWTR_CLOUD_AUTH_TOKENS, /^ENC\[AES256_GCM,/);
});

test('the only durable Mindwtr writer is stopped for backup and included in restore', () => {
  assert.ok(policy.stop_groups.applications.includes('mindwtr-cloud'));
  assert.ok(paths.includes('/srv/home-lab-state/mindwtr-data'));
  assert.ok(recovery.services.includes('mindwtr-cloud'));
  assert.ok(recovery.paths.includes('/srv/home-lab-state/mindwtr-data'));
});
