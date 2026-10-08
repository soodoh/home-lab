const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const yaml = require('js-yaml');

const binary = process.env.TRAEFIK_TEST_BINARY;
const upstreamCache = 'no-cache, no-store, max-age=0, must-revalidate';
const readYaml = (name) => yaml.load(fs.readFileSync(name, 'utf8'));

// Run against the deployed Traefik version, not a simulated rule/header engine:
// TRAEFIK_TEST_BINARY=/private/work/traefik node --test scripts/controller/test-traefik-kobo-covers.test.cjs
// Keep TMPDIR within the caller's private disposable workspace.
test('native Traefik permits private offline cover storage without changing other Kobo routes', {
  skip: !binary && 'set TRAEFIK_TEST_BINARY to the reviewed Traefik binary',
  timeout: 30000,
}, async (t) => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'traefik-kobo-covers-'));
  fs.chmodSync(work, 0o700);
  t.after(() => fs.rmSync(work, { recursive: true, force: true }));

  const backend = http.createServer((req, res) => {
    res.setHeader('Cache-Control', upstreamCache);
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    const status = req.url.includes('/invalid-token/') ? 401
      : req.url.includes('/BL-missing/') ? 404
        : req.url.includes('/BL-error/') ? 500 : 200;
    res.statusCode = status;
    res.setHeader('Content-Type', status === 200 ? 'image/jpeg' : 'application/json');
    res.end(status === 200 ? Buffer.from([0xff, 0xd8, 0xff]) : JSON.stringify({ status }));
  });
  backend.listen(0, '127.0.0.1');
  await once(backend, 'listening');
  t.after(() => new Promise((resolve) => backend.close(resolve)));

  const listener = http.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));

  const dynamic = readYaml('services/data/traefik/routes.yml');
  for (const service of Object.values(dynamic.http.services)) {
    service.loadBalancer.servers = [{ url: `http://127.0.0.1:${backend.address().port}` }];
  }
  fs.writeFileSync(path.join(work, 'routes.yml'), yaml.dump(dynamic));
  const config = readYaml('services/data/traefik/traefik.yml');
  config.entryPoints = {
    websecure: {
      address: `127.0.0.1:${port}`,
      http: { middlewares: config.entryPoints.websecure.http.middlewares },
    },
  };
  delete config.certificatesResolvers;
  config.providers.file.filename = path.join(work, 'routes.yml');
  config.log = { level: 'ERROR' };
  fs.writeFileSync(path.join(work, 'traefik.yml'), yaml.dump(config));

  const child = spawn(binary, ['--configFile', path.join(work, 'traefik.yml')], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let diagnostics = '';
  child.stdout.on('data', (chunk) => { diagnostics = (diagnostics + chunk).slice(-12000); });
  child.stderr.on('data', (chunk) => { diagnostics = (diagnostics + chunk).slice(-12000); });
  let spawnError;
  child.on('error', (error) => { spawnError = error; });
  t.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null || spawnError) return;
    const closed = once(child, 'close');
    child.kill('SIGTERM');
    await closed;
  });

  const request = (pathname, method = 'GET', host = 'books.diloreto.com') => new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: pathname, method, headers: { Host: host } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.setTimeout(2000, () => req.destroy(new Error('fixture request timed out')));
    req.on('error', reject);
    req.end();
  });
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    assert.equal(spawnError, undefined);
    assert.equal(child.exitCode, null, diagnostics);
    try {
      const res = await request('/ready');
      if (res.status === 200) { ready = true; break; }
    } catch { /* File-provider startup is asynchronous. */ }
    await delay(100);
  }
  assert.ok(ready, diagnostics);

  const root = '/api/kobo/fixture-token/v1/books/';
  for (const suffix of [
    'BL-fixture/thumbnail/300/400/false/image.jpg',
    'BL-fixture/thumbnail/300/400/true/image.jpg',
    'BL-fixture/thumbnail/300/400/90/false/image.jpg',
    'BL-fixture/1/thumbnail/300/400/90/true/image.jpg',
    'BL-fixture/1/thumbnail/300/400/false/image.jpg',
  ]) {
    const res = await request(root + suffix);
    assert.equal(res.status, 200, suffix);
    assert.equal(res.headers['cache-control'], 'private, max-age=0', suffix);
    assert.equal(res.headers.pragma, undefined);
    assert.equal(res.headers.expires, undefined);
    assert.equal(res.headers['content-type'], 'image/jpeg');
    // This loopback fixture is HTTP; live TLS/HSTS is checked after deployment.
    assert.equal(res.headers['strict-transport-security'], undefined);
    assert.deepEqual(res.body, Buffer.from([0xff, 0xd8, 0xff]));
  }
  const cover = root + 'BL-fixture/thumbnail/300/400/false/image.jpg';
  const head = await request(cover, 'HEAD');
  assert.equal(head.status, 200);
  assert.equal(head.headers['cache-control'], 'private, max-age=0');
  assert.equal(head.body.length, 0);

  // Native Headers is not status-conditional: zero freshness avoids giving
  // authorization, missing-cover, or server failures a positive cache lifetime.
  for (const [pathname, expected] of [
    [cover.replace('/fixture-token/', '/invalid-token/'), 401],
    [cover.replace('/BL-fixture/', '/BL-missing/'), 404],
    [cover.replace('/BL-fixture/', '/BL-error/'), 500],
  ]) {
    const res = await request(pathname);
    assert.equal(res.status, expected);
    assert.equal(res.headers['cache-control'], 'private, max-age=0');
    assert.deepEqual(JSON.parse(res.body), { status: expected });
  }

  for (const pathname of [
    '/api/v1/auth/login',
    '/api/v1/settings',
    '/api/v1/media/book/BL-fixture/cover.jpg',
    '/api/kobo/fixture-token/v1/initialization',
    '/api/kobo/fixture-token/v1/library/sync',
    root + '38/download',
    root + 'kobo-store-image/thumbnail/300/400/false/image.jpg',
    root + 'BL-fixture/thumbnail/300/400/false/image.jpg/extra',
  ]) {
    const res = await request(pathname);
    assert.equal(res.headers['cache-control'], upstreamCache, pathname);
    assert.equal(res.headers.pragma, 'no-cache', pathname);
    assert.equal(res.headers.expires, '0', pathname);
  }
  const post = await request(cover, 'POST');
  assert.equal(post.headers['cache-control'], upstreamCache);
  const unlisted = await request(cover, 'GET', 'unlisted.diloreto.com');
  assert.equal(unlisted.status, 404);
  assert.notEqual(unlisted.headers['cache-control'], 'private, max-age=0');
  assert.equal(diagnostics, '');
});
