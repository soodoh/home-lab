const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { resolve } = require('node:path');
const yaml = require('js-yaml');

const root = resolve(__dirname, '..');

function lint(message) {
  const result = spawnSync(process.execPath, [
    resolve(root, 'node_modules/.bin/commitlint'),
    '--config', resolve(root, 'commitlint.config.ts'),
  ], { cwd: root, input: message + '\n', encoding: 'utf8' });
  assert.ifError(result.error);
  return result;
}

test('the typed conventional configuration accepts valid messages with arbitrary scopes', () => {
  for (const message of ['fix: preserve backups', 'chore(deps): update CI tooling', 'feat(new-scope): add service']) {
    const result = lint(message);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  }
});

test('commitlint rejects missing and invalid conventional types', () => {
  for (const message of ['update packages', 'not-a-type: update packages']) {
    const result = lint(message);
    assert.equal(result.status, 1, result.stdout + result.stderr);
  }
});

test('Lefthook natively validates the actual hook configuration without installing hooks', () => {
  const result = spawnSync(resolve(root, 'node_modules/.bin/lefthook'), ['validate'], {
    cwd: root, encoding: 'utf8',
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('the YAML reader preserves image aliases and rejects duplicate service keys', () => {
  const model = yaml.load('image: &image example:1.2.3\nservices:\n  first: {image: *image}\n  second: {image: *image}\n');
  assert.equal(model.services.first.image, 'example:1.2.3');
  assert.equal(model.services.second.image, model.services.first.image);
  assert.throws(() => yaml.load('services:\n  app: {}\n  app: {}\n'), yaml.YAMLException);
});
