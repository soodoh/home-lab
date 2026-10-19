#!/usr/bin/env node
// Exercise repository policy with the same pinned Renovate implementation as CI.
import assert from 'node:assert/strict';
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (!process.argv[2]) {
  throw new Error('Usage: node scripts/test-renovate-policy.mjs <renovate executable>');
}
const renovateDist = dirname(realpathSync(process.argv[2]));
const native = (path) => import(pathToFileURL(resolve(renovateDist, path)).href);
const [defaults, presets, utils, rules, versioning, filtering, classification, buckets] =
  await Promise.all([
    native('config/defaults.js'),
    native('config/presets/index.js'),
    native('config/utils.js'),
    native('util/package-rules/index.js'),
    native('modules/versioning/index.js'),
    native('workers/repository/process/lookup/filter.js'),
    native('workers/repository/process/lookup/update-type.js'),
    native('workers/repository/process/lookup/bucket.js'),
  ]);
await (await native('logger/index.js')).init();
const repositoryConfig = JSON.parse(readFileSync(new URL('../renovate.json', import.meta.url)));
const resolved = await presets.resolveConfigPresets(repositoryConfig);
const config = utils.mergeChildConfig(defaults.getConfig(), resolved.config);
assert.equal(config.platformAutomerge, true);
assert.equal(config.automergeType, 'pr');
assert.equal(config.automergeStrategy, 'squash');

function verifyLabels(update, expected, message = update.depName) {
  const labels = [...new Set([...(update.labels ?? []), ...(update.addLabels ?? [])])];
  assert.deepEqual(labels, [expected], message);
}

function manualLabel(dep) {
  if (dep.datasource === 'terraform-provider') return 'tofu-provider';
  return dep.datasource === 'docker' ? 'compose-manual' : 'tooling-manual';
}

async function dependency(packageName, currentValue, attributes = {}) {
  return rules.applyPackageRules({
    ...config,
    manager: 'docker-compose',
    datasource: 'docker',
    packageFile: 'services/servarr.yml',
    depName: packageName,
    packageName,
    currentValue,
    currentVersion: currentValue,
    ...attributes,
  });
}

async function verifyUpdate(dep, newVersion, expectedType) {
  const api = versioning.get(dep.versioning ?? 'docker');
  const accepted = filtering.filterVersions(
    dep, dep.currentVersion, undefined, [{ version: newVersion }], api,
  );
  assert.equal(accepted.length, 1, `${dep.depName}: ${newVersion} must be eligible`);
  const updateType = classification.classifyRelease(api, dep.currentVersion, newVersion);
  assert.equal(updateType, expectedType);
  const update = await rules.applyPackageRules({ ...dep, updateType });
  assert.equal(update.enabled, true);
  if (expectedType === 'major') {
    assert.equal(update.automerge, false, `${dep.depName}: major must remain manual`);
    assert.equal(update.groupName, null, `${dep.depName}: major must remain ungrouped`);
    verifyLabels(update, 'compose-manual');
    assert.equal(buckets.getBucket(dep, dep.currentVersion, newVersion, api), 'major');
  } else {
    assert.equal(update.automerge, true);
    assert.equal(update.groupName, 'routine Compose images');
    verifyLabels(update, 'compose-routine');
    assert.equal(buckets.getBucket(dep, dep.currentVersion, newVersion, api), 'non-major');
  }
}

for (const [packageName, current, updates] of [
  ['ghcr.io/linuxserver/sonarr', '4.0.20', [['4.0.21', 'patch'], ['5.0.0', 'major']]],
  ['radrootllc/karaoke-eternal', '2.0.2', [['2.0.3', 'patch'], ['2.1.0', 'minor'], ['3.0.0', 'major']]],
  ['postgres', '18.6-alpine', [['18.7-alpine', 'minor'], ['19.0-alpine', 'major']]],
  ['postgres', '19.0-alpine', [['19.1-alpine', 'minor'], ['20.0-alpine', 'major']]],
  ['ghcr.io/linuxserver/qbittorrent', '5.2.4', [
    ['5.2.5', 'patch'], ['5.3.0', 'minor'], ['6.0.0', 'major'],
  ]],
  ['ghcr.io/linuxserver/qbittorrent', '6.0.0', [
    ['6.0.1', 'patch'], ['6.1.0', 'minor'], ['7.0.0', 'major'],
    ['14.0.0', 'major'], ['15.0.0', 'major'],
  ]],
  ['linuxserver/qbittorrent', '5.2.4', [
    ['5.2.5', 'patch'], ['5.3.0', 'minor'], ['6.0.0', 'major'],
  ]],
]) {
  const dep = await dependency(packageName, current);
  for (const [next, type] of updates) await verifyUpdate(dep, next, type);
  const digest = await rules.applyPackageRules({ ...dep, updateType: 'digest' });
  assert.equal(digest.automerge, true);
  assert.equal(digest.groupName, 'routine Compose images');
  verifyLabels(digest, 'compose-routine');
}

const qbit = await dependency('ghcr.io/linuxserver/qbittorrent', '5.2.4');
const qbitApi = versioning.get(qbit.versioning);
const misleadingTags = [
  '14.3.9', 'v14.3.9', '18.04.1', '20.04.1', '2026.10.1', 'v2026.10.1',
  '6.0.0-rc.1', '6.0.0-libtorrentv1', '6.0.0_v2.0.15-ls480',
  'version-6.0.0', 'amd64-6.0.0', 'latest', 'libtorrentv1',
];
const releases = ['5.2.4', '5.2.5', '5.3.0', '6.0.0', ...misleadingTags]
  .map((version) => ({ version }));
const eligible = filtering.filterVersions(qbit, '5.2.4', undefined, releases, qbitApi);
assert.deepEqual(eligible.map((release) => release.version), ['5.2.5', '5.3.0', '6.0.0']);
const grouped = buckets.groupReleasesIntoBuckets(qbit, '5.2.4', eligible, qbitApi);
assert.deepEqual(grouped['non-major'].map((release) => release.version), ['5.2.5', '5.3.0']);
assert.deepEqual(grouped.major.map((release) => release.version), ['6.0.0']);

// Native extraction proves that real workflow inputs and package-manager pins
// do not accidentally inherit the Action/devDependency automerge permissions.
const [globalConfig, githubActions, pip, npm, bun, regex, matching, terraform] = await Promise.all([
  native('config/global.js'),
  native('modules/manager/github-actions/extract.js'),
  native('modules/manager/pip_requirements/extract.js'),
  native('modules/manager/npm/extract/common/package-file.js'),
  native('modules/manager/bun/extract.js'),
  native('modules/manager/custom/regex/index.js'),
  native('util/string-match.js'),
  native('modules/manager/terraform/extract.js'),
]);
globalConfig.GlobalConfig.set({ localDir: fileURLToPath(new URL('../', import.meta.url)) });
const readRepository = (path) => readFileSync(new URL('../' + path, import.meta.url), 'utf8');

async function verifyPolicy(dep, manager, packageFile, updateType, automatic) {
  const updated = await rules.applyPackageRules({
    ...config, ...dep, manager, packageFile, updateType,
    packageName: dep.packageName ?? dep.depName,
  });
  const label = `${dep.depName} (${manager}, ${packageFile}, ${updateType})`;
  assert.equal(updated.automerge, automatic, label);
  assert.equal(updated.groupName, automatic ? 'development and CI tooling' : null, label);
  if (automatic) {
    assert.equal(updated.groupSlug, 'development-ci-tooling', label);
  }
  verifyLabels(updated, automatic ? 'tooling-routine' : manualLabel(dep), label);
}

const ciPackages = pip.extractPackageFile(readRepository('controller/requirements-ci.txt')).deps;
assert.deepEqual(ciPackages.map((dep) => dep.depName).sort(),
  ['ansible-lint', 'jsonschema', 'requests', 'yamllint']);
for (const dep of ciPackages) {
  for (const type of ['minor', 'patch']) {
    await verifyPolicy(dep, 'pip_requirements', 'controller/requirements-ci.txt', type, true);
  }
  await verifyPolicy(dep, 'pip_requirements', 'controller/requirements-ci.txt', 'major', false);
  await verifyPolicy(dep, 'pip_requirements', 'controller/requirements.txt', 'patch', false);
}
for (const dep of pip.extractPackageFile(readRepository('controller/requirements.txt')).deps) {
  for (const file of ['controller/requirements.txt', 'controller/requirements-ci.txt']) {
    await verifyPolicy(dep, 'pip_requirements', file, 'patch', false);
  }
}

const bunFiles = await bun.extractAllPackageFiles(config, ['bun.lock', 'package.json']);
assert.equal(bunFiles.length, 1);
assert.deepEqual(bunFiles[0].lockFiles, ['bun.lock']);
const jsPackages = bunFiles[0].deps;
assert.deepEqual(jsPackages, npm.extractPackageJson(JSON.parse(readRepository('package.json')), 'package.json').deps);
assert(jsPackages.some((dep) => dep.depName === 'bun' && dep.depType === 'packageManager'));
assert(jsPackages.some((dep) => dep.depName === '@types/node' && dep.depType === 'devDependencies'));
for (const manager of ['npm', 'bun']) {
  for (const dep of jsPackages) {
    const development = dep.depType === 'devDependencies';
    for (const type of ['minor', 'patch']) await verifyPolicy(dep, manager, 'package.json', type, development);
    await verifyPolicy(dep, manager, 'package.json', 'major', false);
  }
}

const workflowFile = '.github/workflows/ci.yml';
const workflow = readRepository(workflowFile);
const actionDeps = (await githubActions.extractPackageFile(workflow, workflowFile)).deps;
const actionReferences = actionDeps.filter((dep) => dep.depType === 'action');
assert(actionReferences.length >= 5);
for (const dep of actionReferences) {
  for (const type of ['minor', 'patch', 'digest']) {
    await verifyPolicy(dep, 'github-actions', workflowFile, type, true);
  }
  await verifyPolicy(dep, 'github-actions', workflowFile, 'major', false);
}
const runtimeInputs = actionDeps.filter((dep) => dep.depType === 'uses-with');
assert(runtimeInputs.some((dep) => dep.depName === 'python'));
assert(runtimeInputs.some((dep) => dep.depName === 'opentofu'));
for (const dep of actionDeps.filter((dep) => dep.depType !== 'action')) {
  for (const type of ['minor', 'patch', 'digest', 'major']) {
    await verifyPolicy(dep, 'github-actions', workflowFile, type, false);
  }
}

function customDependencies(packageFile) {
  return config.customManagers.flatMap((manager) => {
    if (!matching.matchRegexOrGlobList(packageFile, manager.managerFilePatterns)) return [];
    return regex.extractPackageFile(readRepository(packageFile), packageFile, manager)?.deps ?? [];
  });
}
const validator = customDependencies(workflowFile).find((dep) => dep.depName === 'renovate');
assert(validator, 'the annotated Renovate validator must be extracted');
for (const type of ['minor', 'patch']) await verifyPolicy(validator, 'custom.regex', workflowFile, type, true);
await verifyPolicy(validator, 'custom.regex', workflowFile, 'major', false);

const tofuFile = 'infrastructure/tofu/servarr/versions.tf';
const tofuDependencies = (await terraform.extractPackageFile(readRepository(tofuFile), tofuFile, config)).deps;
assert(tofuDependencies.some((dep) => dep.datasource === 'terraform-provider'));
assert(tofuDependencies.some((dep) => dep.depType === 'required_version'));
for (const dep of tofuDependencies) {
  for (const type of ['minor', 'patch', 'major']) {
    await verifyPolicy(dep, 'terraform', tofuFile, type, false);
  }
}

const sopsFile = 'ansible/roles/compose_schedule/defaults/main.yml';
const sops = customDependencies(sopsFile);
assert.equal(sops.length, 1);
for (const type of ['minor', 'patch', 'digest', 'major']) {
  await verifyPolicy(sops[0], 'custom.regex', sopsFile, type, false);
}
const wolfFile = 'services/data/wolf/security.json';
const spawnedImages = customDependencies(wolfFile);
assert.equal(spawnedImages.length, 3);
for (const dep of spawnedImages) {
  const update = await rules.applyPackageRules({
    ...config, ...dep, packageName: dep.depName,
    manager: 'custom.regex', packageFile: wolfFile, updateType: 'digest',
  });
  assert.equal(update.automerge, true, dep.depName);
  assert.equal(update.groupName, 'routine Compose images');
  assert.equal(update.groupSlug, 'routine-compose-images');
  assert.equal(update.minimumReleaseAge, '3 days');
  verifyLabels(update, 'compose-routine');
  for (const type of ['minor', 'patch', 'major', 'pinDigest']) {
    await verifyPolicy(dep, 'custom.regex', wolfFile, type, false);
  }
  await verifyPolicy(dep, 'custom.regex', 'services/data/wolf/other.json', 'digest', false);
  await verifyPolicy(dep, 'docker-compose', wolfFile, 'digest', false);
  for (const tag of ['latest', 'stable', '1.0.0', dep.currentValue === 'main' ? 'edge' : 'main']) {
    await verifyPolicy({ ...dep, currentValue: tag }, 'custom.regex', wolfFile, 'digest', false);
  }
}
await verifyPolicy({ datasource: 'docker', depName: 'ghcr.io/games-on-whales/unknown', currentValue: 'edge' },
  'custom.regex', wolfFile, 'digest', false);

// Boundary fixtures cover categories without a current update and future edits
// that might otherwise enlarge one of the narrowly scoped admitted groups.
for (const [dep, manager, file] of [
  [{ depName: 'python', currentValue: '3.14', depType: 'uses-with', datasource: 'github-tags' }, 'github-actions', workflowFile],
  [{ depName: 'actions/checkout', currentValue: 'main', depType: 'action', datasource: 'github-digest' }, 'github-actions', workflowFile],
  [{ depName: 'node', currentValue: '24.21.0' }, 'nvm', '.nvmrc'],
  [{ depName: 'node', currentValue: '^24.0.0', depType: 'engines', datasource: 'npm' }, 'npm', 'package.json'],
  [{ depName: 'community.docker', currentValue: '5.3.0' }, 'ansible-galaxy', 'ansible/collections/requirements.yml'],
  [{ depName: 'hashicorp/aws', currentValue: '6.68.0', datasource: 'terraform-provider' }, 'terraform', 'infrastructure/tofu/aws-foundation/versions.tf'],
  [{ depName: 'restic/restic', currentValue: 'v0.18.0', datasource: 'github-tags' }, 'custom.regex', workflowFile],
  [{ depName: 'rclone/rclone', currentValue: 'v1.70.0', datasource: 'github-tags' }, 'custom.regex', workflowFile],
  [{ depName: 'requests', currentValue: '2.34.2', datasource: 'pypi' }, 'pip_requirements', 'other/requirements.txt'],
  [{ depName: 'new-validator', currentValue: '1.0.0', datasource: 'pypi' }, 'pip_requirements', 'controller/requirements-ci.txt'],
  [{ depName: 'js-yaml', currentValue: '^5.0.0', depType: 'dependencies', datasource: 'npm' }, 'npm', 'package.json'],
]) {
  for (const type of ['minor', 'patch', 'digest', 'major']) await verifyPolicy(dep, manager, file, type, false);
}

for (const type of ['minor', 'patch', 'digest']) {
  const flare = await dependency('ghcr.io/flaresolverr/flaresolverr', 'v3.5.2');
  const update = await rules.applyPackageRules({ ...flare, updateType: type });
  assert.equal(update.automerge, true);
  assert.equal(update.groupName, 'routine Compose images');
  assert.equal(update.minimumReleaseAge, '3 days');
  verifyLabels(update, 'compose-routine');
}
const wolfServer = await dependency('ghcr.io/games-on-whales/wolf', 'stable', { packageFile: 'services/gaming.yml' });
const wolfDigest = await rules.applyPackageRules({ ...wolfServer, updateType: 'digest' });
assert.equal(wolfDigest.automerge, true);
assert.equal(wolfDigest.groupName, 'routine Compose images');
verifyLabels(wolfDigest, 'compose-routine');
for (const [name, value, attributes, type] of [
  ['radrootllc/karaoke-eternal', 'latest', {}, 'digest'],
  ['ghcr.io/linuxserver/sonarr', '5.0.0-rc.1', {}, 'digest'],
  ['ghcr.io/linuxserver/sonarr', '4.0.20', {}, 'pinDigest'],
  ['ghcr.io/games-on-whales/wolf', 'stable', {}, 'digest'],
  ['ghcr.io/games-on-whales/wolf', 'stable', { packageFile: 'services/gaming.yml' }, 'major'],
]) {
  const dep = await dependency(name, value, attributes);
  const update = await rules.applyPackageRules({ ...dep, updateType: type });
  assert.equal(update.automerge, false);
  assert.equal(update.groupName, null);
  verifyLabels(update, 'compose-manual');
}

console.log('Native Renovate policy: platform automerge, single-category labels, Compose/tooling admission, manual boundaries and tag filtering passed');
