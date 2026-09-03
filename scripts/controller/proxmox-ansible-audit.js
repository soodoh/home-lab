#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Ajv2020 = require("ajv/dist/2020");
const { load } = require("js-yaml");
const {
  canonicalJson,
  observationSpecification,
  projectProxmoxPolicy,
  validateProjection,
} = require("./proxmox-host-projection");

const root = path.resolve(__dirname, "../..");
const maxObservationBytes = 1024 * 1024;
const domainNames = [
  "accounts", "auditAbsence", "health", "managedArtifacts", "managedFiles", "managedFragments", "packages",
  "protectedAccess", "protectedHardware", "pveAccess", "pveFirewall", "pveStorage", "services", "storage",
  "tailscale", "timezone", "vm",
];
const summaryNames = ["health", "protectedAccess", "protectedHardware", "pveAccess", "pveFirewall", "pveStorage", "storage", "tailscale", "vm"];
const protectedValue = /(?:\/etc\/pve(?:\/|$)|authorized_keys|ssh_host_|\/dev\/(?:disk|serial)|\/root\/\.config\/home-lab|\b[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\b|\b[0-9a-f]{4}:[0-9a-f]{4}\b|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b)/i;
const secretReference = /(?:HOMELAB_[A-Z0-9_]*|PROXMOX_[A-Z0-9_]*_SSH_PUBLIC_KEYS|TAILSCALE_AUTH_KEY)/i;
const uuid = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i;
const hex64 = /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/i;
const forbiddenKeys = new Set(["argv", "command", "executable", "payload", "script"]);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readRegular(file, limit = maxObservationBytes) {
  const metadata = fs.lstatSync(file);
  if (!metadata.isFile() || metadata.nlink !== 1) throw new Error(`input is not a single-link regular file: ${file}`);
  if (metadata.size > limit) throw new Error(`input exceeds fixed size limit: ${file}`);
  return fs.readFileSync(file);
}

function parseCanonicalRaw(raw, label, limit) {
  if (raw.length > limit) throw new Error(`input exceeds fixed size limit: ${label}`);
  const value = JSON.parse(raw.toString("utf8"));
  if (!raw.equals(Buffer.from(canonicalJson(value)))) throw new Error(`JSON input is not canonical: ${label}`);
  return { raw, value };
}

function parseCanonical(file, limit) {
  return parseCanonicalRaw(readRegular(file, limit), file, limit);
}

function readStdinBounded(limit) {
  const chunks = [];
  let total = 0;
  while (true) {
    const chunk = Buffer.alloc(65536);
    const count = fs.readSync(0, chunk, 0, chunk.length, null);
    if (count === 0) break;
    total += count;
    if (total > limit) throw new Error("standard input exceeds fixed size limit");
    chunks.push(chunk.subarray(0, count));
  }
  return Buffer.concat(chunks, total);
}

function validateNoSensitiveLiterals(value, key = "") {
  if (Array.isArray(value)) {
    for (const child of value) validateNoSensitiveLiterals(child, key);
    return;
  }
  if (value && typeof value === "object") {
    for (const [childKey, child] of Object.entries(value)) {
      if (forbiddenKeys.has(childKey.toLowerCase())) throw new Error(`forbidden observation field: ${childKey}`);
      validateNoSensitiveLiterals(child, childKey);
    }
    return;
  }
  if (typeof value === "string" && (protectedValue.test(value) || secretReference.test(value) || uuid.test(value) ||
      (key !== "observerSha256" && hex64.test(value)))) {
    throw new Error(`observation contains a forbidden sensitive literal in ${key || "value"}`);
  }
}

function mapBy(records, key) {
  const result = new Map();
  for (const record of records) {
    if (result.has(record[key])) throw new Error(`duplicate observation identity: ${record[key]}`);
    result.set(record[key], record);
  }
  return result;
}

function requireRecordDomain(domain, expectedCount) {
  assert.equal(domain.status, "complete");
  assert.equal(domain.unexpectedCount, 0);
  assert.equal(domain.records.length, expectedCount);
}

function audit(artifactDirectory, observationPath) {
  const manifestPath = path.join(artifactDirectory, "manifest.json");
  const specificationPath = path.join(artifactDirectory, "observation-spec.json");
  const observerPath = path.join(artifactDirectory, "proxmox-observer");
  const packageObserverPath = path.join(artifactDirectory, "proxmox-package-candidate-observer");
  const { raw: manifestRaw, value: manifest } = parseCanonical(manifestPath, 64 * 1024);
  const { raw: specificationRaw, value: specification } = parseCanonical(specificationPath, 1024 * 1024);
  const observerRaw = readRegular(observerPath, 1024 * 1024);
  const packageObserverRaw = readRegular(packageObserverPath, 1024 * 1024);
  const { raw: observationRaw, value: observation } = observationPath === "-" ?
    parseCanonicalRaw(readStdinBounded(maxObservationBytes), "standard input", maxObservationBytes) :
    parseCanonical(observationPath, maxObservationBytes);

  const manifestSchema = JSON.parse(readRegular(path.join(root, "infrastructure/host-lifecycle/proxmox/observer-artifact.schema.json"), 64 * 1024));
  const observationSchemaRaw = readRegular(path.join(root, "infrastructure/host-lifecycle/proxmox/observation.schema.json"), 1024 * 1024);
  const projectionSchemaRaw = readRegular(path.join(root, "infrastructure/host-lifecycle/proxmox/projection.schema.json"), 1024 * 1024);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validateManifest = ajv.compile(manifestSchema);
  if (!validateManifest(manifest)) throw new Error(`artifact manifest validation failed: ${JSON.stringify(validateManifest.errors)}`);
  const validateObservation = ajv.compile(JSON.parse(observationSchemaRaw));
  if (!validateObservation(observation)) throw new Error(`observation schema validation failed: ${JSON.stringify(validateObservation.errors)}`);

  assert.equal(manifest.observer_sha256, sha256(observerRaw));
  assert.equal(manifest.package_observer_sha256, sha256(packageObserverRaw));
  assert.equal(manifest.package_observer_template_sha256, sha256(readRegular(path.join(root, "infrastructure/maintenance/host/package-candidate-observer"), 1024 * 1024)));
  assert.equal(manifest.specification_sha256, sha256(specificationRaw));
  assert.equal(manifest.observation_schema_sha256, sha256(observationSchemaRaw));
  assert.equal(manifest.projection_schema_sha256, sha256(projectionSchemaRaw));

  const contractRaw = readRegular(path.join(root, "infrastructure/contract/home-lab.yml"), 1024 * 1024);
  const contract = load(contractRaw.toString("utf8"));
  const packageManifestRaw = readRegular(path.join(root, contract.proxmox.packages.manifest.path), 16 * 1024 * 1024);
  const packageManifest = JSON.parse(packageManifestRaw.toString("utf8"));
  const projection = projectProxmoxPolicy(contract, packageManifest);
  validateProjection(projection, JSON.parse(projectionSchemaRaw));
  assert.equal(manifest.contract_sha256, sha256(contractRaw));
  assert.equal(manifest.package_manifest_sha256, sha256(packageManifestRaw));
  assert.equal(manifest.projection_sha256, sha256(Buffer.from(canonicalJson(projection))));
  assert.equal(canonicalJson(specification), canonicalJson(observationSpecification(projection, manifest.private_preparer_sha256)));

  validateNoSensitiveLiterals(observation);
  assert.equal(observation.format, "home-lab-proxmox-observation-v1");
  assert.equal(observation.protocol, 4);
  assert.equal(observation.observerSha256, manifest.observer_sha256);
  assert.deepEqual(Object.keys(observation.domains).sort(), [...domainNames].sort());
  assert.deepEqual(observation.host, {
    architecture: specification.expectedIdentity.architecture,
    hostname: specification.expectedIdentity.hostname,
    kernel: projection.kernelPolicy.current,
    os: specification.expectedIdentity.os,
    pveVersion: specification.expectedIdentity.pveVersion,
  });

  const domains = observation.domains;
  const expectedFiles = mapBy(projection.managedFiles, "path");
  requireRecordDomain(domains.managedFiles, expectedFiles.size);
  for (const record of domains.managedFiles.records) {
    const expected = expectedFiles.get(record.target);
    assert(expected, `unexpected managed file: ${record.target}`);
    assert.deepEqual(record, { contentMatches: true, groupMatches: true, mode: expected.mode, ownerMatches: true, target: expected.path, type: "file" });
  }

  const expectedFragments = mapBy(projection.managedFileFragments, "path");
  requireRecordDomain(domains.managedFragments, expectedFragments.size);
  for (const record of domains.managedFragments.records) {
    const expected = expectedFragments.get(record.target);
    assert(expected, `unexpected managed fragment: ${record.target}`);
    assert.deepEqual(record, { groupMatches: true, matchCount: 1, mode: expected.mode, ownerMatches: true, target: expected.path, type: "file" });
  }

  const expectedArtifacts = mapBy(projection.managedArtifacts, "path");
  requireRecordDomain(domains.managedArtifacts, expectedArtifacts.size);
  for (const record of domains.managedArtifacts.records) {
    const expected = expectedArtifacts.get(record.target);
    assert(expected, `unexpected managed artifact: ${record.target}`);
    assert.deepEqual(record, { contentMatches: true, groupMatches: true, mode: expected.mode, ownerMatches: true,
      symlinkTargetMatches: true, target: expected.path, type: expected.symlinkTarget ? "symlink" : "file" });
  }

  const expectedAbsence = mapBy(projection.auditAbsence, "path");
  requireRecordDomain(domains.auditAbsence, expectedAbsence.size);
  for (const record of domains.auditAbsence.records) {
    const expected = expectedAbsence.get(record.target);
    assert(expected, `unexpected absence target: ${record.target}`);
    assert.deepEqual(record, { count: 0, target: expected.path, type: expected.absence });
  }

  const expectedPackages = packageManifest.packages.map((item) => ({ name: item.name, version: item.version }))
    .sort((left, right) => left.name.localeCompare(right.name));
  requireRecordDomain(domains.packages, expectedPackages.length);
  assert.deepEqual(domains.packages.records, expectedPackages);

  const expectedAccounts = mapBy(specification.accounts, "name");
  requireRecordDomain(domains.accounts, expectedAccounts.size);
  for (const record of domains.accounts.records) {
    const expected = expectedAccounts.get(record.name);
    assert(expected, `unexpected account: ${record.name}`);
    assert.deepEqual(record, { commentMatches: true, exists: true, expectedGroupsMatch: true, home: expected.home,
      name: expected.name, passwordLocked: true, primaryGroupMatches: true, shell: expected.shell });
  }

  const expectedServices = mapBy(projection.nativeServices, "name");
  requireRecordDomain(domains.services, expectedServices.size);
  for (const record of domains.services.records) {
    const expected = expectedServices.get(record.name);
    assert(expected, `unexpected service: ${record.name}`);
    assert.deepEqual(record, { active: expected.state === "started", enabled: expected.enabled, name: expected.name });
  }

  requireRecordDomain(domains.timezone, 1);
  assert.deepEqual(domains.timezone.records, [{ name: "system", timezone: specification.timezone }]);

  for (const name of summaryNames) {
    const summary = domains[name];
    assert.equal(summary.status, "complete", `${name} observation unavailable`);
    assert.equal(summary.matches, true, `${name} parity failed`);
    assert.equal(summary.observedCount, summary.expectedCount, `${name} observed count differs`);
    assert(Number.isInteger(summary.expectedCount) && summary.expectedCount > 0, `${name} expected count is invalid`);
  }
  assert.equal(domains.protectedAccess.expectedCount, specification.protectedAccessExpectedCount);
  assert.equal(domains.protectedHardware.expectedCount, specification.protectedExpectedCount);

  const result = {
    format: "home-lab-proxmox-ansible-audit-v1",
    version: 1,
    artifact_manifest_sha256: sha256(manifestRaw),
    domain_count: domainNames.length,
    host: observation.host.hostname,
    observation_sha256: sha256(observationRaw),
    observer_sha256: manifest.observer_sha256,
    parity: true,
    protected_summary_dependency: {
      private_preparer_sha256: manifest.private_preparer_sha256,
      status: "transitional-exact-helper",
    },
  };
  process.stdout.write(canonicalJson(result));
}

function main() {
  const argumentsList = process.argv.slice(2);
  let artifactDirectory;
  let observationPath;
  for (let index = 0; index < argumentsList.length; index += 1) {
    if (argumentsList[index] === "--artifact-dir" && argumentsList[index + 1]) artifactDirectory = path.resolve(argumentsList[++index]);
    else if (argumentsList[index] === "--observation" && argumentsList[index + 1]) {
      const supplied = argumentsList[++index];
      observationPath = supplied === "-" ? "-" : path.resolve(supplied);
    } else throw new Error("usage: proxmox-ansible-audit.js --artifact-dir ABSOLUTE_PATH --observation FILE_OR_DASH");
  }
  if (!artifactDirectory || !observationPath) throw new Error("usage: proxmox-ansible-audit.js --artifact-dir ABSOLUTE_PATH --observation FILE_OR_DASH");
  audit(artifactDirectory, observationPath);
}

if (require.main === module) main();
module.exports = { audit, validateNoSensitiveLiterals };
