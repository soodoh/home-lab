#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");

const root = path.resolve(__dirname, "../..");
const schema = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/vm-100/facts.schema.json"), "utf8"));
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const expectedRootPolicy = new Map([
  ["docker-volumes", ["/var/lib/docker/volumes", "copy"]],
  ["home-assistant", ["/home/docker/hass", "copy"]],
  ["compose-deployment", ["/srv/docker-compose", "regenerate"]],
  ["compose-runtime-inputs", ["/etc/docker-compose", "regenerate"]],
  ["compose-controller-state", ["/var/lib/docker-compose", "regenerate"]],
  ["home-backups", ["/home/docker/backups", "pending"]],
  ["games-backups", ["/mnt/games/backups", "pending"]],
  ["storage-backups", ["/mnt/storage/backups", "pending"]],
  ["media", ["/mnt/storage/media", "reuse"]],
  ["games", ["/mnt/games", "reuse"]],
  ["wolf", ["/mnt/games/wolf", "reuse"]],
]);
const expectedApplications = ["authentik", "prowlarr", "radarr", "radarr-4k", "sonarr"];
const expectedLegacyVolumes = new Set(["happier-data", "nzbget-data", "nzbhydra2-data"]);
const forbiddenKey = /(?:private|plaintext|password|token|apiKey|secretValue|identityContent)/iu;

function declaredVolumes() {
  const volumes = new Set();
  for (const filename of fs.readdirSync(path.join(root, "services")).filter((name) => name.endsWith(".yml")).sort()) {
    const document = load(fs.readFileSync(path.join(root, "services", filename), "utf8"));
    for (const name of Object.keys(document?.volumes ?? {})) volumes.add(name);
  }
  return [...volumes].sort();
}

function rejectForbiddenKeys(value, location = "facts") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectForbiddenKeys(item, `${location}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (forbiddenKey.test(key)) throw new Error(`${location}.${key} is a forbidden sensitive field`);
    rejectForbiddenKeys(nested, `${location}.${key}`);
  }
}

function validateFacts(facts, expectedCommit) {
  if (!validateSchema(facts)) throw new Error(`VM 100 facts failed schema validation: ${JSON.stringify(validateSchema.errors)}`);
  rejectForbiddenKeys(facts);
  if (expectedCommit && facts.controllerCommit !== expectedCommit) throw new Error("VM 100 facts commit binding differs");

  const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
  if (facts.authority.vmid !== contract.vm_100.vmid || facts.authority.hostName !== contract.vm_100.host_name ||
      facts.authority.networkIdentity !== contract.vm_100.network_identity ||
      facts.authority.deploymentAuthority !== contract.vm_100.deployment_authority) {
    throw new Error("VM 100 facts authority differs from the canonical contract");
  }
  if (facts.sops.recipient !== contract.recovery.recovery_age_recipient) {
    throw new Error("VM 100 observed SOPS recipient differs from the canonical public recipient");
  }

  const declared = declaredVolumes();
  if (declared.length !== facts.docker.declaredVolumeCount) throw new Error("declared Compose volume count differs");
  const observed = new Map(facts.docker.volumes.map((volume) => [volume.logicalName, volume]));
  if (observed.size !== facts.docker.volumes.length) throw new Error("duplicate observed Docker volume identity");
  const expectedVolumes = [...new Set([...declared, ...expectedLegacyVolumes])].sort();
  if (JSON.stringify([...observed.keys()].sort()) !== JSON.stringify(expectedVolumes)) {
    throw new Error("observed Docker volume set differs from declared plus protected legacy volumes");
  }
  for (const [name, volume] of observed) {
    const expectedEngineName = `docker-compose_${name}`;
    if (volume.legacy !== expectedLegacyVolumes.has(name)) throw new Error(`legacy classification differs for ${name}`);
    if (volume.engineName !== expectedEngineName || volume.mountpoint !== `/var/lib/docker/volumes/${expectedEngineName}/_data`) {
      throw new Error(`Docker volume engine identity or mountpoint differs for ${name}`);
    }
  }

  const roots = new Map(facts.mutableRoots.map((entry) => [entry.class, entry]));
  if (roots.size !== facts.mutableRoots.length || roots.size !== expectedRootPolicy.size) throw new Error("mutable-root class set is incomplete or duplicated");
  for (const [classification, [expectedPath, expectedDisposition]] of expectedRootPolicy) {
    const entry = roots.get(classification);
    if (!entry || entry.path !== expectedPath || entry.disposition !== expectedDisposition) {
      throw new Error(`mutable-root policy differs for ${classification}`);
    }
    if (entry.bytesAvailable > entry.bytesTotal || (entry.sizeBytes !== null && entry.sizeBytes > entry.bytesTotal)) {
      throw new Error(`mutable-root capacity is invalid for ${classification}`);
    }
    const requiresSize = ["docker-volumes", "home-assistant", "home-backups", "games-backups", "storage-backups", "wolf"].includes(classification);
    if ((entry.sizeBytes !== null) !== requiresSize) throw new Error(`mutable-root size policy differs for ${classification}`);
    if (entry.filesystem === "ext4" && entry.filesystemFeatures.length === 0) throw new Error(`ext4 features are unavailable for ${classification}`);
    if (entry.filesystem !== "ext4" && entry.filesystemFeatures.length !== 0) throw new Error(`non-ext4 feature list is nonempty for ${classification}`);
  }
  if (roots.get("media").filesystem !== "nfs4" || roots.get("storage-backups").filesystem !== "nfs4") {
    throw new Error("NFS mutable roots do not report nfs4");
  }
  if (roots.get("games").filesystem !== "ext4" || roots.get("wolf").filesystem !== "ext4") {
    throw new Error("games mutable roots do not report ext4");
  }
  for (const group of [["games", "games-backups", "wolf"], ["media", "storage-backups"]]) {
    const [first, ...rest] = group.map((classification) => roots.get(classification));
    if (rest.some((entry) => entry.mountId !== first.mountId || entry.source !== first.source || entry.filesystem !== first.filesystem)) {
      throw new Error(`related mutable roots do not share mount identity, source, and filesystem: ${group.join(",")}`);
    }
  }
  for (const classification of ["docker-volumes", "home-assistant"]) {
    if (roots.get(classification).multiplyLinkedFileCount !== 0) {
      throw new Error(`copied mutable root contains multiply-linked files: ${classification}`);
    }
  }

  const applications = facts.applications.map((application) => application.name).sort();
  if (JSON.stringify(applications) !== JSON.stringify(expectedApplications)) throw new Error("application inventory scope differs");
  const expectedFindings = new Map([
    ["application-import-identifiers-pending", "blocker"],
    ["independent-recovery-recipient-pending", "blocker"],
    ["nixos-recipient-pending", "blocker"],
  ]);
  if (facts.findings.length !== expectedFindings.size) throw new Error("VM 100 fact blocker set is incomplete");
  for (const finding of facts.findings) {
    if (expectedFindings.get(finding.code) !== finding.severity) throw new Error(`unexpected VM 100 fact finding: ${finding.code}`);
  }
  return facts;
}

function main() {
  const args = process.argv.slice(2);
  let expectedCommit;
  let input;
  while (args.length) {
    const argument = args.shift();
    if (argument === "--commit" && args.length) expectedCommit = args.shift();
    else if (!input) input = argument;
    else throw new Error("usage: validate-vm-100-facts.js [--commit SHA] FACTS.json");
  }
  if (!input) throw new Error("usage: validate-vm-100-facts.js [--commit SHA] FACTS.json");
  validateFacts(JSON.parse(fs.readFileSync(input, "utf8")), expectedCommit);
  console.log("vm_100_facts=verified");
}

if (require.main === module) main();
module.exports = { declaredVolumes, validateFacts };
