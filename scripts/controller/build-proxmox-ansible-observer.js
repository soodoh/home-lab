#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const {
  canonicalJson,
  observationSpecification,
  projectProxmoxPolicy,
  validateProjection,
} = require("./proxmox-host-projection");

const root = path.resolve(__dirname, "../..");
const contractPath = path.join(root, "infrastructure/contract/home-lab.yml");
const projectionSchemaPath = path.join(root, "infrastructure/host-lifecycle/proxmox/projection.schema.json");
const observerTemplatePath = path.join(root, "infrastructure/host-lifecycle/proxmox/observer-template.py");
const compatibilityTemplatePath = path.join(root, "nix/proxmox/observer-template.py");
const observationSchemaPath = path.join(root, "infrastructure/host-lifecycle/proxmox/observation.schema.json");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function regularFile(file) {
  const metadata = fs.lstatSync(file);
  if (!metadata.isFile() || metadata.nlink !== 1) throw new Error(`source is not a single-link regular file: ${file}`);
  return fs.readFileSync(file);
}

function writeExclusive(file, content, mode) {
  const descriptor = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode);
  try {
    fs.writeFileSync(descriptor, content);
    fs.fsyncSync(descriptor);
    fs.fchmodSync(descriptor, mode);
  } finally {
    fs.closeSync(descriptor);
  }
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function build(outputDirectory, privatePreparerSha256) {
  if (!path.isAbsolute(outputDirectory)) throw new Error("output directory must be absolute");
  if (!/^[0-9a-f]{64}$/.test(privatePreparerSha256)) throw new Error("private preparer SHA-256 is malformed");
  if (fs.existsSync(outputDirectory)) throw new Error("output directory already exists");

  const contractRaw = regularFile(contractPath);
  const contract = load(contractRaw.toString("utf8"));
  const packageManifestPath = path.join(root, contract.proxmox.packages.manifest.path);
  const packageManifestRaw = regularFile(packageManifestPath);
  const packageManifest = JSON.parse(packageManifestRaw.toString("utf8"));
  const projectionSchemaRaw = regularFile(projectionSchemaPath);
  const projection = projectProxmoxPolicy(contract, packageManifest);
  validateProjection(projection, JSON.parse(projectionSchemaRaw.toString("utf8")));

  const template = regularFile(observerTemplatePath);
  const compatibilityTemplate = regularFile(compatibilityTemplatePath);
  if (!template.equals(compatibilityTemplate)) {
    throw new Error("neutral observer template differs from the transitional Nix compatibility mirror");
  }
  const marker = "'@OBSERVATION_SPEC@'";
  const templateText = template.toString("utf8");
  if (templateText.split(marker).length !== 2) throw new Error("observer template marker cardinality differs");
  const specification = observationSpecification(projection, privatePreparerSha256);
  const specificationRaw = Buffer.from(canonicalJson(specification));
  const observer = Buffer.from(templateText.replace(marker, JSON.stringify(specificationRaw.toString("utf8").trim())));
  const observationSchemaRaw = regularFile(observationSchemaPath);
  const projectionRaw = Buffer.from(canonicalJson(projection));
  const manifest = {
    format: "home-lab-proxmox-ansible-observer-artifact-v1",
    version: 1,
    contract_sha256: sha256(contractRaw),
    observation_schema_sha256: sha256(observationSchemaRaw),
    observer_sha256: sha256(observer),
    observer_template_sha256: sha256(template),
    package_manifest_sha256: sha256(packageManifestRaw),
    private_preparer_sha256: privatePreparerSha256,
    projection_schema_sha256: sha256(projectionSchemaRaw),
    projection_sha256: sha256(projectionRaw),
    specification_sha256: sha256(specificationRaw),
  };

  const parent = path.dirname(outputDirectory);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const temporary = `${outputDirectory}.tmp-${process.pid}`;
  if (fs.existsSync(temporary)) throw new Error("temporary output directory already exists");
  fs.mkdirSync(temporary, { mode: 0o700 });
  try {
    writeExclusive(path.join(temporary, "proxmox-observer"), observer, 0o755);
    writeExclusive(path.join(temporary, "observation-spec.json"), specificationRaw, 0o644);
    writeExclusive(path.join(temporary, "manifest.json"), Buffer.from(canonicalJson(manifest)), 0o644);
    fsyncDirectory(temporary);
    fs.renameSync(temporary, outputDirectory);
    fsyncDirectory(parent);
  } catch (error) {
    fs.rmSync(temporary, { recursive: true, force: true });
    throw error;
  }
  process.stdout.write(`proxmox_ansible_observer_artifact=${outputDirectory} sha256=${manifest.observer_sha256}\n`);
}

function main() {
  const argumentsList = process.argv.slice(2);
  let outputDirectory;
  let privatePreparerSha256;
  for (let index = 0; index < argumentsList.length; index += 1) {
    if (argumentsList[index] === "--output-dir" && argumentsList[index + 1]) outputDirectory = path.resolve(argumentsList[++index]);
    else if (argumentsList[index] === "--private-preparer-sha256" && argumentsList[index + 1]) privatePreparerSha256 = argumentsList[++index];
    else throw new Error("usage: build-proxmox-ansible-observer.js --output-dir ABSOLUTE_PATH --private-preparer-sha256 SHA256");
  }
  if (!outputDirectory || !privatePreparerSha256) {
    throw new Error("usage: build-proxmox-ansible-observer.js --output-dir ABSOLUTE_PATH --private-preparer-sha256 SHA256");
  }
  build(outputDirectory, privatePreparerSha256);
}

if (require.main === module) main();
module.exports = { build, sha256 };
