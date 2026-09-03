#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const Ajv2020 = require("ajv/dist/2020");
const { load } = require("js-yaml");
const { build, sha256 } = require("./build-proxmox-ansible-observer");
const {
  canonicalJson,
  observationSpecification,
  projectProxmoxPolicy,
  validateProjection,
} = require("./proxmox-host-projection");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative));
const contract = load(read("infrastructure/contract/home-lab.yml").toString("utf8"));
const packageManifest = JSON.parse(read(contract.proxmox.packages.manifest.path));
const projectionSchema = JSON.parse(read("infrastructure/host-lifecycle/proxmox/projection.schema.json"));
const projection = projectProxmoxPolicy(contract, packageManifest);
validateProjection(projection, projectionSchema);

const neutralTemplate = read("infrastructure/host-lifecycle/proxmox/observer-template.py");
const compatibilityTemplate = read("nix/proxmox/observer-template.py");
assert(neutralTemplate.equals(compatibilityTemplate), "transitional Nix observer mirror differs from neutral source");
assert(read("infrastructure/host-lifecycle/proxmox/observation.schema.json")
  .equals(read("nix/proxmox/observation.schema.json")), "transitional observation schema mirror differs from neutral source");
assert(read("infrastructure/host-lifecycle/proxmox/projection.schema.json")
  .equals(read("nix/proxmox/projection.schema.json")), "transitional projection schema mirror differs from neutral source");

const privatePreparerSha256 = "a".repeat(64);
const specification = observationSpecification(projection, privatePreparerSha256);
assert.deepEqual(Object.keys(specification).sort(), [
  "accounts", "aptSourceNames", "auditAbsence", "conventionalKeysAbsent", "expectedIdentity", "health",
  "legacyTofuAccessRequired", "managedArtifacts", "managedFiles", "managedFragments", "networkSnippetNames",
  "privatePreparerSha256", "protectedAccessExpectedCount", "protectedExpectedCount", "pveAccessRoles",
  "pveFirewall", "pveStorage", "services", "storage", "tailscale", "timezone",
].sort());

const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "proxmox-ansible-observer-test-"));
try {
  const projectionPath = path.join(temporaryRoot, "projection.json");
  fs.writeFileSync(projectionPath, canonicalJson(projection));
  const python = spawnSync("python3", ["-c", [
    "import importlib.util,json,pathlib,sys",
    `source=pathlib.Path(${JSON.stringify(path.join(root, "nix/proxmox/bundle.py"))})`,
    "spec=importlib.util.spec_from_file_location('bundle',source)",
    "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)",
    "value=module.observation_specification(json.loads(pathlib.Path(sys.argv[1]).read_bytes()))",
    "value['privatePreparerSha256']=sys.argv[2]",
    "sys.stdout.buffer.write(module.canonical_json(value))",
  ].join(";"), projectionPath, privatePreparerSha256], { encoding: "utf8" });
  assert.equal(python.status, 0, python.stderr);
  assert.equal(canonicalJson(specification), python.stdout, "neutral observation specification differs from transitional renderer");

  const outputDirectory = path.join(temporaryRoot, "artifact");
  build(outputDirectory, privatePreparerSha256);
  const observer = fs.readFileSync(path.join(outputDirectory, "proxmox-observer"));
  const specificationRaw = fs.readFileSync(path.join(outputDirectory, "observation-spec.json"));
  const manifestRaw = fs.readFileSync(path.join(outputDirectory, "manifest.json"));
  const manifest = JSON.parse(manifestRaw);
  const manifestSchema = JSON.parse(read("infrastructure/host-lifecycle/proxmox/observer-artifact.schema.json"));
  const validateManifest = new Ajv2020({ allErrors: true, strict: true }).compile(manifestSchema);
  assert(validateManifest(manifest), JSON.stringify(validateManifest.errors));
  assert.equal(manifest.observer_sha256, sha256(observer));
  assert.equal(manifest.specification_sha256, sha256(specificationRaw));
  assert.equal(manifest.private_preparer_sha256, privatePreparerSha256);
  assert.equal(manifestRaw.toString("utf8"), canonicalJson(manifest));
  assert.equal(specificationRaw.toString("utf8"), canonicalJson(specification));
  assert(!observer.includes("@OBSERVATION_SPEC@"));
  for (const [name, mode] of [["proxmox-observer", 0o755], ["observation-spec.json", 0o644], ["manifest.json", 0o644]]) {
    const metadata = fs.lstatSync(path.join(outputDirectory, name));
    assert(metadata.isFile() && metadata.nlink === 1, `${name} must be a single-link regular file`);
    assert.equal(metadata.mode & 0o777, mode, `${name} mode differs`);
  }
  const compile = spawnSync("python3", ["-c", "import pathlib,sys;compile(pathlib.Path(sys.argv[1]).read_bytes(),sys.argv[1],'exec')", path.join(outputDirectory, "proxmox-observer")], { encoding: "utf8" });
  assert.equal(compile.status, 0, compile.stderr);
  const version = spawnSync(path.join(outputDirectory, "proxmox-observer"), ["version"], { encoding: "utf8" });
  assert.equal(version.status, 0, version.stderr);
  assert.deepEqual(JSON.parse(version.stdout), { capabilities: ["observe"], helper: "proxmox-observer", protocol: 4, version: 1 });
  assert.throws(() => build(outputDirectory, privatePreparerSha256), /already exists/);
  assert.throws(() => observationSpecification(projection, "bad"), /malformed/);
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}

console.log("proxmox_ansible_observer=verified domains=17");
