#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { load, loadAll } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");
const {
  manifestFromObservedTransition,
  manifestSha256,
  normalizeManifest,
  parseDpkgStatusTsv,
  renderManifest,
  versionPattern,
} = require("./proxmox-package-manifest");
const {
  validateProxmoxPackageArtifactBinding,
  validateProxmoxPackagePolicy,
} = require("./validate-proxmox-package-policy");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const manifestPath = path.join(root, contract.proxmox.packages.manifest.path);
const manifestRaw = fs.readFileSync(manifestPath, "utf8");
const manifest = JSON.parse(manifestRaw);
const schema = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/contract/proxmox-package-manifest.schema.json"), "utf8"));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

function expectFailure(contractValue, manifestValue, expected, label) {
  const failures = validateProxmoxPackagePolicy(contractValue, manifestValue);
  if (!failures.some((failure) => failure.includes(expected))) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(failures)}`);
  }
}

function expectThrow(operation, expected, label) {
  try {
    operation();
  } catch (error) {
    if (error.message.includes(expected)) return;
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(error.message)}`);
  }
  throw new Error(`${label}: unexpectedly passed`);
}

if (!validate(manifest)) throw new Error(`package manifest schema failed: ${JSON.stringify(validate.errors)}`);
if (manifestRaw !== renderManifest(manifest)) throw new Error("tracked package manifest is not canonically rendered");
if (manifestSha256(manifestRaw) !== contract.proxmox.packages.manifest.sha256) throw new Error("tracked package manifest hash differs from contract");
const installedDelta = manifest.provenance.solverResult.changes.reduce(
  (count, change) => count + (change.action === "install" ? 1 : change.action === "remove" ? -1 : 0),
  manifest.provenance.installedInventory.installedRecords,
);
if (manifest.packages.length !== installedDelta) throw new Error("manifest count does not match its observed and simulated provenance");
if (manifest.packages.some((entry) => entry.name === "snapd" || entry.name.startsWith("snapd:"))) {
  throw new Error("non-installed snapd leaked into the expected manifest");
}
if (validateProxmoxPackagePolicy(contract, manifest).length) {
  throw new Error(`current package policy failed: ${JSON.stringify(validateProxmoxPackagePolicy(contract, manifest))}`);
}
const bindingFailures = validateProxmoxPackageArtifactBinding(
  contract,
  manifest,
  manifestRaw,
  path.relative(root, manifestPath),
);
if (bindingFailures.length) throw new Error(`current package artifact binding failed: ${JSON.stringify(bindingFailures)}`);
for (const [mutation, expected] of [
  [(value) => { value.proxmox.packages.manifest.sha256 = "0".repeat(64); }, "SHA-256 differs"],
  [(value) => { value.proxmox.packages.manifest.path = "infrastructure/contract/other.json"; }, "path differs"],
]) {
  const changed = structuredClone(contract);
  mutation(changed);
  const failures = validateProxmoxPackageArtifactBinding(changed, manifest, manifestRaw, path.relative(root, manifestPath));
  if (!failures.some((failure) => failure.includes(expected))) throw new Error(`package artifact binding did not reject ${expected}`);
}

const inventoryFixture = "hi \tzfsutils-linux\t2.4.3-pve1\nri \tbash\t5.2-1\nrc \tsnapd\t2.0-1\nii \tgit\t1:2:3-1\nii \tlibcurl4t64:amd64\t8.0-1\n";
const simulationFixture = [
  "Inst git [1:2:3-1] (1:2:3-2 Debian:13/stable [all])",
  "Inst libcurl4t64 [8.0-1] (8.0-2 Debian:13/stable [amd64])",
  "Conf git (1:2:3-2 Debian:13/stable [amd64])",
  "",
].join("\n");
const parsedInventory = parseDpkgStatusTsv(inventoryFixture);
if (parsedInventory.installedRecords !== 4 || parsedInventory.totalRecords !== 5
    || !parsedInventory.packages.some((entry) => entry.name === "zfsutils-linux")
    || !parsedInventory.packages.some((entry) => entry.name === "bash")
    || parsedInventory.packages.some((entry) => entry.name === "snapd")) {
  throw new Error("dpkg status ingestion did not use the installed status character");
}
const fixtureManifest = manifestFromObservedTransition(inventoryFixture, simulationFixture, "amd64");
if (fixtureManifest.packages.map((entry) => `${entry.name}=${entry.version}`).join(",")
    !== "bash=5.2-1,git=1:2:3-2,libcurl4t64:amd64=8.0-2,zfsutils-linux=2.4.3-pve1") {
  throw new Error("observed transaction rendering produced an unexpected final map");
}
if (renderManifest(fixtureManifest) !== renderManifest(manifestFromObservedTransition(inventoryFixture, simulationFixture, "amd64"))) {
  throw new Error("observed transaction rendering is not deterministic");
}
const removalManifest = manifestFromObservedTransition(inventoryFixture, "Remv bash [5.2-1] []\n", "amd64");
if (removalManifest.packages.some((entry) => entry.name === "bash")) {
  throw new Error("valid APT removal transition was not applied");
}
for (const invalid of ["latest", "unstable1", "latest!", "1.0-"]) {
  if (versionPattern.test(invalid)) throw new Error(`invalid Debian version passed normalization: ${invalid}`);
}
for (const valid of ["1:2:3-1", "1:2.47.3-0+deb13u1", "2025.1", "7.5-pve2"]) {
  if (!versionPattern.test(valid)) throw new Error(`valid Debian version failed normalization: ${valid}`);
}
for (const [operation, expected, label] of [
  [() => normalizeManifest({ ...structuredClone(manifest), architecture: 42 }), "architecture", "non-string architecture"],
  [() => normalizeManifest({ ...structuredClone(manifest), packages: [{ name: 42, version: "1.0" }] }), "binary package name", "non-string name"],
  [() => normalizeManifest({ ...structuredClone(manifest), packages: [{ name: "git", version: 42 }] }), "package version", "non-string version"],
  [() => parseDpkgStatusTsv("git\t1.0\n"), "dpkg status TSV", "missing status"],
  [() => manifestFromObservedTransition(inventoryFixture, "Inst malformed\n", "amd64"), "unrecognized APT transition", "malformed install transition"],
  [() => manifestFromObservedTransition(inventoryFixture, "Remv git trailing-junk\n", "amd64"), "unrecognized APT transition", "malformed remove transition"],
  [() => manifestFromObservedTransition(inventoryFixture, "Inst git [1:2:3-1] (1:2:3-2 Debian [arm64])\n", "amd64"), "foreign architecture", "foreign simulation architecture"],
]) expectThrow(operation, expected, label);

for (const [mutation, expected, label] of [
  [(value) => { value.provenance.solverResult.changes[0].previousVersion = null; }, "upgrade transition fields", "upgrade missing previous"],
  [(value) => { value.provenance.solverResult.changes[0].version = value.provenance.solverResult.changes[0].previousVersion; }, "upgrade transition fields", "upgrade without version change"],
  [(value) => { value.provenance.solverResult.changes[0].action = "install"; }, "install transition fields", "install with previous version"],
  [(value) => { value.provenance.solverResult.changes[0].action = "remove"; }, "remove transition fields", "remove with final version"],
  [(value) => { value.provenance.solverResult.changes.push(structuredClone(value.provenance.solverResult.changes[0])); }, "duplicate solver transition", "duplicate transition name"],
  [(value) => { value.provenance.solverResult.changes[0].version = "999.0"; }, "does not match final manifest", "transition target version mismatch"],
  [(value) => { value.provenance.solverResult.changes[0].action = "remove"; value.provenance.solverResult.changes[0].version = null; }, "removed package remains", "removed package present in final manifest"],
  [(value) => { const change = value.provenance.solverResult.changes[0]; change.action = "install"; change.name = "missing-package"; change.previousVersion = null; }, "does not match final manifest", "install target absent from final manifest"],
]) {
  const changed = structuredClone(manifest);
  mutation(changed);
  expectThrow(() => normalizeManifest(changed), expected, label);
}

const malformedSchemaValues = [
  (() => { const value = structuredClone(manifest); value.packages[0].version = 12; return value; })(),
  (() => { const value = structuredClone(manifest); value.packages[0].version = "latest"; return value; })(),
  (() => { const value = structuredClone(manifest); value.packages[0].version = "1.0-"; return value; })(),
  (() => { const value = structuredClone(manifest); value.packages[0].name = "libc6:arm64"; return value; })(),
  (() => { const value = structuredClone(manifest); value.provenance.solverResult.changes[0].previousVersion = null; return value; })(),
  (() => { const value = structuredClone(manifest); value.provenance.solverResult.changes[0].action = "remove"; return value; })(),
];
for (const value of [...malformedSchemaValues.slice(0, 3), ...malformedSchemaValues.slice(4)]) {
  if (validate(value)) throw new Error("malformed package manifest unexpectedly passed its schema");
}

const duplicateCategory = structuredClone(contract);
duplicateCategory.proxmox.packages.critical.push({
  role: "firewall",
  ...structuredClone(duplicateCategory.proxmox.packages.direct[0]),
});
expectFailure(duplicateCategory, manifest, "appears in both direct and critical", "duplicate package category");

const duplicateCriticalRole = structuredClone(contract);
duplicateCriticalRole.proxmox.packages.critical[0].role = duplicateCriticalRole.proxmox.packages.critical[1].role;
expectFailure(duplicateCriticalRole, manifest, "role proxmox-archive-keyring is duplicated", "duplicate semantic role");

const prohibitedSelected = structuredClone(contract);
prohibitedSelected.proxmox.packages.prohibited.push(prohibitedSelected.proxmox.packages.direct[0].name);
expectFailure(prohibitedSelected, manifest, "is also prohibited", "selected prohibited package");

const prohibitedManifest = structuredClone(manifest);
prohibitedManifest.packages.push({ name: "snapd:amd64", version: "2.0-1" });
expectFailure(contract, prohibitedManifest, "prohibited package snapd:amd64", "architecture-qualified prohibited manifest package");

const foreignArchitecture = structuredClone(manifest);
foreignArchitecture.packages[0].name = `${foreignArchitecture.packages[0].name.split(":")[0]}:arm64`;
expectFailure(contract, foreignArchitecture, "foreign architecture qualifier", "foreign multiarch manifest package");

const missingManifestEntry = structuredClone(manifest);
missingManifestEntry.packages = missingManifestEntry.packages.filter((entry) => entry.name !== contract.proxmox.packages.direct[0].name);
expectFailure(contract, missingManifestEntry, "is missing from the package manifest", "missing selected package");

const mismatchedManifestEntry = structuredClone(manifest);
mismatchedManifestEntry.packages.find((entry) => entry.name === contract.proxmox.packages.direct[0].name).version = "0.0.1";
expectFailure(contract, mismatchedManifestEntry, "version differs", "mismatched selected version");

const wrongArchitecture = structuredClone(manifest);
wrongArchitecture.architecture = "arm64";
expectFailure(contract, wrongArchitecture, "architecture differs", "wrong architecture");

const wrongKernelVersion = structuredClone(contract);
wrongKernelVersion.proxmox.packages.critical.find((entry) => entry.role === "retained-kernel").version = "0.0.1";
expectFailure(wrongKernelVersion, manifest, "version must match kernel release", "wrong kernel package version");

const secretMarkedManifest = structuredClone(manifest);
secretMarkedManifest.packages[0].version = "TOKEN";
expectFailure(contract, secretMarkedManifest, "protected-input marker", "secret-marked manifest");

const hostTasks = loadAll(fs.readFileSync(path.join(root, "ansible/roles/proxmox_host/tasks/main.yml"), "utf8")).flat();
if (hostTasks.some((task) => task.name === "Refresh the live canonical APT cache immediately before package mutation"
    || task.name === "Install exact required and critical host packages without distribution upgrade")) {
  throw new Error("a separate live-cache package mutation path remains");
}
const transactionInclude = hostTasks.find((task) => task.name === "Verify the complete exact package transaction with isolated APT metadata");
if (transactionInclude?.["ansible.builtin.include_tasks"] !== "verify-exact-packages.yml") {
  throw new Error("host package transaction does not use the shared exact manifest task");
}
const verificationTasks = loadAll(fs.readFileSync(
  path.join(root, "ansible/roles/proxmox_host/tasks/verify-exact-packages.yml"), "utf8",
)).flat();
const transactionTask = verificationTasks[0]?.block?.find((task) => task.name === "Run the exact package manifest helper");
const modeArguments = transactionTask?.vars?.proxmox_host_package_helper_mode_arguments;
if (!transactionTask || !modeArguments.includes("--apply")
    || !modeArguments.includes("--allow-existing-extras")
    || !modeArguments.includes("proxmox_cleanup_migration_confirmed")
    || !modeArguments.includes("--verify-installed-only")
    || !transactionTask.changed_when.includes("changed=true")) {
  throw new Error("isolated transaction helper does not own guarded mutation and changed reporting");
}

const cleanupTasks = loadAll(fs.readFileSync(path.join(root, "ansible/roles/proxmox_cleanup/tasks/main.yml"), "utf8")).flat();
for (const [taskName, preflightName] of [
  ["Remove only contract-listed prohibited packages", "Preflight prohibited package removal"],
  ["Remove only kernel packages outside the exact retained owner set", "Preflight removal of kernels outside the exact retained owner set"],
]) {
  const task = cleanupTasks.find((candidate) => candidate.name === taskName);
  const preflight = cleanupTasks.find((candidate) => candidate.name === preflightName);
  if (!task || task["ansible.builtin.apt"].autoremove !== false
      || "fail_on_autoremove" in task["ansible.builtin.apt"]
      || preflight?.["ansible.builtin.include_tasks"] !== "preflight-package-removal.yml") {
    throw new Error(`${taskName} lacks the shared fail-closed solver preflight`);
  }
}
const removalPreflightTasks = loadAll(fs.readFileSync(path.join(root, "ansible/roles/proxmox_cleanup/tasks/preflight-package-removal.yml"), "utf8")).flat();
const removalAssertion = removalPreflightTasks.find((task) => task.name.startsWith("Require removal to remain exact"));
if (!removalAssertion || !removalAssertion["ansible.builtin.assert"].that.some((condition) => condition.includes("proxmox-ve"))
    || !removalAssertion["ansible.builtin.assert"].that.some((condition) => condition.includes("difference"))) {
  throw new Error("removal solver preflight does not constrain every removal and protect proxmox-ve");
}
if (!cleanupTasks.some((task) => task.name === "Verify the Proxmox VE metapackage remains installed after cleanup")) {
  throw new Error("cleanup does not verify the Proxmox VE metapackage");
}

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "proxmox-package-manifest."));
try {
  const inventoryPath = path.join(tempRoot, "inventory.tsv");
  const simulationPath = path.join(tempRoot, "simulation.log");
  const regenerated = path.join(tempRoot, "manifest.json");
  fs.writeFileSync(inventoryPath, inventoryFixture);
  fs.writeFileSync(simulationPath, simulationFixture);
  const result = spawnSync(
    path.join(root, "scripts/render-proxmox-package-manifest"),
    ["--inventory", inventoryPath, "--simulation", simulationPath, "--architecture", "amd64", "--output", regenerated],
    { cwd: root, encoding: "utf8", timeout: 10_000 },
  );
  if (result.status !== 0) throw new Error(`manifest regeneration failed: ${result.stderr}`);
  if (fs.readFileSync(regenerated, "utf8") !== renderManifest(fixtureManifest)) throw new Error("CLI regeneration differs from library rendering");
  const arbitraryManifest = spawnSync(
    path.join(root, "scripts/render-proxmox-package-manifest"),
    ["--manifest", regenerated, "--output", path.join(tempRoot, "arbitrary.json")],
    { cwd: root, encoding: "utf8", timeout: 10_000 },
  );
  if (arbitraryManifest.status === 0) throw new Error("renderer accepted arbitrary manifest input mode");
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

console.log(`proxmox_package_manifest=verified packages=${manifest.packages.length}`);
