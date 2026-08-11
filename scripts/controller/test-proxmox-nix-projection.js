#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");
const {
  canonicalJson,
  projectProxmoxPolicy,
  validateProjection,
} = require("./proxmox-nix-projection");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const schema = JSON.parse(fs.readFileSync(path.join(root, "nix/proxmox/projection.schema.json"), "utf8"));
const projectionPath = path.join(root, "nix/proxmox/projection.json");
const packageManifest = JSON.parse(fs.readFileSync(path.join(root, contract.proxmox.packages.manifest.path), "utf8"));
const tracked = fs.readFileSync(projectionPath, "utf8");
const projected = projectProxmoxPolicy(contract, packageManifest);
const rendered = canonicalJson(projected);

validateProjection(projected, schema);
if (tracked !== rendered) throw new Error("tracked Proxmox Nix projection differs from pure allowlist output");
if (canonicalJson(JSON.parse(tracked)) !== tracked) throw new Error("tracked Proxmox Nix projection is not canonical JSON");
if (canonicalJson(projectProxmoxPolicy(structuredClone(contract), structuredClone(packageManifest))) !== rendered) {
  throw new Error("projection bytes are not stable across equivalent inputs");
}

function valueAt(document, segments) {
  return segments.reduce((value, segment) => value[segment], document);
}
function objectPaths(value, current = [], found = []) {
  if (value && typeof value === "object" && !Array.isArray(value)) found.push(current);
  if (Array.isArray(value)) value.forEach((item, index) => objectPaths(item, [...current, index], found));
  else if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) objectPaths(nested, [...current, key], found);
  }
  return found;
}
const schemaValidate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
for (const segments of objectPaths(projected)) {
  const unknown = structuredClone(projected);
  valueAt(unknown, segments).unexpectedProjectionField = true;
  if (schemaValidate(unknown)) throw new Error(`projection schema is open at ${segments.join(".") || "/"}`);
}

function mutateExcludedInputs(value) {
  value.network.proxmox.mac = "AA:AA:AA:AA:AA:AA";
  value.network.arch.mac = "BB:BB:BB:BB:BB:BB";
  value.proxmox.api_endpoint = "https://protected-controller.invalid/api";
  value.proxmox.vfio.device_ids = ["ffff:ffff"];
  value.proxmox.vfio.modprobe_file.path = "/protected/hardware-bound-vfio.conf";
  value.proxmox.access.sudo_validation.executable = "/protected/controller/validator";
  for (const account of value.proxmox.access.service_accounts) {
    account.ssh_directory.path = `/protected/${account.name}/ssh-directory`;
    account.authorized_keys.file.path = `/protected/${account.name}/authorized-keys`;
    account.authorized_keys.secret_ref = `MUTATED_${account.name.toUpperCase().replace("-", "_")}_KEY_REF`;
  }
  for (const account of value.proxmox.access.human_accounts) {
    account.ssh_directory.path = "/protected/human/ssh-directory";
    account.authorized_keys.files.forEach((file, index) => { file.path = `/protected/human/key-${index}`; });
  }
  value.proxmox.access.pve.accounts.forEach((account, index) => {
    account.token_name = `mutated-token-${index}`;
    account.user = `mutated-${index}@pam`;
    account.token_escrow.directory.path = `/protected/token-${index}`;
    account.token_escrow.file.path = `/protected/token-${index}.env`;
  });
  value.proxmox.ssh.host_key_sentinel.path = "/protected/ssh-host-key";
  value.proxmox.tailscale.auth_key_secret_ref = "MUTATED_TAILSCALE_SECRET_REF";
  value.proxmox.health.local_api_url = "https://protected-endpoint.invalid";
  value.proxmox.firewall.compatibility_config_path = "/etc/pve/protected-compatibility-path";
  value.proxmox.packages.manifest.path = "/protected/controller/package-manifest.json";
  value.proxmox.root_cleanup = { mutated_cleanup_marker: "/protected/cleanup-marker" };
  value.proxmox.vm = { mutated_hardware_identity: "ffff:eeee" };
  value.storage.zfs.pool_guid_secret_ref = "MUTATED_POOL_GUID_REF";
  value.storage.zfs.members = [{ secret_ref: "MUTATED_MEMBER_REF", mirror: 999 }];
  return value;
}
const mutatedRendered = canonicalJson(projectProxmoxPolicy(
  mutateExcludedInputs(structuredClone(contract)), structuredClone(packageManifest),
));
if (mutatedRendered !== rendered) {
  throw new Error("runtime-only secret, hardware, compatibility, cleanup, or controller-location mutation changed projection");
}
const reorderedPveAccounts = structuredClone(contract);
reorderedPveAccounts.proxmox.access.pve.accounts.reverse();
if (canonicalJson(projectProxmoxPolicy(reorderedPveAccounts, structuredClone(packageManifest))) !== rendered) {
  throw new Error("PVE principal bindings depend on account array position");
}
const expectedServicePolicies = {
  "chrony.service": { safetyClass: "guarded", automatic: true, requiresWatchdog: false },
  "nfs-server.service": { safetyClass: "data-critical", automatic: false, requiresWatchdog: false },
  "ssh.service": { safetyClass: "access-critical", automatic: false, requiresWatchdog: true },
  "tailscaled.service": { safetyClass: "access-critical", automatic: false, requiresWatchdog: true },
};
if (projected.planningPolicy.servicePolicies.length !== 4) throw new Error("service policy coverage differs");
for (const policy of projected.planningPolicy.servicePolicies) {
  const expected = expectedServicePolicies[policy.name];
  if (!expected || policy.safetyClass !== expected.safetyClass || policy.automatic !== expected.automatic ||
      policy.requiresWatchdog !== expected.requiresWatchdog) throw new Error(`unsafe projected service policy: ${policy.name}`);
}
for (const mutation of [
  (value) => value.proxmox.planning_policy.service_policies.pop(),
  (value) => { value.proxmox.planning_policy.service_policies[1].name = "chrony.service"; },
  (value) => { value.proxmox.planning_policy.service_policies.find((item) => item.name === "ssh.service").automatic = true; },
]) {
  const invalid = structuredClone(contract); mutation(invalid);
  let rejected = false;
  try { projectProxmoxPolicy(invalid, structuredClone(packageManifest)); } catch { rejected = true; }
  if (!rejected) throw new Error("invalid service policy coverage/classification was accepted");
}

const installedDelta = packageManifest.provenance.solverResult.changes.reduce(
  (count, change) => count + (change.action === "install" ? 1 : change.action === "remove" ? -1 : 0),
  packageManifest.provenance.installedInventory.installedRecords,
);
if (projected.packagePolicy.manifestPackageCount !== packageManifest.packages.length ||
    packageManifest.packages.length !== installedDelta || packageManifest.packages.length !== 1353) {
  throw new Error("derived projection package count differs from manifest, provenance, or current expected content");
}

const forbiddenKeyPattern = /^(?:api_endpoint|auth_key_secret_ref|bdf|by_id_secret_ref|compatibility_config_path|device_ids|filesystem_uuid|iommu_group|mac|mapping|materialization|members|pci|pool_guid_secret_ref|port_secret_ref|projectable|rom_file|serial_secret_ref|smbios_uuid|subsystem_id|token_escrow|token_name|usb|vendor_device)$/u;
function inspectProjectionKeys(value) {
  if (Array.isArray(value)) return value.forEach(inspectProjectionKeys);
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (forbiddenKeyPattern.test(key) || key.endsWith("_secret_ref") || key.includes("compatibility") ||
        (key !== "requiresApproval" && /(?:approval|cleanup|confirmed|marker|migration)/iu.test(key))) {
      throw new Error(`forbidden source key leaked into projection: ${key}`);
    }
    inspectProjectionKeys(nested);
  }
}
inspectProjectionKeys(projected);

const forbiddenValues = new Set();
function collectForbidden(value, key = "") {
  if (Array.isArray(value)) {
    value.forEach((nested) => collectForbidden(nested, key));
    return;
  }
  if (value && typeof value === "object") {
    if (typeof value.kind === "string" && value.kind.startsWith("runtime-protected-") && typeof value.path === "string") {
      forbiddenValues.add(value.path);
    }
    for (const [nestedKey, nested] of Object.entries(value)) collectForbidden(nested, nestedKey);
    return;
  }
  if (typeof value !== "string") return;
  if (key.endsWith("_secret_ref") || [
    "api_endpoint", "local_api_url", "compatibility_config_path", "mac", "bdf", "vendor_device",
    "subsystem_id", "filesystem_uuid", "smbios_uuid", "mapping", "host", "executable",
  ].includes(key)) forbiddenValues.add(value);
}
collectForbidden(contract);
for (const value of contract.proxmox.vfio.device_ids) forbiddenValues.add(value);
for (const value of Object.values(contract.proxmox.root_cleanup)) {
  if (Array.isArray(value)) value.forEach((item) => {
    // Historical inspection roots and the fixed reviewed helper directory are not protected values.
    if (!["/usr/local", "/usr/local/libexec/home-lab"].includes(item)) forbiddenValues.add(item);
  });
}
forbiddenValues.add(contract.proxmox.packages.manifest.path);

function assertForbiddenValuesAbsent(content, label) {
  if (content.includes("/etc/pve")) throw new Error(`${label} contains a PVE compatibility path`);
  for (const forbidden of forbiddenValues) {
    if (forbidden && content.includes(forbidden)) throw new Error(`${label} contains protected value ${JSON.stringify(forbidden)}`);
  }
}
assertForbiddenValuesAbsent(tracked, "tracked projection");

function scanTree(scanPath) {
  const files = [];
  function visit(current) {
    const currentStat = fs.lstatSync(current);
    if (currentStat.isSymbolicLink()) throw new Error(`scan path contains a symlink: ${current}`);
    if (currentStat.isFile()) {
      files.push(current);
      return;
    }
    if (!currentStat.isDirectory()) throw new Error(`scan path contains unsupported entry: ${current}`);
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) visit(path.join(current, entry.name));
  }
  visit(scanPath);
  for (const file of files) assertForbiddenValuesAbsent(fs.readFileSync(file).toString("latin1"), `scanned file ${file}`);
}

const scanArgument = process.argv.findIndex((argument) => argument === "--scan-path" || argument === "--bundle");
if (scanArgument !== -1) {
  const scanRoot = process.argv[scanArgument + 1];
  if (!scanRoot) throw new Error(`${process.argv[scanArgument]} requires a path`);
  scanTree(scanRoot);
}

console.log(`proxmox_nix_projection_tests=passed forbidden_values=${forbiddenValues.size}`);
