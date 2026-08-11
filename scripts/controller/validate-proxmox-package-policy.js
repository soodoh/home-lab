"use strict";

const { manifestSha256, renderManifest } = require("./proxmox-package-manifest");

function duplicates(values) {
  const seen = new Set();
  const repeated = new Set();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated].sort();
}

function validateProxmoxPackageArtifactBinding(contract, manifest, manifestRaw, relativePath) {
  const failures = [];
  if (contract.proxmox.packages.manifest.path !== relativePath) failures.push("package manifest path differs from contract");
  if (contract.proxmox.packages.manifest.sha256 !== manifestSha256(manifestRaw)) failures.push("package manifest SHA-256 differs from contract");
  if (manifestRaw !== renderManifest(manifest)) failures.push("package manifest is not canonical");
  return failures;
}

function validateProxmoxPackagePolicy(contract, manifest) {
  const failures = [];
  const policy = contract.proxmox.packages;
  const directNames = policy.direct.map((entry) => entry.name);
  const criticalNames = policy.critical.map((entry) => entry.name);
  const selected = [...policy.direct, ...policy.critical];
  const selectedNames = selected.map((entry) => entry.name);
  const prohibited = new Set(policy.prohibited);

  for (const duplicate of duplicates(directNames)) failures.push(`direct package ${duplicate} is duplicated`);
  for (const duplicate of duplicates(criticalNames)) failures.push(`critical package ${duplicate} is duplicated`);
  for (const duplicate of duplicates(selectedNames)) failures.push(`package ${duplicate} appears in both direct and critical sets`);
  for (const name of selectedNames) {
    if (prohibited.has(name)) failures.push(`selected package ${name} is also prohibited`);
  }
  for (const name of policy.permitted_manual) {
    if (prohibited.has(name)) failures.push(`permitted manual package ${name} is also prohibited`);
  }

  if (manifest.architecture !== policy.architecture) failures.push("package manifest architecture differs from contract");
  const manifestPackages = new Map(manifest.packages.map((entry) => [entry.name, entry.version]));
  if (manifestPackages.size !== manifest.packages.length) failures.push("package manifest names must be unique");
  for (const manifestEntry of manifest.packages) {
    const [baseName, qualifier] = manifestEntry.name.split(":");
    if (qualifier && qualifier !== policy.architecture) {
      failures.push(`package manifest entry ${manifestEntry.name} has a foreign architecture qualifier`);
    }
    if (prohibited.has(baseName)) failures.push(`prohibited package ${manifestEntry.name} appears in the package manifest`);
  }
  for (const entry of selected) {
    const candidates = manifest.packages.filter((candidate) => candidate.name === entry.name || candidate.name === `${entry.name}:${policy.architecture}`);
    if (candidates.length === 0) failures.push(`selected package ${entry.name} is missing from the package manifest`);
    else if (candidates.length > 1) failures.push(`selected package ${entry.name} is ambiguous in the package manifest`);
    else if (candidates[0].version !== entry.version) failures.push(`selected package ${entry.name} version differs from the package manifest`);
  }

  const criticalByRole = new Map();
  for (const entry of policy.critical) {
    if (criticalByRole.has(entry.role)) failures.push(`critical package role ${entry.role} is duplicated`);
    criticalByRole.set(entry.role, entry);
  }
  const roleNames = {
    "debian-archive-keyring": "debian-archive-keyring",
    "proxmox-archive-keyring": "proxmox-archive-keyring",
    "pve-manager": "pve-manager",
    "default-kernel": "proxmox-default-kernel",
    "default-headers": "pve-headers",
    "zfs-daemon": "zfs-zed",
    "zfs-tools": "zfsutils-linux",
    "legacy-firewall": "pve-firewall",
    firewall: "proxmox-firewall",
  };
  for (const [role, name] of Object.entries(roleNames)) {
    const entry = criticalByRole.get(role);
    if (!entry) failures.push(`critical package role ${role} is missing`);
    else if (entry.name !== name) failures.push(`critical package role ${role} must select ${name}`);
  }
  const kernelRelease = contract.proxmox.kernels.current;
  const kernelVersion = kernelRelease.replace(/-pve$/u, "");
  for (const [role, name] of [
    ["retained-kernel", `proxmox-kernel-${kernelRelease}-signed`],
    ["retained-kernel-headers", `proxmox-headers-${kernelRelease}`],
  ]) {
    const entry = criticalByRole.get(role);
    if (!entry) failures.push(`critical package role ${role} is missing`);
    else {
      if (entry.name !== name) failures.push(`critical package role ${role} must select ${name}`);
      if (entry.version !== kernelVersion) failures.push(`${entry.name} version must match kernel release ${kernelRelease}`);
    }
  }

  const serializedManifest = JSON.stringify(manifest);
  const protectedPatterns = [
    /BEGIN (?:RSA |OPENSSH |AGE )?PRIVATE KEY/u,
    /(?:PASSWORD|TOKEN|SECRET|AUTH_KEY)/u,
    /HOMELAB_/u,
    /PROXMOX_(?:PLAN|APPLY|FIREWALL)_SSH_PUBLIC_KEYS/u,
    /\/dev\/(?:disk|serial)\//u,
  ];
  if (protectedPatterns.some((pattern) => pattern.test(serializedManifest))) {
    failures.push("package manifest contains a protected-input marker");
  }

  return failures;
}

module.exports = { validateProxmoxPackageArtifactBinding, validateProxmoxPackagePolicy };
