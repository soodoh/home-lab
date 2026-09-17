"use strict";

function duplicates(values) {
  const seen = new Set();
  const repeated = new Set();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated].sort();
}

function validateProxmoxPackagePolicy(contract) {
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

  return failures;
}

module.exports = { validateProxmoxPackagePolicy };
