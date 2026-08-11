"use strict";

const crypto = require("node:crypto");

const packageNamePattern = /^[a-z0-9][a-z0-9+.-]+(?::[a-z0-9][a-z0-9-]*)?$/;
const versionPattern = /^(?:[0-9]+:)?[0-9][0-9A-Za-z.+:~]*(?:-[0-9A-Za-z.+~]+)*$/;
const architecturePattern = /^[a-z0-9][a-z0-9-]*$/;
const sha256Pattern = /^[0-9a-f]{64}$/;

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function normalizePackageRecords(records) {
  if (!Array.isArray(records) || records.length === 0) throw new Error("package manifest must contain packages");
  const packages = records.map((record) => {
    if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("package manifest record must be an object");
    const keys = Object.keys(record).sort();
    if (JSON.stringify(keys) !== JSON.stringify(["name", "version"])) throw new Error("package manifest record must contain only name and version");
    if (typeof record.name !== "string" || !packageNamePattern.test(record.name)) {
      throw new Error(`invalid Debian binary package name: ${String(record.name)}`);
    }
    if (typeof record.version !== "string" || !versionPattern.test(record.version)) {
      throw new Error(`invalid Debian package version for ${record.name}`);
    }
    return { name: record.name, version: record.version };
  });
  packages.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  for (let index = 1; index < packages.length; index += 1) {
    if (packages[index - 1].name === packages[index].name) throw new Error(`duplicate package manifest entry: ${packages[index].name}`);
  }
  return packages;
}

function normalizeProvenance(provenance) {
  if (!provenance || typeof provenance !== "object" || Array.isArray(provenance)) throw new Error("package manifest provenance must be an object");
  if (JSON.stringify(Object.keys(provenance).sort()) !== JSON.stringify(["installedInventory", "solverResult"])) {
    throw new Error("package manifest provenance shape is invalid");
  }
  const inventory = provenance.installedInventory;
  const solver = provenance.solverResult;
  if (!inventory || typeof inventory !== "object" || Array.isArray(inventory)
      || JSON.stringify(Object.keys(inventory).sort()) !== JSON.stringify(["format", "installedRecords", "sha256"])) {
    throw new Error("installed inventory provenance shape is invalid");
  }
  if (inventory.format !== "dpkg-query-status-tsv-v1" || !Number.isInteger(inventory.installedRecords)
      || inventory.installedRecords < 1 || typeof inventory.sha256 !== "string" || !sha256Pattern.test(inventory.sha256)) {
    throw new Error("installed inventory provenance is invalid");
  }
  if (!solver || typeof solver !== "object" || Array.isArray(solver)
      || JSON.stringify(Object.keys(solver).sort()) !== JSON.stringify(["changes", "format", "sha256"])) {
    throw new Error("solver-result provenance shape is invalid");
  }
  if (solver.format !== "apt-get-simulate-v1" || typeof solver.sha256 !== "string" || !sha256Pattern.test(solver.sha256)
      || !Array.isArray(solver.changes) || solver.changes.length === 0) {
    throw new Error("solver-result provenance is invalid");
  }
  const changes = solver.changes.map((change) => {
    if (!change || typeof change !== "object" || Array.isArray(change)) throw new Error("solver change must be an object");
    const keys = Object.keys(change).sort();
    if (JSON.stringify(keys) !== JSON.stringify(["action", "name", "previousVersion", "version"])) {
      throw new Error("solver change shape is invalid");
    }
    if (!["install", "remove", "upgrade"].includes(change.action)
        || typeof change.name !== "string" || !packageNamePattern.test(change.name)
        || (change.previousVersion !== null && (typeof change.previousVersion !== "string" || !versionPattern.test(change.previousVersion)))
        || (change.version !== null && (typeof change.version !== "string" || !versionPattern.test(change.version)))) {
      throw new Error("solver change is invalid");
    }
    if ((change.action === "install" && (change.previousVersion !== null || change.version === null))
        || (change.action === "remove" && (change.previousVersion === null || change.version !== null))
        || (change.action === "upgrade" && (change.previousVersion === null || change.version === null
          || change.previousVersion === change.version))) {
      throw new Error(`solver ${change.action} transition fields are invalid for ${change.name}`);
    }
    return {
      action: change.action,
      name: change.name,
      previousVersion: change.previousVersion,
      version: change.version,
    };
  });
  changes.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  for (let index = 1; index < changes.length; index += 1) {
    if (changes[index - 1].name === changes[index].name) throw new Error(`duplicate solver transition: ${changes[index].name}`);
  }
  return {
    installedInventory: {
      format: inventory.format,
      sha256: inventory.sha256,
      installedRecords: inventory.installedRecords,
    },
    solverResult: { format: solver.format, sha256: solver.sha256, changes },
  };
}

function normalizeManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("package manifest must be an object");
  const keys = Object.keys(manifest).sort();
  if (JSON.stringify(keys) !== JSON.stringify(["architecture", "packages", "provenance", "version"])) {
    throw new Error("package manifest must contain only version, architecture, provenance, and packages");
  }
  if (manifest.version !== 1) throw new Error("unsupported package manifest version");
  if (typeof manifest.architecture !== "string" || !architecturePattern.test(manifest.architecture)) {
    throw new Error("invalid package manifest architecture");
  }
  const packages = normalizePackageRecords(manifest.packages);
  const provenance = normalizeProvenance(manifest.provenance);
  const packageMap = new Map(packages.map((entry) => [entry.name, entry.version]));
  for (const change of provenance.solverResult.changes) {
    if (change.action === "remove") {
      if (packageMap.has(change.name)) throw new Error(`removed package remains in final manifest: ${change.name}`);
    } else if (packageMap.get(change.name) !== change.version) {
      throw new Error(`solver transition does not match final manifest: ${change.name}`);
    }
  }
  return {
    version: 1,
    architecture: manifest.architecture,
    provenance,
    packages,
  };
}

function parseDpkgStatusTsv(text) {
  if (typeof text !== "string") throw new Error("dpkg status TSV must be text");
  const records = [];
  let totalRecords = 0;
  for (const [index, rawLine] of text.split(/\r?\n/u).entries()) {
    if (rawLine === "") continue;
    const fields = rawLine.split("\t");
    if (fields.length !== 3 || !/^[A-Za-z?]{2} $/u.test(fields[0])) throw new Error(`invalid dpkg status TSV at line ${index + 1}`);
    totalRecords += 1;
    if (fields[0][1] === "i") records.push({ name: fields[1], version: fields[2] });
  }
  return { packages: normalizePackageRecords(records), totalRecords, installedRecords: records.length };
}

function resolvePackageName(name, architecture, packageMap) {
  const candidates = [...packageMap.keys()].filter((candidate) => candidate === name || candidate.startsWith(`${name}:`));
  const architectureMatch = candidates.find((candidate) => candidate === `${name}:${architecture}`);
  if (architectureMatch) return architectureMatch;
  if (candidates.length === 1) return candidates[0];
  if (candidates.length === 0) return name;
  throw new Error(`ambiguous simulated package name: ${name}`);
}

function applyAptSimulation(packages, simulation, architecture) {
  if (typeof simulation !== "string") throw new Error("APT simulation must be text");
  const packageMap = new Map(normalizePackageRecords(packages).map((entry) => [entry.name, entry.version]));
  const changes = [];
  for (const line of simulation.split(/\r?\n/u)) {
    const install = /^Inst (\S+)(?: \[([^\]]+)\])? \((\S+)(?: .*?)? \[([^\]]+)\]\)(?: .*|)$/u.exec(line);
    if (install) {
      const [, simulatedName, reportedPrevious, version, reportedArchitecture] = install;
      if (reportedArchitecture !== architecture && reportedArchitecture !== "all") {
        throw new Error(`simulated foreign architecture for ${simulatedName}`);
      }
      const name = resolvePackageName(simulatedName, architecture, packageMap);
      const previousVersion = packageMap.get(name) || null;
      if (reportedPrevious && previousVersion !== reportedPrevious) throw new Error(`simulated previous version differs for ${name}`);
      packageMap.set(name, version);
      changes.push({ action: previousVersion === null ? "install" : "upgrade", name, previousVersion, version });
      continue;
    }
    const remove = /^Remv (\S+)(?: \[([^\]]+)\])?(?: \[[^\]]*\])?$/u.exec(line);
    if (remove) {
      const name = resolvePackageName(remove[1], architecture, packageMap);
      const previousVersion = packageMap.get(name) || null;
      if (previousVersion === null) throw new Error(`simulated removal is not installed: ${name}`);
      if (remove[2] && previousVersion !== remove[2]) throw new Error(`simulated removal version differs for ${name}`);
      packageMap.delete(name);
      changes.push({ action: "remove", name, previousVersion, version: null });
      continue;
    }
    if (line.startsWith("Inst") || line.startsWith("Remv")) {
      throw new Error(`unrecognized APT transition record: ${line}`);
    }
  }
  if (changes.length === 0) throw new Error("APT simulation contains no package transition records");
  return { packages: normalizePackageRecords([...packageMap].map(([name, version]) => ({ name, version }))), changes };
}

function manifestFromObservedTransition(inventoryText, simulationText, architecture) {
  if (typeof architecture !== "string" || !architecturePattern.test(architecture)) throw new Error("invalid package manifest architecture");
  const inventory = parseDpkgStatusTsv(inventoryText);
  const result = applyAptSimulation(inventory.packages, simulationText, architecture);
  return normalizeManifest({
    version: 1,
    architecture,
    provenance: {
      installedInventory: {
        format: "dpkg-query-status-tsv-v1",
        sha256: sha256(inventoryText),
        installedRecords: inventory.installedRecords,
      },
      solverResult: {
        format: "apt-get-simulate-v1",
        sha256: sha256(simulationText),
        changes: result.changes,
      },
    },
    packages: result.packages,
  });
}

function renderManifest(manifest) {
  return `${JSON.stringify(normalizeManifest(manifest), null, 2)}\n`;
}

function manifestSha256(rendered) {
  return sha256(rendered);
}

module.exports = {
  applyAptSimulation,
  manifestFromObservedTransition,
  manifestSha256,
  normalizeManifest,
  packageNamePattern,
  parseDpkgStatusTsv,
  renderManifest,
  versionPattern,
};
