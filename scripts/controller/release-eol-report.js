#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const maxResponseBytes = 1024 * 1024;

function canonicalJson(value) {
  function sort(candidate) {
    if (Array.isArray(candidate)) return candidate.map(sort);
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(Object.keys(candidate).sort().map((key) => [key, sort(candidate[key])]));
    }
    return candidate;
  }
  return `${JSON.stringify(sort(value))}\n`;
}

function sha256(raw) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function parseTimestamp(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) throw new Error(`${label} is not a UTC-seconds timestamp`);
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch)) throw new Error(`${label} is invalid`);
  return epoch;
}

function validateSource(source, product, observedEpoch, maxAgeDays) {
  if (!Buffer.isBuffer(source.raw) || source.raw.length < 2 || source.raw.length > maxResponseBytes) throw new Error(`${product} source size is invalid`);
  const value = JSON.parse(source.raw.toString("utf8"));
  if (!value || value.schema_version !== "1.2.1" || value.result?.name !== product || !Array.isArray(value.result.releases)) {
    throw new Error(`${product} source envelope is invalid`);
  }
  const generatedEpoch = Date.parse(value.generated_at);
  if (!Number.isFinite(generatedEpoch) || generatedEpoch > observedEpoch || observedEpoch - generatedEpoch > maxAgeDays * 86400000) {
    throw new Error(`${product} source is stale or future-dated`);
  }
  return value;
}

function buildReport(contract, packageManifest, sources, observedAt) {
  const policy = contract.lifecycle.maintenance.release_monitor;
  if (policy.automatic_apply !== false) throw new Error("release monitor cannot authorize mutation");
  const observedEpoch = parseTimestamp(observedAt, "observed_at");
  const currentVersions = {
    debian: contract.debian.point_release,
    proxmox: packageManifest.packages.find((item) => item.name === "pve-manager")?.version,
  };
  if (!currentVersions.proxmox) throw new Error("PVE manager version is absent from the exact package manifest");
  const productNames = { debian: "debian", proxmox: "proxmox-ve" };
  const warnings = [];
  const blockers = [];
  const outputSources = {};

  for (const host of ["debian", "proxmox"]) {
    const sourcePolicy = policy.sources[host];
    const source = sources[host];
    const value = validateSource(source, productNames[host], observedEpoch, policy.max_source_age_days);
    const release = value.result.releases.find((item) => item.name === sourcePolicy.cycle);
    if (!release || typeof release.latest?.name !== "string") {
      blockers.push(`${host}-cycle-unavailable`);
      continue;
    }
    const eolKnown = typeof release.eolFrom === "string";
    if (sourcePolicy.require_maintained && (!release.isMaintained || release.isEol)) blockers.push(`${host}-release-unmaintained`);
    if (sourcePolicy.require_eol_known && !eolKnown) blockers.push(`${host}-eol-unknown`);
    else if (!eolKnown) warnings.push(`${host}-eol-unknown`);
    if (eolKnown) {
      const eolEpoch = Date.parse(`${release.eolFrom}T00:00:00Z`);
      if (!Number.isFinite(eolEpoch)) blockers.push(`${host}-eol-invalid`);
      else if (eolEpoch <= observedEpoch) blockers.push(`${host}-eol-reached`);
      else if (eolEpoch - observedEpoch <= policy.warning_days * 86400000) warnings.push(`${host}-eol-within-warning-window`);
    }
    if (host === "debian" && currentVersions[host] !== release.latest.name) warnings.push("debian-point-release-behind");
    if (host === "proxmox" && currentVersions[host] !== release.latest.name && !currentVersions[host].startsWith(`${release.latest.name}.`)) {
      warnings.push("proxmox-release-behind");
    }
    outputSources[host] = {
      api: sourcePolicy.api,
      cycle: sourcePolicy.cycle,
      current_version: currentVersions[host],
      latest_version: release.latest.name,
      release_date: release.releaseDate ?? null,
      eol: release.eolFrom ?? null,
      extended_support_end: release.eoesFrom ?? null,
      maintained: release.isMaintained === true && release.isEol === false,
      eol_known: eolKnown,
      source_generated_at: value.generated_at,
      source_last_modified: value.last_modified,
      source_sha256: sha256(source.raw),
    };
  }
  warnings.sort();
  blockers.sort();
  return {
    format: "home-lab-release-eol-report-v1",
    version: 1,
    observed_at: observedAt,
    automatic_apply: false,
    status: blockers.length ? "blocking" : warnings.length ? "warning" : "healthy",
    warnings,
    blockers,
    sources: outputSources,
  };
}

function fetchFixed(urlText) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlText);
    if (url.protocol !== "https:" || url.hostname !== "endoflife.date" || !url.pathname.startsWith("/api/v1/products/")) {
      reject(new Error("release source URL is outside the fixed endoflife.date API"));
      return;
    }
    const request = https.get(url, { headers: { accept: "application/json", "user-agent": "home-lab-release-monitor/1" }, timeout: 15000 }, (response) => {
      if (response.statusCode !== 200 || response.headers.location) {
        response.resume();
        reject(new Error(`release source returned HTTP ${response.statusCode}`));
        return;
      }
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        length += chunk.length;
        if (length > maxResponseBytes) request.destroy(new Error("release source exceeds fixed size limit"));
        else chunks.push(chunk);
      });
      response.on("end", () => resolve(Buffer.concat(chunks, length)));
    });
    request.on("timeout", () => request.destroy(new Error("release source timed out")));
    request.on("error", reject);
  });
}

async function main() {
  const argumentsList = process.argv.slice(2);
  const fetch = argumentsList.includes("--fetch");
  const valueAfter = (name) => {
    const index = argumentsList.indexOf(name);
    return index >= 0 && argumentsList[index + 1] ? argumentsList[index + 1] : undefined;
  };
  if (argumentsList.some((item) => !["--fetch", "--debian-json", "--proxmox-json", "--observed-at"].includes(item) &&
      !argumentsList.includes(item, Math.max(0, argumentsList.indexOf(item) - 1)))) {
    throw new Error("unsupported release report argument");
  }
  const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
  const packageManifest = JSON.parse(fs.readFileSync(path.join(root, contract.proxmox.packages.manifest.path), "utf8"));
  let sources;
  if (fetch) {
    if (valueAfter("--debian-json") || valueAfter("--proxmox-json")) throw new Error("fetch and fixture inputs are mutually exclusive");
    const [debian, proxmox] = await Promise.all([
      fetchFixed(contract.lifecycle.maintenance.release_monitor.sources.debian.api),
      fetchFixed(contract.lifecycle.maintenance.release_monitor.sources.proxmox.api),
    ]);
    sources = { debian: { raw: debian }, proxmox: { raw: proxmox } };
  } else {
    const debianPath = valueAfter("--debian-json");
    const proxmoxPath = valueAfter("--proxmox-json");
    if (!debianPath || !proxmoxPath) throw new Error("both fixed release fixture paths are required");
    sources = { debian: { raw: fs.readFileSync(path.resolve(debianPath)) }, proxmox: { raw: fs.readFileSync(path.resolve(proxmoxPath)) } };
  }
  const observedAt = valueAfter("--observed-at") ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const report = buildReport(contract, packageManifest, sources, observedAt);
  process.stdout.write(canonicalJson(report));
  if (report.status === "blocking") process.exitCode = 2;
}

if (require.main === module) main().catch((error) => {
  process.stderr.write(`release-eol-report: ${error.message}\n`);
  process.exitCode = 1;
});
module.exports = { buildReport, canonicalJson, validateSource };
