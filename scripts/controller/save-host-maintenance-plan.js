#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");
const { load } = require("js-yaml");
const { buildCandidateLock } = require("./package-transaction-lock");

const root = path.resolve(__dirname, "../..");

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

function extractObservations(log, variable) {
  const marker = `"${variable}":`;
  const values = [];
  let offset = 0;
  while (true) {
    const markerIndex = log.indexOf(marker, offset);
    if (markerIndex < 0) break;
    const start = log.indexOf("{", markerIndex + marker.length);
    if (start < 0) throw new Error(`observation ${variable} has no object`);
    let depth = 0;
    let inString = false;
    let escaped = false;
    let end = -1;
    for (let index = start; index < log.length; index += 1) {
      const character = log[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') inString = true;
      else if (character === "{") depth += 1;
      else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          end = index + 1;
          break;
        }
      }
    }
    if (end < 0) throw new Error(`observation ${variable} is truncated`);
    values.push(JSON.parse(log.slice(start, end)));
    offset = end;
  }
  return values;
}

function buildPlan({ kind, host, evidence, bindings, nowEpoch }) {
  if (!new Set(["package", "reboot"]).has(kind)) throw new Error("maintenance plan kind is invalid");
  if (!new Set(["debian", "proxmox"]).has(host) || evidence.contract_host !== host) {
    throw new Error("maintenance plan host binding differs");
  }
  if (!/^[0-9a-f]{40}$/.test(bindings.git_commit)) throw new Error("maintenance plan Git binding is invalid");
  for (const name of ["contract_sha256", "inventory_sha256"]) {
    if (!/^[0-9a-f]{64}$/.test(bindings[name])) throw new Error(`maintenance plan binding ${name} is invalid`);
  }
  if (!Number.isInteger(bindings.max_observation_age_seconds) || bindings.max_observation_age_seconds < 1 ||
      bindings.max_observation_age_seconds > 1800) {
    throw new Error("maintenance plan freshness binding is invalid");
  }
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(bindings.host_key_fingerprint)) {
    throw new Error("maintenance plan host-key fingerprint is invalid");
  }
  if (!Number.isInteger(nowEpoch) || nowEpoch <= 0) throw new Error("maintenance plan clock is invalid");

  const payload = kind === "package" ? evidence.proposal : evidence.evidence;
  const observedAt = payload?.observed_at;
  const observedEpoch = Date.parse(observedAt) / 1000;
  if (!Number.isInteger(observedEpoch) || nowEpoch < observedEpoch || nowEpoch - observedEpoch > bindings.max_observation_age_seconds) {
    throw new Error("maintenance plan observation is stale or future-dated");
  }
  if (kind === "package") {
    if (evidence.apply_authorized !== false || evidence.proposal_valid !== true || evidence.metadata_fresh !== true ||
        payload.solver?.returncode !== 0 || payload.holds?.length || payload.change_counts?.remove || payload.change_counts?.downgrade ||
        !/^[0-9a-f]{64}$/.test(payload.proposal_sha256)) {
      throw new Error("package proposal is not safe to save");
    }
  } else if (evidence.reboot_authorized !== false || !/^[0-9a-f]{64}$/.test(payload?.evidence_sha256) ||
      typeof payload.current_kernel !== "string" || typeof payload.target_kernel !== "string" ||
      !/^[0-9a-f-]{36}$/.test(payload.boot_id)) {
    throw new Error("reboot proposal is not safe to save");
  }

  const createdAt = new Date(nowEpoch * 1000).toISOString().replace(".000Z", "Z");
  const expiresAt = new Date((observedEpoch + bindings.max_observation_age_seconds) * 1000).toISOString().replace(".000Z", "Z");
  const packageTransactionLock = kind === "package" ? buildCandidateLock({
    host,
    lifecycle: "production",
    proposal: payload,
    bindings,
    generatedAt: createdAt,
    expiresAt,
  }) : undefined;
  const material = {
    format: "home-lab-host-maintenance-plan-v1",
    version: 1,
    kind,
    host,
    created_at: createdAt,
    expires_at: expiresAt,
    bindings,
    evidence: payload,
    evidence_sha256: sha256(canonicalJson(payload)),
    blockers: kind === "package"
      ? [...new Set([...(evidence.apply_blockers || []), ...packageTransactionLock.blockers])].sort()
      : evidence.blockers || [],
    actionable: kind === "reboot" && evidence.preconditions_met && evidence.plan_inputs_complete,
    authorized: false,
    ...(packageTransactionLock ? { package_transaction_lock: packageTransactionLock } : {}),
  };
  return {
    ...material,
    plan_sha256: sha256(canonicalJson(material)),
  };
}

function writePlan(outputDirectory, plan) {
  const resolved = path.resolve(outputDirectory);
  const allowed = path.join(root, ".local", "host-maintenance-plans");
  if (resolved !== allowed) throw new Error("maintenance plan output directory is fixed");
  fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
  fs.chmodSync(resolved, 0o700);
  const target = path.join(resolved, `${plan.plan_sha256}.json`);
  const descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try {
    fs.writeFileSync(descriptor, canonicalJson(plan));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  return target;
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) throw new Error(`missing ${name}`);
  return process.argv[index + 1];
}

function main() {
  const kind = argument("--kind");
  const host = argument("--host");
  const logPath = path.resolve(argument("--log"));
  const hostKeyFingerprint = argument("--host-key-fingerprint");
  const status = childProcess.execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" });
  if (status !== "") throw new Error("maintenance plans require a clean worktree");
  const commit = childProcess.execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  const contractRaw = fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"));
  const inventoryRaw = fs.readFileSync(path.join(root, host === "proxmox" ? "ansible/inventory/proxmox-production.yml" : "ansible/inventory/production.yml"));
  const contract = load(contractRaw);
  const variable = kind === "package" ? (host === "proxmox" ? "proxmox_package_plan_observation" : "package_lifecycle_observation") : "reboot_lifecycle_observation";
  const observations = extractObservations(fs.readFileSync(logPath, "utf8"), variable);
  const evidence = observations.find((value) => value.contract_host === host);
  if (!evidence) throw new Error("requested maintenance observation is absent");
  const plan = buildPlan({
    kind,
    host,
    evidence,
    bindings: {
      git_commit: commit,
      contract_sha256: sha256(contractRaw),
      inventory_sha256: sha256(inventoryRaw),
      host_key_fingerprint: hostKeyFingerprint,
      max_observation_age_seconds: contract.proxmox.planning_policy.max_observation_age_seconds,
      max_metadata_age_seconds: contract.lifecycle.maintenance.package_plan.max_metadata_age_seconds,
    },
    nowEpoch: Math.floor(Date.now() / 1000),
  });
  const target = writePlan(path.join(root, ".local", "host-maintenance-plans"), plan);
  process.stdout.write(`${JSON.stringify({ plan_sha256: plan.plan_sha256, path: target })}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`save-host-maintenance-plan: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { buildPlan, canonicalJson, extractObservations, writePlan };
