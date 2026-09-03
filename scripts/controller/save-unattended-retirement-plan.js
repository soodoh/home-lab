#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");
const { load } = require("js-yaml");
const { extractObservations } = require("./save-host-maintenance-plan");

const root = path.resolve(__dirname, "../..");
function canonicalJson(value) {
  const sort = (candidate) => Array.isArray(candidate) ? candidate.map(sort) : candidate && typeof candidate === "object" ?
    Object.fromEntries(Object.keys(candidate).sort().map((key) => [key, sort(candidate[key])])) : candidate;
  return `${JSON.stringify(sort(value))}\n`;
}
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function validateObservation(observation) {
  if (observation?.format !== "home-lab-unattended-retirement-observation-v1" || observation.version !== 1 ||
      observation.host !== "debian" || !Array.isArray(observation.units) || !Array.isArray(observation.files) ||
      !Array.isArray(observation.processes) || !Array.isArray(observation.locks)) throw new Error("retirement observation is invalid");
  const material = { files: observation.files, locks: observation.locks, processes: observation.processes, units: observation.units };
  if (sha256(canonicalJson(material).trimEnd()) !== observation.observation_sha256) throw new Error("retirement observation hash differs");
  if (observation.units.map((item) => item.name).join("\0") !==
      "apt-daily.timer\0apt-daily-upgrade.timer\0unattended-upgrades.service") throw new Error("retirement unit set differs");
  if (observation.files.some((item) => item.exists && item.safe !== true)) throw new Error("retirement source file is unsafe");
}

function buildPlan({ observation, contract, bindings, nowEpoch }) {
  validateObservation(observation);
  const policy = contract.lifecycle.maintenance.unattended_upgrade_retirement;
  if (policy.automatic_apply !== false || policy.package_removal !== false || policy.refuse_active_upgrade !== true) {
    throw new Error("retirement policy could authorize unsafe mutation");
  }
  const observedEpoch = Date.parse(observation.observed_at) / 1000;
  if (!Number.isInteger(observedEpoch) || nowEpoch < observedEpoch || nowEpoch - observedEpoch > bindings.max_observation_age_seconds) {
    throw new Error("retirement observation is stale or future-dated");
  }
  if (!/^[0-9a-f]{40}$/.test(bindings.git_commit) || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(bindings.host_key_fingerprint) ||
      !/^[0-9a-f]{64}$/.test(bindings.contract_sha256) || !/^[0-9a-f]{64}$/.test(bindings.inventory_sha256)) {
    throw new Error("retirement plan binding is invalid");
  }
  const desiredRaw = Buffer.from(policy.periodic_file.content);
  const desired = {
    units: policy.units.map((name) => ({ active_state: "inactive", name, unit_file_state: "masked" })),
    periodic_file: { content_base64: desiredRaw.toString("base64"), group: policy.periodic_file.group,
      mode: policy.periodic_file.mode, owner: policy.periodic_file.owner, path: policy.periodic_file.path,
      sha256: sha256(desiredRaw) },
    package_removal: false,
  };
  const currentPeriodic = observation.files.find((item) => item.path === policy.periodic_file.path);
  const drift = observation.units.some((item) => item.active_state !== "inactive" || item.unit_file_state !== "masked") ||
    !currentPeriodic?.exists || currentPeriodic.sha256 !== desired.periodic_file.sha256 || currentPeriodic.mode !== policy.periodic_file.mode;
  const blockers = ["separate-exact-authorization-required"];
  if (observation.processes.length) blockers.push("active-package-process");
  if (observation.locks.length) blockers.push("active-package-lock");
  if (!drift) blockers.push("no-retirement-drift");
  if (observation.units.some((item) => item.load_state === "not-found" || item.active_state === "unknown" || item.unit_file_state === "unknown")) {
    blockers.push("unit-state-unavailable");
  }
  const createdAt = new Date(nowEpoch * 1000).toISOString().replace(".000Z", "Z");
  const material = {
    format: "home-lab-unattended-retirement-plan-v1", version: 1, host: "debian", lifecycle: "production",
    created_at: createdAt,
    expires_at: new Date((observedEpoch + bindings.max_observation_age_seconds) * 1000).toISOString().replace(".000Z", "Z"),
    automatic_apply: false, authorized: false, package_removal: false, bindings,
    observation, observation_sha256: sha256(canonicalJson(observation)), desired,
    rollback: { files: observation.files, units: observation.units }, blockers: [...new Set(blockers)].sort(),
    actionable: blockers.length === 1,
  };
  return { ...material, plan_sha256: sha256(canonicalJson(material)) };
}

function writePlan(plan) {
  const directory = path.join(root, ".local/unattended-retirement-plans");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const target = path.join(directory, `${plan.plan_sha256}.json`);
  const descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(descriptor, canonicalJson(plan)); fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  return target;
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing ${name}`);
  return process.argv[index + 1];
}

function main() {
  const logPath = path.resolve(argument("--log"));
  const hostKeyFingerprint = argument("--host-key-fingerprint");
  const status = childProcess.execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" });
  if (status) throw new Error("retirement plans require a clean worktree");
  const commit = childProcess.execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  const origin = childProcess.execFileSync("git", ["rev-parse", "origin/main"], { cwd: root, encoding: "utf8" }).trim();
  if (commit !== origin) throw new Error("retirement plans require pushed HEAD");
  const contractRaw = fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"));
  const inventoryRaw = fs.readFileSync(path.join(root, "ansible/inventory/production.yml"));
  const observations = extractObservations(fs.readFileSync(logPath, "utf8"), "unattended_retirement_plan_observation");
  if (observations.length !== 1) throw new Error("exactly one retirement observation is required");
  const plan = buildPlan({ observation: observations[0], contract: load(contractRaw), nowEpoch: Math.floor(Date.now() / 1000),
    bindings: { git_commit: commit, contract_sha256: sha256(contractRaw), inventory_sha256: sha256(inventoryRaw),
      host_key_fingerprint: hostKeyFingerprint, max_observation_age_seconds: 1800 } });
  const target = writePlan(plan);
  process.stdout.write(`${JSON.stringify({ authorized: false, path: target, plan_sha256: plan.plan_sha256 })}\n`);
}
if (require.main === module) main();
module.exports = { buildPlan, canonicalJson, validateObservation };
