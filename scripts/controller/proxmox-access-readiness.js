#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");
const { load } = require("js-yaml");
const { canonicalJson, planProxmoxAccessCutover } = require("./proxmox-access-cutover");

const root = path.resolve(__dirname, "../..");
const outputRoot = path.join(root, ".local", "proxmox-access-readiness");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function extractObject(log, variable) {
  const marker = `"${variable}":`;
  const markerIndex = log.indexOf(marker);
  if (markerIndex < 0) throw new Error(`observation ${variable} is absent`);
  const start = log.indexOf("{", markerIndex + marker.length);
  if (start < 0) throw new Error(`observation ${variable} has no object`);
  let depth = 0;
  let inString = false;
  let escaped = false;
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
      if (depth === 0) return JSON.parse(log.slice(start, index + 1));
    }
  }
  throw new Error(`observation ${variable} is truncated`);
}

function loadPrivateCanonical(file) {
  const resolved = path.resolve(file);
  const metadata = fs.lstatSync(resolved);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== process.getuid() ||
      (metadata.mode & 0o777) !== 0o600 || metadata.nlink !== 1) {
    throw new Error("access evidence receipt metadata differs");
  }
  const raw = fs.readFileSync(resolved, "utf8");
  const value = JSON.parse(raw);
  if (canonicalJson(value) !== raw) throw new Error("access evidence receipt is not canonical");
  return { value, raw };
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) throw new Error(`missing ${name}`);
  return process.argv[index + 1];
}

function main() {
  const logPath = path.resolve(argument("--log"));
  const receiptPath = path.resolve(argument("--receipt"));
  const status = childProcess.execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" });
  if (status !== "") throw new Error("access readiness requires a clean worktree");
  const commit = childProcess.execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  const origin = childProcess.execFileSync("git", ["rev-parse", "origin/main"], { cwd: root, encoding: "utf8" }).trim();
  if (commit !== origin) throw new Error("access readiness requires clean pushed HEAD");

  const contractRaw = fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"));
  const inventoryRaw = fs.readFileSync(path.join(root, "ansible/inventory/production.yml"));
  const contract = load(contractRaw);
  const observation = extractObject(fs.readFileSync(logPath, "utf8"), "access_cutover_plan_observation");
  const { value: receipt, raw: receiptRaw } = loadPrivateCanonical(receiptPath);
  if (receipt.format !== "home-lab-proxmox-access-evidence-v1" || receipt.commit !== commit ||
      receipt.contract_sha256 !== sha256(contractRaw) || receipt.inventory_sha256 !== sha256(inventoryRaw) ||
      receipt.host_key_fingerprint !== "SHA256:uaxG9uESfphESCqWx3ialKjK0doHnVcFoUIGWMGcaYQ" ||
      Date.now() > Date.parse(receipt.expires_at)) {
    throw new Error("access evidence receipt binding or freshness differs");
  }
  const proofs = receipt.proofs;
  const capabilities = observation.capabilities;
  const hostEvidence = {
    accounts: observation.evidence.accounts,
    conventional_key_files: observation.conventional_key_files,
    pubkey_authentication: observation.sshd.pubkey_authentication,
    permit_root_login: observation.sshd.permit_root_login,
    plan_observer_proven: capabilities.plan.verified && proofs.plan_observer.positive && proofs.plan_observer.injection_rejected,
    canaries_proven: capabilities.deploy.verified && capabilities.firewall.verified && proofs.deploy_transport.positive &&
      proofs.deploy_transport.injection_rejected && proofs.firewall_transport.positive &&
      proofs.firewall_transport.injection_rejected && proofs.human_session.positive &&
      proofs.tailnet_policy.tests_present && proofs.tailnet_policy.live_plan_noop,
    root_keys_attributed: proofs.root_keys.complete,
    console_attested: proofs.console.attested,
  };
  const sources = {
    tailnet: fs.readFileSync(path.join(root, "infrastructure/tofu/tailscale/main.tf"), "utf8"),
    inventory: inventoryRaw.toString(),
    firewallController: fs.readFileSync(path.join(root, "scripts/controller/proxmox-firewall.py"), "utf8"),
    firewallTransport: fs.readFileSync(path.join(root, "infrastructure/proxmox-firewall/host/proxmox-firewall-transport"), "utf8"),
    planTransport: fs.readFileSync(path.join(root, "infrastructure/proxmox-access/host/proxmox-ansible-plan-transport"), "utf8"),
  };
  const readiness = planProxmoxAccessCutover(contract, sources, hostEvidence);
  const material = {
    format: "home-lab-proxmox-access-readiness-v1",
    commit,
    contract_sha256: sha256(contractRaw),
    inventory_sha256: sha256(inventoryRaw),
    receipt_sha256: sha256(receiptRaw),
    live_evidence_sha256: observation.evidence.evidence_sha256,
    readiness,
    authorized: false,
  };
  const digest = sha256(canonicalJson(material));
  const result = { ...material, evidence_sha256: digest };
  fs.mkdirSync(outputRoot, { recursive: true, mode: 0o700 });
  fs.chmodSync(outputRoot, 0o700);
  const target = path.join(outputRoot, `${digest}.json`);
  const descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try {
    fs.writeFileSync(descriptor, canonicalJson(result));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  process.stdout.write(`${JSON.stringify({ blockers: readiness.blockers, evidence_sha256: digest, path: target, ready: readiness.ready })}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`proxmox-access-readiness: ${error.message}\n`);
  process.exitCode = 1;
}
