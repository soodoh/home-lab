#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const expectedRoots = ["aws-foundation", "omada", "proxmox", "proxmox-legacy", "tailscale"];

function sha256(body) {
  return crypto.createHash("sha256").update(body).digest("hex");
}

function buildAttestation(manifestBody, commit, createdAt) {
  const manifest = JSON.parse(manifestBody.toString("utf8"));
  if (manifest.commit !== commit) {
    throw new Error("plan manifest commit does not match HEAD");
  }
  if (manifest.phase !== "steady" || manifest.stage !== "converge") {
    throw new Error("plan manifest is not a steady converge plan");
  }
  if (manifest.proxmox_host_plan?.actions !== 0 || manifest.proxmox_host_plan?.status !== "ready") {
    throw new Error("Proxmox host plan is not zero-action ready");
  }
  const roots = manifest.plans.map((plan) => ({ root: plan.root, changed: plan.changed, sha256: plan.sha256 })).sort((left, right) => left.root.localeCompare(right.root));
  if (JSON.stringify(roots.map((plan) => plan.root)) !== JSON.stringify(expectedRoots)) {
    throw new Error("plan roots differ from the required qualification set");
  }
  if (roots.some((plan) => plan.changed !== false)) {
    throw new Error("an OpenTofu plan contains actions");
  }
  if (roots.some((plan) => typeof plan.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(plan.sha256))) {
    throw new Error("an OpenTofu plan digest is invalid");
  }
  return {
    schemaVersion: 1,
    commit,
    createdAt,
    phase: "steady",
    stage: "converge",
    manifestSha256: sha256(manifestBody),
    proxmoxHostActions: 0,
    allActionsZero: true,
    roots,
  };
}

function validatePlanArtifacts(manifest, manifestPath, nowMs = Date.now()) {
  const manifestDirectory = path.dirname(manifestPath);
  const reconcileMarker = `${path.sep}.reconcile${path.sep}`;
  const reconcileOffset = manifestPath.lastIndexOf(reconcileMarker);
  if (reconcileOffset <= 0) {
    throw new Error("plan manifest is not beneath a repository .reconcile directory");
  }
  const repositoryRoot = manifestPath.slice(0, reconcileOffset);
  const maximumAgeMs = 60 * 60 * 1000;
  const minimumAgeMs = -5 * 60 * 1000;
  const assertFreshRegularFile = (target, label) => {
    const metadata = fs.statSync(target);
    if (!metadata.isFile()) {
      throw new Error(`${label} is not a regular file`);
    }
    const ageMs = nowMs - metadata.mtimeMs;
    if (ageMs < minimumAgeMs || ageMs > maximumAgeMs) {
      throw new Error(`${label} is not fresh`);
    }
    return fs.readFileSync(target);
  };
  assertFreshRegularFile(manifestPath, "plan manifest");
  for (const plan of manifest.plans) {
    const target = path.resolve(manifestDirectory, plan.file);
    if (!target.startsWith(`${manifestDirectory}${path.sep}`)) {
      throw new Error(`plan path escapes the plan directory: ${plan.root}`);
    }
    const body = assertFreshRegularFile(target, `plan ${plan.root}`);
    if (sha256(body) !== plan.sha256) {
      throw new Error(`plan digest differs: ${plan.root}`);
    }
  }
  const hostTarget = path.resolve(repositoryRoot, manifest.proxmox_host_plan.file);
  const reconcileRoot = path.join(repositoryRoot, ".reconcile");
  if (!hostTarget.startsWith(`${reconcileRoot}${path.sep}`)) {
    throw new Error("Proxmox host plan path escapes .reconcile");
  }
  const hostBody = assertFreshRegularFile(hostTarget, "Proxmox host plan");
  if (sha256(hostBody) !== manifest.proxmox_host_plan.file_sha256) {
    throw new Error("Proxmox host plan file digest differs");
  }
  const hostPlan = JSON.parse(hostBody.toString("utf8"));
  if (hostPlan.status !== "ready" || !Array.isArray(hostPlan.actions) || hostPlan.actions.length !== 0 || hostPlan.planSha256 !== manifest.proxmox_host_plan.plan_sha256) {
    throw new Error("Proxmox host plan content is not zero-action ready");
  }
}

function main(argv) {
  if (argv.length !== 4 || argv[0] !== "--manifest" || argv[2] !== "--output") {
    throw new Error("usage: attest-debian-qualification-plan.js --manifest FILE --output FILE");
  }
  const manifestPath = path.resolve(argv[1]);
  const outputPath = path.resolve(argv[3]);
  const repoRoot = path.resolve(__dirname, "../..");
  const reconcileRoot = path.join(repoRoot, ".reconcile");
  if (outputPath !== reconcileRoot && !outputPath.startsWith(`${reconcileRoot}${path.sep}`)) {
    throw new Error("attestation output must remain under .reconcile");
  }
  const manifestBody = fs.readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBody.toString("utf8"));
  validatePlanArtifacts(manifest, manifestPath);
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).trim();
  const createdAt = fs.statSync(manifestPath).mtime.toISOString();
  const attestation = buildAttestation(manifestBody, commit, createdAt);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(outputPath, `${JSON.stringify(attestation, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(outputPath, 0o600);
  process.stdout.write(`${outputPath}\n`);
}

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}

module.exports = { buildAttestation, sha256, validatePlanArtifacts };
