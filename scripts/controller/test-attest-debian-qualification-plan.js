#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { fixture } = require("./test-proxmox-check-evidence");
const { canonicalJson } = require("./proxmox-host-projection");
const { execFileSync } = require("node:child_process");
const ROOT = path.resolve(__dirname, "../..");
const { buildAttestation, sha256, validatePlanArtifacts } = require("./attest-debian-qualification-plan.js");

const commit = "a".repeat(40);
const manifest = {
  version: 6,
  commit,
  phase: "steady",
  stage: "converge",
  proxmox_host_check: { file: `.reconcile/plans/${"f".repeat(64)}.check.json`, sha256: "f".repeat(64) },
  plans: [
    { root: "tailscale", file: "tailscale.tfplan", sha256: "1".repeat(64), changed: false },
    { root: "proxmox", file: "proxmox.tfplan", sha256: "2".repeat(64), changed: false },
    { root: "aws-foundation", file: "aws-foundation.tfplan", sha256: "3".repeat(64), changed: false },
    { root: "omada", file: "omada.tfplan", sha256: "4".repeat(64), changed: false },
  ],
};
const body = Buffer.from(`${JSON.stringify(manifest)}\n`);
const attestation = buildAttestation(body, commit, "2026-08-17T18:00:00.000Z");
assert.equal(attestation.commit, commit);
assert.equal(attestation.allActionsZero, true);
assert.equal(attestation.proxmoxHostScope, "audit");
assert.equal(attestation.proxmoxHostCheckSha256, manifest.proxmox_host_check.sha256);
assert.deepEqual(attestation.roots.map((plan) => plan.root), ["aws-foundation", "omada", "proxmox", "tailscale"]);
assert.match(attestation.manifestSha256, /^[0-9a-f]{64}$/);
assert.equal(attestation.roots.every((plan) => /^[0-9a-f]{64}$/.test(plan.sha256)), true);

for (const mutate of [
  (value) => { value.commit = "b".repeat(40); },
  (value) => { value.phase = "recovery"; },
  (value) => { value.version = 5; },
  (value) => { value.proxmox_host_plan = { actions: 0 }; },
  (value) => { value.plans[0].changed = true; },
  (value) => { value.plans.pop(); },
  (value) => { value.plans[0].sha256 = "invalid"; },
]) {
  const invalid = structuredClone(manifest);
  mutate(invalid);
  assert.throws(() => buildAttestation(Buffer.from(JSON.stringify(invalid)), commit, "2026-08-17T18:00:00.000Z"));
}

const reconcile = path.join(ROOT, ".reconcile");
fs.mkdirSync(reconcile, { recursive: true, mode: 0o700 });
const temporaryRoot = fs.mkdtempSync(path.join(reconcile, "attestation-test-"));
let savedEvidence;
try {
  const planDirectory = path.join(temporaryRoot, "plans");
  fs.mkdirSync(planDirectory);
  const artifactManifest = structuredClone(manifest);
  artifactManifest.commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  for (const plan of artifactManifest.plans) {
    const planBody = Buffer.from(`plan:${plan.root}\n`);
    fs.writeFileSync(path.join(planDirectory, plan.file), planBody, { mode: 0o600 });
    plan.sha256 = sha256(planBody);
  }
  const evidence = fixture(temporaryRoot), raw = Buffer.from(canonicalJson(evidence)), digest = sha256(raw);
  const relative = `.reconcile/plans/${digest}.check.json`;
  savedEvidence = path.join(ROOT, relative);
  fs.mkdirSync(path.dirname(savedEvidence), { recursive: true, mode: 0o700 });
  fs.writeFileSync(savedEvidence, raw, { mode: 0o600, flag: "wx" });
  artifactManifest.proxmox_host_check = { file: relative, sha256: digest };
  const manifestPath = path.join(planDirectory, "manifest.json");
  fs.writeFileSync(manifestPath, canonicalJson(artifactManifest), { mode: 0o600 });
  validatePlanArtifacts(artifactManifest, manifestPath);
  fs.appendFileSync(path.join(planDirectory, artifactManifest.plans[0].file), "tampered");
  assert.throws(() => validatePlanArtifacts(artifactManifest, manifestPath));
} finally {
  if (savedEvidence) fs.rmSync(savedEvidence, { force: true });
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}
process.stdout.write("Debian neutral plan attestation tests passed\n");
