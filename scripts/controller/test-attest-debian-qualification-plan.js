#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { buildAttestation, sha256, validatePlanArtifacts } = require("./attest-debian-qualification-plan.js");

const commit = "a".repeat(40);
const manifest = {
  commit,
  phase: "steady",
  stage: "converge",
  proxmox_host_plan: { actions: 0, status: "ready" },
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
assert.equal(attestation.proxmoxHostActions, 0);
assert.deepEqual(attestation.roots.map((plan) => plan.root), ["aws-foundation", "omada", "proxmox", "tailscale"]);
assert.match(attestation.manifestSha256, /^[0-9a-f]{64}$/);
assert.equal(attestation.roots.every((plan) => /^[0-9a-f]{64}$/.test(plan.sha256)), true);

for (const mutate of [
  (value) => { value.commit = "b".repeat(40); },
  (value) => { value.phase = "recovery"; },
  (value) => { value.proxmox_host_plan.actions = 1; },
  (value) => { value.plans[0].changed = true; },
  (value) => { value.plans.pop(); },
  (value) => { value.plans[0].sha256 = "invalid"; },
]) {
  const invalid = structuredClone(manifest);
  mutate(invalid);
  assert.throws(() => buildAttestation(Buffer.from(JSON.stringify(invalid)), commit, "2026-08-17T18:00:00.000Z"));
}

const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "debian-plan-attestation-"));
try {
  const planDirectory = path.join(temporaryRoot, ".reconcile/plans");
  fs.mkdirSync(planDirectory, { recursive: true });
  const artifactManifest = structuredClone(manifest);
  for (const plan of artifactManifest.plans) {
    const planBody = Buffer.from(`plan:${plan.root}\n`);
    fs.writeFileSync(path.join(planDirectory, plan.file), planBody);
    plan.sha256 = sha256(planBody);
  }
  const hostPlan = { status: "ready", actions: [], planSha256: "f".repeat(64) };
  const hostBody = Buffer.from(`${JSON.stringify(hostPlan)}\n`);
  const hostFile = ".reconcile/plans/host-plan.json";
  fs.writeFileSync(path.join(temporaryRoot, hostFile), hostBody);
  artifactManifest.proxmox_host_plan = {
    actions: 0,
    status: "ready",
    file: hostFile,
    file_sha256: sha256(hostBody),
    plan_sha256: hostPlan.planSha256,
  };
  const manifestPath = path.join(planDirectory, "manifest.json");
  fs.writeFileSync(manifestPath, `${JSON.stringify(artifactManifest)}\n`);
  validatePlanArtifacts(artifactManifest, manifestPath);
  fs.appendFileSync(path.join(planDirectory, artifactManifest.plans[0].file), "tampered");
  assert.throws(() => validatePlanArtifacts(artifactManifest, manifestPath));
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}

process.stdout.write("Debian plan attestation tests passed\n");
