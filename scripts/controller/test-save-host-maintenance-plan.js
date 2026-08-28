#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {
  buildPlan,
  canonicalJson,
  extractObservations,
} = require("./save-host-maintenance-plan");

const nowEpoch = Date.parse("2026-08-28T08:30:00Z") / 1000;
const bindings = {
  git_commit: "a".repeat(40),
  contract_sha256: "b".repeat(64),
  inventory_sha256: "c".repeat(64),
  host_key_fingerprint: `SHA256:${"A".repeat(43)}`,
  max_observation_age_seconds: 1800,
};
const proposal = {
  observed_at: "2026-08-28T08:29:00Z",
  proposal_sha256: "d".repeat(64),
  solver: { returncode: 0 },
  holds: [],
  change_counts: { install: 0, upgrade: 1, downgrade: 0, remove: 0 },
  changes: [{ action: "upgrade", name: "fixture", previous_version: "1", candidate_version: "2", origin: "Debian-Security", security: true }],
};
const packageEvidence = {
  contract_host: "debian",
  proposal,
  proposal_valid: true,
  metadata_fresh: true,
  apply_authorized: false,
  apply_blockers: ["saved-reviewed-plan-required"],
};
const packagePlan = buildPlan({ kind: "package", host: "debian", evidence: packageEvidence, bindings, nowEpoch });
assert.equal(packagePlan.format, "home-lab-host-maintenance-plan-v1");
assert.equal(packagePlan.actionable, true);
assert.equal(packagePlan.authorized, false);
assert.deepEqual(packagePlan.evidence.changes, proposal.changes);
assert.match(packagePlan.plan_sha256, /^[0-9a-f]{64}$/);
assert.equal(
  packagePlan.plan_sha256,
  buildPlan({ kind: "package", host: "debian", evidence: structuredClone(packageEvidence), bindings: structuredClone(bindings), nowEpoch }).plan_sha256,
);

const rebootEvidence = {
  contract_host: "debian",
  evidence: {
    observed_at: "2026-08-28T08:29:30Z",
    evidence_sha256: "e".repeat(64),
    current_kernel: "6.12.101+deb13-amd64",
    target_kernel: "6.12.105+deb13-amd64",
    boot_id: "87b6fad8-db9a-46fa-bf0d-68b9b28237f3",
  },
  blockers: ["expected-current-kernel-missing"],
  preconditions_met: false,
  plan_inputs_complete: false,
  reboot_authorized: false,
};
const rebootPlan = buildPlan({ kind: "reboot", host: "debian", evidence: rebootEvidence, bindings, nowEpoch });
assert.equal(rebootPlan.actionable, false);
assert.equal(rebootPlan.authorized, false);
assert.deepEqual(rebootPlan.blockers, rebootEvidence.blockers);

const syntheticLog = `prefix\n{"package_lifecycle_observation":${JSON.stringify(packageEvidence)}}\nmiddle\n{"package_lifecycle_observation":${JSON.stringify({ ...packageEvidence, contract_host: "proxmox" })}}\n`;
const extracted = extractObservations(syntheticLog, "package_lifecycle_observation");
assert.equal(extracted.length, 2);
assert.equal(extracted[0].contract_host, "debian");
assert.equal(extracted[1].contract_host, "proxmox");
assert.throws(() => extractObservations('{"fixture": {', "fixture"), /truncated/);

const unsafeRemoval = structuredClone(packageEvidence);
unsafeRemoval.proposal.change_counts.remove = 1;
assert.throws(() => buildPlan({ kind: "package", host: "debian", evidence: unsafeRemoval, bindings, nowEpoch }), /not safe/);
assert.throws(
  () => buildPlan({ kind: "package", host: "debian", evidence: packageEvidence, bindings, nowEpoch: nowEpoch + 3600 }),
  /stale/,
);
const wrongHost = structuredClone(packageEvidence);
wrongHost.contract_host = "proxmox";
assert.throws(() => buildPlan({ kind: "package", host: "debian", evidence: wrongHost, bindings, nowEpoch }), /host binding/);

const source = fs.readFileSync(path.join(__dirname, "save-host-maintenance-plan.js"), "utf8");
for (const required of [
  "--porcelain",
  "--untracked-files=all",
  "O_EXCL",
  "0o600",
  'authorized: false',
  'maintenance plans require a clean worktree',
]) {
  assert(source.includes(required), `saved maintenance planner omits ${required}`);
}
assert(!source.includes("execSync("), "saved maintenance planner must not invoke a shell");
assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}\n');

console.log("saved_host_maintenance_plan=verified");
