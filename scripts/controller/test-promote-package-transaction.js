#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Ajv2020 = require("ajv/dist/2020");
const { load } = require("js-yaml");
const { buildCandidateLock, canonicalJson: candidateJson } = require("./package-transaction-lock");
const { canonicalJson, promote, sealReview } = require("./promote-package-transaction");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const change = { action: "upgrade", candidate_version: "2", name: "fixture", origin: "Debian:stable-security",
  policy_sha256: "6".repeat(64), previous_version: "1", security: true };
const proposal = {
  version: 2, host: "debian", observed_at: "2026-09-03T08:29:00Z", metadata_mtime_epoch: 1,
  metadata_age_seconds: 120, installed_inventory_sha256: "1".repeat(64), installed_status_sha256: "2".repeat(64),
  expected_manifest_sha256: "3".repeat(64), manifest_matches: true, holds: [], kept_back: [],
  apt_state_hashes: { configuration_sha256: "4".repeat(64), keyrings_sha256: "5".repeat(64), sources_sha256: "7".repeat(64) },
  apt_tree_safe: true, apt_unsafe_paths: [], active_lifecycle_locks: [], size_parse_complete: true,
  download_bytes: 1000, disk_delta_bytes: 500, solver: { returncode: 0, stdout_sha256: "8".repeat(64) },
  changes: [change], change_counts: { install: 0, upgrade: 1, downgrade: 0, remove: 0 }, security_changes: 1,
};
const proposalMaterial = {
  host: proposal.host, installed_inventory_sha256: proposal.installed_inventory_sha256,
  metadata_mtime_epoch: proposal.metadata_mtime_epoch, holds: proposal.holds,
  solver_stdout_sha256: proposal.solver.stdout_sha256, changes: proposal.changes,
  installed_status_sha256: proposal.installed_status_sha256, expected_manifest_sha256: proposal.expected_manifest_sha256,
  manifest_matches: proposal.manifest_matches, apt_state_hashes: proposal.apt_state_hashes,
  apt_tree_safe: proposal.apt_tree_safe, apt_unsafe_paths: proposal.apt_unsafe_paths,
  active_lifecycle_locks: proposal.active_lifecycle_locks, kept_back: proposal.kept_back,
  download_bytes: proposal.download_bytes, disk_delta_bytes: proposal.disk_delta_bytes,
  size_parse_complete: proposal.size_parse_complete,
};
proposal.proposal_sha256 = hash(candidateJson(proposalMaterial, false));
const candidate = buildCandidateLock({
  host: "debian", lifecycle: "production", proposal,
  bindings: { git_commit: "a".repeat(40), contract_sha256: "b".repeat(64), inventory_sha256: "c".repeat(64),
    host_key_fingerprint: `SHA256:${"A".repeat(43)}`, max_metadata_age_seconds: 86400 },
  generatedAt: "2026-09-03T08:30:00Z", expiresAt: "2026-09-03T08:59:00Z",
});
const reviewMaterial = {
  format: "home-lab-package-impact-review-v1", version: 1, host: "debian",
  created_at: "2026-09-03T08:31:00Z", expires_at: "2026-09-03T08:50:00Z", reviewer: "fixture-reviewer",
  candidate_transaction_sha256: candidate.transaction_sha256,
  changes_sha256: hash(canonicalJson(candidate.transaction.changes)), approved_additions: [],
  approved_removals: [], approved_downgrades: [],
  approved_origins: [{ name: change.name, candidate_version: change.candidate_version, origin: change.origin, policy_sha256: change.policy_sha256 }],
  affected_services: ["cron.service"], protected_services: [], needrestart_assessment: "no-protected-restart",
  reboot_required: false, reboot_reasons: [], lane: "no-restart-safe", automatic_apply: false,
  automatic_reboot: false, authorized: false,
};
const review = sealReview(reviewMaterial);
const finalLock = promote(candidate, review, contract, "2026-09-03T08:32:00Z");
assert.equal(finalLock.actionable, true);
assert.equal(finalLock.authorized, false);
assert.equal(finalLock.automatic_apply, false);
assert.equal(finalLock.automatic_reboot, false);
assert.deepEqual(finalLock.blockers, ["separate-exact-authorization-required"]);
assert.deepEqual(finalLock.transaction.exact_install_specs, ["fixture=2"]);
assert.equal(finalLock.bindings.candidate_transaction_sha256, candidate.transaction_sha256);
assert.match(finalLock.final_sha256, /^[0-9a-f]{64}$/);

const ajv = new Ajv2020({ allErrors: true, strict: true, formats: { "date-time": true } });
for (const [name, value] of [["package-impact-review.schema.json", review], ["package-transaction-final.schema.json", finalLock]]) {
  const schema = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/maintenance", name)));
  const validate = ajv.compile(schema);
  assert(validate(value), JSON.stringify(validate.errors));
}
const wrongOrigin = sealReview({ ...reviewMaterial, approved_origins: [{ ...reviewMaterial.approved_origins[0], origin: "other" }] });
assert.throws(() => promote(candidate, wrongOrigin, contract, "2026-09-03T08:32:00Z"), /origins differ/);
const protectedRestart = sealReview({ ...reviewMaterial, affected_services: ["docker.service"], protected_services: ["docker.service"] });
assert.throws(() => promote(candidate, protectedRestart, contract, "2026-09-03T08:32:00Z"), /disruptive impact/);
assert.throws(() => promote(candidate, review, contract, "2026-09-03T09:00:00Z"), /stale/);
const tamperedReview = { ...review, reviewer: "attacker" };
assert.throws(() => promote(candidate, tamperedReview, contract, "2026-09-03T08:32:00Z"), /hash differs/);
const tamperedCandidate = structuredClone(candidate);
tamperedCandidate.transaction.changes[0].candidate_version = "3";
assert.throws(() => promote(tamperedCandidate, review, contract, "2026-09-03T08:32:00Z"), /candidate hash differs/);
const rebootMismatch = sealReview({ ...reviewMaterial, reboot_required: true });
assert.throws(() => promote(candidate, rebootMismatch, contract, "2026-09-03T08:32:00Z"), /reboot reasons differ/);
assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}\n');
console.log("package_transaction_promotion=verified");
