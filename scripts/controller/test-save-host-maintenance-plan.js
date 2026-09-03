#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Ajv2020 = require("ajv/dist/2020");
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
  max_metadata_age_seconds: 86400,
};
const proposal = {
  version: 2,
  host: "debian",
  observed_at: "2026-08-28T08:29:00Z",
  metadata_mtime_epoch: nowEpoch - 120,
  metadata_age_seconds: 120,
  installed_inventory_format: "dpkg-query-status-tsv-v1",
  installed_records: 100,
  installed_inventory_sha256: "d".repeat(64),
  installed_package_records: 100,
  installed_status_sha256: "e".repeat(64),
  expected_manifest_records: 0,
  expected_manifest_sha256: "f".repeat(64),
  manifest_matches: true,
  solver: { returncode: 0, stdout_sha256: "1".repeat(64), stderr_sha256: "2".repeat(64) },
  holds: [],
  kept_back: [],
  download_bytes: 1024,
  disk_delta_bytes: 512,
  apt_tree_safe: true,
  apt_unsafe_paths: [],
  size_parse_complete: true,
  active_lifecycle_locks: [],
  apt_state_hashes: {
    configuration_sha256: "3".repeat(64),
    keyrings_sha256: "4".repeat(64),
    sources_sha256: "5".repeat(64),
  },
  change_counts: { install: 0, upgrade: 1, downgrade: 0, remove: 0 },
  security_changes: 1,
  changes: [{ action: "upgrade", name: "fixture", previous_version: "1", candidate_version: "2", origin: "Debian-Security", policy_sha256: "6".repeat(64), security: true }],
};
const proposalMaterial = {
  host: proposal.host,
  installed_inventory_sha256: proposal.installed_inventory_sha256,
  metadata_mtime_epoch: proposal.metadata_mtime_epoch,
  holds: proposal.holds,
  solver_stdout_sha256: proposal.solver.stdout_sha256,
  changes: proposal.changes,
  installed_status_sha256: proposal.installed_status_sha256,
  expected_manifest_sha256: proposal.expected_manifest_sha256,
  manifest_matches: proposal.manifest_matches,
  apt_state_hashes: proposal.apt_state_hashes,
  apt_tree_safe: proposal.apt_tree_safe,
  apt_unsafe_paths: proposal.apt_unsafe_paths,
  active_lifecycle_locks: proposal.active_lifecycle_locks,
  kept_back: proposal.kept_back,
  download_bytes: proposal.download_bytes,
  disk_delta_bytes: proposal.disk_delta_bytes,
  size_parse_complete: proposal.size_parse_complete,
};
proposal.proposal_sha256 = crypto.createHash("sha256").update(canonicalJson(proposalMaterial).trimEnd()).digest("hex");
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
assert.equal(packagePlan.actionable, false);
assert.equal(packagePlan.authorized, false);
assert.deepEqual(packagePlan.evidence.changes, proposal.changes);
assert.equal(packagePlan.package_transaction_lock.automatic_apply, false);
assert.equal(packagePlan.package_transaction_lock.authorized, false);
assert.deepEqual(packagePlan.package_transaction_lock.transaction.exact_install_specs, ["fixture=2"]);
assert.equal(packagePlan.package_transaction_lock.transaction.affected_services, null);
assert(packagePlan.blockers.includes("impact-review-required"));
assert(packagePlan.blockers.includes("separate-exact-authorization-required"));
assert.match(packagePlan.package_transaction_lock.transaction_sha256, /^[0-9a-f]{64}$/);
assert.match(packagePlan.plan_sha256, /^[0-9a-f]{64}$/);
assert.equal(
  packagePlan.plan_sha256,
  buildPlan({ kind: "package", host: "debian", evidence: structuredClone(packageEvidence), bindings: structuredClone(bindings), nowEpoch }).plan_sha256,
);

const lockSchema = JSON.parse(fs.readFileSync(path.join(__dirname, "../../infrastructure/maintenance/package-transaction-lock.schema.json")));
const validateLock = new Ajv2020({ allErrors: true, strict: true, formats: { "date-time": true } }).compile(lockSchema);
assert(validateLock(packagePlan.package_transaction_lock), JSON.stringify(validateLock.errors));
const tamperedProposal = structuredClone(packageEvidence);
tamperedProposal.proposal.changes[0].origin = "unreviewed-origin";
assert.throws(() => buildPlan({ kind: "package", host: "debian", evidence: tamperedProposal, bindings, nowEpoch }), /hash differs/);
const missingAptBinding = structuredClone(packageEvidence);
delete missingAptBinding.proposal.apt_state_hashes.sources_sha256;
assert.throws(() => buildPlan({ kind: "package", host: "debian", evidence: missingAptBinding, bindings, nowEpoch }), /APT sources/);
const staleMetadataBindings = { ...bindings, max_metadata_age_seconds: 60 };
assert.throws(() => buildPlan({ kind: "package", host: "debian", evidence: packageEvidence, bindings: staleMetadataBindings, nowEpoch }), /metadata is stale/);

const rebootPayload = {
  observed_at: "2026-08-28T08:29:30Z",
  host: "debian",
  current_kernel: "6.12.101+deb13-amd64",
  target_kernel: "6.12.105+deb13-amd64",
  installed_kernels: ["6.12.101+deb13-amd64", "6.12.105+deb13-amd64"],
  boot_id: "87b6fad8-db9a-46fa-bf0d-68b9b28237f3",
  reboot_required_file: true,
  reboot_required_packages: ["linux-image-amd64"],
  health: { compose_service: "active", mounts: { "/mnt/storage": true } },
  backup: { durable_chain_clear: true },
  backup_unit_states: { "home-lab-restic-daily.target": "inactive" },
  active_conflict_locks: [],
  tailscale_backend_state: "Running",
  window_eligible: true,
  pending_package_transaction_sha256: "9".repeat(64),
  reboot_indicated: true,
};
const rebootMaterial = Object.fromEntries([
  "host", "boot_id", "current_kernel", "installed_kernels", "target_kernel", "reboot_required_file",
  "reboot_required_packages", "health", "backup", "backup_unit_states", "active_conflict_locks",
  "tailscale_backend_state", "window_eligible", "pending_package_transaction_sha256",
].map((name) => [name, rebootPayload[name]]));
rebootPayload.evidence_sha256 = crypto.createHash("sha256").update(canonicalJson(rebootMaterial).trimEnd()).digest("hex");
const rebootEvidence = {
  contract_host: "debian",
  evidence: rebootPayload,
  expected: { current_kernel: rebootPayload.current_kernel, target_kernel: rebootPayload.target_kernel, boot_id: rebootPayload.boot_id },
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
