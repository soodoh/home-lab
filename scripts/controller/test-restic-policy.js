#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const Ajv2020 = require("ajv/dist/2020");
const { load } = require("js-yaml");
const { globRegex, validateProtonQualificationEvidence, validateResticInitializationEvidence, validateResticFirstRunEvidence, validateResticPolicy } = require("./validate-restic-policy");

const base = load(fs.readFileSync("infrastructure/contract/home-lab.yml", "utf8")).backups.restic;
const qualificationEvidenceSchema = JSON.parse(fs.readFileSync("infrastructure/evidence/proton-qualification.schema.json", "utf8"));
const initializationEvidenceSchema = JSON.parse(fs.readFileSync("infrastructure/evidence/restic-repository-initialization.schema.json", "utf8"));
const firstRunEvidenceSchema = JSON.parse(fs.readFileSync("infrastructure/evidence/restic-first-run.schema.json", "utf8"));
const validateQualificationEvidenceSchema = new Ajv2020({ allErrors: true, strict: true }).compile(qualificationEvidenceSchema);
new Ajv2020({ allErrors: true, strict: true }).compile(initializationEvidenceSchema);
const validateFirstRunSchema = new Ajv2020({ allErrors: true, strict: true }).compile(firstRunEvidenceSchema);
const clone = () => structuredClone(base);
const resetInitializationReady = (value) => {
  value.initialization.state = "ready";
  value.initialization.source_policy_sha256 = null;
  value.initialization.evidence_sha256 = null;
  value.initialization.verified_at = null;
  for (const repository of Object.values(value.repositories)) repository.id = null;
};
const resetFirstRunReady = (value) => {
  value.first_run.state = "ready";
  value.first_run.source_policy_sha256 = null;
  value.first_run.artifact_sha256 = null;
  value.first_run.aws_evidence_sha256 = null;
  value.first_run.evidence_sha256 = null;
  value.first_run.completed_at = null;
  value.first_run.baseline = { games: [], nfs: [], proton: [] };
  value.first_run.snapshots = { games: null, nfs: null, proton: null };
};
assert.deepEqual(validateResticPolicy(base), []);
assert(globRegex("/srv/**/cache/**").test("/srv/cache/value"));
assert(globRegex("/srv/**/cache/**").test("/srv/app/nested/cache/value"));

let fixture = clone();
fixture.classified_paths.push({ path: fixture.sources[0].path, class: "preserve", owner_services: ["fixture"] });
assert(validateResticPolicy(fixture).some((failure) => failure.includes("exactly one class")));

fixture = clone();
fixture.classified_paths.push({ path: `${fixture.sources[0].path}/user-data`, class: "external", owner_services: ["fixture"] });
assert(validateResticPolicy(fixture).some((failure) => failure.includes("replace-tree")));
fixture = clone();
fixture.classified_paths.push({ path: `${fixture.sources[0].path}/cache`, class: "regenerate", owner_services: ["fixture"] });
assert(validateResticPolicy(fixture).some((failure) => failure.includes("replace-tree")));

fixture = clone();
fixture.sources[0].path = `${fixture.repositories.games.path}/source`;
assert(validateResticPolicy(fixture).some((failure) => failure.includes("under repository")));

fixture = clone();
fixture.excludes.push(fixture.critical_fixtures[0]);
assert(validateResticPolicy(fixture).some((failure) => failure.includes("critical fixture")));
fixture = clone();
fixture.excludes = fixture.excludes.filter((pattern) => pattern !== "/srv/home-lab-state/jellyfin-data/config/.cache/**");
assert(validateResticPolicy(fixture).some((failure) => failure.includes("Offen equivalent")));

fixture = clone();
fixture.sources.find((entry) => entry.mutable_database).writers = ["undeclared-writer"];
assert(validateResticPolicy(fixture).some((failure) => failure.includes("not stopped")));

fixture = clone();
fixture.sources = fixture.sources.map((entry) => ({ ...entry, writers: entry.writers.filter((writer) => writer !== fixture.stop_groups.applications[0]) }));
assert(validateResticPolicy(fixture).some((failure) => failure.includes("no backed-up state")));

fixture = clone();
fixture.retention.keep_daily = 8;
assert(validateResticPolicy(fixture).some((failure) => failure.includes("retention invariants")));

fixture = clone();
fixture.proton.trash_cleanup = "automatic";
assert(validateResticPolicy(fixture).some((failure) => failure.includes("manual-only")));

fixture = clone();
fixture.classified_paths.find((entry) => entry.path === "/mnt/storage/media/caro-tachidesk").class = "preserve";
assert(validateResticPolicy(fixture).some((failure) => failure.includes("must be external")));

fixture = clone();
fixture.restore.modes = ["fresh", "in-place"];
fixture.restore.activation_status = "available";
assert(validateResticPolicy(fixture).some((failure) => failure.includes("must not advertise")));

fixture = clone();
fixture.proton.minimum_free_bytes = 107374182400;
assert(validateResticPolicy(fixture).some((failure) => failure.includes("decimal")));

fixture = clone();
resetInitializationReady(fixture);
fixture.credentials = { bootstrap_enabled: true, state: "provisioned" };
fixture.qualification.state = "ready";
fixture.qualification.username_sha256 = "a".repeat(64);
fixture.qualification.evidence_sha256 = null;
fixture.qualification.verified_at = null;
assert(validateResticPolicy(fixture).some((failure) => failure.includes("ready repository initialization")));

fixture = clone();
fixture.credentials = { bootstrap_enabled: true, state: "provisioned" };
fixture.qualification.state = "pending";
fixture.qualification.username_sha256 = null;
assert(validateResticPolicy(fixture).some((failure) => failure.includes("pending Proton qualification")));

fixture = clone();
fixture.credentials = { bootstrap_enabled: false, state: "absent" };
fixture.qualification.state = "ready";
assert(validateResticPolicy(fixture).some((failure) => failure.includes("ready Proton qualification")));

fixture = clone();
fixture.credentials = { bootstrap_enabled: true, state: "provisioned" };
fixture.qualification.state = "qualified";
fixture.qualification.username_sha256 = "a".repeat(64);
fixture.qualification.verified_at = "2026-08-24T18:00:00Z";
const qualificationEvidence = {
  account_username_sha256: fixture.qualification.username_sha256,
  minimum_allocated_bytes: 1000000000000,
  observed_total_bytes: 1073741824000,
  cache_invalidation: "pass",
  fixture_bytes: 4096,
  fixture_sha256: "c".repeat(64),
  free_bytes: 800000000000,
  operations: ["about", "lsjson", "copyto", "cat", "moveto", "deletefile", "rmdir"],
  original_file_size: "pass",
  password_reauthentication: "pass",
  range_count: 1024,
  range_offset: 1024,
  remote_cleanup: "pass",
  replace_existing_draft: "configured",
  state: "qualified",
  trash_cleanup: "manual-only",
  used_bytes: 200000000000,
  verified_at: fixture.qualification.verified_at,
  version: 1,
};
assert(validateQualificationEvidenceSchema(qualificationEvidence));
const rawQualificationEvidence = Buffer.from(`${JSON.stringify(qualificationEvidence)}\n`);
fixture.qualification.evidence_sha256 = crypto.createHash("sha256").update(rawQualificationEvidence).digest("hex");
assert.deepEqual(validateResticPolicy(fixture), []);
assert.deepEqual(validateProtonQualificationEvidence(fixture, qualificationEvidence, rawQualificationEvidence), []);
assert(validateProtonQualificationEvidence(fixture, qualificationEvidence, Buffer.from("{}\n"))
  .some((failure) => failure.includes("SHA-256")));

fixture = clone();
resetInitializationReady(fixture);
fixture.repositories.games.id = "a".repeat(64);
assert(validateResticPolicy(fixture).some((failure) => failure.includes("three absent repositories")));
fixture = clone();
fixture.initialization.state = "initialized";
fixture.repositories.games.id = "a".repeat(64);
fixture.repositories.nfs.id = "b".repeat(64);
fixture.repositories.proton.id = "c".repeat(64);
fixture.initialization.source_policy_sha256 = "d".repeat(64);
fixture.initialization.evidence_sha256 = "e".repeat(64);
fixture.initialization.verified_at = "2026-08-26T01:00:00Z";
assert.deepEqual(validateResticPolicy(fixture), []);
const initializationEvidence = {
  version: 1, type: "restic-repository-initialization", state: "initialized",
  source_policy_sha256: fixture.initialization.source_policy_sha256,
  lock_owner_sha256: "f".repeat(64), helper_sha256: fixture.initialization.helper_sha256,
  restic_sha256: fixture.tools.restic.installed_sha256, rclone_sha256: fixture.tools.rclone.installed_sha256,
  qualification_evidence_sha256: fixture.qualification.evidence_sha256,
  account_username_sha256: fixture.qualification.username_sha256,
  repository_ids: { games: fixture.repositories.games.id, nfs: fixture.repositories.nfs.id, proton: fixture.repositories.proton.id },
  chunker_polynomial: "1234abcd",
  operations: ["init-games", "init-nfs-from-games-copy-chunker-params", "normalize-games-access", "init-proton-from-games-copy-chunker-params"],
  mounts: { games: "pass", nfs: "pass" }, proton_minimum_allocated_bytes: 1000000000000,
  proton_minimum_free_bytes: 100000000000, proton_observed_total_bytes: 1073741824000,
  proton_observed_free_bytes: 1073741824000, started_at: "2026-08-26T00:59:00Z", completed_at: fixture.initialization.verified_at,
};
assert(new Ajv2020({ allErrors: true, strict: true }).compile(initializationEvidenceSchema)(initializationEvidence));
const rawInitializationEvidence = Buffer.from(`${JSON.stringify(initializationEvidence)}\n`);
fixture.initialization.evidence_sha256 = crypto.createHash("sha256").update(rawInitializationEvidence).digest("hex");
assert.deepEqual(validateResticInitializationEvidence(fixture, initializationEvidence, rawInitializationEvidence), []);
fixture.repositories.proton.id = fixture.repositories.nfs.id;
assert(validateResticPolicy(fixture).some((failure) => failure.includes("three distinct IDs")));

fixture = clone();
fixture.first_run.baseline.games = ["a".repeat(64)];
assert(validateResticPolicy(fixture).some((failure) => failure.includes("three empty repositories")));
fixture = clone();
resetFirstRunReady(fixture);
fixture.first_run.snapshots.games = "a".repeat(64);
assert(validateResticPolicy(fixture).some((failure) => failure.includes("ready Restic first run")));
fixture = clone();
fixture.first_run.state = "completed";
fixture.first_run.source_policy_sha256 = "a".repeat(64);
fixture.first_run.artifact_sha256 = "b".repeat(64);
fixture.first_run.aws_evidence_sha256 = "c".repeat(64);
fixture.first_run.completed_at = "2026-08-26T02:00:00Z";
fixture.first_run.snapshots = { games: "d".repeat(64), nfs: "e".repeat(64), proton: "f".repeat(64) };
const firstRunEvidence = {
  version: 1, type: "restic-first-run", state: "completed", lock_owner_sha256: "1".repeat(64),
  source_policy_sha256: fixture.first_run.source_policy_sha256, artifact_sha256: fixture.first_run.artifact_sha256,
  aws_evidence_sha256: fixture.first_run.aws_evidence_sha256, helper_sha256: fixture.first_run.helper_sha256,
  runner_sha256: fixture.runner.sha256, restic_sha256: fixture.tools.restic.installed_sha256, rclone_sha256: fixture.tools.rclone.installed_sha256,
  initialization_evidence_sha256: fixture.initialization.evidence_sha256, qualification_evidence_sha256: fixture.qualification.evidence_sha256,
  repository_ids: Object.fromEntries(Object.entries(fixture.repositories).map(([name, value]) => [name, value.id])), snapshots: fixture.first_run.snapshots,
  initially_running_writers: [], stopped_writers: [], restarted_writers: [], writers_healthy: "pass",
  repository_checks: { games: true, nfs: true, proton: true }, retention: { games: true, nfs: true, proton: true },
  quota: { used: 1, free: 1073741824000, total: 1073741824000, active: 1, warning: 0 },
  timers: { daily_timer: "disabled-inactive", maintenance_timer: "disabled-inactive" },
  started_at: "2026-08-26T01:00:00Z", completed_at: fixture.first_run.completed_at,
};
assert(validateFirstRunSchema(firstRunEvidence));
const rawFirstRun = Buffer.from(`${JSON.stringify(firstRunEvidence)}\n`);
fixture.first_run.evidence_sha256 = crypto.createHash("sha256").update(rawFirstRun).digest("hex");
assert.deepEqual(validateResticPolicy(fixture), []);
assert.deepEqual(validateResticFirstRunEvidence(fixture, firstRunEvidence, rawFirstRun), []);

console.log("restic_policy_semantics=verified");
