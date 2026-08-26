#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const Ajv2020 = require("ajv/dist/2020");
const { load } = require("js-yaml");
const { globRegex, validateProtonQualificationEvidence, validateResticPolicy } = require("./validate-restic-policy");

const base = load(fs.readFileSync("infrastructure/contract/home-lab.yml", "utf8")).backups.restic;
const qualificationEvidenceSchema = JSON.parse(fs.readFileSync("infrastructure/evidence/proton-qualification.schema.json", "utf8"));
const validateQualificationEvidenceSchema = new Ajv2020({ allErrors: true, strict: true }).compile(qualificationEvidenceSchema);
const clone = () => structuredClone(base);
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
fixture.credentials = { bootstrap_enabled: true, state: "provisioned" };
fixture.qualification.state = "ready";
fixture.qualification.username_sha256 = "a".repeat(64);
fixture.qualification.evidence_sha256 = null;
fixture.qualification.verified_at = null;
assert.deepEqual(validateResticPolicy(fixture), []);

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

console.log("restic_policy_semantics=verified");
