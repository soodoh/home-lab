#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const { load } = require("js-yaml");
const { globRegex, validateResticPolicy } = require("./validate-restic-policy");

const base = load(fs.readFileSync("infrastructure/contract/home-lab.yml", "utf8")).backups.restic;
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
fixture.proton.hard_failure_used_bytes = 966367641600;
assert(validateResticPolicy(fixture).some((failure) => failure.includes("decimal")));

console.log("restic_policy_semantics=verified");
