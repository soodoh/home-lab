#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const config = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../renovate.json"), "utf8"));

const dockerRules = config.packageRules.filter((rule) => rule.matchDatasources?.includes("docker"));
const defaults = dockerRules.filter((rule) => !rule.matchPackageNames);
assert.equal(defaults.length, 1, "one explicit default Docker policy is required");
assert.equal(defaults[0].automerge, false, "Docker updates require manual merge");
assert.equal(defaults[0].pinDigests, true);
assert.equal(defaults[0].groupName, null);
assert.equal(defaults[0].separateMinorPatch, true);
assert.equal(defaults[0].minimumReleaseAge, "3 days");

const canaries = dockerRules.filter((rule) => rule.matchPackageNames?.includes("ghcr.io/flaresolverr/flaresolverr"));
assert.equal(canaries.length, 1, "retain the single FlareSolverr classification rule");
assert.deepEqual(canaries[0].matchPackageNames, ["ghcr.io/flaresolverr/flaresolverr"]);
assert.equal(canaries[0].automerge, false, "FlareSolverr requires explicit manual merge");
assert.equal(canaries[0].minimumReleaseAge, "7 days");
assert.deepEqual(canaries[0].labels, ["dependencies", "compose-canary"]);

// Check nested source settings too: a later exception must not restore automerge.
function checkManualPolicy(value) {
  if (!value || typeof value !== "object") return;
  for (const [key, setting] of Object.entries(value)) {
    if (key === "automerge") assert.equal(setting, false, "source updates must not enable automerge");
    assert.notEqual(key, "automergeType", "remove automerge type permissions");
    assert.notEqual(key, "platformAutomerge", "remove platform automerge permissions");
    checkManualPolicy(setting);
  }
}
checkManualPolicy(config);
console.log("renovate_update_policy=verified manual_merge=true deployment_authorized=false");
