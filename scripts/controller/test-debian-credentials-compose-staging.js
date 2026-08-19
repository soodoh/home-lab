#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "infrastructure/debian/stage-credentials-compose-offline.sh"), "utf8");
const coordinator = fs.readFileSync(path.join(root, "scripts/qualify-debian-inert"), "utf8");
const runner = fs.readFileSync(path.join(root, "scripts/run-debian-credentials-compose-staging"), "utf8");
const finalizer = fs.readFileSync(path.join(root, "scripts/finalize-debian-credentials-compose"), "utf8");
const stage = contract.debian.cutover.credentials_stage;
const artifact = stage.current_compose_artifact_sha256;

assert.equal(stage.phase, "credentials-staged");
assert.equal(stage.compose_validation, "staged-quiet-pass");
assert.equal(stage.staging_evidence, "infrastructure/evidence/vm-100-debian-credentials-compose-staged.json");
assert.equal(stage.docker_runtime, "inactive");
assert.equal(stage.tailscale, "deferred");
const finalEvidence = JSON.parse(fs.readFileSync(path.join(root, stage.staging_evidence), "utf8"));
assert.equal(finalEvidence.stage, "credentials-staged");
assert.equal(finalEvidence.stagingEvidence.transitionState, "complete");
assert.equal(finalEvidence.stagingEvidence.archRestore, "verified");
assert.equal(finalEvidence.stagingEvidence.composeValidation, "quiet-pass");
assert.equal(finalEvidence.stagingEvidence.runtimeEnvironmentInstalled, false);
assert.equal(finalEvidence.stagingEvidence.artifactSha256, stage.current_compose_artifact_sha256);
assert.notEqual(finalEvidence.stagingEvidence.hostBootIdBefore, finalEvidence.stagingEvidence.hostBootIdAfter);
assert.ok(script.includes(`readonly ARTIFACT_SHA256=${artifact}`));
assert.ok(script.includes("readonly DEBIAN_RECIPIENT=age1atumjua6hxyls6z8v20tsgy72304x72lqjstwmwzqy5ma4txyfsse7xakv"));
assert.match(script, /verify_inert \|\| fail/);
assert.match(script, /verify_protected_mounts_absent \|\| fail/);
assert.match(script, /SOPS_AGE_KEY_FILE=\$IDENTITY sops decrypt/);
assert.match(script, /restore-dotenv-layout\.py/);
assert.match(script, /docker compose[\s\S]*config --quiet >\/dev\/null 2>&1/);
assert.match(script, /DOCKER_HOST=unix:\/\/\/run\/home-lab-no-docker\.sock/);
assert.match(script, /compose-model-inventory\.py" desired/);
assert.match(script, /runtimeEnvironmentInstalled:false/);
assert.match(script, /privateIdentityExported:false/);
assert.match(script, /\[\[ ! -e \/etc\/docker-compose\/production\.env/);
assert.doesNotMatch(script, /cat .*production\.env|set -x|tailscale up|docker compose.* up|docker start|systemctl start/);

assert.ok(coordinator.includes("credentials_sha=742fc18c9784da71daafe556ba45a128ca2b67f23b3d0bb6d31b604267994928"));
assert.match(coordinator, /python3 scripts\/compose-artifact\.py copy/);
assert.match(coordinator, /write_credentials_pending_evidence "\$credentials_marker"/);
assert.match(coordinator, /mark_credentials_evidence_awaiting_reboot "\$arch_reboot_config_sha"/);
assert.match(coordinator, /home-lab-debian-credentials-transition-v1/);
assert.match(coordinator, /finalize_credentials_mode == true/);
assert.match(coordinator, /verify_arch_post_restore[\s\S]*mv -T "\$finalize_evidence" "\$CREDENTIALS_LOG"/);
assert.ok(runner.includes("readonly CONFIRMATION=stage-reviewed-vm-100-debian-credentials-compose-offline"));
assert.ok(finalizer.includes("readonly CONFIRMATION=finalize-reviewed-vm-100-debian-credentials-after-reboot"));
for (const wrapper of [runner, finalizer]) {
  assert.match(wrapper, /\[\[ -t 0 \]\]/);
  assert.match(wrapper, /exec "\$root\/scripts\/qualify-debian-inert"/);
}

process.stdout.write("debian credential and Compose staging tests passed\n");
