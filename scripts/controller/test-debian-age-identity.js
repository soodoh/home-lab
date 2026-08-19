#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "infrastructure/debian/prepare-age-identity.sh"), "utf8");
const coordinator = fs.readFileSync(path.join(root, "scripts/qualify-debian-inert"), "utf8");
const runner = fs.readFileSync(path.join(root, "scripts/run-debian-age-identity-preparation"), "utf8");
const finalizer = fs.readFileSync(path.join(root, "scripts/finalize-debian-age-identity"), "utf8");
const sopsConfig = fs.readFileSync(path.join(root, ".sops.yaml"), "utf8");
const stage = contract.debian.cutover.credentials_stage;

assert.equal(contract.debian.cutover.stage, "storage-rehearsed");
assert.equal(stage.phase, "recipient-committed");
assert.equal(stage.identity_path, "/etc/sops/age/keys.txt");
assert.equal(stage.recipient_evidence, "infrastructure/evidence/vm-100-debian-age-identity.json");
assert.equal(stage.recipient_commit_evidence, "infrastructure/evidence/vm-100-debian-sops-recipient.json");
assert.equal(stage.private_identity_exported, false);
assert.equal(stage.expected_sops_recipient_count, 3);
assert.equal(stage.current_compose_artifact_sha256, "d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c");
const evidence = JSON.parse(fs.readFileSync(path.join(root, stage.recipient_evidence), "utf8"));
assert.equal(evidence.stage, "identity-generated");
assert.equal(evidence.identityEvidence.transitionState, "complete");
assert.equal(evidence.identityEvidence.archRestore, "verified");
assert.equal(evidence.identityEvidence.privateIdentityExported, false);
assert.match(evidence.identityEvidence.recipient, /^age1[0-9a-z]{58}$/);
assert.notEqual(evidence.identityEvidence.hostBootIdBefore, evidence.identityEvidence.hostBootIdAfter);
const recipientEvidence = JSON.parse(fs.readFileSync(path.join(root, stage.recipient_commit_evidence), "utf8"));
assert.equal(recipientEvidence.stage, "recipient-committed");
assert.equal(recipientEvidence.validation.plaintextUnchanged, true);
assert.equal(recipientEvidence.validation.variableCount, 90);
assert.equal(recipientEvidence.validation.recipientCount, 3);
assert.equal(recipientEvidence.validation.composeArtifactSha256, stage.current_compose_artifact_sha256);
assert.deepEqual(new Set(recipientEvidence.recipients), new Set(sopsConfig.match(/age1[0-9a-z]{58}/g)));
assert.equal(recipientEvidence.safety.debianPrivateIdentityExported, false);
assert.ok(script.includes(`readonly SOPS_SHA256=${stage.sops_sha256}`));
assert.ok(script.includes(`readonly AGE_ARCHIVE_SHA256=${stage.age_archive_sha256}`));
assert.ok(script.includes(`readonly AGE_SHA256=${stage.age_sha256}`));
assert.ok(script.includes(`readonly AGE_KEYGEN_SHA256=${stage.age_keygen_sha256}`));
assert.match(script, /curl --fail --location --proto '=https' --tlsv1\.2/);
assert.match(script, /mapfile -t archive_entries/);
assert.match(script, /age-keygen -o "\$IDENTITY_FILE" >\/dev\/null 2>&1/);
assert.match(script, /age-keygen -y "\$IDENTITY_FILE"/);
assert.match(script, /identityMetadata:"root:root:600"/);
assert.match(script, /privateIdentityExported:false/);
assert.match(script, /\[\[ ! -e \/etc\/docker-compose \]\]/);
assert.match(script, /verify_inert/);
assert.doesNotMatch(script, /gpg|scp|rsync|cat .*keys\.txt|SOPS_AGE_KEY=/);

assert.ok(coordinator.includes("identity_sha=ecd1bb1849340a29386836c778f966b5c2b66077cde375412e38f832cad23d57"));
assert.match(coordinator, /write_identity_pending_evidence "\$identity_marker"/);
assert.match(coordinator, /mark_identity_evidence_awaiting_reboot "\$arch_reboot_config_sha"/);
assert.match(coordinator, /home-lab-debian-age-transition-v1/);
assert.match(coordinator, /finalize_identity_mode == true/);
assert.match(coordinator, /privateIdentityExported == false/);
assert.match(coordinator, /verify_arch_post_restore[\s\S]*mv -T "\$finalize_evidence" "\$IDENTITY_LOG"/);
assert.ok(runner.includes("readonly CONFIRMATION=prepare-reviewed-vm-100-debian-age-identity"));
assert.ok(finalizer.includes("readonly CONFIRMATION=finalize-reviewed-vm-100-debian-age-after-reboot"));
for (const wrapper of [runner, finalizer]) {
  assert.match(wrapper, /\[\[ -t 0 \]\]/);
  assert.match(wrapper, /exec "\$root\/scripts\/qualify-debian-inert"/);
}

process.stdout.write("debian age identity tests passed\n");
