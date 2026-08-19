#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const cutover = contract.debian.cutover.production_cutover;
const lockPath = path.join(root, cutover.image_lock);
const lockBody = fs.readFileSync(lockPath);
const lock = JSON.parse(lockBody);
const keyGenerator = fs.readFileSync(path.join(root, "scripts/controller/create-debian-production-tailscale-key.py"), "utf8");

assert.equal(contract.debian.cutover.stage, "production-canary");
assert.equal(cutover.phase, "designed");
assert.equal(cutover.scope, "full-compose-and-tailscale");
assert.equal(cutover.compose_artifact_sha256, "d23478a665cfc668efc8bf1296783f05b75a8c84080758c33eb264f45f1e3d5c");
assert.equal(cutover.model_inventory_sha256, "f36ba480734143d51affdc789b2ef782bee063dfb96a248d5048568a82f5a16e");
assert.equal(crypto.createHash("sha256").update(lockBody).digest("hex"), cutover.image_lock_sha256);
assert.equal(lock.schema, 1);
assert.equal(lock.project, "docker-compose");
assert.equal(lock.images.length, cutover.image_service_count);
assert.equal(new Set(lock.images.map((image) => image.service)).size, 41);
assert.equal(new Set(lock.images.map((image) => image.image_id)).size, cutover.unique_image_count);
assert.ok(lock.images.every((image) => /^sha256:[0-9a-f]{64}$/.test(image.image_id)));
assert.ok(lock.images.every((image) => image.repo_digests.length > 0));
assert.equal(cutover.pulls, "disabled");
assert.equal(cutover.tailscale_enrollment, "one-use-preauthorized-key");
assert.equal(cutover.tailscale_tag, "tag:docker-host");
assert.equal(cutover.tailscale_hostname, "docker-host-debian");
assert.equal(cutover.tailscale_key_delivery, "age-encrypted-debian-recipient");
assert.equal(cutover.tailscale_key_artifact, "not-generated");
assert.equal(cutover.production_boot, "pending-physical-reboot-verification");
assert.deepEqual(cutover.rollback_boot_order, ["scsi0", "net0"]);
assert.equal(cutover.rollback_requires_physical_reboot, true);
assert.match(keyGenerator, /reusable": False/);
assert.match(keyGenerator, /ephemeral": False/);
assert.match(keyGenerator, /preauthorized": True/);
assert.match(keyGenerator, /"tags": \[TAG\]/);
assert.match(keyGenerator, /age", "--encrypt", "--recipient", RECIPIENT/);
assert.match(keyGenerator, /"plaintextRetained": False/);
assert.doesNotMatch(keyGenerator, /print\(auth_key|write_text\(auth_key/);

process.stdout.write("debian production cutover tests passed\n");
