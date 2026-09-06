#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { canonicalJson } = require("./proxmox-host-projection");
const { build } = require("./build-proxmox-ansible-observer");
const { sha, parse, readRegular, validate, verifyContent, protectedFacts, dependencies } = require("./proxmox-check-evidence");
const ROOT = path.resolve(__dirname, "../..");

function fixture(dir, now = Date.now()) {
  const artifactDir = path.join(dir, "fixture-artifact");
  const manifest = build(artifactDir);
  const observation = JSON.parse(fs.readFileSync(path.join(ROOT, "infrastructure/host-lifecycle/proxmox/fixture-observation.json")));
  observation.observerSha256 = manifest.observer_sha256;
  const observed = Math.floor(now / 1000) * 1000 - 1000;
  const normalized = "{\"hosts\":[\"proxmox-host-production\"],\"plays\":[\"Check the exact locked Proxmox controller observation\"],\"tasks\":[\"Require the fixed audit-only scope\",\"Independently audit the locked observation against the direct contract\"]}\n";
  const value = { format: "home-lab-proxmox-check-evidence-v1", version: 1,
    commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(), dependencies: dependencies(),
    target: "ansible-plan@proxmox", host_key: "SHA256:" + "a".repeat(43), known_hosts_sha256: "b".repeat(64),
    artifact_manifest_sha256: sha(fs.readFileSync(path.join(artifactDir, "manifest.json"))),
    snapshot: { format: "home-lab-proxmox-locked-observation-v1", nonce: "c".repeat(64), observed_at: new Date(observed).toISOString().replace(".000Z", "Z"),
      host_key: "SHA256:" + "a".repeat(43), scope: "audit", locks: "snapshot-exclusive-v1", producer_sha256: manifest.controller_observer_sha256,
      observer_sha256: manifest.observer_sha256, collector_sha256: manifest.private_preparer_sha256, observation },
    observation_sha256: sha(canonicalJson(observation)), protected_facts_sha256: protectedFacts(observation),
    expires_at: new Date(observed + 300000).toISOString().replace(".000Z", "Z"),
    scope: { tags: ["audit"], inventory: "ansible/inventory/proxmox-production.yml", playbook: "ansible/playbooks/proxmox-controller-check.yml",
      normalized, normalized_sha256: sha(normalized),
      recap: { changed: 0, failed: 0, unreachable: 0, ok: 2, skipped: 0, rescued: 0, ignored: 0 } } };
  return value;
}
function main() {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "neutral-evidence-test-"));
  try {
    const now = Date.now(), value = fixture(dir, now), expected = { commit: value.commit, dependencies: value.dependencies, host_key: value.host_key };
    assert.deepEqual(validate(value, expected, now), value);
    const verification = path.join(dir, "verification"); fs.mkdirSync(verification);
    verifyContent(value, verification);
    let rejected = 0;
    const mutations = [
      v => { v.format = "home-lab-proxmox-plan-v1"; }, v => { v.version = 5; }, v => { v.applyEligible = true; },
      v => { v.commit = "d".repeat(40); }, v => { v.dependencies[Object.keys(v.dependencies)[0]] = "e".repeat(64); },
      v => { v.host_key = "SHA256:" + "b".repeat(43); }, v => { v.target = "ansible-deploy@proxmox"; },
      v => { v.snapshot.observed_at = "2000-01-01T00:00:00Z"; }, v => { v.expires_at = "2099-01-01T00:00:00Z"; },
      v => { v.scope.tags = []; }, v => { v.scope.tags = ["audit", "packages"]; }, v => { v.scope.tags = ["packages"]; },
      v => { v.scope.playbook = "ansible/playbooks/proxmox-site.yml"; }, v => { v.scope.inventory = "ansible/inventory/proxmox-bootstrap.yml"; },
      v => { v.scope.normalized += "changed scope"; }, v => { v.scope.recap.changed = 1; }, v => { v.scope.recap.failed = 1; },
      v => { v.scope.recap.ignored = 1; }, v => { v.scope.recap.skipped = 1; }, v => { v.snapshot.locks = "unlocked"; },
      v => { delete v.snapshot.observation.domains.protectedHardware; }, v => { v.protected_facts_sha256 = "0".repeat(64); },
      v => { v.snapshot.observation.domains.vm.matches = false; }, v => { v.snapshot.observation.extra = true; },
    ];
    for (const mutate of mutations) { const invalid = structuredClone(value); mutate(invalid); assert.throws(() => validate(invalid, expected, now)); rejected++; }
    assert.throws(() => validate(value, expected, Date.parse(value.snapshot.observed_at) - 1));
    assert.throws(() => validate(value, expected, Date.parse(value.expires_at)));
    // Producer and complete-domain checks cannot be bypassed by recalculating envelope digests.
    for (const mutate of [v => { v.snapshot.producer_sha256 = "f".repeat(64); }, v => { v.snapshot.collector_sha256 = "f".repeat(64); },
      v => { v.snapshot.observation.domains.protectedHardware.matches = false; }]) {
      const invalid = structuredClone(value); mutate(invalid);
      const testDir = fs.mkdtempSync(path.join(dir, "producer-"));
      assert.throws(() => verifyContent(invalid, testDir));
    }
    const raw = Buffer.from(canonicalJson(value));
    assert.deepEqual(parse(raw), value);
    for (const noncanonical of [Buffer.from(raw.toString().replace('"version":1', '"version":1,"version":1')), Buffer.from(raw + " "), Buffer.alloc(2 * 1024 * 1024 + 1)]) assert.throws(() => parse(noncanonical));
    const file = path.join(dir, "evidence.json"); fs.writeFileSync(file, raw, { mode: 0o600 });
    assert(readRegular(file, raw.length, true).equals(raw));
    assert.throws(() => readRegular(file, raw.length - 1));
    const link = path.join(dir, "symlink"); fs.symlinkSync(file, link); assert.throws(() => readRegular(link));
    const hardlink = path.join(dir, "hardlink"); fs.linkSync(file, hardlink); assert.throws(() => readRegular(file)); fs.unlinkSync(hardlink);
    fs.chmodSync(file, 0o644); assert.throws(() => readRegular(file, raw.length, true));
    const fifo = path.join(dir, "fifo"); execFileSync("mkfifo", [fifo]); assert.throws(() => readRegular(fifo));
    const ancestor = path.join(dir, "alias"); fs.symlinkSync(dir, ancestor); assert.throws(() => readRegular(path.join(ancestor, "evidence.json")));
    console.log(`neutral_check_evidence=passed hostile_mutations=${rejected} canonical_metadata_freshness_producer_scope=verified`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
if (require.main === module) main();
module.exports = { fixture };
