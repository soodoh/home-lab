#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const Ajv2020 = require("ajv/dist/2020");
const { load } = require("js-yaml");
const { buildReport, canonicalJson } = require("./release-eol-report");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative));
const contract = load(read("infrastructure/contract/home-lab.yml").toString("utf8"));
const packageManifest = JSON.parse(read(contract.proxmox.packages.manifest.path));
const rawSources = {
  debian: read("infrastructure/maintenance/fixtures/endoflife-debian.json"),
  proxmox: read("infrastructure/maintenance/fixtures/endoflife-proxmox-ve.json"),
};
const sources = { debian: { raw: rawSources.debian }, proxmox: { raw: rawSources.proxmox } };
const observedAt = "2026-09-03T08:00:00Z";
const report = buildReport(contract, packageManifest, sources, observedAt);
assert.equal(report.format, "home-lab-release-eol-report-v1");
assert.equal(report.automatic_apply, false);
assert.equal(report.status, "warning");
assert.deepEqual(report.blockers, []);
assert.deepEqual(report.warnings, ["proxmox-eol-unknown"]);
assert.equal(report.sources.debian.current_version, contract.debian.point_release);
assert.equal(report.sources.debian.latest_version, "13.6");
assert.equal(report.sources.debian.eol, "2028-08-09");
assert.equal(report.sources.debian.extended_support_end, "2030-06-30");
assert.equal(report.sources.proxmox.current_version, "9.2.11");
assert.equal(report.sources.proxmox.latest_version, "9.2");
assert.equal(report.sources.proxmox.eol, null);

const schema = JSON.parse(read("infrastructure/maintenance/release-eol-report.schema.json"));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
assert(validate(report), JSON.stringify(validate.errors));
assert.equal(canonicalJson(report), `${JSON.stringify(JSON.parse(canonicalJson(report)))}\n`);

function changedSource(host, mutate) {
  const value = JSON.parse(rawSources[host]);
  mutate(value);
  return { raw: Buffer.from(JSON.stringify(value)) };
}
const stale = { ...sources, debian: changedSource("debian", (value) => { value.generated_at = "2026-08-01T00:00:00+00:00"; }) };
assert.throws(() => buildReport(contract, packageManifest, stale, observedAt), /stale/);
const future = { ...sources, proxmox: changedSource("proxmox", (value) => { value.generated_at = "2026-09-04T00:00:00+00:00"; }) };
assert.throws(() => buildReport(contract, packageManifest, future, observedAt), /future/);
const wrongProduct = { ...sources, proxmox: changedSource("proxmox", (value) => { value.result.name = "debian"; }) };
assert.throws(() => buildReport(contract, packageManifest, wrongProduct, observedAt), /envelope/);
const missingCycle = { ...sources, debian: changedSource("debian", (value) => { value.result.releases[0].name = "12"; }) };
assert.equal(buildReport(contract, packageManifest, missingCycle, observedAt).status, "blocking");
const unmaintained = { ...sources, debian: changedSource("debian", (value) => { value.result.releases[0].isMaintained = false; value.result.releases[0].isEol = true; }) };
assert(buildReport(contract, packageManifest, unmaintained, observedAt).blockers.includes("debian-release-unmaintained"));
const unknownRequiredEol = { ...sources, debian: changedSource("debian", (value) => { value.result.releases[0].eolFrom = null; }) };
assert(buildReport(contract, packageManifest, unknownRequiredEol, observedAt).blockers.includes("debian-eol-unknown"));
const behindContract = structuredClone(contract);
behindContract.debian.point_release = "13.5";
assert(buildReport(behindContract, packageManifest, sources, observedAt).warnings.includes("debian-point-release-behind"));

const cli = spawnSync(path.join(root, "scripts/controller/release-eol-report.js"), [
  "--debian-json", path.join(root, "infrastructure/maintenance/fixtures/endoflife-debian.json"),
  "--proxmox-json", path.join(root, "infrastructure/maintenance/fixtures/endoflife-proxmox-ve.json"),
  "--observed-at", observedAt,
], { encoding: "utf8" });
assert.equal(cli.status, 0, cli.stderr);
assert.deepEqual(JSON.parse(cli.stdout), report);
const source = read("scripts/controller/release-eol-report.js").toString("utf8");
for (const required of ["automatic_apply: false", "endoflife.date", "maxResponseBytes", "source timed out", "status === \"blocking\""]) {
  assert(source.includes(required), `release report omits ${required}`);
}
for (const forbidden of ["child_process", "execSync", "spawnSync", "shell: true", "ansible-deploy", "tofu-apply"]) {
  assert(!source.includes(forbidden), `release report contains mutation or shell surface ${forbidden}`);
}

const workflow = read(".github/workflows/release-eol-report.yml").toString("utf8");
for (const required of ["permissions:\n  contents: read", "workflow_dispatch:", "schedule:", "bun install --frozen-lockfile --ignore-scripts",
  "release-eol-report.js --fetch", "retention-days: 14"]) {
  assert(workflow.includes(required), `release workflow omits ${required}`);
}
assert.equal((workflow.match(/uses: [^@]+@[0-9a-f]{40}/g) ?? []).length, 3, "workflow actions must be pinned to full commits");
for (const forbidden of ["secrets.", "contents: write", "pull-requests: write", "ansible-deploy", "tofu apply", "ansible-playbook"]) {
  assert(!workflow.includes(forbidden), `release workflow contains authority ${forbidden}`);
}

const renovate = JSON.parse(read("renovate.json"));
assert(renovate.customManagers.length >= 2);
const lifecycleManager = renovate.customManagers.find((manager) => manager.matchStrings?.some((pattern) => pattern.includes("depName=(?<depName>")));
assert(lifecycleManager);
assert.equal(lifecycleManager.customType, "regex");
const markerPattern = new RegExp(lifecycleManager.matchStrings[0], "g");
const markerText = [read("ansible/collections/requirements.yml"), read("ansible/group_vars/docker_host.yml"),
  read("infrastructure/contract/home-lab.yml")].map((value) => value.toString("utf8")).join("\n");
const dependencies = [...markerText.matchAll(markerPattern)].map((match) => `${match.groups.depName}@${match.groups.currentValue}`);
assert.deepEqual(dependencies.sort(), [
  "FiloSottile/age@1.3.1", "ansible-collections/community.general@13.2.0", "getsops/sops@3.13.3",
  "restic/restic@0.19.1", "tailscale/tailscale@1.102.3", "tailscale/tailscale@1.102.3",
].sort());
const lifecycleRule = renovate.packageRules.find((rule) => rule.matchManagers?.includes("custom.regex"));
assert(lifecycleRule && lifecycleRule.automerge === false && lifecycleRule.labels.includes("host-maintenance-candidate"));

console.log("release_eol_report=verified sources=2");
