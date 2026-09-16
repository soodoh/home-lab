#!/usr/bin/env node
"use strict";

// Local only: export source inputs into a private temporary checkout, then run
// Node with an empty home/environment, read-only FS permissions and no subprocess
// or network access. Never copy operational receipts, state or credentials.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { load, dump } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const temporary = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "home-lab-source-test-")));
const checkout = path.join(temporary, "checkout");
const home = path.join(temporary, "home");
const dependencies = fs.realpathSync(path.join(root, "node_modules"));
const contractPath = "infrastructure/contract/home-lab.yml";
const inputs = [
  "scripts/validate-contract",
  ...[
    "validate-vm-artifact-references", "validate-proxmox-host-policy",
    "validate-proxmox-package-policy", "proxmox-package-manifest", "validate-restic-policy",
  ].map((name) => `scripts/controller/${name}.js`),
  ...[
    "qualify-proton-backup", "initialize-restic-repositories", "restic-backup",
    "run-first-restic-backup", "prove-aws-recovery-hold",
  ].map((name) => `scripts/${name}`),
  contractPath, "infrastructure/contract/schema.json",
  "infrastructure/host-lifecycle/proxmox/package-manifest.json",
  "infrastructure/host-lifecycle/proxmox/package-manifest.schema.json",
  "services/servarr.yml", "services/data/restic/files-from", "services/data/restic/excludes",
  ...fs.readdirSync(path.join(root, "infrastructure/tofu/proxmox"))
    .filter((name) => name.endsWith(".tf"))
    .map((name) => `infrastructure/tofu/proxmox/${name}`),
];

function put(relative, content) {
  const destination = path.join(checkout, relative);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, content);
}

let cases = 0;
try {
  fs.mkdirSync(home);
  for (const relative of inputs) put(relative, fs.readFileSync(path.join(root, relative)));
  // Node's permission model denies writes and child processes. These tripwires
  // additionally reject network APIs (not covered by Node 24 FS permissions).
  const guard = path.join(temporary, "offline.cjs");
  fs.writeFileSync(guard, `
    const deny = () => { throw new Error("offline test forbids network access"); };
    const net = require("node:net");
    net.connect = net.createConnection = net.Socket.prototype.connect = deny;
    require("node:tls").connect = deny;
    require("node:http").request = require("node:http").get = deny;
    require("node:https").request = require("node:https").get = deny;
    require("node:dgram").createSocket = deny;
    for (const dns of [require("node:dns"), require("node:dns/promises")]) {
      for (const key of Object.keys(dns)) {
        if (/^(lookup|resolve|reverse)/.test(key) && typeof dns[key] === "function") dns[key] = deny;
      }
    }
    globalThis.fetch = deny;
    globalThis.WebSocket = class { constructor() { deny(); } };
  `);
  function run(args = []) {
    const result = spawnSync(process.execPath, [
      "--permission", `--allow-fs-read=${temporary}`, `--allow-fs-read=${dependencies}`,
      "--require", guard, path.join(checkout, "scripts/validate-contract"), ...args,
    ], {
      cwd: checkout,
      env: { HOME: home, PATH: "", NODE_PATH: dependencies, LANG: "C", LC_ALL: "C" },
      encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024,
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    return result;
  }
  function passes(label) {
    const result = run();
    assert.equal(result.status, 0, `${label}: ${result.stderr}`);
    assert.match(result.stdout, /contract source valid; historical evidence not checked/);
    assert.match(result.stdout, /Not backup health, restore qualification, or permission to deploy/);
    assert.doesNotMatch(result.stdout, /operationally complete/);
    cases++;
  }
  function rejects(label, pattern, args = [], status = 1) {
    const result = run(args);
    assert.equal(result.status, status, `${label}: ${result.stderr}`);
    assert.equal(result.stdout, "", `${label}: failure must not report source success`);
    assert.match(result.stderr, pattern, label);
    cases++;
  }
  function retiredModesReject(label) {
    for (const option of ["--historical-evidence", "--operational"]) {
      rejects(`${label}: ${option}`, /--historical-evidence and --operational are retired; no validation performed\./, [option], 2);
    }
  }

  for (const absent of [".git", ".local", ".reconcile", ".terraform", "secrets", "infrastructure/evidence", "infrastructure/retirement"]) {
    assert.equal(fs.existsSync(path.join(checkout, absent)), false, absent);
  }
  passes("source-only checkout without any evidence or evidence schemas");
  const contract = load(fs.readFileSync(path.join(checkout, contractPath), "utf8"));
  assert.equal(contract.backups.restic.first_run.state, "completed");
  assert.equal(contract.backups.restic.first_run.aws_evidence_file, "infrastructure/evidence/restic-first-run-aws.json");
  assert.equal(fs.existsSync(path.join(checkout, contract.backups.restic.first_run.aws_evidence_file)), false);

  retiredModesReject("absent historical inputs");
  for (const args of [["--historical-evidenc"], ["source"], ["--historical-evidence=true"], ["--operational=true"]]) {
    rejects(`unsupported arguments: ${args.join(" ")}`, /usage:/, args, 2);
  }
  for (const args of [
    ["--historical-evidence", "--operational"], ["--operational", "--historical-evidence"],
    ["--historical-evidence", "--historical-evidence"], ["--operational", "--operational"],
    ["--unknown", "--operational"],
  ]) {
    rejects(`retired arguments cannot fall through: ${args.join(" ")}`, /are retired; no validation performed\./, args, 2);
  }

  // Poison receipts, schemas and manifest are entirely synthetic. Neither source
  // validation nor flag rejection may parse these former historical inputs.
  for (const name of ["proton-qualification", "restic-repository-initialization", "restic-first-run", "restic-first-run-aws", "restic-restore-proof", "restic-schedule-activation", "offen-retirement", "offen-retirement-finalizing", "offen-retirement-staged"]) {
    for (const suffix of [".json", ".schema.json"]) {
      put(`infrastructure/evidence/${name}${suffix}`, "not-json: synthetic historical poison\n");
    }
  }
  for (const suffix of [".json", ".schema.json"]) {
    put(`infrastructure/retirement/offen-retirement-manifest${suffix}`, "not-json: synthetic historical poison\n");
  }
  passes("malformed historical inputs are not source inputs");
  retiredModesReject("malformed historical inputs");

  put(contractPath, "[synthetic malformed YAML\n");
  rejects("source validation still parses configuration", /YAMLException/);
  retiredModesReject("reject before parsing even malformed configuration");
  put(contractPath, fs.readFileSync(path.join(root, contractPath)));

  for (const [label, mutate, pattern] of [
    ["schema rejects automatic package apply", (value) => { value.lifecycle.maintenance.package_plan.hosts.debian.automatic_apply = true; }, /must be equal to constant/],
    ["schema rejects missing policy", (value) => { delete value.backups.restic; }, /required property/],
    ["semantic writer coverage", (value) => { value.backups.restic.sources.find((entry) => entry.mutable_database).writers = ["synthetic-unmanaged-writer"]; }, /mutable database writer .* is not stopped/],
    ["critical exclusion", (value) => { value.backups.restic.excludes.push(value.backups.restic.critical_fixtures[0]); }, /Restic exclusion matches critical fixture/],
    ["helper source binding", (value) => { value.backups.restic.runner.sha256 = "0".repeat(64); }, /Restic runner SHA-256 differs/],
    ["package source binding", (value) => { value.proxmox.packages.manifest.sha256 = "0".repeat(64); }, /package manifest SHA-256 differs/],
    ["declared legacy state consistency", (value) => { value.backups.restic.first_run.snapshots.nfs = value.backups.restic.first_run.snapshots.games; }, /completed Restic first run requires exact distinct snapshots/],
  ]) {
    const fixture = structuredClone(contract);
    mutate(fixture);
    put(contractPath, dump(fixture));
    rejects(label, pattern);
  }
  put(contractPath, fs.readFileSync(path.join(root, contractPath)));
  for (const relative of ["services/data/restic/files-from", "services/data/restic/excludes"]) {
    put(relative, "synthetic-invalid-input\n");
    rejects(relative, /generated Restic .* differs from the contract/);
    put(relative, fs.readFileSync(path.join(root, relative)));
  }
  passes("restored source fixture");
  assert.deepEqual(fs.readdirSync(home), [], "validator must leave the isolated home empty");
  for (const absent of [".local", ".reconcile", ".terraform", "secrets"]) {
    assert.equal(fs.existsSync(path.join(checkout, absent)), false, absent);
  }
  console.log(`contract_source_offline=${cases} cases passed (synthetic fixtures; no operational qualification)`);
} finally {
  // Only the mkdtemp-owned fixture; no repository artifact cleanup.
  fs.rmSync(temporary, { recursive: true, force: true });
}
