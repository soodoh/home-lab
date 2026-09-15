#!/usr/bin/env node
"use strict";

// Evidence is a read-only audit receipt, never a saved host apply plan.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const Ajv2020 = require("ajv/dist/2020");
const { canonicalJson } = require("./proxmox-host-projection");
const { audit } = require("./proxmox-ansible-audit");
const ROOT = path.resolve(__dirname, "../..");
const PLAYBOOK = "ansible/playbooks/proxmox-controller-check.yml";
const INVENTORY = "ansible/inventory/proxmox-production.yml";
const LIMIT = 2 * 1024 * 1024;
const sha = value => crypto.createHash("sha256").update(value).digest("hex");
const schema = new Ajv2020({ strict: true, allErrors: true }).addSchema(JSON.parse(fs.readFileSync(path.join(ROOT, "infrastructure/host-lifecycle/proxmox/observation.schema.json"))), "https://home-lab.invalid/schemas/observation.json").compile(JSON.parse(fs.readFileSync(path.join(ROOT, "infrastructure/host-lifecycle/proxmox/check-evidence.schema.json"))));

const { readRegular } = require("./neutral-input");
function parse(raw) {
  if (raw.length > LIMIT) throw new Error("evidence exceeds bound");
  const value = JSON.parse(raw.toString("utf8"));
  if (!raw.equals(Buffer.from(canonicalJson(value)))) throw new Error("noncanonical evidence");
  return value;
}
function git(args) { return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim(); }
function dependencies() {
  // Explicit source/dependency inventory; never read .local, .env or encrypted secrets.
  const files = git(["ls-files", "--", "ansible", "scripts/controller",
    "infrastructure/contract", "infrastructure/host-lifecycle/proxmox", "infrastructure/proxmox-access", "infrastructure/maintenance/host/package-candidate-observer", "package.json", "bun.lock"])
    .split("\n").filter(Boolean).sort();
  return Object.fromEntries(files.map(file => [file, sha(readRegular(path.join(ROOT, file), 16 * LIMIT))]));
}
function cleanCommit() {
  if (git(["status", "--porcelain", "--untracked-files=all"])) throw new Error("clean committed source required");
  return git(["rev-parse", "HEAD"]);
}
function artifact(directory) {
  execFileSync(process.execPath, [path.join(ROOT, "scripts/controller/build-proxmox-ansible-observer.js"), "--output-dir", directory], { cwd: ROOT, stdio: "pipe" });
  return parse(readRegular(path.join(directory, "manifest.json")));
}
function time(value) {
  const result = Date.parse(value);
  if (!Number.isFinite(result) || new Date(result).toISOString().replace(".000Z", "Z") !== value) throw new Error("invalid evidence time");
  return result;
}
function normalizeScope(output) {
  const plays = [...output.matchAll(/^PLAY \[([^\]\n]+)\]/gm)].map(match => match[1]);
  const tasks = [...output.matchAll(/^TASK \[([^\]\n]+)\]/gm)].map(match => match[1]);
  assert.deepEqual(plays, ["Check the exact locked Proxmox controller observation"]);
  assert.deepEqual(tasks, ["Require the fixed audit-only scope", "Independently audit the locked observation against the direct contract"]);
  const hosts = [...output.matchAll(/^([^\s]+)\s*:\s*ok=\d+/gm)].map(match => match[1]);
  assert.deepEqual(hosts, ["proxmox-host-production"]);
  return canonicalJson({ plays, tasks, hosts });
}
function protectedFacts(observation) {
  return sha(canonicalJson(Object.fromEntries(["protectedAccess", "protectedHardware", "storage", "vm", "health", "pveAccess", "pveFirewall", "pveStorage", "tailscale"].map(name => [name, observation.domains[name]]))));
}
function validate(value, expected, now = Date.now()) {
  if (!schema(value)) throw new Error("neutral evidence schema differs");
  assert.equal(value.commit, expected.commit, "source commit differs");
  assert.deepEqual(value.dependencies, expected.dependencies, "source dependencies differ");
  assert.equal(value.host_key, value.snapshot.host_key, "host trust differs");
  if (expected.host_key) assert.equal(value.host_key, expected.host_key, "independent host trust differs");
  if (expected.known_hosts_sha256) assert.equal(value.known_hosts_sha256, expected.known_hosts_sha256, "known-host identity differs");
  const observed = time(value.snapshot.observed_at), expires = time(value.expires_at);
  if (observed > now || now - observed > 300000 || expires !== observed + 300000 || now >= expires) throw new Error("evidence not fresh");
  assert.equal(value.observation_sha256, sha(canonicalJson(value.snapshot.observation)));
  assert.equal(value.protected_facts_sha256, protectedFacts(value.snapshot.observation));
  assert.equal(value.scope.normalized_sha256, sha(value.scope.normalized));
  assert.equal(value.snapshot.observation.observerSha256, value.snapshot.observer_sha256);
  return value;
}
function verifyContent(value, temporary) {
  const dir = path.join(temporary, "artifact");
  const manifest = artifact(dir);
  assert.equal(value.artifact_manifest_sha256, sha(readRegular(path.join(dir, "manifest.json"))));
  assert.equal(value.snapshot.producer_sha256, manifest.controller_observer_sha256);
  assert.equal(value.snapshot.observer_sha256, manifest.observer_sha256);
  assert.equal(value.snapshot.collector_sha256, manifest.private_preparer_sha256);
  const observation = path.join(temporary, "observation.json");
  fs.writeFileSync(observation, canonicalJson(value.snapshot.observation), { mode: 0o600, flag: "wx" });
  const result = audit(dir, observation);
  assert.equal(result.parity, true);
  assert.equal(result.domain_count, 17);
}
function temporaryRun(callback) {
  // macOS /var and /tmp aliases are resolved before strict ancestor validation.
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "home-lab-neutral-"));
  try { return callback(directory); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function verifyRecord(record, commit, now = Date.now()) {
  assert.deepEqual(Object.keys(record).sort(), ["file", "sha256"]);
  assert.match(record.sha256, /^[0-9a-f]{64}$/);
  assert.equal(record.file, `.reconcile/plans/${record.sha256}.check.json`);
  const raw = readRegular(path.join(ROOT, record.file), LIMIT, true);
  assert.equal(sha(raw), record.sha256);
  const value = validate(parse(raw), { commit, dependencies: dependencies() }, now);
  temporaryRun(dir => verifyContent(value, dir));
  return value;
}
function verifyManifest(file) {
  const raw = readRegular(file, LIMIT, true);
  const manifest = parse(raw);
  // Top-level reconcile checks retain provider and Compose semantics. All consumers
  // reject legacy host authority even if a caller supplies otherwise valid binaries.
  assert.deepEqual(Object.keys(manifest).sort(), ["ansible_extra_vars_file_sha256", "backend_bucket", "commit", "compose_artifact_sha256", "controller_boundary_manifest", "offen_retirement_operation", "phase", "plans", "proxmox_host_check", "recovery_backup_identity_sha256", "recovery_expectations_sha256", "stage", "version"].sort());
  // Boundary semantics/current-file equality are checked by the shared Python
  // admission before this host-only reader or any provider invocation.
  assert.deepEqual(Object.keys(manifest.controller_boundary_manifest).sort(), ["document", "path", "sha256"]);
  assert(path.isAbsolute(manifest.controller_boundary_manifest.path));
  assert.match(manifest.controller_boundary_manifest.sha256, /^[0-9a-f]{64}$/);
  assert.match(manifest.compose_artifact_sha256, /^[0-9a-f]{64}$/);
  assert.equal(typeof manifest.backend_bucket, "string");
  assert.equal(manifest.recovery_backup_identity_sha256, "");
  assert.equal(manifest.recovery_expectations_sha256, "");
  assert.equal(manifest.offen_retirement_operation, "");
  assert.match(manifest.ansible_extra_vars_file_sha256, /^(?:[0-9a-f]{64})?$/);
  assert(Array.isArray(manifest.plans));
  const roots = manifest.plans.map(plan => plan.root);
  assert.equal(new Set(roots).size, roots.length);
  for (const required of ["aws-foundation", "proxmox"]) assert(roots.includes(required));
  for (const plan of manifest.plans) {
    assert.deepEqual(Object.keys(plan).sort(), ["root", "file", "sha256", "changed", "tailscale_policy_before_sha256", "tailscale_policy_after_sha256", "tailscale_policy_etag"].sort());
    assert(["aws-foundation", "proxmox", "omada", "tailscale", "authentik"].includes(plan.root));
    assert.equal(plan.file, plan.root + ".tfplan");
    assert.match(plan.sha256, /^[0-9a-f]{64}$/);
    assert.equal(typeof plan.changed, "boolean");
    if (plan.root === "tailscale") {
      assert.match(plan.tailscale_policy_before_sha256, /^[0-9a-f]{64}$/);
      assert.match(plan.tailscale_policy_after_sha256, /^[0-9a-f]{64}$/);
      assert.match(plan.tailscale_policy_etag, /^(W\/)?"[^"\x00-\x1f]+"$/);
    } else for (const key of ["tailscale_policy_before_sha256", "tailscale_policy_after_sha256", "tailscale_policy_etag"]) assert.equal(plan[key], "");
    assert.equal(sha(readRegular(path.join(path.dirname(file), plan.file), 256 * LIMIT, true)), plan.sha256);
  }
  assert.equal(manifest.version, 6);
  assert.equal(manifest.phase, "steady");
  assert.equal(manifest.stage, "converge", "unsupported external-owner/VM-start stage");
  assert(!Object.hasOwn(manifest, "proxmox_host_plan"), "legacy host plan forbidden");
  assert.equal(manifest.commit, git(["rev-parse", "HEAD"]));
  return verifyRecord(manifest.proxmox_host_check, manifest.commit);
}
function trust() {
  const file = process.env.RECONCILE_PROXMOX_KNOWN_HOSTS;
  const hostKey = process.env.RECONCILE_PROXMOX_HOST_KEY_SHA256;
  if (!file || !path.isAbsolute(file) || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(hostKey || "")) throw new Error("independently verified Proxmox known-host file and fingerprint required");
  const raw = readRegular(file, 4096, true);
  const match = /^proxmox ssh-ed25519 ([A-Za-z0-9+/]+={0,2})\n$/.exec(raw.toString("utf8"));
  if (!match) throw new Error("dedicated single-host ed25519 known-host input required");
  const actual = "SHA256:" + crypto.createHash("sha256").update(Buffer.from(match[1], "base64")).digest("base64").replace(/=+$/, "");
  assert.equal(actual, hostKey, "independently verified key does not match known-host input");
  return { file, host_key: hostKey, known_hosts_sha256: sha(raw) };
}
function collect() {
  const commit = cleanCommit(), pinned = trust(), deps = dependencies();
  return temporaryRun(directory => {
    const dir = path.join(directory, "artifact"), manifest = artifact(dir);
    const nonce = crypto.randomBytes(32).toString("hex");
    const started = Date.now();
    let responseSha = null;
    try {
    const raw = execFileSync("ssh", ["-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
      "-o", "UpdateHostKeys=no", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519",
      "-o", "UserKnownHostsFile=" + pinned.file, "-o", "IdentitiesOnly=yes", "-o", "ClearAllForwardings=yes",
      "-o", "PermitLocalCommand=no", "-o", "RequestTTY=no", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
      "-o", "ServerAliveCountMax=2", "ansible-plan@proxmox", "observe-controller"],
    { input: nonce + "\n", maxBuffer: LIMIT, timeout: 200000, stdio: ["pipe", "pipe", "pipe"] });
    responseSha = sha(raw);
    const snapshot = parse(raw);
    assert.equal(snapshot.nonce, nonce);
    assert(time(snapshot.observed_at) >= Math.floor(started / 1000) * 1000, "replayed observation");
    assert.equal(snapshot.producer_sha256, manifest.controller_observer_sha256, "installed capability migration required");
    assert.equal(snapshot.observer_sha256, manifest.observer_sha256);
    assert.equal(snapshot.collector_sha256, manifest.private_preparer_sha256);
    const observation = path.join(directory, "observation.json");
    fs.writeFileSync(observation, canonicalJson(snapshot.observation), { mode: 0o600, flag: "wx" });
    audit(dir, observation);
    const log = path.join(directory, "check.log");
    const environment = { ...process.env, ANSIBLE_CONFIG: path.join(ROOT, "ansible/ansible.cfg"), ANSIBLE_NOCOLOR: "1", ANSIBLE_STDOUT_CALLBACK: "default",
      RECONCILE_PROXMOX_CHECK_ARTIFACT: dir, RECONCILE_PROXMOX_CHECK_OBSERVATION: observation };
    const output = execFileSync("ansible-playbook", ["-i", INVENTORY, PLAYBOOK, "--check", "--tags", "audit"],
      { cwd: ROOT, env: environment, maxBuffer: 65536, timeout: 240000, stdio: ["ignore", "pipe", "pipe"] });
    fs.writeFileSync(log, output, { mode: 0o600, flag: "wx" });
    const normalized = normalizeScope(execFileSync("python3", [path.join(ROOT, "scripts/controller/normalize-ansible-plan.py"), log], { encoding: "utf8", maxBuffer: 65536 }));
    const recap = JSON.parse(execFileSync("python3", [path.join(ROOT, "scripts/controller/parse-ansible-recap.py"), log, "proxmox-host-production"]));
    delete recap.host;
    const value = { format: "home-lab-proxmox-check-evidence-v1", version: 1, commit, dependencies: deps,
      target: "ansible-plan@proxmox", host_key: pinned.host_key, known_hosts_sha256: pinned.known_hosts_sha256,
      artifact_manifest_sha256: sha(readRegular(path.join(dir, "manifest.json"))), snapshot,
      observation_sha256: sha(canonicalJson(snapshot.observation)), protected_facts_sha256: protectedFacts(snapshot.observation),
      expires_at: new Date(time(snapshot.observed_at) + 300000).toISOString().replace(".000Z", "Z"),
      scope: { tags: ["audit"], inventory: INVENTORY, playbook: PLAYBOOK, normalized, normalized_sha256: sha(normalized), recap } };
    validate(value, { commit, dependencies: dependencies(), ...pinned });
    assert.equal(cleanCommit(), commit);
    return value;
    } catch (error) {
      const failures = path.join(ROOT, ".reconcile/check-failures");
      fs.mkdirSync(failures, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(failures, nonce + ".json"), canonicalJson({
        format: "home-lab-proxmox-check-failure-v1", commit, nonce, response_sha256: responseSha,
        failed_at: new Date().toISOString(), automatic_retry_allowed: false,
        reason: "locked-check-failed", requires_new_reviewed_plan: true,
      }), { mode: 0o600, flag: "wx" });
      throw error;
    }
  });
}
function save(value) {
  const raw = Buffer.from(canonicalJson(value)), digest = sha(raw);
  const file = `.reconcile/plans/${digest}.check.json`;
  fs.mkdirSync(path.join(ROOT, ".reconcile/plans"), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(ROOT, file), raw, { mode: 0o600, flag: "wx" });
  return { file, sha256: digest };
}
function recheck(file) {
  const before = verifyManifest(file);
  const after = collect();
  // Retain the fresh receipt even on a mismatch; never retry a failed observation.
  const record = save(after);
  for (const key of ["commit", "dependencies", "target", "host_key", "known_hosts_sha256", "artifact_manifest_sha256", "observation_sha256", "protected_facts_sha256", "scope"]) {
    assert.deepEqual(after[key], before[key], `unreviewed ${key} drift; new plan required`);
  }
  return record;
}
if (require.main === module) {
  try {
    const [operation, file, ...extra] = process.argv.slice(2);
    if (extra.length || !["collect", "verify", "recheck"].includes(operation) || (operation === "collect" ? file : !file)) throw new Error("usage: proxmox-check-evidence.js collect | verify MANIFEST | recheck MANIFEST");
    const result = operation === "collect" ? save(collect()) : operation === "recheck" ? recheck(file) : (verifyManifest(file), { verified: true });
    process.stdout.write(canonicalJson(result));
  } catch (_) {
    // Do not spill child stdout/stderr or protected file content through exceptions.
    process.stderr.write("neutral Proxmox check refused; preserve receipts, verify capability/trust/freshness, and obtain a new reviewed plan\n");
    process.exitCode = 66;
  }
}
module.exports = { normalizeScope, sha, parse, readRegular, validate, verifyRecord, verifyManifest, protectedFacts, dependencies, verifyContent };
