#!/usr/bin/env node
"use strict";
// Offline publication planner. No network client, gh invocation, host identity or token loading.
const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");
const { canonicalJson, sha, keys, hash, time, integer, flags, FLAGS, HOSTS, TOPICS } = require("./maintenance-report");
const reject = () => { throw Error("maintenance publication rejected"); };
function safeValues(values) {
  if (!values || typeof values !== "object" || Array.isArray(values)) reject();
  const allowed = new Set(["install", "upgrade", "downgrade", "remove", "metadata_age_seconds", "transaction_sha256", "candidate_semantics_sha256", "unsafe_apt", "incomplete_sizes", "active_locks", "required", "backup_proven", "current", "latest", "major", "maintained", "eol", "source_sha256", "source_generated_at", "cloud_image", "standalone_tools", "ansible_collections", "opentofu_providers", "items", "issue_number", "covered", "sha256"]);
  function walk(v, key, depth) {
    if (depth > 4) reject();
    if (typeof v === "string") {
      if (key.endsWith("sha256")) hash(v);
      else if (key === "source_generated_at") time(v);
      else if (key === "eol") { if (!/^\d{4}-\d\d-\d\d$/.test(v)) reject(); }
      else if (!["current", "latest"].includes(key) || !/^[0-9][a-zA-Z0-9.+:~_-]{0,63}$/.test(v)) reject();
    } else if (typeof v === "number") integer(v, 100000000);
    else if (typeof v === "boolean" || v === null) return;
    else if (Array.isArray(v)) { if (key !== "items" || v.length > 20) reject(); for (const item of v) walk(item, "", depth+1); }
    else if (v && typeof v === "object") for (const [k, item] of Object.entries(v)) { if (!allowed.has(k)) reject(); walk(item, k, depth+1); }
    else reject();
  }
  walk(values, "", 0);
}
function publicationValues(entry) {
  // Exact hashes/times remain in the signed private report. Issue updates reflect
  // changed state, not merely a fresh measurement of the same state.
  const values = {...entry.values};
  if (entry.topic === "package") { delete values.metadata_age_seconds; delete values.transaction_sha256; }
  if (entry.topic === "release") { delete values.source_generated_at; delete values.source_sha256; }
  return values;
}
function verifyReport(report, expected) {
  keys(report, ["format", "source_commit", "contract_sha256", "observed_at", "expires_at", ...Object.keys(FLAGS), "complete", "entries", "report_sha256"]);
  flags(report);
  if (report.format !== "home-lab-maintenance-collection-v1" || report.source_commit !== expected.source_commit || report.contract_sha256 !== expected.contract_sha256 || typeof report.complete !== "boolean") reject();
  const { report_sha256: digest, ...material } = report;
  hash(digest); if (sha(canonicalJson(material)) !== digest) reject();
  if (time(report.expires_at) !== time(report.observed_at)+86400000 || !Array.isArray(report.entries) || report.entries.length < 10 || report.entries.length > 50) reject();
  const seen = new Set();
  for (const entry of report.entries) {
    keys(entry, ["host", "topic", "dedup_key", "freshness", "observed_at", "expires_at", "input_sha256", "evidence_sha256", "provenance", "status", "detail", "values", ...Object.keys(FLAGS)]);
    flags(entry); safeValues(entry.values);
    if (!HOSTS.includes(entry.host) || ![...TOPICS, "migration"].includes(entry.topic)) reject();
    const suffix = entry.topic === "migration" ? `migration/${integer(entry.values.major, 999)}` : entry.topic;
    if (entry.dedup_key !== sha(`home-lab/maintenance/v1/${entry.host}/${suffix}`) || seen.has(entry.dedup_key)) reject();
    seen.add(entry.dedup_key);
    if (!["fresh", "stale", "missing", "invalid"].includes(entry.freshness) || !["blocked", "failed", "stale", "missing", "invalid"].includes(entry.status)) reject();
    if (!["input-missing", "input-stale", "input-invalid", "capability-unavailable", "prerequisite-invalid", "transport-failed", "invalid-output", "collection-interrupted", "apt-metadata-stale", "exact-impact-review-required", "reboot-separate-plan-required", "reboot-observation-unknown", "observation-only", "release-review-required", "pin-review-required", "manual-migration-review-required"].includes(entry.detail)) reject();
    if (entry.observed_at !== null) time(entry.observed_at);
    if (entry.expires_at !== null) time(entry.expires_at);
    if (entry.input_sha256 !== null) hash(entry.input_sha256);
    if (entry.evidence_sha256 !== null) hash(entry.evidence_sha256);
    if (![null, "attestation-only", "challenge-verified", "reviewed-local-input", "failed-collection"].includes(entry.provenance)) reject();
  }
  for (const host of HOSTS) for (const topic of TOPICS) if (!seen.has(sha(`home-lab/maintenance/v1/${host}/${topic}`))) reject();
}
function planPublication(input, trust, now) {
  if (Buffer.byteLength(canonicalJson(input)) > 262144) reject();
  keys(trust, ["repository", "source_commit", "contract_sha256", "public_key_pem", "public_key_sha256"]);
  if (trust.repository !== "soodoh/home-lab" || !/^[a-f0-9]{40}$/.test(trust.source_commit)) reject(); hash(trust.contract_sha256);
  if (sha(trust.public_key_pem) !== trust.public_key_sha256) reject();
  const key = crypto.createPublicKey(trust.public_key_pem); if (key.asymmetricKeyType !== "ed25519") reject();
  keys(input, ["report", "provenance", "signature", "registry"]);
  const p = input.provenance;
  keys(p, ["format", "repository", "source_commit", "contract_sha256", "issued_at", "expires_at", "collector", "workflow_artifact", "report_sha256", "registry_sha256"]);
  if (p.format !== "home-lab-maintenance-publication-provenance-v1" || p.repository !== trust.repository || p.source_commit !== trust.source_commit || p.contract_sha256 !== trust.contract_sha256 || p.collector !== "existing-mac" || p.workflow_artifact !== false) reject();
  const epoch = time(now);
  if (!(time(p.issued_at) <= epoch && epoch < time(p.expires_at) && time(p.expires_at)-time(p.issued_at) <= 86400000)) reject();
  if (typeof input.signature !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(input.signature) || !crypto.verify(null, Buffer.from(canonicalJson(p)), key, Buffer.from(input.signature, "base64"))) reject();
  verifyReport(input.report, trust);
  if (p.report_sha256 !== sha(canonicalJson(input.report)) || p.registry_sha256 !== sha(canonicalJson(input.registry)) || time(input.report.observed_at) > time(p.issued_at)) reject();
  if (!Array.isArray(input.registry) || input.registry.length > 50) reject();
  const registry = new Map(), numbers = new Set();
  for (const item of input.registry) {
    keys(item, ["dedup_key", "issue_number", "content_sha256"]); hash(item.dedup_key); hash(item.content_sha256); integer(item.issue_number, 100000000);
    if (!item.issue_number || registry.has(item.dedup_key) || numbers.has(item.issue_number)) reject();
    registry.set(item.dedup_key, item); numbers.add(item.issue_number);
  }
  const requests = [];
  for (const entry of input.report.entries) {
    // Re-evaluate the Mac clock at consumption: never restamp an offline controller as fresh.
    const stale = time(input.report.expires_at) <= epoch || (entry.expires_at !== null && time(entry.expires_at) <= epoch);
    const status = stale ? "stale" : entry.status;
    const title = `[maintenance] ${entry.host} ${entry.topic}${entry.topic === "migration" ? ` ${entry.values.major}` : ""}`;
    const body = `<!-- home-lab-maintenance:${entry.dedup_key} -->\nCandidate awareness only. No apply, reboot, retry or migration authorization.\nStatus: ${status}\nReason: ${stale ? "input-stale" : entry.detail}\nSource: ${input.report.source_commit}\nContract: ${input.report.contract_sha256}\nProvenance: ${entry.provenance ?? "missing"}\nSummary: ${canonicalJson(stale ? {} : publicationValues(entry)).trim()}\n`;
    const content_sha256 = sha(canonicalJson({title, body}));
    const previous = registry.get(entry.dedup_key);
    if (previous?.content_sha256 === content_sha256) continue;
    requests.push({ method: previous ? "PATCH" : "POST", path: `/repos/soodoh/home-lab/issues${previous ? `/${previous.issue_number}` : ""}`,
      body: {title, body}, dedup_key: entry.dedup_key, content_sha256 });
  }
  return { format: "home-lab-maintenance-publication-plan-v1", ...FLAGS, live_send_enabled: false,
    setup_gate: "reviewed-signing-provenance-and-issues-only-token-required", report_sha256: input.report.report_sha256, requests };
}
function readBounded(name, protectedFile) {
  if (protectedFile) {
    if (!path.isAbsolute(name)) reject();
    for (let directory = path.dirname(name); ; directory = path.dirname(directory)) {
      const s = fs.lstatSync(directory);
      if (!s.isDirectory() || ![0, process.getuid()].includes(s.uid) || ((s.mode & 0o022) && !(s.uid === 0 && (s.mode & 0o1000)))) reject();
      if (directory === path.dirname(directory)) break;
    }
  }
  const fd = fs.openSync(name, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || before.size < 2 || before.size > 262144 || (protectedFile && (before.uid !== process.getuid() || (before.mode & 0o777) !== 0o600))) reject();
    const buffer = Buffer.alloc(262145);
    const length = fs.readSync(fd, buffer, 0, buffer.length, 0);
    if (length !== before.size || length > 262144) reject();
    const raw = buffer.subarray(0, length).toString("utf8"), after = fs.fstatSync(fd), current = fs.lstatSync(name);
    for (const k of ["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "nlink"]) if (before[k] !== after[k] || after[k] !== current[k]) reject();
    const value = JSON.parse(raw); if (raw !== canonicalJson(value)) reject(); return value;
  } finally { fs.closeSync(fd); }
}
if (require.main === module) {
  try {
    if (process.argv.length !== 6 || process.argv[2] !== "--trust" || process.argv[4] !== "--input") reject();
    const report = planPublication(readBounded(process.argv[5], false), readBounded(process.argv[3], true), new Date().toISOString().replace(/\.\d{3}Z$/, "Z"));
    process.stdout.write(canonicalJson(report));
  } catch { process.stderr.write("maintenance publication rejected\n"); process.exitCode = 65; }
}
module.exports = { planPublication, verifyReport };
