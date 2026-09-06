#!/usr/bin/env node
"use strict";
// Only reduced, enumerated fields cross the private collector/publication boundary.
const crypto = require("node:crypto");
const { buildCandidateLock, canonicalJson, validateProposal } = require("./package-transaction-lock");
const sha = (v) => crypto.createHash("sha256").update(v).digest("hex");
const HOSTS = ["debian", "proxmox"];
const TOPICS = ["package", "reboot", "release", "pins", "migrations"];
const FLAGS = { authorized: false, automatic_apply: false, automatic_reboot: false, automatic_retry_allowed: false };
const fail = () => { throw new Error("maintenance input rejected"); };
function keys(v, names) {
  if (!v || Array.isArray(v) || typeof v !== "object" || Object.keys(v).sort().join() !== [...names].sort().join()) fail();
}
function match(v, re) { if (typeof v !== "string" || !re.test(v)) fail(); return v; }
function hash(v) { return match(v, /^[a-f0-9]{64}$/); }
function time(v) { match(v, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/); const n = Date.parse(v); if (!Number.isFinite(n) || new Date(n).toISOString().replace('.000Z', 'Z') !== v) fail(); return n; }
function integer(v, max = 100000) { if (!Number.isSafeInteger(v) || v < 0 || v > max) fail(); return v; }
function safeVersion(v) { return match(v, /^[0-9][a-zA-Z0-9.+:~_-]{0,63}$/); }
function flags(v) { for (const [k, value] of Object.entries(FLAGS)) if (v[k] !== value) fail(); }
function context(v) {
  keys(v, ["source_commit", "contract_sha256", "hosts"]);
  match(v.source_commit, /^[a-f0-9]{40}$/); hash(v.contract_sha256); keys(v.hosts, HOSTS);
  for (const host of HOSTS) {
    keys(v.hosts[host], ["host_key_fingerprint", "inventory_sha256"]);
    match(v.hosts[host].host_key_fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/); hash(v.hosts[host].inventory_sha256);
  }
}
function envelope(record, expected, host, topic, now) {
  keys(record, ["format", "source_commit", "contract_sha256", "host", "topic", "host_key_fingerprint", "observed_at", "expires_at", "provenance", "evidence_sha256", "payload_sha256", "payload"]);
  if (record.format !== "home-lab-maintenance-input-v1" || record.source_commit !== expected.source_commit || record.contract_sha256 !== expected.contract_sha256 || record.host !== host || record.topic !== topic || record.host_key_fingerprint !== expected.hosts[host].host_key_fingerprint) fail();
  if (!["attestation-only", "challenge-verified", "reviewed-local-input", "failed-collection"].includes(record.provenance)) fail();
  hash(record.evidence_sha256); hash(record.payload_sha256);
  if (sha(canonicalJson(record.payload)) !== record.payload_sha256) fail();
  const observed = time(record.observed_at), expires = time(record.expires_at);
  if (observed > now || expires <= observed || expires - observed > 86400000) fail();
  return expires <= now || now - observed > 86400000 ? "stale" : "fresh";
}
function validateMaintenanceProposal(p, host) {
  keys(p, ["version", "host", "observed_at", "metadata_refresh_performed", "metadata_newest_path", "metadata_mtime_epoch", "metadata_age_seconds", "installed_inventory_format", "installed_records", "installed_inventory_sha256", "installed_package_records", "installed_status_sha256", "expected_manifest_records", "expected_manifest_sha256", "manifest_matches", "holds", "solver", "changes", "change_counts", "security_changes", "apt_state_hashes", "apt_tree_safe", "apt_unsafe_paths", "active_lifecycle_locks", "kept_back", "download_bytes", "disk_delta_bytes", "size_parse_complete", "proposal_sha256"]);
  validateProposal(p, host);
  keys(p.solver, ["command", "returncode", "stdout_sha256", "stderr_sha256"]);
  if (p.solver.command !== "apt-get-simulate" || p.metadata_refresh_performed !== false || p.installed_inventory_format !== "dpkg-query-status-tsv-v1") fail();
  keys(p.apt_state_hashes, ["configuration_sha256", "keyrings_sha256", "sources_sha256"]);
  for (const change of p.changes) keys(change, ["action", "name", "candidate_version", "previous_version", "origin", "policy_sha256", "security"]);
  function bounded(v) {
    if (typeof v === "string" && (v.length > 512 || /[^\x20-\x7e]|https?:\/\/|PRIVATE KEY|(?:password|token|secret)=|gh[pousr]_/i.test(v))) fail();
    if (Array.isArray(v) && v.length > 10000) fail();
    if (v && typeof v === "object") for (const item of Object.values(v)) bounded(item);
  }
  bounded(p);
}
function summarize(record, expected) {
  const p = record.payload, host = record.host;
  if (record.provenance === "failed-collection") {
    keys(p, ["failure"]);
    if (!["capability-unavailable", "prerequisite-invalid", "transport-failed", "invalid-output", "collection-interrupted"].includes(p.failure)) fail();
    return { status: "failed", detail: p.failure, values: {} };
  }
  if (record.topic === "package") {
    if (!["attestation-only", "challenge-verified"].includes(record.provenance)) fail();
    keys(p, ["proposal", "candidate"]);
    validateMaintenanceProposal(p.proposal, host);
    if (p.proposal.metadata_refresh_performed !== false || time(p.proposal.observed_at) !== time(record.observed_at)) fail();
    // Age is recomputed from the metadata timestamp, never trusted from the producer.
    integer(p.proposal.metadata_mtime_epoch, Number.MAX_SAFE_INTEGER);
    const age = Math.floor(time(record.observed_at) / 1000) - p.proposal.metadata_mtime_epoch;
    if (age < 0 || age !== p.proposal.metadata_age_seconds) fail();
    if (age > 86400) return { status: "blocked", detail: "apt-metadata-stale", values: {} };
    const candidate = buildCandidateLock({ host, lifecycle: "production", proposal: p.proposal,
      generatedAt: record.observed_at, expiresAt: record.expires_at,
      bindings: { git_commit: expected.source_commit, contract_sha256: expected.contract_sha256,
        ...expected.hosts[host], max_metadata_age_seconds: 86400 } });
    if (canonicalJson(candidate) !== canonicalJson(p.candidate)) fail();
    const counts = p.proposal.change_counts;
    for (const value of Object.values(counts)) integer(value, 10000);
    return { status: "blocked", detail: "exact-impact-review-required", values: {
      install: counts.install, upgrade: counts.upgrade, downgrade: counts.downgrade, remove: counts.remove,
      metadata_age_seconds: age, transaction_sha256: candidate.transaction_sha256,
      candidate_semantics_sha256: sha(canonicalJson({changes:p.proposal.changes, holds:p.proposal.holds,
        kept_back:p.proposal.kept_back, installed_inventory_sha256:p.proposal.installed_inventory_sha256,
        expected_manifest_sha256:p.proposal.expected_manifest_sha256, apt_state_hashes:p.proposal.apt_state_hashes})),
      unsafe_apt: !p.proposal.apt_tree_safe, incomplete_sizes: !p.proposal.size_parse_complete,
      active_locks: p.proposal.active_lifecycle_locks.length > 0 } };
  }
  if (record.topic === "reboot") {
    if (record.provenance !== "challenge-verified") fail();
    keys(p, ["required", "backup_proven"]);
    if (!(p.required === null || typeof p.required === "boolean") || p.backup_proven !== false) fail();
    return { status: "blocked", detail: p.required === null ? "reboot-observation-unknown" : p.required ? "reboot-separate-plan-required" : "observation-only", values: p };
  }
  if (record.provenance !== "reviewed-local-input") fail();
  if (record.topic === "release") {
    keys(p, ["current", "latest", "major", "maintained", "eol", "source_sha256", "source_generated_at"]);
    safeVersion(p.current); safeVersion(p.latest); integer(p.major, 999); hash(p.source_sha256);
    if (typeof p.maintained !== "boolean" || !(p.eol === null || /^\d{4}-\d\d-\d\d$/.test(p.eol))) fail();
    if (time(p.source_generated_at) > time(record.observed_at) || time(record.observed_at) - time(p.source_generated_at) > 7 * 86400000) fail();
    return { status: "blocked", detail: "release-review-required", values: p };
  }
  if (record.topic === "pins") {
    keys(p, ["cloud_image", "standalone_tools", "ansible_collections", "opentofu_providers"]);
    for (const v of Object.values(p)) { keys(v, ["covered", "sha256"]); if (typeof v.covered !== "boolean") fail(); hash(v.sha256); }
    return { status: "blocked", detail: "pin-review-required", values: p };
  }
  keys(p, ["items"]);
  if (!Array.isArray(p.items) || p.items.length > 20) fail();
  const seen = new Set();
  for (const item of p.items) {
    keys(item, ["major", "issue_number"]); integer(item.major, 999); integer(item.issue_number, 100000000);
    if (item.major === 0 || item.issue_number === 0 || seen.has(item.major)) fail(); seen.add(item.major);
  }
  return { status: "blocked", detail: "manual-migration-review-required", values: { items: [...p.items].sort((a,b) => a.major-b.major) } };
}
function aggregate(expected, records, observedAt) {
  context(expected); const now = time(observedAt);
  if (!Array.isArray(records) || records.length > 10 || Buffer.byteLength(canonicalJson(records)) > 1048576) fail();
  const map = new Map();
  for (const record of records) {
    if (!HOSTS.includes(record.host) || !TOPICS.includes(record.topic)) fail();
    const key = `${record.host}/${record.topic}`; if (map.has(key)) fail(); map.set(key, record);
  }
  const entries = [];
  for (const host of HOSTS) for (const topic of TOPICS) {
    const key = `${host}/${topic}`, record = map.get(key);
    let result = { status: "missing", detail: "input-missing", values: {} }, freshness = "missing";
    let binding = { observed_at: null, expires_at: null, input_sha256: null, evidence_sha256: null, provenance: null };
    if (record) {
      binding.input_sha256 = sha(canonicalJson(record));
      try {
        freshness = envelope(record, expected, host, topic, now); result = summarize(record, expected);
        binding = { observed_at: record.observed_at, expires_at: record.expires_at, input_sha256: sha(canonicalJson(record)), evidence_sha256: record.evidence_sha256, provenance: record.provenance };
        if (freshness === "stale") result = { status: "stale", detail: "input-stale", values: {} };
      } catch { freshness = "invalid"; result = { status: "invalid", detail: "input-invalid", values: {} }; }
    }
    entries.push({ host, topic, dedup_key: sha(`home-lab/maintenance/v1/${key}`), freshness, ...binding, ...result, ...FLAGS });
    if (topic === "migrations" && result.values.items) for (const item of result.values.items) {
      entries.push({ host, topic: "migration", dedup_key: sha(`home-lab/maintenance/v1/${host}/migration/${item.major}`), freshness, ...binding,
        status: "blocked", detail: "manual-migration-review-required", values: item, ...FLAGS });
    }
  }
  const material = { format: "home-lab-maintenance-collection-v1", source_commit: expected.source_commit,
    contract_sha256: expected.contract_sha256, observed_at: observedAt, expires_at: new Date(now + 86400000).toISOString().replace('.000Z', 'Z'),
    ...FLAGS, complete: entries.every(e => e.freshness === "fresh" && e.status === "blocked"), entries };
  return { ...material, report_sha256: sha(canonicalJson(material)) };
}
if (require.main === module) {
  let raw = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => { raw += chunk; if (Buffer.byteLength(raw) > 1048576) { process.stderr.write("maintenance input rejected\n"); process.exit(65); } });
  process.stdin.on("end", () => { try {
    const input = JSON.parse(raw); if (raw !== canonicalJson(input)) fail();
    keys(input, ["context", "records", "observed_at"]);
    process.stdout.write(canonicalJson(aggregate(input.context, input.records, input.observed_at)));
  } catch { process.stderr.write("maintenance input rejected\n"); process.exitCode = 65; } });
}
module.exports = { validateMaintenanceProposal, aggregate, canonicalJson, sha, keys, hash, time, integer, flags, FLAGS, HOSTS, TOPICS };
