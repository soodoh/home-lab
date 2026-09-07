#!/usr/bin/env node
"use strict";
// Offline presentation only: verifyReport checks structure/self-hash, not source authority.
const { verifyReport } = require("./maintenance-publish");
const { canonicalJson, keys, hash, time, integer, FLAGS, HOSTS, TOPICS } = require("./maintenance-report");
const MAX_BYTES = 262144;
const DAY_MS = 86400000;
const DIAGNOSTIC = "maintenance advisory input rejected\n";
const reject = () => { throw new Error(DIAGNOSTIC.trim()); };
const osNow = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const yesNo = value => value ? "yes" : "no";
function boolean(value) { if (typeof value !== "boolean") reject(); }
function count(value, max = 10000) { integer(value, max); return value; }

// Only fixed labels, checked numbers and booleans become candidate text. No free-form values.
function candidate(entry) {
  const v = entry.values;
  switch (entry.topic) {
    case "package":
      keys(v, ["install", "upgrade", "downgrade", "remove", "metadata_age_seconds", "transaction_sha256", "candidate_semantics_sha256", "unsafe_apt", "incomplete_sizes", "active_locks"]);
      if (entry.detail !== "exact-impact-review-required") reject();
      count(v.metadata_age_seconds, 86400);
      hash(v.transaction_sha256); hash(v.candidate_semantics_sha256);
      for (const key of ["unsafe_apt", "incomplete_sizes", "active_locks"]) boolean(v[key]);
      return `needs-review; install=${count(v.install)}; upgrade=${count(v.upgrade)}; downgrade=${count(v.downgrade)}; remove=${count(v.remove)}; unsafe-apt=${yesNo(v.unsafe_apt)}; incomplete-sizes=${yesNo(v.incomplete_sizes)}; active-locks=${yesNo(v.active_locks)}`;
    case "reboot":
      keys(v, ["required", "backup_proven"]);
      if (v.backup_proven !== false) reject();
      if (v.required === null && entry.detail === "reboot-observation-unknown") return "unknown; reboot=unknown; backup=unknown";
      boolean(v.required);
      if (entry.detail !== (v.required ? "reboot-separate-plan-required" : "observation-only")) reject();
      return `${v.required ? "needs-review" : "observation-only"}; reboot-required=${yesNo(v.required)}; backup=unknown`;
    case "release":
      keys(v, ["current", "latest", "major", "maintained", "eol", "source_sha256", "source_generated_at"]);
      if (entry.detail !== "release-review-required") reject();
      for (const value of [v.current, v.latest]) if (typeof value !== "string" || !/^[0-9][a-zA-Z0-9.+:~_-]{0,63}$/.test(value)) reject();
      boolean(v.maintained); hash(v.source_sha256);
      if (v.eol !== null) {
        if (typeof v.eol !== "string" || !/^\d{4}-\d\d-\d\d$/.test(v.eol)) reject();
        time(`${v.eol}T00:00:00Z`);
      }
      if (time(v.source_generated_at) > time(entry.observed_at) || time(entry.observed_at) - time(v.source_generated_at) > 7 * DAY_MS) reject();
      return `needs-review; major=${count(v.major, 999)}; maintained=${yesNo(v.maintained)}; version-change=${yesNo(v.current !== v.latest)}; source-generated=${v.source_generated_at}`;
    case "pins":
      keys(v, ["cloud_image", "standalone_tools", "ansible_collections", "opentofu_providers"]);
      if (entry.detail !== "pin-review-required") reject();
      for (const item of Object.values(v)) { keys(item, ["covered", "sha256"]); boolean(item.covered); hash(item.sha256); }
      if (Object.values(v).some(item => !item.covered)) return "unknown; reason=partial-pin-coverage";
      return "needs-review; covered=4/4";
    case "migrations": {
      keys(v, ["items"]);
      if (entry.detail !== "manual-migration-review-required" || !Array.isArray(v.items) || v.items.length > 20) reject();
      const majors = new Set();
      for (const item of v.items) {
        keys(item, ["major", "issue_number"]);
        if (!count(item.major, 999) || !count(item.issue_number, 100000000) || majors.has(item.major)) reject();
        majors.add(item.major);
      }
      return `needs-review; migration-count=${v.items.length}`;
    }
    default: reject();
  }
}
function classify(entry, report, epoch) {
  if (time(report.observed_at) > epoch) return "unknown; reason=future-report";
  if (time(report.expires_at) <= epoch) return "unknown; reason=stale-report";
  if (!entry) return "unknown; reason=missing";
  if (entry.observed_at === null || entry.expires_at === null) return "unknown; reason=missing-or-invalid";
  const observed = time(entry.observed_at), expires = time(entry.expires_at);
  if (observed > epoch || observed > time(report.observed_at)) return "unknown; reason=future-observation";
  if (expires <= observed || expires - observed > DAY_MS) return "unknown; reason=invalid-time";
  if (expires <= epoch) return "unknown; reason=stale-observation";
  if (entry.freshness !== "fresh" || entry.status !== "blocked") return "unknown; reason=unavailable-observation";
  const provenance = ["package", "reboot"].includes(entry.topic)
    ? (entry.topic === "package" ? ["attestation-only", "challenge-verified"] : ["challenge-verified"])
    : ["reviewed-local-input"];
  if (!provenance.includes(entry.provenance) || entry.input_sha256 === null || entry.evidence_sha256 === null) return "unknown; reason=invalid-observation";
  try {
    const summary = candidate(entry);
    if (entry.topic === "package" && entry.values.metadata_age_seconds * 1000 + epoch - observed > DAY_MS) return "unknown; reason=apt-metadata-stale";
    return summary;
  } catch { return "unknown; reason=invalid-or-incomplete-observation"; }
}

// Accept a parsed existing report or explicit null. `now` is ordinary UTC, injected for tests.
// Exceptions are constant diagnostics; neither errors nor private input are rendered.
function renderAdvisory(report, now = osNow()) {
  try {
    const epoch = time(now);
    if (Buffer.byteLength(canonicalJson(report)) > MAX_BYTES) reject();
    if (report !== null) {
      if (typeof report.source_commit !== "string" || !/^[a-f0-9]{40}$/.test(report.source_commit)) reject();
      hash(report.contract_sha256);
      verifyReport(report, report);
    }
    const lines = ["Maintenance advisory — observation only, not host health or action authority.",
      `Generated (OS UTC): ${now}`,
      `Report aggregated: ${report?.observed_at ?? "unknown"}; report expires: ${report?.expires_at ?? "unknown"}`,
      "Self-hash: structural integrity only; source not authenticated.",
      Object.entries(FLAGS).map(([key, value]) => `${key}=${value}`).join("; "),
      "Zero upgrades do not establish host health. Backup admission remains unknown."];
    const entries = HOSTS.flatMap(host => TOPICS.map(topic =>
      report?.entries.find(entry => entry.host === host && entry.topic === topic) ?? { host, topic }));
    for (const entry of entries) {
      const summary = report === null ? "unknown; reason=missing-report" : classify(entry, report, epoch);
      lines.push(`${entry.host}/${entry.topic}: ${summary}; observed=${entry.observed_at ?? "unknown"}; expires=${entry.expires_at ?? "unknown"}`);
    }
    return lines.join("\n") + "\n";
  } catch { reject(); }
}
if (require.main === module) {
  if (process.argv.length !== 2) { process.stderr.write(DIAGNOSTIC); process.exitCode = 65; }
  else {
    let raw = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("error", () => { process.stderr.write(DIAGNOSTIC); process.exitCode = 65; });
    process.stdin.on("data", chunk => {
      raw += chunk;
      if (Buffer.byteLength(raw) > MAX_BYTES) { process.stderr.write(DIAGNOSTIC); process.exit(65); }
    });
    process.stdin.on("end", () => {
      try {
        const report = JSON.parse(raw);
        // Existing canonical wire also excludes ambiguous duplicate JSON keys.
        if (raw !== canonicalJson(report)) reject();
        process.stdout.write(renderAdvisory(report));
      } catch { process.stderr.write(DIAGNOSTIC); process.exitCode = 65; }
    });
  }
}
module.exports = { renderAdvisory, MAX_BYTES };
