"use strict";

const path = require("node:path");
const crypto = require("node:crypto");

function globRegex(pattern) {
  let expression = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*" && pattern[index + 1] === "*") {
      if (pattern[index + 2] === "/") {
        expression += "(?:.*/)?";
        index += 2;
      } else {
        expression += ".*";
        index += 1;
      }
    } else if (character === "*") expression += "[^/]*";
    else if (character === "?") expression += "[^/]";
    else if (character === "[") {
      const close = pattern.indexOf("]", index + 1);
      if (close === -1) expression += "\\[";
      else {
        expression += pattern.slice(index, close + 1);
        index = close;
      }
    } else expression += character.replace(/[\\^$+?.()|{}]/g, "\\$&");
  }
  return new RegExp(`${expression}(?:/.*)?$`);
}

function validateProtonQualificationEvidence(policy, evidence, rawEvidence) {
  const failures = [];
  const qualification = policy.qualification;
  if (qualification.state !== "qualified") return failures;
  const evidenceSha256 = crypto.createHash("sha256").update(rawEvidence).digest("hex");
  if (evidenceSha256 !== qualification.evidence_sha256) failures.push("Proton qualification evidence SHA-256 differs from the contract");
  if (evidence.account_username_sha256 !== qualification.username_sha256) failures.push("Proton qualification account hash differs from the contract");
  if (evidence.minimum_allocated_bytes !== policy.repositories.proton.minimum_allocated_bytes) failures.push("Proton qualification minimum allocation differs from the contract");
  if (evidence.observed_total_bytes < policy.repositories.proton.minimum_allocated_bytes) failures.push("Proton qualification observed less than the minimum allocation");
  if (evidence.fixture_bytes !== qualification.fixture_bytes
      || evidence.range_offset !== qualification.range_offset
      || evidence.range_count !== qualification.range_count) {
    failures.push("Proton qualification fixture parameters differ from the contract");
  }
  if (evidence.verified_at !== qualification.verified_at) failures.push("Proton qualification timestamp differs from the contract");
  if (evidence.trash_cleanup !== policy.proton.trash_cleanup) failures.push("Proton qualification Trash policy differs from the contract");
  if (evidence.free_bytes < policy.proton.minimum_free_bytes) failures.push("Proton qualification evidence crossed the free-space reserve");
  return failures;
}

function validateResticInitializationEvidence(policy, evidence, rawEvidence) {
  const failures = [];
  const initialization = policy.initialization;
  if (initialization.state !== "initialized") return failures;
  const evidenceSha256 = crypto.createHash("sha256").update(rawEvidence).digest("hex");
  if (evidenceSha256 !== initialization.evidence_sha256) failures.push("Restic initialization evidence SHA-256 differs from the contract");
  if (evidence.source_policy_sha256 !== initialization.source_policy_sha256) failures.push("Restic initialization source policy hash differs from the contract");
  if (evidence.completed_at !== initialization.verified_at) failures.push("Restic initialization timestamp differs from the contract");
  for (const name of ["games", "nfs", "proton"]) {
    if (evidence.repository_ids[name] !== policy.repositories[name].id) failures.push(`Restic initialization ${name} repository ID differs from the contract`);
  }
  if (evidence.helper_sha256 !== initialization.helper_sha256
      || evidence.restic_sha256 !== policy.tools.restic.installed_sha256
      || evidence.rclone_sha256 !== policy.tools.rclone.installed_sha256) failures.push("Restic initialization tool hashes differ from the contract");
  if (evidence.qualification_evidence_sha256 !== policy.qualification.evidence_sha256
      || evidence.account_username_sha256 !== policy.qualification.username_sha256) failures.push("Restic initialization Proton identity differs from qualified evidence");
  if (evidence.proton_observed_total_bytes < policy.repositories.proton.minimum_allocated_bytes
      || evidence.proton_observed_free_bytes < policy.proton.minimum_free_bytes) failures.push("Restic initialization Proton quota crossed a contract threshold");
  return failures;
}

function validateResticFirstRunEvidence(policy, evidence, rawEvidence) {
  const failures = [];
  const firstRun = policy.first_run;
  if (firstRun.state !== "completed") return failures;
  const hash = crypto.createHash("sha256").update(rawEvidence).digest("hex");
  if (hash !== firstRun.evidence_sha256) failures.push("Restic first-run evidence SHA-256 differs from the contract");
  if (evidence.source_policy_sha256 !== firstRun.source_policy_sha256
      || evidence.artifact_sha256 !== firstRun.artifact_sha256
      || evidence.aws_evidence_sha256 !== firstRun.aws_evidence_sha256
      || evidence.completed_at !== firstRun.completed_at) failures.push("Restic first-run evidence bindings differ from the contract");
  for (const name of ["games", "nfs", "proton"]) {
    if (evidence.snapshots[name] !== firstRun.snapshots[name]) failures.push(`Restic first-run ${name} snapshot differs from the contract`);
    if (evidence.repository_ids[name] !== policy.repositories[name].id) failures.push(`Restic first-run ${name} repository differs from the contract`);
  }
  if (evidence.helper_sha256 !== firstRun.helper_sha256 || evidence.runner_sha256 !== policy.runner.sha256) failures.push("Restic first-run helper or runner hash differs");
  if (evidence.quota.total < policy.repositories.proton.minimum_allocated_bytes || evidence.quota.free < policy.proton.minimum_free_bytes) failures.push("Restic first-run quota crossed a threshold");
  return failures;
}

function validateResticPolicy(policy) {
  const failures = [];
  const stoppedApplications = policy.stop_groups.applications;
  const stoppedDatabases = policy.stop_groups.databases;
  const stoppedWriters = [...stoppedApplications, ...stoppedDatabases];
  const sourcePaths = policy.sources.map((entry) => entry.path);
  const classified = [
    ...policy.sources.map((entry) => ({ path: entry.path, class: entry.class })),
    ...policy.classified_paths,
  ];
  const classifiedPaths = classified.map((entry) => entry.path);
  if (new Set(sourcePaths).size !== sourcePaths.length) failures.push("Restic source paths must be unique");
  if (new Set(classifiedPaths).size !== classifiedPaths.length) failures.push("every Restic policy path must have exactly one class");
  for (const entry of classified) {
    if (!path.posix.isAbsolute(entry.path) || path.posix.normalize(entry.path) !== entry.path) {
      failures.push(`Restic classified path must be normalized and absolute: ${entry.path}`);
    }
  }
  for (const source of policy.sources) {
    for (const repository of Object.values(policy.repositories)) {
      if (typeof repository.path !== "string" || repository.path.startsWith("rclone:")) continue;
      if (source.path === repository.path || source.path.startsWith(`${repository.path}/`)) {
        failures.push(`Restic source ${source.path} is under repository ${repository.path}`);
      }
    }
  }
  for (const tree of classified.filter((entry) => entry.class === "replace-tree")) {
    for (const child of classified) {
      if (child.path.startsWith(`${tree.path}/`)) failures.push(`replace-tree ${tree.path} contains classified descendant ${child.path}`);
    }
  }
  const writerSources = new Set(policy.sources.flatMap((entry) => entry.writers));
  for (const writer of stoppedWriters) {
    if (!writerSources.has(writer)) failures.push(`stopped writer ${writer} has no backed-up state`);
  }
  for (const source of policy.sources.filter((entry) => entry.mutable_database)) {
    for (const writer of source.writers) {
      if (!stoppedWriters.includes(writer)) failures.push(`mutable database writer ${writer} is not stopped`);
    }
    if (!source.writers.length) failures.push(`mutable database ${source.path} has no declared writer`);
  }
  if (new Set(stoppedWriters).size !== stoppedWriters.length) failures.push("Restic stop groups overlap");
  const startOrderSet = [...new Set(policy.stop_groups.start_order)].sort();
  const stoppedWriterSet = [...new Set(stoppedWriters)].sort();
  if (JSON.stringify(startOrderSet) !== JSON.stringify(stoppedWriterSet)) failures.push("Restic start order must contain exactly the stopped writers");
  for (const fixture of policy.critical_fixtures) {
    if (policy.excludes.some((pattern) => globRegex(pattern).test(fixture))) failures.push(`Restic exclusion matches critical fixture ${fixture}`);
  }
  const requiredExcludes = [
    "/srv/home-lab-state/calibre-web-data/log_archive/**",
    "/srv/home-lab-state/hass-data/.cache/**",
    "/srv/home-lab-state/jellyfin-data/config/.cache/**",
    "/srv/home-lab-state/omada-data/data/mongodb-preupgrade.tar",
    "/srv/home-lab-state/qbittorrent-data/.cache/**",
  ];
  for (const pattern of requiredExcludes) {
    if (!policy.excludes.includes(pattern)) failures.push(`Restic exclusion is missing reviewed Offen equivalent ${pattern}`);
  }
  const classByPath = new Map(classified.map((entry) => [entry.path, entry.class]));
  for (const [requiredPath, requiredClass] of [
    ["/mnt/storage/media/caro-tachidesk", "external"],
    ["/mnt/storage/media/calibre/books", "external"],
    ["/mnt/storage/media/nextcloud/data", "external"],
    ["/mnt/storage/media/tachidesk", "external"],
  ]) {
    if (classByPath.get(requiredPath) !== requiredClass) failures.push(`Restic path ${requiredPath} must be ${requiredClass}`);
  }
  if (JSON.stringify(policy.restore.modes) !== JSON.stringify(["staging"])
      || policy.restore.activation_status !== "unavailable-pending-isolated-proofs"
      || policy.restore.activation["replace-tree"] !== "unavailable"
      || policy.restore.activation["replace-entries"] !== "unavailable") {
    failures.push("Restic policy must not advertise unavailable activation modes");
  }
  if (policy.schedule.proton_independent_timer !== false
      || policy.retention.keep_daily !== 7
      || policy.retention.keep_weekly !== 5
      || policy.retention.keep_monthly !== 12) {
    failures.push("Restic schedule and retention invariants differ");
  }
  if (policy.proton.trash_cleanup !== "manual-only") failures.push("Proton Trash cleanup must remain manual-only");
  if (policy.repositories.proton.minimum_allocated_bytes !== 1000000000000
      || policy.proton.warning_minimum_used_bytes !== 100000000000
      || policy.proton.minimum_free_bytes !== 100000000000) {
    failures.push("Proton quota thresholds must use the reviewed decimal GB/TB values");
  }
  const qualification = policy.qualification;
  const credentials = policy.credentials;
  const usernameRecorded = typeof qualification.username_sha256 === "string";
  const evidenceRecorded = typeof qualification.evidence_sha256 === "string" && typeof qualification.verified_at === "string";
  if (qualification.state === "pending" && (
    credentials.bootstrap_enabled !== false
    || credentials.state !== "absent"
    || qualification.username_sha256 !== null
    || qualification.evidence_sha256 !== null
    || qualification.verified_at !== null
  )) failures.push("pending Proton qualification must remain credential-free and evidence-free");
  if (qualification.state === "ready" && (
    credentials.bootstrap_enabled !== true
    || credentials.state !== "provisioned"
    || !usernameRecorded
    || qualification.evidence_sha256 !== null
    || qualification.verified_at !== null
  )) failures.push("ready Proton qualification requires provisioned credentials and an exact account hash");
  if (qualification.state === "qualified" && (
    credentials.bootstrap_enabled !== true
    || credentials.state !== "provisioned"
    || !usernameRecorded
    || !evidenceRecorded
  )) failures.push("qualified Proton state requires bound account and evidence hashes");
  if (!/^[0-9a-f]{64}$/.test(policy.tools.restic.installed_sha256)) failures.push("installed Restic hash must be contract-backed");
  const initialization = policy.initialization;
  const repositoryIds = Object.values(policy.repositories).map((repository) => repository.id);
  const initializedEvidence = typeof initialization.source_policy_sha256 === "string"
    && typeof initialization.evidence_sha256 === "string"
    && typeof initialization.verified_at === "string";
  if (initialization.state === "ready" && (
    qualification.state !== "qualified"
    || repositoryIds.some((id) => id !== null)
    || initialization.source_policy_sha256 !== null
    || initialization.evidence_sha256 !== null
    || initialization.verified_at !== null
  )) failures.push("ready repository initialization requires qualified Proton and three absent repositories");
  if (initialization.state === "initialized" && (
    repositoryIds.some((id) => typeof id !== "string" || !/^[0-9a-f]{64}$/.test(id))
    || new Set(repositoryIds).size !== 3
    || !initializedEvidence
  )) failures.push("initialized repository state requires three distinct IDs and bound evidence");
  if (!/^[0-9a-f]{64}$/.test(policy.runner.sha256)) failures.push("Restic runner hash must be contract-backed");
  const firstRun = policy.first_run;
  const firstRunFields = [firstRun.source_policy_sha256, firstRun.artifact_sha256, firstRun.aws_evidence_sha256, firstRun.evidence_sha256, firstRun.completed_at];
  const firstRunSnapshots = Object.values(firstRun.snapshots);
  if (JSON.stringify(firstRun.baseline) !== JSON.stringify({ games: [], nfs: [], proton: [] })) {
    failures.push("Restic first-run baseline must commit three empty repositories");
  }
  if (firstRun.state === "ready" && (initialization.state !== "initialized" || firstRunFields.some((value) => value !== null) || firstRunSnapshots.some((value) => value !== null))) {
    failures.push("ready Restic first run requires initialized repositories and null evidence");
  }
  if (firstRun.state === "completed" && (firstRunFields.some((value) => typeof value !== "string")
      || firstRunSnapshots.some((value) => typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
      || new Set(firstRunSnapshots).size !== 3)) failures.push("completed Restic first run requires exact distinct snapshots and evidence");
  return failures;
}

module.exports = { globRegex, validateProtonQualificationEvidence, validateResticInitializationEvidence, validateResticFirstRunEvidence, validateResticPolicy };
