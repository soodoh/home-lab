"use strict";

const path = require("node:path");

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
  if (policy.migration_state === "inert" && (
    JSON.stringify(policy.restore.modes) !== JSON.stringify(["staging"])
    || policy.restore.activation_status !== "unavailable-pending-isolated-proofs"
    || policy.restore.activation["replace-tree"] !== "unavailable"
    || policy.restore.activation["replace-entries"] !== "unavailable"
  )) failures.push("inert Restic policy must not advertise unavailable activation modes");
  if (policy.schedule.proton_independent_timer !== false
      || policy.retention.keep_daily !== 7
      || policy.retention.keep_weekly !== 5
      || policy.retention.keep_monthly !== 12) {
    failures.push("Restic schedule and retention invariants differ");
  }
  if (policy.proton.trash_cleanup !== "manual-only") failures.push("Proton Trash cleanup must remain manual-only");
  if (policy.repositories.proton.allocated_bytes !== 1000000000000
      || policy.proton.warning_minimum_used_bytes !== 100000000000
      || policy.proton.hard_failure_used_bytes !== 900000000000) {
    failures.push("Proton quota thresholds must use the reviewed decimal GB/TB values");
  }
  return failures;
}

module.exports = { globRegex, validateResticPolicy };
