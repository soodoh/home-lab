#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");

function canonicalJson(value, newline = true) {
  function sort(candidate) {
    if (Array.isArray(candidate)) return candidate.map(sort);
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(Object.keys(candidate).sort().map((key) => [key, sort(candidate[key])]));
    }
    return candidate;
  }
  return `${JSON.stringify(sort(value))}${newline ? "\n" : ""}`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function requireSha(value, label) {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`${label} is not a SHA-256 digest`);
}

function validateProposal(proposal, host) {
  if (proposal?.version !== 2 || proposal.host !== host || proposal.solver?.returncode !== 0) {
    throw new Error("package proposal envelope is invalid");
  }
  if (!Array.isArray(proposal.changes) || !Array.isArray(proposal.holds) || !Array.isArray(proposal.kept_back) || !Array.isArray(proposal.active_lifecycle_locks) || !Array.isArray(proposal.apt_unsafe_paths)) {
    throw new Error("package proposal arrays are invalid");
  }
  for (const name of ["installed_inventory_sha256", "installed_status_sha256", "expected_manifest_sha256", "proposal_sha256"]) {
    requireSha(proposal[name], `proposal ${name}`);
  }
  for (const name of ["configuration_sha256", "keyrings_sha256", "sources_sha256"]) {
    requireSha(proposal.apt_state_hashes?.[name], `APT ${name}`);
  }
  if (typeof proposal.apt_tree_safe !== "boolean" || typeof proposal.size_parse_complete !== "boolean" ||
      !(proposal.download_bytes === null || Number.isInteger(proposal.download_bytes) && proposal.download_bytes >= 0) ||
      !(proposal.disk_delta_bytes === null || Number.isInteger(proposal.disk_delta_bytes))) {
    throw new Error("package proposal safety or size evidence is invalid");
  }
  const actions = new Set(["install", "upgrade", "downgrade", "remove"]);
  const seen = new Set();
  for (const change of proposal.changes) {
    if (!actions.has(change.action) || typeof change.name !== "string" || !change.name || seen.has(change.name) ||
        typeof change.origin !== "string" || typeof change.security !== "boolean") {
      throw new Error("package proposal change is invalid or duplicated");
    }
    seen.add(change.name);
    if (change.action === "install" && change.previous_version !== null) throw new Error("package addition has a current version");
    if (change.action === "remove" && (change.candidate_version !== null || change.policy_sha256 !== null)) throw new Error("package removal has candidate policy");
    if (change.action !== "install" && typeof change.previous_version !== "string") throw new Error("package change lacks a current version");
    if (change.action !== "remove" && (typeof change.candidate_version !== "string" || !change.candidate_version || !change.origin)) {
      throw new Error("package change lacks an exact candidate or origin");
    }
    if (change.action !== "remove") requireSha(change.policy_sha256, "package candidate policy");
  }
  const sorted = [...proposal.changes].sort((left, right) => {
    const leftKey = `${left.name}\0${left.action}\0${left.candidate_version ?? ""}`;
    const rightKey = `${right.name}\0${right.action}\0${right.candidate_version ?? ""}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  if (canonicalJson(sorted) !== canonicalJson(proposal.changes)) throw new Error("package proposal changes are not canonical");
  const counts = Object.fromEntries([...actions].map((action) => [action, proposal.changes.filter((item) => item.action === action).length]));
  if (canonicalJson(counts) !== canonicalJson(proposal.change_counts)) throw new Error("package proposal change counts differ");
  if (proposal.security_changes !== proposal.changes.filter((item) => item.security).length) throw new Error("security change count differs");

  const material = {
    host,
    installed_inventory_sha256: proposal.installed_inventory_sha256,
    metadata_mtime_epoch: proposal.metadata_mtime_epoch,
    holds: proposal.holds,
    solver_stdout_sha256: proposal.solver.stdout_sha256,
    changes: proposal.changes,
    installed_status_sha256: proposal.installed_status_sha256,
    expected_manifest_sha256: proposal.expected_manifest_sha256,
    manifest_matches: proposal.manifest_matches,
    apt_state_hashes: proposal.apt_state_hashes,
    apt_tree_safe: proposal.apt_tree_safe,
    apt_unsafe_paths: proposal.apt_unsafe_paths,
    active_lifecycle_locks: proposal.active_lifecycle_locks,
    kept_back: proposal.kept_back,
    download_bytes: proposal.download_bytes,
    disk_delta_bytes: proposal.disk_delta_bytes,
    size_parse_complete: proposal.size_parse_complete,
  };
  if (sha256(canonicalJson(material, false)) !== proposal.proposal_sha256) throw new Error("package proposal hash differs");
}

function buildCandidateLock({ host, lifecycle, proposal, bindings, generatedAt, expiresAt }) {
  if (!new Set(["debian", "proxmox"]).has(host) || lifecycle !== "production") throw new Error("package lock target is invalid");
  validateProposal(proposal, host);
  if (!/^[0-9a-f]{40}$/.test(bindings.git_commit)) throw new Error("package lock Git binding is invalid");
  for (const name of ["contract_sha256", "inventory_sha256"]) requireSha(bindings[name], `package lock ${name}`);
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(bindings.host_key_fingerprint)) throw new Error("package lock host-key binding is invalid");
  if (!Number.isInteger(bindings.max_metadata_age_seconds) || bindings.max_metadata_age_seconds < 1 ||
      !Number.isInteger(proposal.metadata_age_seconds) || proposal.metadata_age_seconds < 0 ||
      proposal.metadata_age_seconds > bindings.max_metadata_age_seconds) {
    throw new Error("package proposal metadata is stale");
  }
  const generatedEpoch = Date.parse(generatedAt);
  const expiresEpoch = Date.parse(expiresAt);
  const observedEpoch = Date.parse(proposal.observed_at);
  if (![generatedEpoch, expiresEpoch, observedEpoch].every(Number.isFinite) || generatedEpoch < observedEpoch || expiresEpoch <= generatedEpoch) {
    throw new Error("package lock timestamps are invalid");
  }
  const changes = proposal.changes;
  const exactInstallSpecs = changes.filter((item) => item.action !== "remove").map((item) => `${item.name}=${item.candidate_version}`);
  const blockers = ["impact-review-required", "separate-exact-authorization-required"];
  if (proposal.holds.length) blockers.push("held-packages");
  if (proposal.kept_back.length) blockers.push("kept-back-packages");
  if (proposal.change_counts.remove) blockers.push("package-removal-review-required");
  if (proposal.change_counts.downgrade) blockers.push("package-downgrade-review-required");
  if (!changes.length) blockers.push("no-package-changes");
  if (!proposal.manifest_matches) blockers.push("installed-package-manifest-drift");
  if (!proposal.apt_tree_safe) blockers.push("apt-state-tree-unsafe");
  if (!proposal.size_parse_complete) blockers.push("package-size-evidence-incomplete");
  if (proposal.active_lifecycle_locks.length) blockers.push("active-lifecycle-lock");

  const material = {
    format: "home-lab-package-transaction-lock-v1",
    version: 1,
    host,
    lifecycle,
    base_commit: bindings.git_commit,
    generated_at: generatedAt,
    expires_at: expiresAt,
    automatic_apply: false,
    authorized: false,
    bindings: {
      contract_sha256: bindings.contract_sha256,
      inventory_sha256: bindings.inventory_sha256,
      proposal_sha256: proposal.proposal_sha256,
      host_key_fingerprint: bindings.host_key_fingerprint,
      installed_package_set_sha256: proposal.installed_status_sha256,
      apt_sources_sha256: proposal.apt_state_hashes.sources_sha256,
      apt_keyrings_sha256: proposal.apt_state_hashes.keyrings_sha256,
      apt_configuration_sha256: proposal.apt_state_hashes.configuration_sha256,
      max_metadata_age_seconds: bindings.max_metadata_age_seconds,
    },
    transaction: {
      changes,
      exact_install_specs: exactInstallSpecs,
      additions: changes.filter((item) => item.action === "install").map((item) => item.name),
      removals: changes.filter((item) => item.action === "remove").map((item) => item.name),
      downgrades: changes.filter((item) => item.action === "downgrade").map((item) => item.name),
      holds: proposal.holds,
      kept_back: proposal.kept_back,
      download_bytes: proposal.download_bytes,
      disk_delta_bytes: proposal.disk_delta_bytes,
      apt_tree_safe: proposal.apt_tree_safe,
      apt_unsafe_paths: proposal.apt_unsafe_paths,
      size_parse_complete: proposal.size_parse_complete,
      affected_services: null,
      needrestart_result: null,
      reboot_required: null,
      reboot_reasons: [],
      safety_classification: "impact-review-required",
    },
    blockers: [...new Set(blockers)].sort(),
  };
  return { ...material, transaction_sha256: sha256(canonicalJson(material)) };
}

module.exports = { buildCandidateLock, canonicalJson, validateProposal };
