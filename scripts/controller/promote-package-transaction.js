#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");

function canonicalJson(value) {
  function sort(candidate) {
    if (Array.isArray(candidate)) return candidate.map(sort);
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(Object.keys(candidate).sort().map((key) => [key, sort(candidate[key])]));
    }
    return candidate;
  }
  return `${JSON.stringify(sort(value))}\n`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function without(value, key) {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

function compareCanonical(left, right, message) {
  if (canonicalJson(left) !== canonicalJson(right)) throw new Error(message);
}

function sealReview(material) {
  if (Object.hasOwn(material, "review_sha256")) throw new Error("review material already has a hash");
  return { ...material, review_sha256: sha256(canonicalJson(material)) };
}

function validateCandidate(candidate) {
  if (candidate?.format !== "home-lab-package-transaction-lock-v1" || candidate.version !== 1 ||
      candidate.automatic_apply !== false || candidate.authorized !== false || candidate.lifecycle !== "production") {
    throw new Error("package candidate envelope is invalid");
  }
  if (sha256(canonicalJson(without(candidate, "transaction_sha256"))) !== candidate.transaction_sha256) {
    throw new Error("package candidate hash differs");
  }
  compareCanonical(candidate.blockers, ["impact-review-required", "separate-exact-authorization-required"],
    "package candidate has unresolved safety blockers");
  const transaction = candidate.transaction;
  if (!transaction.apt_tree_safe || !transaction.size_parse_complete || transaction.apt_unsafe_paths.length ||
      transaction.holds.length || transaction.kept_back.length || transaction.removals.length || transaction.downgrades.length ||
      transaction.changes.length < 1 || !Number.isInteger(transaction.download_bytes) || !Number.isInteger(transaction.disk_delta_bytes)) {
    throw new Error("package candidate is not promotable");
  }
  if (transaction.changes.some((item) => !new Set(["install", "upgrade"]).has(item.action))) {
    throw new Error("package candidate contains a prohibited action");
  }
}

function validateReview(candidate, review, contract, nowEpoch) {
  if (review?.format !== "home-lab-package-impact-review-v1" || review.version !== 1 || review.host !== candidate.host ||
      review.automatic_apply !== false || review.automatic_reboot !== false || review.authorized !== false) {
    throw new Error("package impact review envelope is invalid");
  }
  if (sha256(canonicalJson(without(review, "review_sha256"))) !== review.review_sha256) throw new Error("package impact review hash differs");
  if (review.candidate_transaction_sha256 !== candidate.transaction_sha256) throw new Error("package impact review candidate binding differs");
  const created = Date.parse(review.created_at) / 1000;
  const expires = Date.parse(review.expires_at) / 1000;
  if (![created, expires, nowEpoch].every(Number.isInteger) || created > nowEpoch || nowEpoch > expires || expires <= created ||
      created < Date.parse(candidate.generated_at) / 1000 || created > Date.parse(candidate.expires_at) / 1000) {
    throw new Error("package impact review is stale or future-dated");
  }
  const changes = candidate.transaction.changes;
  if (review.changes_sha256 !== sha256(canonicalJson(changes))) throw new Error("package impact review change binding differs");
  compareCanonical(review.approved_additions, candidate.transaction.additions, "approved additions differ");
  compareCanonical(review.approved_removals, [], "package removals require a separate migration policy");
  compareCanonical(review.approved_downgrades, [], "package downgrades require a separate migration policy");
  const origins = changes.map((item) => ({ name: item.name, candidate_version: item.candidate_version,
    origin: item.origin, policy_sha256: item.policy_sha256 }));
  compareCanonical(review.approved_origins, origins, "approved package origins differ");
  const sortedAffected = [...review.affected_services].sort();
  compareCanonical(review.affected_services, sortedAffected, "affected services are not canonical");
  const expectedProtected = sortedAffected.filter((service) => contract.lifecycle.maintenance.package_plan.protected_services.includes(service));
  compareCanonical(review.protected_services, expectedProtected, "protected service impact differs");
  if (review.reboot_required !== (review.reboot_reasons.length > 0)) throw new Error("reboot reasons differ from reboot decision");
  if (review.lane === "no-restart-safe" && (review.needrestart_assessment !== "no-protected-restart" ||
      review.protected_services.length || review.reboot_required)) {
    throw new Error("no-restart lane has disruptive impact");
  }
  if (review.lane === "maintenance-window" && review.needrestart_assessment !== "maintenance-window-required") {
    throw new Error("maintenance-window lane assessment differs");
  }
}

function promote(candidate, review, contract, observedAt) {
  validateCandidate(candidate);
  const nowEpoch = Date.parse(observedAt) / 1000;
  if (!Number.isInteger(nowEpoch)) throw new Error("promotion clock is invalid");
  validateReview(candidate, review, contract, nowEpoch);
  const expiresAt = new Date(Math.min(Date.parse(candidate.expires_at), Date.parse(review.expires_at))).toISOString().replace(".000Z", "Z");
  const transaction = candidate.transaction;
  const material = {
    format: "home-lab-package-transaction-final-v1",
    version: 1,
    host: candidate.host,
    lifecycle: "production",
    base_commit: candidate.base_commit,
    generated_at: observedAt,
    expires_at: expiresAt,
    lane: review.lane,
    automatic_apply: false,
    automatic_reboot: false,
    actionable: true,
    authorized: false,
    bindings: {
      candidate_transaction_sha256: candidate.transaction_sha256,
      review_sha256: review.review_sha256,
      changes_sha256: review.changes_sha256,
      contract_sha256: candidate.bindings.contract_sha256,
      inventory_sha256: candidate.bindings.inventory_sha256,
      host_key_fingerprint: candidate.bindings.host_key_fingerprint,
      installed_package_set_sha256: candidate.bindings.installed_package_set_sha256,
      apt_sources_sha256: candidate.bindings.apt_sources_sha256,
      apt_keyrings_sha256: candidate.bindings.apt_keyrings_sha256,
      apt_configuration_sha256: candidate.bindings.apt_configuration_sha256,
      proposal_sha256: candidate.bindings.proposal_sha256,
    },
    transaction: {
      changes: transaction.changes,
      exact_install_specs: transaction.exact_install_specs,
      additions: transaction.additions,
      download_bytes: transaction.download_bytes,
      disk_delta_bytes: transaction.disk_delta_bytes,
      affected_services: review.affected_services,
      protected_services: review.protected_services,
      needrestart_assessment: review.needrestart_assessment,
      reboot_required: review.reboot_required,
      reboot_reasons: review.reboot_reasons,
      safety_classification: review.lane,
    },
    blockers: ["separate-exact-authorization-required"],
  };
  return { ...material, final_sha256: sha256(canonicalJson(material)) };
}

module.exports = { canonicalJson, promote, sealReview, validateCandidate, validateReview };
