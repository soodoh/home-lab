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

function planProxmoxTimezoneHandoff(contract, sources, parity) {
  if (!contract || !sources || !parity) throw new Error("timezone handoff inputs are required");
  const policy = contract.lifecycle?.hosts?.proxmox?.domain_handoffs?.timezone;
  if (!policy || policy.target_owner !== "ansible" || policy.parity_required !== true || policy.single_writer !== true) {
    throw new Error("timezone handoff policy is invalid");
  }
  if (policy.state === "transferred" ? policy.current_owner !== "ansible" : policy.current_owner !== "nix") {
    throw new Error("timezone handoff owner and state disagree");
  }
  for (const name of ["projection", "planner", "activator"]) {
    if (typeof sources[name] !== "string") throw new Error(`timezone handoff source ${name} is required`);
  }
  if (typeof parity.ansible_parity !== "boolean" || typeof parity.nix_runtime_parity !== "boolean") {
    throw new Error("timezone handoff parity booleans are required");
  }

  const planningDomainPresent = contract.proxmox.planning_policy.domains.some((entry) => entry.domain === "timezone");
  const mutationSources = {
    activator_dispatch_present: /set_timezone\(|"timezone"\}.*dispatchable|action\["domain"\] == "timezone"/s.test(sources.activator),
    planner_action_present: /"timezone"\s*:\s*"set-timezone"/.test(sources.planner),
    planner_desired_state_present: /"timezone"\s*:\s*\[\{"name":\s*"system",\s*"timezone":\s*projection\["timezone"\]\}\]/.test(sources.planner),
    projection_desired_state_present: /timezone:\s*systemTimezone/.test(sources.projection),
  };
  const blockers = [];
  if (policy.state !== "ready") blockers.push("handoff-state-not-ready");
  if (!parity.ansible_parity) blockers.push("ansible-timezone-parity-unproven");
  if (!parity.nix_runtime_parity) blockers.push("nix-timezone-parity-unproven");
  if (planningDomainPresent) blockers.push("nix-planning-domain-present");
  if (Object.values(mutationSources).some(Boolean)) blockers.push("nix-mutation-source-present");
  blockers.push("saved-handoff-plan-required", "separate-handoff-authorization-required");

  const planMaterial = {
    version: 1,
    domain: "timezone",
    from_owner: policy.current_owner,
    to_owner: policy.target_owner,
    state: policy.state,
    ansible_parity: parity.ansible_parity,
    nix_runtime_parity: parity.nix_runtime_parity,
    planning_domain_present: planningDomainPresent,
    mutation_sources: mutationSources,
    blockers,
    ready: blockers.length === 2,
    authorized: false,
  };
  return {
    ...planMaterial,
    plan_sha256: crypto.createHash("sha256").update(canonicalJson(planMaterial)).digest("hex"),
  };
}

module.exports = { canonicalJson, planProxmoxTimezoneHandoff };
