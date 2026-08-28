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

function hclBlocks(section) {
  return section.match(/\{[\s\S]*?\}/g) || [];
}

function quotedValues(block, field) {
  const match = block.match(new RegExp(`${field}\\s*=\\s*\\[([^\\]]*)\\]`));
  return match ? [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]) : [];
}

function planProxmoxAccessCutover(contract, sources, hostEvidence) {
  if (!contract || !sources || !hostEvidence) throw new Error("access cutover inputs are required");
  const policy = contract.lifecycle?.hosts?.proxmox?.access_cutover;
  if (!policy || policy.state === "complete") throw new Error("pending access cutover policy is required");
  for (const name of ["tailnet", "inventory", "firewallController", "firewallTransport"]) {
    if (typeof sources[name] !== "string") throw new Error(`access cutover source ${name} is required`);
  }
  if (!Array.isArray(hostEvidence.accounts) || !Array.isArray(hostEvidence.conventional_key_files)) {
    throw new Error("reduced host access evidence is invalid");
  }
  for (const name of ["plan_observer_proven", "canaries_proven", "root_keys_attributed", "console_attested"]) {
    if (typeof hostEvidence[name] !== "boolean") throw new Error(`access cutover evidence ${name} is required`);
  }

  const sshSection = sources.tailnet.split("ssh = [", 2)[1]?.split("tests = [", 1)[0] || "";
  const proxmoxSshBlocks = hclBlocks(sshSection).filter((block) => /dst\s*=\s*\[local\.tags\.proxmox\]/.test(block));
  const grantedUsers = new Set(proxmoxSshBlocks.flatMap((block) => quotedValues(block, "users")));
  const testsSection = sources.tailnet.split("sshTests = [", 2)[1] || "";
  const proxmoxTest = hclBlocks(testsSection).find((block) => /dst\s*=\s*\[local\.tags\.proxmox\]/.test(block)) || "";
  const acceptedUsers = new Set(quotedValues(proxmoxTest, "accept"));
  const deniedUsers = new Set(quotedValues(proxmoxTest, "deny"));

  const tailnet = {
    required_grants_present: policy.required_tailnet_users.every((name) => grantedUsers.has(name)),
    required_test_accepts_present: policy.required_tailnet_users.every((name) => acceptedUsers.has(name)),
    forbidden_test_denies_present: policy.forbidden_tailnet_users.every((name) => deniedUsers.has(name)),
    granted_users: [...grantedUsers].sort(),
    test_accepts: [...acceptedUsers].sort(),
    test_denies: [...deniedUsers].sort(),
  };
  const sourceChecks = {
    firewall_magicdns_target_present: sources.firewallController.includes(`PVE_SSH_TARGET = "${policy.firewall_magicdns_target}"`),
    firewall_transport_tailscale_compatible: !sources.firewallTransport.includes('[ "$2" != "$self" ]') &&
      !sources.firewallTransport.includes("SSH_ORIGINAL_COMMAND"),
    plan_inventory_identity_present: /ansible_user:\s*ansible-plan/.test(sources.inventory),
  };
  const account = (name) => hostEvidence.accounts.find((item) => item.name === name);
  const targetAccounts = Object.fromEntries(Object.entries(policy.target_identities).map(([kind, name]) => [
    kind,
    Boolean(account(name)?.exists),
  ]));
  const retiredAccountsAbsent = policy.retire_identities.every((name) => !account(name)?.exists);
  const rootAccount = account("root");
  if (!rootAccount?.exists || !Array.isArray(rootAccount.groups)) throw new Error("root group evidence is required");
  const unexpectedRootGroups = rootAccount.groups.filter((name) => name !== "root").sort();

  const blockers = [];
  if (policy.state !== "ready") blockers.push("access-cutover-state-not-ready");
  if (!targetAccounts.plan) blockers.push("ansible-plan-account-absent");
  if (!targetAccounts.apply) blockers.push("ansible-deploy-account-absent");
  if (!tailnet.required_grants_present) blockers.push("tailnet-required-user-grants-missing");
  if (!tailnet.required_test_accepts_present || !tailnet.forbidden_test_denies_present) blockers.push("tailnet-ssh-tests-incomplete");
  if (!sourceChecks.plan_inventory_identity_present) blockers.push("plan-inventory-identity-not-cut-over");
  if (!sourceChecks.firewall_magicdns_target_present) blockers.push("firewall-controller-still-uses-lan-target");
  if (!sourceChecks.firewall_transport_tailscale_compatible) blockers.push("firewall-transport-not-tailscale-compatible");
  if (hostEvidence.conventional_key_files.length) blockers.push("conventional-authorized-keys-present");
  if (hostEvidence.pubkey_authentication !== "no") blockers.push("openssh-pubkey-authentication-enabled");
  if (hostEvidence.permit_root_login !== "no") blockers.push("openssh-root-login-enabled");
  if (!retiredAccountsAbsent) blockers.push("transitional-tofu-identities-present");
  if (unexpectedRootGroups.length) blockers.push("unexpected-root-supplementary-groups");
  if (!hostEvidence.plan_observer_proven) blockers.push("plan-fixed-observer-helper-proof-required");
  if (!hostEvidence.canaries_proven) blockers.push("independent-live-session-canaries-required");
  if (!hostEvidence.root_keys_attributed) blockers.push("root-key-owner-attribution-required");
  if (!hostEvidence.console_attested) blockers.push("physical-console-attestation-required");
  blockers.push("saved-access-cutover-plan-required", "separate-access-cutover-authorization-required");

  const material = {
    version: 1,
    policy_state: policy.state,
    target_accounts: targetAccounts,
    transitional_accounts_absent: retiredAccountsAbsent,
    unexpected_root_supplementary_groups: unexpectedRootGroups,
    tailnet,
    source_checks: sourceChecks,
    conventional_key_file_count: hostEvidence.conventional_key_files.length,
    pubkey_authentication: hostEvidence.pubkey_authentication,
    permit_root_login: hostEvidence.permit_root_login,
    attestations: {
      plan_observer_proven: hostEvidence.plan_observer_proven,
      canaries_proven: hostEvidence.canaries_proven,
      root_keys_attributed: hostEvidence.root_keys_attributed,
      console_attested: hostEvidence.console_attested,
    },
    blockers,
    ready: blockers.length === 2,
    authorized: false,
  };
  return {
    ...material,
    plan_sha256: crypto.createHash("sha256").update(canonicalJson(material)).digest("hex"),
  };
}

module.exports = { canonicalJson, planProxmoxAccessCutover };
