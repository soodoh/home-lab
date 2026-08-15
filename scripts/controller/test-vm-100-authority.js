#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const {
  assertOrdinaryMutationPermitted,
  refusalReason,
  validateAuthority,
} = require("./check-vm-100-authority");

const root = path.resolve(__dirname, "../..");
for (const [authority, activationEnabled] of [["arch", false], ["migration-in-progress", false], ["nixos", true]]) {
  const vm100 = { deployment_authority: authority, nixos_activation_enabled: activationEnabled };
  if (validateAuthority(vm100) !== authority) throw new Error(`${authority} relation was not preserved`);
}
for (const vm100 of [
  { deployment_authority: "arch", nixos_activation_enabled: true },
  { deployment_authority: "migration-in-progress", nixos_activation_enabled: true },
  { deployment_authority: "nixos", nixos_activation_enabled: false },
  { deployment_authority: "dual", nixos_activation_enabled: false },
]) {
  let rejected = false;
  try { validateAuthority(vm100); } catch { rejected = true; }
  if (!rejected) throw new Error(`invalid authority relation was accepted: ${JSON.stringify(vm100)}`);
}
if (assertOrdinaryMutationPermitted({ deployment_authority: "arch", nixos_activation_enabled: false }) !== "arch") {
  throw new Error("Arch ordinary mutation was unexpectedly refused");
}
for (const [authority, activationEnabled] of [["migration-in-progress", false], ["nixos", true]]) {
  let refused = false;
  try {
    assertOrdinaryMutationPermitted({ deployment_authority: authority, nixos_activation_enabled: activationEnabled });
  } catch (error) {
    refused = error.code === "VM100_ORDINARY_MUTATION_INHIBITED" && error.authority === authority;
  }
  if (!refused) throw new Error(`${authority} authority did not refuse ordinary mutation`);
}
if (refusalReason("migration-in-progress") !== "migration_in_progress") throw new Error("migration refusal reason differs");
if (refusalReason("nixos") !== "nixos_authoritative") throw new Error("NixOS refusal reason differs");

const checkerSource = fs.readFileSync(path.join(root, "scripts/controller/check-vm-100-authority.js"), "utf8");
if (checkerSource.includes("js-yaml") || !checkerSource.includes("nix/vm-100/projection.json")) {
  throw new Error("authority checker must remain dependency-free and projection-bound");
}

const current = spawnSync(
  process.execPath,
  ["scripts/controller/check-vm-100-authority.js", "--require-ordinary-mutation"],
  { cwd: root, encoding: "utf8" },
);
if (current.status !== 0 || current.stdout !== "vm_100_mutation_authority=arch\n") {
  throw new Error(`checked Arch authority gate failed: ${current.stderr}`);
}

console.log("vm_100_authority=verified");
