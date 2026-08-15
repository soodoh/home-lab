#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "../..");
const projectionPath = path.join(root, "nix/vm-100/projection.json");

function validateAuthority(vm100) {
  const activationByAuthority = {
    arch: false,
    "migration-in-progress": false,
    nixos: true,
  };
  const authority = vm100?.deployment_authority;
  if (!Object.hasOwn(activationByAuthority, authority) ||
      vm100.nixos_activation_enabled !== activationByAuthority[authority]) {
    throw new Error("VM 100 deployment authority and NixOS activation relation is invalid");
  }
  return authority;
}

function assertOrdinaryMutationPermitted(vm100) {
  const authority = validateAuthority(vm100);
  if (authority !== "arch") {
    const error = new Error(`ordinary steady/recovery mutation is inhibited for VM 100 authority ${authority}`);
    error.code = "VM100_ORDINARY_MUTATION_INHIBITED";
    error.authority = authority;
    throw error;
  }
  return authority;
}

function refusalReason(authority) {
  if (authority === "migration-in-progress") return "migration_in_progress";
  if (authority === "nixos") return "nixos_authoritative";
  throw new Error(`no ordinary-mutation refusal reason for authority ${authority}`);
}

function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "--require-ordinary-mutation") {
    throw new Error("usage: check-vm-100-authority.js --require-ordinary-mutation");
  }
  const projection = JSON.parse(fs.readFileSync(projectionPath, "utf8"));
  const vm100 = {
    deployment_authority: projection.deploymentAuthority,
    nixos_activation_enabled: projection.nixosActivationEnabled,
  };
  try {
    const authority = assertOrdinaryMutationPermitted(vm100);
    process.stdout.write(`vm_100_mutation_authority=${authority}\n`);
  } catch (error) {
    if (error.code === "VM100_ORDINARY_MUTATION_INHIBITED") {
      const reason = refusalReason(error.authority);
      process.stderr.write(`vm_100_mutation=refused reason=${reason}\n`);
      process.exitCode = 77;
      return;
    }
    throw error;
  }
}

if (require.main === module) main();
module.exports = { assertOrdinaryMutationPermitted, refusalReason, validateAuthority };
