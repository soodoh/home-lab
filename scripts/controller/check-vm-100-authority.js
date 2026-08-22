#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");
const root = path.resolve(__dirname, "../..");
const contractPath = path.join(root, "infrastructure/contract/home-lab.yml");

function validateAuthority(vm100) {
  const authority = vm100?.deployment_authority;
  if (authority !== "debian") {
    throw new Error("VM 100 deployment authority must be debian");
  }
  return authority;
}

function assertOrdinaryMutationPermitted(vm100) {
  return validateAuthority(vm100);
}

function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "--require-ordinary-mutation") {
    throw new Error("usage: check-vm-100-authority.js --require-ordinary-mutation");
  }
  const contract = yaml.load(fs.readFileSync(contractPath, "utf8"));
  try {
    const authority = assertOrdinaryMutationPermitted(contract.vm_100);
    process.stdout.write(`vm_100_mutation_authority=${authority}\n`);
  } catch (error) {
    if (error.code === "VM100_ORDINARY_MUTATION_INHIBITED") {
      process.stderr.write(`vm_100_mutation=refused reason=${refusalReason(error.authority)}\n`);
      process.exitCode = 77;
      return;
    }
    throw error;
  }
}

if (require.main === module) main();
module.exports = { assertOrdinaryMutationPermitted, validateAuthority };
