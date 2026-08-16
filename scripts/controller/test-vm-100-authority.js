#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const {
  assertOrdinaryMutationPermitted,
  refusalReason,
  validateAuthority,
} = require("./check-vm-100-authority");

const root = path.resolve(__dirname, "../..");
for (const authority of ["arch", "flatcar"]) {
  if (validateAuthority({ deployment_authority: authority }) !== authority) {
    throw new Error(`${authority} authority was not preserved`);
  }
}
for (const authority of ["migration-in-progress", "nixos", "dual", undefined]) {
  let rejected = false;
  try { validateAuthority({ deployment_authority: authority }); } catch { rejected = true; }
  if (!rejected) throw new Error(`retired or invalid authority was accepted: ${authority}`);
}
if (assertOrdinaryMutationPermitted({ deployment_authority: "arch" }) !== "arch") {
  throw new Error("Arch ordinary mutation was unexpectedly refused");
}
let refused = false;
try {
  assertOrdinaryMutationPermitted({ deployment_authority: "flatcar" });
} catch (error) {
  refused = error.code === "VM100_ORDINARY_MUTATION_INHIBITED" && error.authority === "flatcar";
}
if (!refused || refusalReason("flatcar") !== "flatcar_authoritative") {
  throw new Error("Flatcar authority did not refuse the Arch mutation path");
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
