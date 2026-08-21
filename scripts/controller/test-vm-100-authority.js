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
const applyGuard = fs.readFileSync(path.join(root, "ansible/roles/apply_guard/tasks/main.yml"), "utf8");
if (!applyGuard.includes("vm_100.deployment_authority == 'arch'") || !applyGuard.includes("when: not ansible_check_mode")) {
  throw new Error("Ansible ordinary Arch convergence is not gated by VM 100 authority");
}
for (const authority of ["arch", "debian"]) {
  if (validateAuthority({ deployment_authority: authority }) !== authority) {
    throw new Error(`${authority} authority was not preserved`);
  }
}
for (const authority of ["migration-in-progress", "nixos", "flatcar", "dual", undefined]) {
  let rejected = false;
  try { validateAuthority({ deployment_authority: authority }); } catch { rejected = true; }
  if (!rejected) throw new Error(`retired or invalid authority was accepted: ${authority}`);
}
if (assertOrdinaryMutationPermitted({ deployment_authority: "arch" }) !== "arch") {
  throw new Error("Arch ordinary mutation was unexpectedly refused");
}
for (const [authority, reason] of [["debian", "debian_authoritative"]]) {
  let refused = false;
  try {
    assertOrdinaryMutationPermitted({ deployment_authority: authority });
  } catch (error) {
    refused = error.code === "VM100_ORDINARY_MUTATION_INHIBITED" && error.authority === authority;
  }
  if (!refused || refusalReason(authority) !== reason) {
    throw new Error(`${authority} authority did not refuse the Arch mutation path`);
  }
}

const current = spawnSync(
  process.execPath,
  ["scripts/controller/check-vm-100-authority.js", "--require-ordinary-mutation"],
  { cwd: root, encoding: "utf8" },
);
if (current.status !== 77 || current.stderr !== "vm_100_mutation=refused reason=debian_authoritative\n") {
  throw new Error(`checked Debian authority gate failed: stdout=${current.stdout} stderr=${current.stderr}`);
}
console.log("vm_100_authority=verified");
