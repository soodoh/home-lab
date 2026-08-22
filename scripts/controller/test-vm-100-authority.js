#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { assertOrdinaryMutationPermitted, validateAuthority } = require("./check-vm-100-authority");

const root = path.resolve(__dirname, "../..");
const applyGuard = fs.readFileSync(path.join(root, "ansible/roles/apply_guard/tasks/main.yml"), "utf8");
if (!applyGuard.includes("vm_100.deployment_authority == 'debian'") || !applyGuard.includes("when: not ansible_check_mode")) {
  throw new Error("Ansible convergence does not require Debian authority");
}

if (validateAuthority({ deployment_authority: "debian" }) !== "debian") {
  throw new Error("Debian authority was not preserved");
}
for (const authority of ["arch", "migration-in-progress", "nixos", "flatcar", "dual", undefined]) {
  let rejected = false;
  try { validateAuthority({ deployment_authority: authority }); } catch { rejected = true; }
  if (!rejected) throw new Error(`retired or invalid authority was accepted: ${authority}`);
}
if (assertOrdinaryMutationPermitted({ deployment_authority: "debian" }) !== "debian") {
  throw new Error("Debian ordinary mutation was unexpectedly refused");
}

const current = spawnSync(
  process.execPath,
  ["scripts/controller/check-vm-100-authority.js", "--require-ordinary-mutation"],
  { cwd: root, encoding: "utf8" },
);
if (current.status !== 0 || current.stdout !== "vm_100_mutation_authority=debian\n" || current.stderr !== "") {
  throw new Error(`checked Debian authority gate failed: stdout=${current.stdout} stderr=${current.stderr}`);
}
console.log("vm_100_authority=verified");
