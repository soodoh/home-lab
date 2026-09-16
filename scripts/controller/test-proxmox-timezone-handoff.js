#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const contract = load(read("infrastructure/contract/home-lab.yml"));
const baseTasks = load(read("ansible/roles/base/tasks/main.yml"));
// Retiring the completed handoff tools must not remove the shared ownership gate.
// Historical plans and authorizations are preserved, not consumed by this test.
for (const retired of [
  "ansible/roles/proxmox_parity",
  "ansible/playbooks/proxmox-timezone-handoff-plan.yml",
  "scripts/controller/proxmox-timezone-handoff.js",
  "scripts/controller/proxmox-timezone-handoff-transaction.py",
]) {
  assert(!fs.existsSync(path.join(root, retired)), `obsolete timezone parity consumer remains: ${retired}`);
}

const timezoneMutation = baseTasks.find((item) => item.name === "Converge the system timezone outside check mode");
assert(timezoneMutation, "Ansible timezone convergence task is required");
assert(timezoneMutation.when.includes("base_timezone_mutation_authorized | bool"));
const ownership = baseTasks.find((item) => item.name === "Resolve timezone mutation ownership");
assert.match(ownership["ansible.builtin.set_fact"].base_timezone_mutation_authorized, /state == 'transferred'/);
assert.match(ownership["ansible.builtin.set_fact"].base_timezone_mutation_authorized, /current_owner == 'ansible'/);

const handoff = contract.lifecycle.hosts.proxmox.domain_handoffs.timezone;
assert.deepEqual(handoff, {
  current_owner: "ansible",
  target_owner: "ansible",
  state: "transferred",
  parity_required: true,
  single_writer: true,
});

console.log("proxmox_timezone_handoff=verified");
