#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const { planProxmoxTimezoneHandoff } = require("./proxmox-timezone-handoff");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const contract = load(read("infrastructure/contract/home-lab.yml"));
const sources = {
  projection: read("scripts/controller/proxmox-nix-projection.js"),
  planner: read("nix/proxmox/planner.py"),
  activator: read("nix/proxmox/activator-template.py"),
};
const tasks = load(read("ansible/roles/proxmox_parity/tasks/main.yml"));
const baseTasks = load(read("ansible/roles/base/tasks/main.yml"));
const playbook = load(read("ansible/playbooks/proxmox-timezone-handoff-plan.yml"))[0];

const current = planProxmoxTimezoneHandoff(contract, sources, {
  ansible_parity: true,
  nix_runtime_parity: false,
});
assert.equal(current.ready, false);
assert.equal(current.authorized, true);
assert.deepEqual(current.blockers, ["nix-timezone-parity-unproven"]);
assert.match(current.plan_sha256, /^[0-9a-f]{64}$/);

const readyContract = structuredClone(contract);
readyContract.lifecycle.hosts.proxmox.domain_handoffs.timezone.state = "ready";
readyContract.lifecycle.hosts.proxmox.domain_handoffs.timezone.current_owner = "nix";
readyContract.proxmox.planning_policy.domains = readyContract.proxmox.planning_policy.domains.filter(
  (entry) => entry.domain !== "timezone",
);
const ready = planProxmoxTimezoneHandoff(
  readyContract,
  { projection: "", planner: "", activator: "" },
  { ansible_parity: true, nix_runtime_parity: true },
);
assert.equal(ready.ready, true);
assert.equal(ready.authorized, false);
assert.deepEqual(ready.blockers, ["saved-handoff-plan-required", "separate-handoff-authorization-required"]);

const invalidOwner = structuredClone(contract);
invalidOwner.lifecycle.hosts.proxmox.domain_handoffs.timezone.current_owner = "nix";
assert.throws(
  () => planProxmoxTimezoneHandoff(invalidOwner, sources, { ansible_parity: true, nix_runtime_parity: true }),
  /owner and state disagree/,
);

const allowedModules = new Set([
  "ansible.builtin.assert",
  "ansible.builtin.command",
  "ansible.builtin.debug",
  "ansible.builtin.set_fact",
]);
for (const item of tasks) {
  const modules = Object.keys(item).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1, `${item.name} must use one builtin module`);
  assert(allowedModules.has(modules[0]), `${item.name} uses mutation-capable module ${modules[0]}`);
}
const observer = tasks.find((item) => item.name === "Observe timezone and reduced installed Nix domain evidence");
assert(observer, "Proxmox parity observer task is required");
assert.equal(observer.changed_when, false);
assert.equal(observer.check_mode, false);
const observerScript = observer["ansible.builtin.command"].argv[2];
for (const required of [
  '"/usr/bin/timedatectl", "show"',
  'observer_path, "observe"',
  '"localtime_matches"',
  '"evidence_sha256"',
]) {
  assert(observerScript.includes(required), `Proxmox parity observer omits ${required}`);
}
for (const forbidden of ["set-timezone", 'observer_path, "apply"', 'observer_path, "prepare"']) {
  assert(!observerScript.includes(forbidden), `Proxmox parity observer contains mutation path ${forbidden}`);
}
const timezoneMutation = baseTasks.find((item) => item.name === "Converge the system timezone outside check mode");
assert(timezoneMutation, "Ansible timezone convergence task is required");
assert(timezoneMutation.when.includes("base_timezone_mutation_authorized | bool"));
const ownership = baseTasks.find((item) => item.name === "Resolve timezone mutation ownership");
assert.match(ownership["ansible.builtin.set_fact"].base_timezone_mutation_authorized, /state == 'transferred'/);
const publish = tasks.find((item) => item.name === "Publish timezone handoff status");
assert(publish, "timezone handoff status task is required");
const published = publish["ansible.builtin.set_fact"].proxmox_parity_timezone_handoff_observation;
assert.match(published.handoff_ready, /state == 'transferred'/);
assert.match(published.handoff_authorized, /current_owner == 'ansible'/);

assert.equal(playbook.hosts, "proxmox_host");
assert.equal(playbook.gather_facts, false);
assert.equal(playbook.any_errors_fatal, true);
assert.equal(playbook.serial, 1);
assert.equal(playbook.roles[0].role, "lifecycle_state");
assert.equal(playbook.roles[0].vars.lifecycle_state_enforce, false);
assert.equal(playbook.roles[1].role, "proxmox_parity");

const handoff = contract.lifecycle.hosts.proxmox.domain_handoffs.timezone;
assert.deepEqual(handoff, {
  current_owner: "ansible",
  target_owner: "ansible",
  state: "transferred",
  parity_required: true,
  single_writer: true,
});

const transaction = read("scripts/controller/proxmox-timezone-handoff-transaction.py");
for (const required of ["PROXMOX_TIMEZONE_HANDOFF_CONFIRMED", "os.O_EXCL", "os.O_NOFOLLOW", "ansible-plan@proxmox", "host_mutation\": False"]) {
  assert(transaction.includes(required), `timezone transaction omits ${required}`);
}
assert(!transaction.includes("StrictHostKeyChecking=no"));

console.log("proxmox_timezone_handoff=verified");
