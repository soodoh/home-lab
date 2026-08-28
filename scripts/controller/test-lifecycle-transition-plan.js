#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const tasks = load(read("ansible/roles/lifecycle_transition_plan/tasks/main.yml"));
const playbook = load(read("ansible/playbooks/lifecycle-transition-plan.yml"))[0];
const contract = load(read("infrastructure/contract/home-lab.yml"));
const inertFixture = load(read("infrastructure/debian/cloud-init/user-data.inert.fixture"));
const productionCloudInit = read("infrastructure/debian/cloud-init/user-data");
const tofuSource = read("infrastructure/tofu/proxmox/main.tf");

const allowedModules = new Set([
  "ansible.builtin.assert",
  "ansible.builtin.debug",
  "ansible.builtin.set_fact",
]);
for (const item of tasks) {
  const modules = Object.keys(item).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1, `${item.name} must use one builtin module`);
  assert(allowedModules.has(modules[0]), `${item.name} uses mutation-capable module ${modules[0]}`);
}
const publish = tasks.find((item) => item.name === "Publish lifecycle transition readiness without authorizing mutation");
assert.equal(publish["ansible.builtin.set_fact"].lifecycle_transition_plan_observation.ready, false);
assert.equal(publish["ansible.builtin.set_fact"].lifecycle_transition_plan_observation.authorized, false);
for (const required of [
  "valid-from-state-marker-required",
  "current-lifecycle-noncompliant",
  "active-lifecycle-lock",
  "recent-backup-attestation-required",
  "physical-console-attestation-required",
  "saved-transition-plan-required",
  "separate-transition-authorization-required",
]) {
  assert(String(publish["ansible.builtin.set_fact"].lifecycle_transition_plan_observation.blockers).includes(required));
}

assert.equal(playbook.hosts, "docker_host:proxmox_host");
assert.equal(playbook.gather_facts, false);
assert.equal(playbook.serial, 1);
assert.equal(playbook.roles[0].vars.lifecycle_state_enforce, false);
assert.equal(playbook.roles[1].role, "lifecycle_transition_plan");
assert.deepEqual(contract.lifecycle.transitions.production, ["maintenance", "recovery", "retired"]);
assert(!contract.lifecycle.transitions.production.includes("bootstrap"));
assert.deepEqual(contract.lifecycle.transitions.retired, []);

assert.equal(inertFixture.hostname, "docker-host");
assert.equal(inertFixture.disable_root, true);
assert.equal(inertFixture.ssh_pwauth, false);
assert.deepEqual(inertFixture.users, []);
assert.equal(inertFixture.package_update, false);
assert.equal(inertFixture.package_upgrade, false);
assert.deepEqual(inertFixture.packages, ["qemu-guest-agent"]);
assert.deepEqual(inertFixture.runcmd, [["systemctl", "enable", "--now", "qemu-guest-agent.service"]]);
for (const forbidden of [
  "ssh_authorized_keys",
  "authorized_keys",
  "tailscale",
  "unattended-upgrades",
  "allow-storage-activation",
  "/mnt/games",
  "/mnt/storage",
  "/srv/home-lab-state",
  "31602ce7-0054-498a-9f24-f51ca491e7b3",
  "d4a19647-7879-4079-9fc9-b3e79711b449",
]) {
  assert(!read("infrastructure/debian/cloud-init/user-data.inert.fixture").includes(forbidden), `inert fixture contains ${forbidden}`);
}
assert(productionCloudInit.includes("ssh_authorized_keys"), "production cloud-init reduction remains an explicit pending diff");
assert(!tofuSource.includes("user-data.inert.fixture"), "inert fixture must not silently change VM 100");
assert.equal(contract.debian.cloud_init.user_data.source_path, "infrastructure/debian/cloud-init/user-data");

console.log("lifecycle_transition_plan=verified");
