#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const yaml = (relative) => load(fs.readFileSync(path.join(root, relative), "utf8"));
const tasks = yaml("ansible/roles/proxmox_package_plan/tasks/main.yml");
const play = yaml("ansible/playbooks/proxmox-packages-plan.yml")[0];
const inventory = yaml("ansible/inventory/proxmox-production.yml");
const group = yaml("ansible/group_vars/proxmox_host.yml");
const allowed = new Set(["ansible.builtin.assert", "ansible.builtin.command", "ansible.builtin.debug", "ansible.builtin.set_fact", "ansible.builtin.slurp", "ansible.builtin.stat"]);
for (const task of tasks) {
  const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1, `${task.name} must use one builtin module`);
  assert(allowed.has(modules[0]), `${task.name} has mutation module ${modules[0]}`);
}
const fetch = tasks.find((task) => task.name === "Fetch the bounded Proxmox package candidate through ansible-plan");
assert(fetch);
assert.equal(fetch.changed_when, false);
assert.equal(fetch.check_mode, false);
assert.equal(fetch.no_log, true);
const argv = fetch["ansible.builtin.command"].argv;
for (const required of ["proxmox_controller_ssh_options", "UserKnownHostsFile=", "proxmox_plan_ssh_target", "proxmox_package_observer_remote_command"]) {
  assert(argv.includes(required), `fixed package fetch omits ${required}`);
}
const publish = tasks.find((task) => task.name === "Publish Proxmox package readiness without authorizing apply");
assert.equal(publish["ansible.builtin.set_fact"].proxmox_package_plan_observation.apply_authorized, false);
assert.equal(group.proxmox_package_observer_remote_command, "observe-package");
assert.deepEqual(play.roles.map((role) => role.role), ["proxmox_complete_audit", "proxmox_package_plan"]);
assert.equal(play.become, false);
assert.equal(inventory.all.children.proxmox_host.hosts["proxmox-host-production"].ansible_connection, "local");
const source = fs.readFileSync(path.join(root, "ansible/roles/proxmox_package_plan/tasks/main.yml"), "utf8");
for (const required of ["package_observer_sha256", "package_observer_template_sha256", "apt-state-tree-unsafe", "package-size-evidence-incomplete", "saved-reviewed-plan-required"]) {
  assert(source.includes(required), `Proxmox package plan omits ${required}`);
}
for (const forbidden of ["ansible-deploy", "apt-get", "become: true", "shell:", "raw:"]) {
  assert(!source.includes(forbidden), `Proxmox package plan exposes ${forbidden}`);
}
// Native sampling is independently runnable from a fresh checkout. It must not
// become a bypass into the retained complete-audit or activation interfaces.
const nativePlay = yaml("ansible/playbooks/observe-proxmox-packages.yml")[0];
const nativeTasks = yaml("ansible/roles/proxmox_package_observe/tasks/main.yml");
assert.equal(nativePlay.hosts, "proxmox");
assert.equal(nativePlay.gather_facts, false);
assert.equal(nativePlay.any_errors_fatal, true);
assert.deepEqual(nativePlay.roles.map((role) => role.role), ["proxmox_observe", "proxmox_package_observe"]);
for (const task of nativeTasks) {
  const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1);
  assert(new Set(["ansible.builtin.assert", "ansible.builtin.command", "ansible.builtin.debug", "ansible.builtin.set_fact", "ansible.builtin.fail"]).has(modules[0]));
}
const nativeCommands = nativeTasks.filter((task) => task["ansible.builtin.command"]);
assert.equal(nativeCommands.length, 1);
const sample = nativeCommands[0];
assert.deepEqual(sample["ansible.builtin.command"].argv, ["/usr/bin/python3", "-I", "-B", "-", "observe", "proxmox"]);
assert.equal(sample.changed_when, false);
assert.equal(sample.failed_when, false); // Deferred only to the immediately following fixed-category failure.
const failure = nativeTasks[nativeTasks.indexOf(sample) + 1];
assert(failure["ansible.builtin.fail"]);
assert.equal(failure.when, "proxmox_package_observe_raw.rc | default(-1) != 0");
assert.equal(sample.check_mode, false);
assert.equal(sample.no_log, true);
assert.equal(sample.timeout, 600);
const stdin = sample["ansible.builtin.command"].stdin;
assert(stdin.includes("infrastructure/maintenance/host/package-candidate-observer"));
assert(stdin.includes("infrastructure/host-lifecycle/proxmox/package-manifest.json"));
const nativeSource = JSON.stringify(nativeTasks);
for (const forbidden of ["nix/", ".local/", ".reconcile/", "artifact_dir", "ansible-plan", "ansible-deploy", "save-host-maintenance-plan", "cacheable"])
  assert(!nativeSource.includes(forbidden), `native sampling depends on ${forbidden}`);
const nativeReport = nativeTasks.find((task) => task["ansible.builtin.debug"])["ansible.builtin.debug"].msg;
assert.equal(nativeReport.apply_authorized, false);
assert.equal(nativeReport.metadata_refresh_performed, false);
assert(!JSON.stringify(nativeReport).includes("proxmox_package_observe_raw"));
assert.equal(yaml("ansible/inventory/host_vars/proxmox.yml").proxmox_package_observe_max_age_seconds,
  yaml("infrastructure/contract/home-lab.yml").lifecycle.maintenance.package_plan.max_metadata_age_seconds);
console.log("proxmox_package_plan=verified");
