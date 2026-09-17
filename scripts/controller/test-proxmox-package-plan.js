#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const yaml = (relative) => load(fs.readFileSync(path.join(root, relative), "utf8"));
for (const retired of ["ansible/roles/proxmox_package_plan", "ansible/roles/proxmox_complete_audit",
  "ansible/playbooks/proxmox-packages-plan.yml", "ansible/inventory/proxmox-production.yml"]) {
  assert(!fs.existsSync(path.join(root, retired)), `retired custom package planning source remains: ${retired}`);
}
// Native inventory is independently runnable from a fresh checkout and grants no
// mutation authority.
const nativePlay = yaml("ansible/playbooks/observe-proxmox-packages.yml")[0];
const nativeTasks = yaml("ansible/roles/proxmox_package_observe/tasks/main.yml");
assert.equal(nativePlay.hosts, "proxmox");
assert.equal(nativePlay.gather_facts, false);
assert.equal(nativePlay.any_errors_fatal, true);
assert.deepEqual(nativePlay.roles.map((role) => role.role), ["proxmox_observe", "proxmox_package_observe"]);
for (const task of nativeTasks) {
  const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1);
  assert(new Set(["ansible.builtin.assert", "ansible.builtin.command", "ansible.builtin.debug", "ansible.builtin.package_facts"]).has(modules[0]));
}
const nativeCommands = nativeTasks.filter((task) => task["ansible.builtin.command"]);
assert.deepEqual(nativeCommands.map((task) => task["ansible.builtin.command"].argv), [
  ["/usr/bin/dpkg", "--audit"], ["/usr/bin/apt-mark", "showhold"],
]);
for (const sample of nativeCommands) {
  assert.equal(sample.changed_when, false);
  assert.equal(sample.failed_when, undefined);
  assert.equal(sample.check_mode, false);
  assert.equal(sample.no_log, true);
  assert.equal(sample.timeout, 60);
}
const facts = nativeTasks.find((task) => task["ansible.builtin.package_facts"]);
assert.deepEqual(facts["ansible.builtin.package_facts"], {manager: "apt", strategy: "first"});
assert.equal(facts.no_log, true);
const nativeSource = JSON.stringify(nativeTasks);
for (const forbidden of ["nix/", ".local/", ".reconcile/", "artifact_dir", "ansible-plan", "ansible-deploy", "save-host-maintenance-plan", "cacheable", "package-candidate-observer", "package-manifest", "apt-get"])
  assert(!nativeSource.includes(forbidden), `native sampling depends on ${forbidden}`);
const nativeReport = nativeTasks.find((task) => task["ansible.builtin.debug"])["ansible.builtin.debug"].msg;
assert.equal(nativeReport.apply_authorized, false);
assert.equal(nativeReport.metadata_refresh_performed, false);
assert.equal(nativeReport.candidate_preview_performed, false);
assert.equal(nativeReport.held_packages, "{{ proxmox_package_holds.stdout_lines | length }}");

// The maintenance path uses core APT, not our collector, manifest or saved plans.
// Its exact no-refresh no-op production cutover completed without package changes.
const maintenancePlay = yaml("ansible/playbooks/maintain-proxmox-packages.yml")[0];
assert.equal(maintenancePlay.hosts, "proxmox");
assert.equal(maintenancePlay.serial, 1);
assert.equal(maintenancePlay.any_errors_fatal, true);
assert.deepEqual(maintenancePlay.roles.map((role) => role.role),
  ["proxmox_observe", "proxmox_package_observe", "proxmox_package_maintenance"]);
assert.equal(maintenancePlay.pre_tasks, undefined);
const maintenance = yaml("ansible/roles/proxmox_package_maintenance/tasks/main.yml");
assert(maintenance.every((task) => Object.keys(task).some((key) =>
  ["ansible.builtin.apt", "ansible.builtin.assert", "ansible.builtin.debug"].includes(key))));
const aptTasks = maintenance.filter((task) => task["ansible.builtin.apt"]);
assert.equal(aptTasks.length, 2);
for (const task of aptTasks) {
  const apt = task["ansible.builtin.apt"];
  for (const field of ["auto_install_module_deps", "allow_downgrade", "allow_change_held_packages", "allow_unauthenticated", "autoremove", "autoclean", "clean", "force"])
    assert.equal(apt[field], false, field);
  assert.equal(apt.fail_on_autoremove, true);
  assert.equal(apt.force_apt_get, true);
  assert.equal(apt.lock_timeout, 0);
  assert.equal(apt.cache_valid_time, 0);
  assert.equal(apt.update_cache, "{{ proxmox_package_refresh_metadata }}");
  assert.equal(apt.dpkg_options, "force-confold");
  assert.equal(task.check_mode, undefined);
  assert.equal(task.no_log, true);
  assert.equal(task.diff, false);
}
assert.equal(aptTasks[0]["ansible.builtin.apt"].name, "{{ proxmox_package_specs }}");
assert.equal(aptTasks[1]["ansible.builtin.apt"].upgrade, "dist");
for (const forbidden of ["nix/", ".local/", ".reconcile/", "manifest", "collector", "receipt", "activator", "save-host-maintenance-plan", "command", "shell"])
  assert(!JSON.stringify(maintenance).includes(forbidden), forbidden);
console.log("proxmox_native_package_inventory_and_maintenance=verified legacy_plan=absent");
