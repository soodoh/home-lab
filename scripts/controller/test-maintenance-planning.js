#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const readYaml = (relative) => load(fs.readFileSync(path.join(root, relative), "utf8"));
const packageTasks = readYaml("ansible/roles/package_lifecycle/tasks/main.yml");
const rebootTasks = readYaml("ansible/roles/reboot_lifecycle/tasks/main.yml");
const packagePlaybook = readYaml("ansible/playbooks/packages-plan.yml")[0];
const rebootPlaybook = readYaml("ansible/playbooks/reboot-plan.yml")[0];
const contract = readYaml("infrastructure/contract/home-lab.yml");
const nixPlanner = fs.readFileSync(path.join(root, "nix/proxmox/planner.py"), "utf8");
const nixActivator = fs.readFileSync(path.join(root, "nix/proxmox/activator-template.py"), "utf8");

function task(tasks, name) {
  const matches = tasks.filter((item) => item.name === name);
  assert.equal(matches.length, 1, `expected one task named ${name}`);
  return matches[0];
}

const allowedModules = new Set([
  "ansible.builtin.assert",
  "ansible.builtin.command",
  "ansible.builtin.debug",
  "ansible.builtin.set_fact",
]);
for (const item of [...packageTasks, ...rebootTasks]) {
  const modules = Object.keys(item).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1, `${item.name} must use one builtin module`);
  assert(allowedModules.has(modules[0]), `${item.name} uses mutation-capable module ${modules[0]}`);
}

for (const item of [...packageTasks, ...rebootTasks].filter((entry) => entry["ansible.builtin.command"])) {
  assert.equal(item.changed_when, false, `${item.name} must report no change`);
  assert.equal(item.check_mode, false, `${item.name} must remain observable in check mode`);
  assert.equal(item.become, true, `${item.name} must use the bounded observer privilege path`);
  const argv = item["ansible.builtin.command"].argv;
  assert(Array.isArray(argv) && argv[0] === "/usr/bin/python3" && argv[1] === "-c", `${item.name} must use fixed Python argv`);
}

const packageObserver = task(packageTasks, "Build a reduced read-only package proposal from existing APT metadata");
const packageScript = packageObserver["ansible.builtin.command"].argv[2];
for (const required of [
  '"/usr/bin/apt-get"',
  '"--simulate"',
  '"Debug::NoLocking=1"',
  '"/usr/bin/dpkg-query"',
  '"/usr/bin/apt-mark", "showhold"',
  '"metadata_refresh_performed": False',
  '"proposal_sha256"',
  'Status-Abbrev',
  'installed_status_lines',
  '"manifest_matches"',
  '"expected_manifest_sha256"',
]) {
  assert(packageScript.includes(required), `package observer omits ${required}`);
}
for (const forbidden of ['"update"', '"install"', '"remove"']) {
  assert(!packageScript.includes(`"/usr/bin/apt-get", ${forbidden}`), `package observer can execute apt-get ${forbidden}`);
}
const packagePublish = task(packageTasks, "Publish package proposal readiness without authorizing apply");
assert.equal(packagePublish["ansible.builtin.set_fact"].package_lifecycle_observation.apply_authorized, false);

const rebootObserver = task(rebootTasks, "Build reduced read-only reboot evidence");
const rebootScript = rebootObserver["ansible.builtin.command"].argv[2];
for (const required of [
  '"/proc/sys/kernel/random/boot_id"',
  '"/var/run/reboot-required"',
  '"home-lab-restic-daily-local.service"',
  '"home-lab-restic-daily-proton.service"',
  '"/usr/sbin/zpool", "status", "-x", "storage"',
  '"/usr/sbin/qm", "status", "100"',
  '"evidence_sha256"',
]) {
  assert(rebootScript.includes(required), `reboot observer omits ${required}`);
}
for (const forbidden of [
  '["/usr/bin/systemctl", "reboot"',
  '["/usr/bin/systemctl", "restart"',
  '"/usr/sbin/reboot"',
  '"/usr/sbin/shutdown"',
]) {
  assert(!rebootScript.includes(forbidden), `reboot observer contains mutation command ${forbidden}`);
}
const rebootPublish = task(rebootTasks, "Publish reboot plan readiness without authorizing reboot");
assert.equal(rebootPublish["ansible.builtin.set_fact"].reboot_lifecycle_observation.reboot_authorized, false);

for (const playbook of [packagePlaybook, rebootPlaybook]) {
  assert.equal(playbook.hosts, "docker_host:proxmox_host");
  assert.equal(playbook.gather_facts, false);
  assert.equal(playbook.any_errors_fatal, true);
  assert.equal(playbook.serial, 1);
  assert.deepEqual(playbook.vars_files, ["{{ playbook_dir }}/../../infrastructure/contract/home-lab.yml"]);
  assert.equal(playbook.roles[0].role, "lifecycle_state");
  assert.equal(playbook.roles[0].vars.lifecycle_state_enforce, false);
}

const packagePolicy = contract.lifecycle.maintenance.package_plan;
assert.equal(packagePolicy.metadata_refresh, "explicit-reviewed-operation");
assert.equal(packagePolicy.max_metadata_age_seconds, 86400);
assert.equal(packagePolicy.resolver, "apt-get-simulate");
assert.equal(packagePolicy.save_exact_versions, true);
assert.equal(packagePolicy.apply_time_replan, false);
assert.equal(packagePolicy.hosts.debian.allowed_apply_scope, "reviewed-exact-set");
assert.equal(packagePolicy.hosts.debian.apply_authority, "exact-saved-package-transaction");
assert.equal(packagePolicy.hosts.proxmox.allowed_apply_scope, "reviewed-exact-set");
assert.equal(packagePolicy.hosts.proxmox.apply_authority, "protected-session");
assert.equal(packagePolicy.hosts.debian.automatic_apply, false);
assert.equal(packagePolicy.hosts.proxmox.automatic_apply, false);
assert.equal(packagePolicy.hosts.debian.automatic_reboot, false);
assert.equal(packagePolicy.hosts.proxmox.automatic_reboot, false);
assert.deepEqual(contract.lifecycle.hosts.proxmox.domain_handoffs.package_set, {
  current_owner: "ansible", target_owner: "ansible", state: "transferred", parity_required: true, single_writer: true,
});
assert(nixPlanner.includes("aggregate package actions remain closed until protected bootstrap"));
assert(!nixActivator.includes("reconcile-package-set"));

const rebootPolicy = contract.lifecycle.maintenance.reboot_plan;
assert.equal(rebootPolicy.automatic, false);
assert.equal(rebootPolicy.one_host_per_transaction, true);
assert.equal(rebootPolicy.backup_max_age_hours, contract.recovery.critical_rpo_hours);
assert.deepEqual(rebootPolicy.console_required_hosts, ["proxmox"]);

console.log("maintenance_planning=verified");
