#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const yaml = (relative) => load(read(relative));
const production = yaml("ansible/inventory/proxmox-production.yml");
const bootstrap = yaml("ansible/inventory/proxmox-bootstrap.yml");
const groupVars = yaml("ansible/group_vars/proxmox_host.yml");
const playbook = yaml("ansible/playbooks/proxmox-audit.yml");
const site = yaml("ansible/playbooks/proxmox-site.yml");
const tasks = yaml("ansible/roles/proxmox_complete_audit/tasks/main.yml");

const host = production.all.children.proxmox_host.hosts["proxmox-host-production"];
assert.equal(host.ansible_connection, "local");
assert.equal(host.lifecycle_contract_host, "proxmox");
assert.equal(host.lifecycle_profile, "production");
assert.equal(host.proxmox_audit_profile, "complete");
assert.equal(host.proxmox_plan_identity, "ansible-plan");
assert.equal(host.proxmox_deploy_identity, "ansible-deploy");
assert.notEqual(host.proxmox_plan_identity, host.proxmox_deploy_identity);
assert.equal(host.proxmox_plan_ssh_target, "ansible-plan@proxmox");
assert(!("ansible_user" in host), "fixed production audit must not expose a generic Ansible SSH shell");
assert(host.proxmox_observer_artifact_dir.includes("HOME_LAB_PROXMOX_OBSERVER_ARTIFACT"));

for (const required of ["-F", "/dev/null", "BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
  "IdentitiesOnly=yes", "ClearAllForwardings=yes", "PermitLocalCommand=no", "RequestTTY=no"]) {
  assert(groupVars.proxmox_controller_ssh_options.includes(required), `fixed audit SSH policy omits ${required}`);
}
assert.equal(groupVars.proxmox_observer_remote_command, "observe");
assert.equal(groupVars.proxmox_complete_audit_domain_count, 17);

const bootstrapHost = bootstrap.all.children.proxmox_host.hosts["proxmox-host-bootstrap"];
assert.equal(bootstrapHost.lifecycle_profile, "bootstrap");
for (const required of ["StrictHostKeyChecking=yes", "UpdateHostKeys=no", "UserKnownHostsFile=", "IdentitiesOnly=yes"]) {
  assert(bootstrapHost.ansible_ssh_common_args.includes(required), `bootstrap SSH policy omits ${required}`);
}
assert(!bootstrapHost.ansible_ssh_common_args.includes("StrictHostKeyChecking=no"));
assert(bootstrapHost.ansible_host.includes("HOME_LAB_PROXMOX_BOOTSTRAP_HOST"));
assert(bootstrapHost.ansible_ssh_common_args.includes("HOME_LAB_PROXMOX_BOOTSTRAP_KNOWN_HOSTS"));

assert.equal(playbook.length, 1);
assert.equal(playbook[0].hosts, "proxmox_host");
assert.equal(playbook[0].gather_facts, false);
assert.equal(playbook[0].become, false);
assert.equal(playbook[0].roles[0].role, "proxmox_complete_audit");
assert.equal(site.length, 1);
assert.equal(site[0]["ansible.builtin.import_playbook"], "proxmox-audit.yml");

const allowedModules = new Set(["ansible.builtin.assert", "ansible.builtin.command", "ansible.builtin.debug", "ansible.builtin.set_fact", "ansible.builtin.stat"]);
for (const task of tasks) {
  const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1, `${task.name} must use exactly one Ansible module`);
  assert(allowedModules.has(modules[0]), `${task.name} uses mutation-capable module ${modules[0]}`);
  if (modules[0] === "ansible.builtin.command") {
    assert.equal(task.changed_when, false, `${task.name} must report no change`);
    assert.equal(task.check_mode, false, `${task.name} must remain observable in check mode`);
    assert.equal(task.no_log, true, `${task.name} must suppress the full observation`);
  }
}

const roleSource = read("ansible/roles/proxmox_complete_audit/tasks/main.yml");
for (const required of ["ansible-plan", "UserKnownHostsFile=", "proxmox-ansible-audit.js", "stdin_add_newline: true"]) {
  assert(roleSource.includes(required), `complete audit role omits ${required}`);
}
for (const forbidden of ["StrictHostKeyChecking=no", "accept-new", "ansible_user: proxmox", "/usr/local/libexec/home-lab/proxmox-observer"]) {
  assert(!roleSource.includes(forbidden), `complete audit role retains forbidden dependency ${forbidden}`);
}
const validatorSource = read("scripts/controller/proxmox-ansible-audit.js");
for (const forbidden of ["nix/proxmox", "child_process", "execSync", "spawnSync", "shell: true"]) {
  assert(!validatorSource.includes(forbidden), `neutral validator retains forbidden dependency ${forbidden}`);
}

console.log("proxmox_complete_audit=verified domains=17");
