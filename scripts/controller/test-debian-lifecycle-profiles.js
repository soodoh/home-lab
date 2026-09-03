#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const yaml = (relative) => load(read(relative));
const contract = yaml("infrastructure/contract/home-lab.yml");
const groupVars = yaml("ansible/group_vars/docker_host.yml");
const site = yaml("ansible/playbooks/site.yml")[0];
const audit = yaml("ansible/playbooks/debian-lifecycle-audit.yml")[0];
const guardTasks = yaml("ansible/roles/debian_lifecycle_guard/tasks/main.yml");
const aptTasks = yaml("ansible/roles/apt_packages/tasks/main.yml");
const aptDefaults = yaml("ansible/roles/apt_packages/defaults/main.yml");
const baseSource = read("ansible/roles/base/tasks/main.yml");

assert.equal(contract.debian.locale, "C.UTF-8");
assert.equal(groupVars.debian_locale, "{{ debian.locale }}");
assert.deepEqual(groupVars.debian_protected_mounts, "{{ debian.qualification.protected_mounts }}");
for (const unit of ["docker.service", "home-lab-compose.service", "home-lab-restic-daily.timer",
  "home-lab-restic-maintenance.timer", "home-lab-restic-recover.service", "tailscaled.service"]) {
  assert(groupVars.debian_lifecycle_inactive_units.includes(unit), `inactive lifecycle audit omits ${unit}`);
}

const profileGuardIndex = site.pre_tasks.findIndex((item) => item.name === "Enforce lifecycle-specific Debian safety boundaries");
const applyGuardIndex = site.pre_tasks.findIndex((item) => item.name === "Enforce the apply safety contract");
assert(profileGuardIndex >= 0 && profileGuardIndex < applyGuardIndex, "lifecycle guard must run before apply planning or locks");
assert.equal(site.pre_tasks[profileGuardIndex]["ansible.builtin.import_role"].name, "debian_lifecycle_guard");
for (const role of site.roles.filter((item) => item.role !== "base")) {
  assert.equal(role.when, "lifecycle_profile == 'production'", `${role.role} is not production-gated`);
}
assert.equal(audit.roles[0].role, "debian_lifecycle_guard");

const allowedGuardModules = new Set(["ansible.builtin.assert", "ansible.builtin.command", "ansible.builtin.stat"]);
for (const task of guardTasks) {
  const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1, `${task.name} must use exactly one builtin module`);
  assert(allowedGuardModules.has(modules[0]), `${task.name} can mutate lifecycle state through ${modules[0]}`);
  if (modules[0] === "ansible.builtin.command") {
    assert.equal(task.changed_when, false, `${task.name} must remain read-only`);
    assert.equal(task.check_mode, false, `${task.name} must execute during check mode`);
  }
}
const guardSource = read("ansible/roles/debian_lifecycle_guard/tasks/main.yml");
for (const required of ["os.lstat", "os.path.ismount", "os.scandir", "entry_count", "LoadState=not-found",
  "ActiveState=inactive", "UnitFileState=disabled", "compose_age_identity_path", "debian_tailscale_state_path"]) {
  assert(guardSource.includes(required), `Debian lifecycle guard omits ${required}`);
}
for (const forbidden of ["mount ", "tailscale up", "age-keygen", "docker compose up", "state: started"]) {
  assert(!guardSource.includes(forbidden), `Debian lifecycle guard contains mutation surface ${forbidden}`);
}

assert.equal(aptDefaults.apt_packages_exact_lock_authorized, false);
assert.deepEqual(aptDefaults.apt_packages_exact_locked_specs, []);
const installTask = aptTasks.find((item) => item.name === "Install only absent requested packages without upgrading present packages");
assert.equal(installTask["ansible.builtin.apt"].name, "{{ apt_packages_exact_locked_specs }}");
assert.equal(installTask["ansible.builtin.apt"].update_cache, false);
const packageGuard = aptTasks.find((item) => item.name === "Require a reviewed exact lock before package installation");
for (const required of ["package_mutation_policy.require_exact_lock_for_all_updates | bool", "not (package_mutation_policy.automatic_apply | bool)",
  "apt_packages_exact_lock_authorized | bool", "apt_packages_exact_locked_names | sort == apt_packages_missing | sort"]) {
  assert(packageGuard["ansible.builtin.assert"].that.includes(required), `package guard omits ${required}`);
}

for (const required of ["dest: /etc/locale.conf", "path: /etc/default/locale", "src: ../locale.conf", "state: link", "LANG={{ debian_locale }}"]) {
  assert(baseSource.includes(required), `base locale ownership omits ${required}`);
}
assert(!baseSource.includes("community.general.locale_gen"));

console.log("debian_lifecycle_profiles=verified profiles=3");
