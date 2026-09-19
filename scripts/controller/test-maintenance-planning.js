#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const readYaml = (relative) => load(fs.readFileSync(path.join(root, relative), "utf8"));
const packageTasks = readYaml("ansible/roles/package_lifecycle/tasks/main.yml");
const packageScript = fs.readFileSync(path.join(root, "infrastructure/maintenance/host/package-candidate-observer"), "utf8");
const rebootTasks = readYaml("ansible/roles/reboot_lifecycle/tasks/main.yml");
const packagePlaybook = readYaml("ansible/playbooks/packages-plan.yml")[0];
const rebootPlaybook = readYaml("ansible/playbooks/reboot-plan.yml")[0];
const contract = readYaml("infrastructure/contract/home-lab.yml");

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
const packageArgv = packageObserver["ansible.builtin.command"].argv;
assert(packageArgv[2].includes("package-candidate-observer"));
assert.deepEqual(packageArgv.slice(3), ["observe", "{{ lifecycle_contract_host }}"]);
for (const required of [
  '"/usr/bin/apt-get"',
  '"--simulate"',
  '"Debug::NoLocking=1"',
  '"/usr/bin/dpkg-query"',
  '"/usr/bin/apt-mark", "showhold"',
  '"metadata_refresh_performed": False',
  '"proposal_sha256"',
  'Status-Abbrev',
  'installed_lines',
  '"manifest_matches"',
  '"expected_manifest_sha256"',
  '"policy_sha256"',
  '"apt_tree_safe"',
  '"size_parse_complete"',
  'os.O_NOFOLLOW',
  'os.fstat',
  '"apt_state_hashes"',
  '"/etc/apt/apt.conf.d"',
  '"/usr/share/keyrings"',
  '"/etc/apt/sources.list.d"',
  '"kept_back"',
  '"download_bytes"',
  '"disk_delta_bytes"',
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
  '"backup_unit_states"',
  '"active_conflict_locks"',
  '"tailscale_backend_state"',
  '"window_eligible"',
  '"pending_package_transaction_sha256"',
  '"/usr/bin/lslocks"',
  '"/usr/bin/tailscale", "status", "--json"',
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

assert.equal(packagePlaybook.hosts, "docker_host");
assert.equal(rebootPlaybook.hosts, "docker_host");
for (const playbook of [packagePlaybook, rebootPlaybook]) {
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
assert.equal(packagePolicy.hosts.proxmox.candidate_scope, "explicit-exact-version-or-dist-upgrade");
assert.equal(packagePolicy.hosts.proxmox.apply_authority, "native-ansible-become");
assert.equal(packagePolicy.hosts.debian.automatic_apply, false);
assert.equal(packagePolicy.hosts.proxmox.automatic_apply, false);
assert.equal(packagePolicy.hosts.debian.automatic_reboot, false);
assert.equal(packagePolicy.hosts.proxmox.automatic_reboot, false);
assert.deepEqual(contract.lifecycle.hosts.proxmox.domain_handoffs.package_set, {
  current_owner: "ansible", target_owner: "ansible", state: "transferred", parity_required: true, single_writer: true,
});
const rebootPolicy = contract.lifecycle.maintenance.reboot_plan;
assert.equal(rebootPolicy.automatic, false);
assert.equal(rebootPolicy.one_host_per_transaction, true);
assert.equal(rebootPolicy.backup_max_age_hours, 24);
assert.deepEqual(rebootPolicy.console_required_hosts, ["proxmox"]);
assert.equal(rebootPolicy.max_plan_age_seconds, 1800);
assert.equal(rebootPolicy.debian_window.backup_buffer_seconds, 10800);
assert(rebootPolicy.inactive_backup_units.includes("home-lab-restic-recover.service"));
assert(rebootPolicy.conflict_locks.includes("/run/lock/home-lab-debian-package.lock"));
assert.deepEqual(rebootPolicy.workload_order.proxmox, ["vm-100-shutdown", "host-reboot", "host-audit", "vm-100-startup", "debian-audit"]);
assert(rebootPolicy.postchecks.debian.includes("production-audit"));

const nativeRebootPlay = readYaml("ansible/playbooks/reboot-proxmox.yml")[0];
const nativeRebootTasks = readYaml("ansible/roles/proxmox_reboot/tasks/main.yml");
assert.equal(nativeRebootPlay.hosts, "proxmox");
assert.equal(nativeRebootPlay.serial, 1);
assert.equal(nativeRebootPlay.any_errors_fatal, true);
assert.deepEqual(nativeRebootPlay.roles.map((item) => item.role),
  ["proxmox_observe", "proxmox_package_observe", "proxmox_reboot"]);
const rebootBlock = nativeRebootTasks.find((item) => item.name === "Execute the attended native reboot with autonomous VM recovery");
const nativeReboot = rebootBlock.block.find((item) => item["ansible.builtin.reboot"]);
assert(nativeReboot);
assert.equal(nativeReboot["ansible.builtin.reboot"].test_command, "/usr/sbin/pveversion");
assert.equal(nativeReboot["ansible.builtin.reboot"].reboot_timeout, 900);
const timer = rebootBlock.block.find((item) => item.name === "Arm a transient controller-loss rollback for VM 100");
assert.deepEqual(timer["ansible.builtin.command"].argv.slice(0, 3),
  ["/usr/bin/systemd-run", "--unit=home-lab-proxmox-vm100-recovery", "--on-active={{ proxmox_reboot_rollback_seconds }}s"]);
assert(timer["ansible.builtin.command"].argv.includes("/usr/sbin/qm"));
assert(timer["ansible.builtin.command"].argv.includes("start"));
const backupStateTask = nativeRebootTasks.find((item) => item.name === "Read backup writer states on the Docker host");
assert.equal(backupStateTask.delegate_to, "docker-host");
assert.deepEqual(backupStateTask["ansible.builtin.command"].argv, [
  "/usr/bin/systemctl", "show", "{{ item }}", "--property=LoadState", "--property=ActiveState", "--no-pager",
]);
assert.deepEqual(backupStateTask.loop, [
  "home-lab-restic-daily-local.service",
  "home-lab-restic-daily-proton.service",
  "home-lab-restic-maintenance-local.service",
  "home-lab-restic-maintenance-proton.service",
]);
const backupRefusal = nativeRebootTasks.find((item) => item.name === "Require every Docker-host backup writer to be loaded and inactive");
assert.deepEqual(backupRefusal["ansible.builtin.assert"].that, [
  "item.rc == 0",
  "item.stderr == ''",
  "'LoadState=loaded' in item.stdout_lines",
  "'ActiveState=inactive' in item.stdout_lines",
]);
const backupReady = (result) => result.rc === 0 && result.stderr === "" &&
  result.stdout_lines.includes("LoadState=loaded") && result.stdout_lines.includes("ActiveState=inactive");
assert(backupReady({rc: 0, stderr: "", stdout_lines: ["LoadState=loaded", "ActiveState=inactive"]}));
for (const rejected of [
  {rc: 0, stderr: "", stdout_lines: ["LoadState=not-found", "ActiveState=inactive"]},
  {rc: 0, stderr: "", stdout_lines: ["LoadState=masked", "ActiveState=inactive"]},
  {rc: 0, stderr: "", stdout_lines: ["LoadState=error", "ActiveState=inactive"]},
  {rc: 0, stderr: "", stdout_lines: ["LoadState=loaded", "ActiveState=failed"]},
  {rc: 0, stderr: "", stdout_lines: ["LoadState=loaded", "ActiveState=activating"]},
]) assert(!backupReady(rejected));
const nativeSource = JSON.stringify(nativeRebootTasks);
for (const required of ["onboot: 1", "home-lab-restic-daily-local.service", "/usr/sbin/zpool", "pool 'storage' is healthy", "proxmox_reboot_console_confirmed", "proxmox_reboot_backup_confirmed", "proxmox_reboot_boot_id_after", "include_role"])
  assert(nativeSource.includes(required), required);
for (const forbidden of ["nix/", ".local/", ".reconcile/", "manifest", "receipt", "plan_sha256", "activator"])
  assert(!nativeSource.includes(forbidden), forbidden);
assert.equal(nativeRebootTasks.filter((item) => item["ansible.builtin.reboot"]).length, 0,
  "reboot module must remain nested in the explicit block");
assert(nativeSource.includes("not ansible_check_mode"));
console.log("maintenance_planning=verified native_reboot=source-guarded");
