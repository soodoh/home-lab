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
const playbook = yaml("ansible/playbooks/proxmox-packages-plan.yml");
assert(!fs.existsSync(path.join(root, "ansible/playbooks/proxmox-audit.yml")), "obsolete standalone audit entrypoint remains");
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
assert.deepEqual(playbook[0].roles, [{ role: "proxmox_complete_audit" }, { role: "proxmox_package_plan" }]);

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

// Native capability observation is separate from the retained 17-domain audit.
// It must work without an artifact directory, installed Nix helpers or old receipts.
const nativePlay = yaml("ansible/playbooks/observe-proxmox.yml");
assert.equal(nativePlay.length, 1);
assert.equal(nativePlay[0].hosts, "proxmox");
assert.equal(nativePlay[0].gather_facts, false);
assert.deepEqual(nativePlay[0].roles, [{ role: "proxmox_observe" }]);
const nativeVars = yaml("ansible/inventory/host_vars/proxmox.yml");
const nativeTasks = yaml("ansible/roles/proxmox_observe/tasks/main.yml");
const nativeSource = read("ansible/roles/proxmox_observe/tasks/main.yml");
for (const forbidden of ["nix/", "bootstrap-proxmox", ".local/", ".reconcile/", "manifest.json", "proxmox-observer observe", "proxmox-private-preparer"])
  assert(!nativeSource.includes(forbidden), `native observation depends on ${forbidden}`);
const nativeAllowed = new Set(["assert", "setup", "command", "service_facts", "stat", "set_fact", "debug"]);
for (const task of nativeTasks) {
  const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1);
  const name = modules[0].slice("ansible.builtin.".length);
  assert(nativeAllowed.has(name), `unexpected native observation module: ${name}`);
  if (name === "command") {
    assert.equal(task.changed_when, false);
    assert.equal(task.check_mode, false);
    const argv = task[modules[0]].argv;
    assert(["/usr/bin/id", "/usr/bin/systemctl", "/usr/bin/python3"].includes(argv[0]));
    if (argv[0] === "/usr/bin/systemctl") assert.equal(argv[1], "show");
  }
  if (name === "stat") {
    assert.equal(task[modules[0]].follow, false);
    if (task.register === "proxmox_observe_repositories") {
      assert.equal(task[modules[0]].get_checksum, true);
      assert.equal(task[modules[0]].checksum_algorithm, "sha256");
    } else assert.equal(task[modules[0]].get_checksum, false);
  }
}
const collect = nativeTasks.find((t) => t.register === "proxmox_observe_protected");
assert.deepEqual(collect["ansible.builtin.command"].argv, ["/usr/bin/python3", "-I", "-B", "-", "summary"]);
assert.equal(collect.no_log, true);
assert.equal(collect.timeout, 120);
for (const name of ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"])
  assert.equal(collect.environment[name], "", `token probe must not use ${name}`);
assert.equal(collect.environment.NO_PROXY, "127.0.0.1,localhost");
assert.equal(collect.environment.no_proxy, "127.0.0.1,localhost");
for (const task of nativeTasks.filter((t) => t["ansible.builtin.assert"] && JSON.stringify(t).includes("proxmox_observe_protected.stdout")))
  assert.equal(task.no_log, true, "raw protected responses must not enter failure logs");
const spec = nativeVars.proxmox_observe_protected_spec;
assert.equal(spec.legacyTofuAccessRequired, false);
assert.equal(spec.conventionalKeysAbsent, true);
assert.equal(spec.protectedAccessExpectedCount, 3);
assert.equal(spec.node, "proxmox");
assert.equal(spec.pool, "storage");
const { projectProxmoxPolicy } = require("./proxmox-host-projection");
const contract = yaml("infrastructure/contract/home-lab.yml");
const projection = projectProxmoxPolicy(contract, JSON.parse(read(contract.proxmox.packages.manifest.path)));
assert.deepEqual(spec.pveAccessBindings, projection.apiIntent.pveAccess.bindings);
const nativePolicy = nativeVars.proxmox_maintenance_policy;
assert.deepEqual(nativePolicy.repository_files, projection.managedFiles.filter((file) =>
  file.path === "/etc/apt/sources.list" || file.path.startsWith("/etc/apt/sources.list.d/")));
assert.deepEqual(nativePolicy.keyrings, projection.managedArtifacts.map((file) => ({
  path: file.path, sha256: file.sha256, symlink_target: file.symlinkTarget,
})));
assert.deepEqual(nativePolicy.chrony_service, { active: true, enabled: true });
const nativeSummary = nativeTasks.at(-1)["ansible.builtin.debug"].msg;
assert.equal(nativeSummary.complete_host_parity, false);
assert.equal(nativeSummary.exclusive_snapshot, false);
assert.equal(nativeSummary.maintenance_authorized, false);
console.log("proxmox_complete_audit=verified domains=17 native_capability_source=verified");
