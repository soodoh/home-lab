#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const yaml = (relative) => load(read(relative));
for (const retired of ["ansible/inventory/proxmox-production.yml", "ansible/inventory/proxmox-bootstrap.yml",
  "ansible/group_vars/proxmox_host.yml", "ansible/playbooks/proxmox-packages-plan.yml",
  "ansible/roles/proxmox_complete_audit", "ansible/roles/proxmox_package_plan",
  "scripts/controller/build-proxmox-ansible-observer.js", "scripts/controller/proxmox-ansible-audit.js"]) {
  assert(!fs.existsSync(path.join(root, retired)), `retired artifact/audit source remains: ${retired}`);
}

// Native capability observation works without an artifact directory, installed
// Nix helpers or old receipts.
const nativePlay = yaml("ansible/playbooks/observe-proxmox.yml");
assert.equal(nativePlay.length, 1);
assert.equal(nativePlay[0].hosts, "proxmox");
assert.equal(nativePlay[0].gather_facts, false);
assert.deepEqual(nativePlay[0].roles, [{ role: "proxmox_observe" }]);
const nativeVars = yaml("ansible/inventory/host_vars/proxmox.yml");
const nativeTasks = yaml("ansible/roles/proxmox_observe/tasks/main.yml").flatMap((task) =>
  task["ansible.builtin.import_tasks"] === "owners.yml" ? yaml("ansible/roles/proxmox_observe/tasks/owners.yml") : [task]);
const nativeSource = read("ansible/roles/proxmox_observe/tasks/main.yml") + read("ansible/roles/proxmox_observe/tasks/owners.yml");
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
assert.equal(spec.conventionalKeyPolicy, "single-inert-pve-root-key");
assert.equal(spec.permittedRootKeyFingerprint, "SHA256:Je+jcqxxdCTlcMc8sZToiF3oZrLIJ+N6mxNhiosUIXw");
assert.equal(spec.protectedAccessExpectedCount, 3);
assert.equal(spec.node, "proxmox");
assert.equal(spec.pool, "storage");
assert(Array.isArray(spec.pveAccessBindings) && spec.pveAccessBindings.length > 0);
const collectorSource = read("infrastructure/host-lifecycle/proxmox/protected-collector-template.py");
for (const required of ["def inert_root_key_ok()", 'os.readlink(ROOT_KEY_LINK) != str(PVE_ROOT_KEY)',
  '"pubkeyauthentication no" in effective', '"permitrootlogin no" in effective',
  'observed == SPEC["permittedRootKeyFingerprint"]'])
  assert(collectorSource.includes(required), `protected collector lacks inert-root-key guard: ${required}`);
const nativePolicy = nativeVars.proxmox_maintenance_policy;
assert.equal(nativePolicy.repository_files.length, 5);
assert.equal(nativePolicy.keyrings.length, 3);
for (const file of nativePolicy.repository_files) {
  assert(file.path === "/etc/apt/sources.list" || file.path.startsWith("/etc/apt/sources.list.d/"));
  assert.equal(file.owner, "root");
  assert.equal(file.group, "root");
  assert.equal(file.mode, "0644");
}
for (const keyring of nativePolicy.keyrings) {
  assert(keyring.path.startsWith("/usr/share/keyrings/"));
  assert.match(keyring.sha256, /^[0-9a-f]{64}$/u);
}
assert.deepEqual(nativePolicy.chrony_service, { active: true, enabled: true });
const retirementPlay = yaml("ansible/playbooks/retire-proxmox-legacy-access.yml")[0];
assert.deepEqual(retirementPlay.roles, [{ role: "proxmox_observe" }, { role: "proxmox_legacy_access_retire" }]);
const retirementSource = read("ansible/roles/proxmox_legacy_access_retire/tasks/main.yml");
for (const required of ["proxmox_legacy_retained_checksums", "force: false", "item.stat.checksum == item.item.stat.checksum or",
  "Verify exact installed retirement boundary", "proxmox-restic-recovery-transport"])
  assert(retirementSource.includes(required), `legacy retirement lacks guarded boundary: ${required}`);
const nativeSummary = nativeTasks.at(-1)["ansible.builtin.debug"].msg;
assert.equal(nativeSummary.complete_host_parity, false);
assert.equal(nativeSummary.exclusive_snapshot, false);
assert.equal(nativeSummary.maintenance_authorized, false);
const configurePlay = yaml("ansible/playbooks/configure-proxmox-maintenance.yml")[0];
assert.equal(configurePlay.hosts, "proxmox");
assert(configurePlay.pre_tasks[0]["ansible.builtin.assert"].that.includes("inventory_hostname == 'proxmox'"));
assert.deepEqual(configurePlay.pre_tasks.at(-1)["ansible.builtin.import_role"], {name: "proxmox_observe", tasks_from: "owners"});
const configuration = yaml("ansible/roles/proxmox_maintenance/tasks/main.yml");
for (const task of configuration) {
  const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1);
  assert(["ansible.builtin.assert", "ansible.builtin.stat", "ansible.builtin.find", "ansible.builtin.copy", "ansible.builtin.systemd_service", "ansible.builtin.debug"].includes(modules[0]));
  assert.equal(task.check_mode, undefined);
}
const copyTask = configuration.find((task) => task["ansible.builtin.copy"]);
assert.equal(copyTask["ansible.builtin.copy"].backup, true);
assert.equal(copyTask["ansible.builtin.copy"].follow, false);
assert.equal(copyTask["ansible.builtin.copy"].unsafe_writes, false);
assert.equal(copyTask.diff, false);
assert.equal(copyTask.no_log, true);
assert.deepEqual(configuration.find((task) => task["ansible.builtin.systemd_service"])["ansible.builtin.systemd_service"],
  {name: "chrony.service", enabled: true, state: "started"});
for (const forbidden of ["nix/", "manifest", "receipt", "activator", "shell", "command", "ansible.builtin.apt", "state: absent"])
  assert(!JSON.stringify(configuration).includes(forbidden), forbidden);
console.log("proxmox_native_observation_and_configuration=verified legacy_artifact_audit=absent");
