#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
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
const qualificationInventory = yaml("ansible/inventory/debian-qualification.yml");
const qualificationHost = qualificationInventory.all.children.docker_host.hosts["debian-lifecycle-qualification"];

assert.equal(contract.debian.locale, "C.UTF-8");
assert.equal(groupVars.debian_locale, "{{ debian.locale }}");
assert.deepEqual(groupVars.debian_protected_mounts, "{{ debian.qualification.protected_mounts }}");
for (const unit of ["docker.service", "docker.socket", "home-lab-compose.service", "tailscaled.service",
  ...Object.keys(groupVars.restic_audit_inert_units)]) {
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
assert.equal(qualificationHost.lifecycle_profile, "inert");
assert.equal(qualificationHost.lifecycle_contract_host, "debian");
assert.equal(qualificationHost.ansible_user, "ansible-deploy");
const qualificationSsh = qualificationHost.ansible_ssh_common_args;
for (const required of ["StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "UpdateHostKeys=no", "IdentityAgent=none", "IdentitiesOnly=yes", "PreferredAuthentications=publickey", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "RequestTTY=no"]) assert(qualificationSsh.includes(required));
assert(qualificationHost.ansible_ssh_private_key_file.includes("HOME_LAB_DEBIAN_QUALIFICATION_PRIVATE_KEY"));

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
for (const required of ["role_path ~ '/files/debian-inactive-path.py'", "entry_count", "LoadState=not-found",
  "ActiveState=inactive", "UnitFileState=disabled", "compose_age_identity_path", "debian_tailscale_state_path"]) {
  assert(guardSource.includes(required), `Debian lifecycle guard omits ${required}`);
}
const inactiveHelper = read("ansible/roles/debian_lifecycle_guard/files/debian-inactive-path.py");
for (const required of ["RESOLVE = 0x01 | 0x04", "STATX_MASK = 0x07FF | 0x1000", "os.scandir(fd)"])
  assert(inactiveHelper.includes(required), `Inactive-path helper omits ${required}`);
assert(!guardSource.includes("os.path.ismount"), "Inactive-path admission must not rely on ismount");
for (const forbidden of ["mount ", "tailscale up", "age-keygen", "docker compose up", "state: started"]) {
  assert(!guardSource.includes(forbidden), `Debian lifecycle guard contains mutation surface ${forbidden}`);
}

assert.equal(aptDefaults.apt_packages_exact_lock_authorized, false);
assert.deepEqual(aptDefaults.apt_packages_exact_locked_specs, []);
const installTask = aptTasks.find((item) => item.name === "Install only absent requested packages without upgrading present packages");
assert.equal(installTask["ansible.builtin.apt"].name, "{{ apt_packages_exact_locked_specs }}");
assert.equal(installTask["ansible.builtin.apt"].update_cache, false);
assert.equal(installTask["ansible.builtin.apt"].auto_install_module_deps, false,
  "apt install source task must explicitly set auto_install_module_deps to boolean false");
const packageGuard = aptTasks.find((item) => item.name === "Require a reviewed exact lock before package installation");
for (const required of ["package_mutation_policy.require_exact_lock_for_all_updates | bool", "not (package_mutation_policy.automatic_apply | bool)",
  "apt_packages_exact_lock_authorized | bool", "apt_packages_exact_locked_names | sort == apt_packages_missing | sort"]) {
  assert(packageGuard["ansible.builtin.assert"].that.includes(required), `package guard omits ${required}`);
}

for (const required of ["dest: /etc/locale.conf", "path: /etc/default/locale", "src: ../locale.conf", "state: link", "LANG={{ debian_locale }}"]) {
  assert(baseSource.includes(required), `base locale ownership omits ${required}`);
}
assert(!baseSource.includes("community.general.locale_gen"));

// Real Ansible source/role evaluation with mocked command endpoints, NOT a full
// site playbook run. Only the Compose dispatch and role are copied into a local
// fixture; every command is replaced before Ansible can execute any effects.
const composeTasks = yaml("ansible/roles/compose/tasks/main.yml");
const composeDispatch = site.roles.find((item) => item.role === "compose");
const bindingName = "Require Compose invocation bindings to match the loaded Debian contract";
const bindingIndex = composeTasks.findIndex((task) => task.name === bindingName);
assert(bindingIndex >= 0, "Compose binding assertion is missing");
const bindings = composeTasks[bindingIndex]["ansible.builtin.assert"].that;
assert.equal(bindings.length, 4);
const aliases = ["compose_runtime_cli", "compose_current_dir", "compose_image_override_path", "compose_runtime_env_path"];
const authorityFields = ["compose_command", "compose_artifact_path", "compose_image_lock_path", "root_environment_path"];
const canonicalCli = contract.debian.transaction.compose_command;
const commandTasks = composeTasks.filter((task) => task["ansible.builtin.command"]);
assert.equal(commandTasks.length, 5);
for (const task of commandTasks) {
  assert.equal(task.changed_when, false, `${task.name} must remain read-only`);
  assert.equal(task.check_mode, false, `${task.name} must run in check mode`);
}

// Keep the existing source templates, but include only variables used by this
// role. No inventory credentials, environment lookups or retained evidence inputs.
const fixtureVars = Object.fromEntries([
  ...aliases, "compose_project_name", "compose_home_dir",
  "audit_expected_compose_service_count", "audit_allowed_declared_compose_service_counts",
  "audit_expected_declared_volume_count", "audit_legacy_volumes",
].map((key) => [key, groupVars[key]]));
fixtureVars.debian = { transaction: Object.fromEntries(authorityFields.map((key) => [key, contract.debian.transaction[key]])) };
fixtureVars.nextcloud = { expected_compose_service_count: contract.nextcloud.expected_compose_service_count };
fixtureVars.lifecycle_profile = "production";
const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "compose-binding-"));
const writeFixture = (relative, value) => fs.writeFileSync(path.join(fixtureRoot, relative), value);
let runs = 0;
try {
  for (const directory of ["home", "tmp", "action_plugins", "roles/compose/tasks", "collections"])
    fs.mkdirSync(path.join(fixtureRoot, directory), { recursive: true });
  writeFixture("inventory", "localhost ansible_connection=local\n");
  writeFixture("ansible.cfg", `[defaults]
roles_path = ${fixtureRoot}/roles
action_plugins = ${fixtureRoot}/action_plugins
collections_path = ${fixtureRoot}/collections
local_tmp = ${fixtureRoot}/tmp
retry_files_enabled = False
host_key_checking = True
stdout_callback = default
[privilege_escalation]
become = False
`);
  // Controller-side action plugin: never calls a module, connection or process.
  // It records Ansible-templated argv/environment and returns deterministic output
  // for the existing register/count assertions. Mimic command's check-mode skip.
  writeFixture("action_plugins/compose_witness.py", `import json
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    _requires_connection = False
    def run(self, tmp=None, task_vars=None):
        if self._task.check_mode:
            return {"skipped": True, "changed": False}
        args = self._task.args
        argv = args["argv"]
        with open(${JSON.stringify(path.join(fixtureRoot, "witness.jsonl"))}, "a") as stream:
            stream.write(json.dumps({"argv": argv, "environment": args["observed_environment"],
                                     "check_mode": self._task.check_mode}) + "\\n")
        lines = []
        if argv[-2:] == ["config", "--services"]:
            lines = ["fixture-service-" + str(i) for i in range(${contract.nextcloud.expected_compose_service_count})]
        return {"changed": True, "rc": 0, "stdout": "\\n".join(lines), "stdout_lines": lines}
`);
  const env = {
    PATH: process.env.PATH, HOME: path.join(fixtureRoot, "home"),
    TMPDIR: path.join(fixtureRoot, "tmp"), LANG: "C.UTF-8",
    ANSIBLE_CONFIG: path.join(fixtureRoot, "ansible.cfg"),
    ANSIBLE_NOCOLOR: "1", PYTHONDONTWRITEBYTECODE: "1",
  };
  const version = spawnSync("ansible-playbook", ["--version"], { cwd: fixtureRoot, env, encoding: "utf8" });
  assert.equal(version.status, 0, `Real Ansible is required (no installation/skip): ${version.error || version.stderr}`);
  console.log(version.stdout.split("\n")[0]);

  function run(label, { tasks = composeTasks, vars = fixtureVars, check = false } = {}) {
    const mockedTasks = tasks.map((source) => {
      const task = structuredClone(source);
      const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
      assert.equal(modules.length, 1);
      assert(["ansible.builtin.assert", "ansible.builtin.command"].includes(modules[0]),
        `Unmocked Compose effect: ${task.name}`);
      if (task["ansible.builtin.command"]) {
        task.compose_witness = {
          ...task["ansible.builtin.command"], observed_environment: task.environment || {},
        };
        delete task["ansible.builtin.command"];
      }
      return task;
    });
    writeFixture("roles/compose/tasks/main.yml", JSON.stringify(mockedTasks));
    writeFixture("play.yml", JSON.stringify([{
      name: "Compose binding source fixture with mocked endpoints", hosts: "localhost",
      gather_facts: false, become: false, vars, roles: [composeDispatch],
    }]));
    writeFixture("witness.jsonl", "");
    const result = spawnSync("ansible-playbook", ["-i", path.join(fixtureRoot, "inventory"),
      path.join(fixtureRoot, "play.yml"), ...(check ? ["--check"] : [])],
    { cwd: fixtureRoot, env, encoding: "utf8", timeout: 30000 });
    assert(!result.error, `${label}: ${result.error}`);
    assert.notEqual(result.status, null, `${label}: ${result.signal}`);
    const output = result.stdout + result.stderr;
    const witnesses = fs.readFileSync(path.join(fixtureRoot, "witness.jsonl"), "utf8"),
      events = witnesses.trim() ? witnesses.trim().split("\n").map((line) => JSON.parse(line)) : [];
    runs++;
    return { label, status: result.status, output, events };
  }
  function succeeded(result) {
    assert.equal(result.status, 0, `${result.label}: ${result.output}`);
    assert.match(result.output, /changed=0\s/, `${result.label}: changed_when drift`);
  }
  function refusedBeforeCommand(result) {
    assert.equal(result.status, 2, `${result.label}: ${result.output}`);
    assert.match(result.output, new RegExp(`TASK \\[compose : ${bindingName}\\]`));
    assert(!result.output.includes("Compose model counts changed"), result.output);
    assert.deepEqual(result.events, [], `${result.label}: command reached before refusal`);
  }
  function positive(tasks = composeTasks, check = false, volumes = []) {
    const result = run("canonical production", {
      tasks, check, vars: { ...fixtureVars, audit_legacy_volumes: volumes },
    });
    succeeded(result);
    const composeEvent = (suffix) => ({ argv: [...canonicalCli, ...suffix], environment: { HOME: "/home/docker" }, check_mode: false });
    assert.deepEqual(result.events, [
      composeEvent(["config", "--quiet"]), composeEvent(["config", "--services"]),
      composeEvent(["config", "--volumes"]),
      ...volumes.map((volume) => ({ argv: ["/usr/bin/docker", "volume", "inspect", volume.engine_name], environment: {}, check_mode: false })),
      composeEvent(["--dry-run", "create", "--no-build", "--pull", "never"]),
    ]);
  }
  const negativeVars = aliases.map((alias, index) => ({
    ...fixtureVars, compose_runtime_cli: canonicalCli,
    [alias]: index === 0 ? [...canonicalCli, "--project-name", "unapproved"] : "/unapproved",
  }));
  for (const check of [false, true]) {
    positive(composeTasks, check);
    positive(composeTasks, check, [
      { logical_name: "fixture-a", engine_name: "fixture-engine-a" },
      { logical_name: "fixture-b", engine_name: "fixture-engine-b" },
    ]);
    for (const [index, vars] of negativeVars.entries()) {
      const negative = run(`independent ${aliases[index]} mismatch`, { vars, check });
      refusedBeforeCommand(negative);
      assert(negative.output.includes(bindings[index]), negative.output);
      // Mutate only the temporary source copy. All other guards and the canonical
      // CLI remain intact for path negatives, so CLI equality cannot mask them.
      const mutant = structuredClone(composeTasks);
      mutant[bindingIndex]["ansible.builtin.assert"].that.splice(index, 1);
      positive(mutant, check);
      const escaped = run(`removed ${aliases[index]} guard`, { tasks: mutant, vars, check });
      succeeded(escaped);
      assert.equal(escaped.events.length, 4);
      assert.throws(() => refusedBeforeCommand(escaped), assert.AssertionError);
      positive(composeTasks, check);
    }
    for (const mutation of ["absent", "after-first-command"]) {
      const mutant = structuredClone(composeTasks);
      const [guard] = mutant.splice(bindingIndex, 1);
      if (mutation === "after-first-command") mutant.splice(1, 0, guard);
      positive(mutant, check);
      const escaped = run(mutation, { tasks: mutant, vars: negativeVars[1], check });
      assert.equal(escaped.events.length, mutation === "absent" ? 4 : 1);
      if (mutation === "absent") succeeded(escaped);
      else assert.equal(escaped.status, 2, escaped.output);
      assert.throws(() => refusedBeforeCommand(escaped), assert.AssertionError);
      positive(composeTasks, check);
    }
    for (const lifecycle_profile of ["inert", "recovery"]) {
      const result = run(lifecycle_profile, { check, vars: { ...negativeVars[0], lifecycle_profile } });
      succeeded(result);
      assert.deepEqual(result.events, []);
    }
  }
  for (const alias of aliases) {
    for (const malformed of [false, true]) {
      const vars = { ...fixtureVars, compose_runtime_cli: canonicalCli };
      if (malformed) vars[alias] = { invalid: true };
      else delete vars[alias];
      refusedBeforeCommand(run(`${alias} ${malformed ? "malformed" : "missing"}`, { vars }));
    }
  }
  for (const field of authorityFields) {
    const vars = structuredClone(fixtureVars);
    delete vars.debian.transaction[field];
    refusedBeforeCommand(run(`missing contract ${field}`, { vars }));
  }
  refusedBeforeCommand(run("malformed transaction", { vars: { ...fixtureVars, debian: { transaction: null } } }));
  for (const override of [
    { audit_allowed_declared_compose_service_counts: [-1] },
    { audit_expected_declared_volume_count: 1 },
  ]) {
    const result = run("model count refusal", { vars: { ...fixtureVars, ...override } });
    assert.equal(result.status, 2, result.output);
    assert.match(result.output, /Compose model counts changed; refusing adoption/);
    assert.equal(result.events.length, 3, "count refusal must precede volume inspection and dry-run create");
  }
  console.log(`compose_contract_bindings=verified real_ansible_mocked_endpoints=true runs=${runs} bindings=4 causal_mutants=6 modes=2`);
} finally {
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
}

console.log("debian_lifecycle_profiles=verified profiles=3");
