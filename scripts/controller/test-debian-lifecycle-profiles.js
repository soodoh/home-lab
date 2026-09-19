#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");

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
const baseTasks = load(baseSource);
const inactiveBaseTasks = yaml("ansible/roles/base/tasks/debian-inactive.yml");
// Fail before fixture creation or Ansible dispatch. Keep system site initialization
// for Debian python3-apt in dist-packages; this command is modeled, never run here.
const aptImportArgv = inactiveBaseTasks.find((task) =>
  task.name === "Require image-provided Python APT bindings without bootstrapping dependencies")["ansible.builtin.command"].argv;
assert.deepEqual(aptImportArgv, ["/usr/bin/python3", "-I", "-B", "-c", "import apt"],
  "Base APT import requires isolated startup with system site retained: -I -B (no -S)");
const baselineSchema = JSON.parse(read("infrastructure/contract/schema.json")).properties.debian;
assert(baselineSchema.required.includes("baseline"));
const validateBaseline = new Ajv2020({ strict: true, allErrors: true }).compile(baselineSchema.properties.baseline);
assert(validateBaseline(contract.debian.baseline), JSON.stringify(validateBaseline.errors));
for (const field of Object.keys(contract.debian.baseline)) {
  for (const replacement of [undefined, null, "unapproved", []]) {
    const invalid = structuredClone(contract.debian.baseline);
    if (replacement === undefined) delete invalid[field];
    else invalid[field] = replacement;
    assert(!validateBaseline(invalid), `baseline subschema accepted invalid ${field}`);
  }
}
assert(!validateBaseline({ ...contract.debian.baseline, automatic_install: true }));
for (const field of ["image_packages", "packages", "services"]) {
  for (const replacement of [contract.debian.baseline[field].slice(1),
    [...contract.debian.baseline[field], "unapproved"], [...contract.debian.baseline[field], contract.debian.baseline[field][0]]]) {
    assert(!validateBaseline({ ...contract.debian.baseline, [field]: replacement }));
  }
}
assert.equal(contract.debian.locale, "C.UTF-8");
assert.equal(groupVars.debian_locale, "{{ debian.locale }}");
assert.deepEqual(groupVars.debian_protected_mounts, "{{ debian.qualification.protected_mounts }}");
for (const unit of ["home-lab-production-guard.service", "docker.service", "docker.socket", "home-lab-compose.service", "tailscaled.service",
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
for (const task of site.tasks) {
  const dispatch = task["ansible.builtin.import_role"];
  assert(["sops_age", "restic_backup", "tailscale", "storage", "docker", "compose"].includes(dispatch.name));
  assert.equal(dispatch.tasks_from, ["storage", "docker", "compose"].includes(dispatch.name) ? "inactive" : "tools");
  assert.equal(task.when, "lifecycle_profile in ['inert', 'recovery']");
  assert.deepEqual(task.tags, [dispatch.name]);
}
assert.equal(audit.roles[0].role, "debian_lifecycle_guard");

assert.deepEqual(guardTasks.find((task) => task.name === "Inspect secret identity and Tailscale state boundaries")["ansible.builtin.stat"], {
  path: "{{ item }}", follow: false, get_checksum: false, get_mime: false, get_attributes: false,
});
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
let fixtureSucceeded = false;
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

  // Evaluate the actual base/imported prerequisite/apt tasks, not a second policy
  // implementation. Only endpoint effects are modeled; no guest modules execute.
  for (const directory of ["roles/base/tasks", "roles/apt_packages/tasks", "roles/apt_packages/defaults"])
    fs.mkdirSync(path.join(fixtureRoot, directory), { recursive: true });
  const pureModules = new Set(["assert", "set_fact", "debug", "include_role", "import_tasks"]);
  const effectModules = new Set(["command", "package_facts", "apt", "copy", "file", "stat", "hostname", "systemd_service"]);
  function mockBaseTasks(tasks) {
    return tasks.map((source) => {
      const task = structuredClone(source);
      const modules = Object.keys(task).filter((key) => key.startsWith("ansible.builtin."));
      assert.equal(modules.length, 1, `Unclassified source task: ${task.name}`);
      const module = modules[0].slice("ansible.builtin.".length);
      assert(pureModules.has(module) || effectModules.has(module), `Unmocked base effect: ${module}`);
      if (module === "include_role") assert.equal(task[modules[0]].name, "apt_packages");
      if (module === "import_tasks") assert.equal(task[modules[0]], "debian-inactive.yml");
      if (effectModules.has(module)) {
        task.base_witness = { module, arguments: task[modules[0]] };
        delete task[modules[0]];
      }
      return task;
    });
  }
  writeFixture("roles/base/tasks/main.yml", JSON.stringify(mockBaseTasks(baseTasks)));
  writeFixture("roles/base/tasks/debian-inactive.yml", JSON.stringify(mockBaseTasks(inactiveBaseTasks)));
  const mockedAptTasks = mockBaseTasks(aptTasks);
  mockedAptTasks.splice(1, 0, {
    name: "Fixture requires package facts to merge without erasing platform facts",
    "ansible.builtin.assert": { that: [
      "ansible_facts.packages is mapping", "ansible_facts.distribution == 'Debian'",
      "ansible_facts.kernel == debian.qualification.kernel_release",
    ] },
  });
  writeFixture("roles/apt_packages/tasks/main.yml", JSON.stringify(mockedAptTasks));
  writeFixture("roles/apt_packages/defaults/main.yml", JSON.stringify(aptDefaults));
  writeFixture("action_plugins/base_witness.py", `import json
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    _requires_connection = False
    def run(self, tmp=None, task_vars=None):
        module = self._task.args["module"]
        args = self._task.args["arguments"]
        check = self._task.check_mode
        with open(${JSON.stringify(path.join(fixtureRoot, "base-state.json"))}) as stream:
            state = json.load(stream)
        with open(${JSON.stringify(path.join(fixtureRoot, "base-events.jsonl"))}, "a") as stream:
            stream.write(json.dumps({"module": module, "args": args, "check": check}) + "\\n")
        before = json.dumps(state, sort_keys=True)
        result = {"changed": False}
        if module == "fixture_facts":
            result["ansible_facts"] = args
        elif module == "command":
            argv = args["argv"]
            stdout = ""
            if argv == ["/usr/bin/python3", "-I", "-B", "-c", "import apt"]:
                if not state["python_apt"]:
                    return {"failed": True, "msg": "synthetic missing Python APT binding"}
            elif argv[:3] == ["/usr/bin/dpkg-query", "--show", "--showformat=$" + "{db:Status-Status}"] and len(argv) == 4:
                stdout = "installed" if argv[3] in state["packages"] else "not-installed"
            elif argv == ["/usr/bin/locale", "-a"]:
                stdout = "C\\nC.utf8\\nPOSIX"
            elif argv == ["/usr/bin/timedatectl", "show", "--property=Timezone", "--value"]:
                stdout = state["timezone"]
            elif argv[:2] == ["/usr/bin/timedatectl", "set-timezone"] and len(argv) == 3:
                assert not check, "timezone mutation in check mode"
                state["timezone"] = argv[2]
            else:
                return {"failed": True, "msg": "unmodeled command refused: " + str(argv)}
            result.update(rc=0, stdout=stdout, stdout_lines=stdout.splitlines())
        elif module == "package_facts":
            assert args == {"manager": "apt"}
            result["ansible_facts"] = {"packages": {name: [{"version": version}] for name, version in state["packages"].items()}}
        elif module == "stat":
            assert args == {"path": "/usr/share/zoneinfo/America/Los_Angeles", "follow": False}
            result["stat"] = {"isreg": True, "islnk": False}
        elif module == "apt":
            assert not check, "apt reached during check mode"
            assert args["state"] == "present" and args["update_cache"] is False and args["auto_install_module_deps"] is False
            assert set(args) <= {"name", "state", "update_cache", "auto_install_module_deps", "policy_rc_d"}
            for spec in args["name"]:
                name, version = spec.split("=", 1)
                assert name not in state["packages"], "attempted upgrade"
                state["packages"][name] = version
        elif module in ["copy", "file"]:
            target = args["dest"] if module == "copy" else args["path"]
            assert target in ["/etc/locale.conf", "/etc/default/locale"], "unapproved path write"
            state["files"][target] = args
        elif module == "hostname":
            assert args["use"] == "systemd"
            state["hostname"] = args["name"]
        elif module == "systemd_service":
            assert args == {"name": "qemu-guest-agent.service", "state": "started", "daemon_reload": False}, "unapproved explicit service call"
            state["services"] = [args["name"]]
        else:
            return {"failed": True, "msg": "unmodeled effect refused: " + module}
        result["changed"] = before != json.dumps(state, sort_keys=True)
        if not check and result["changed"]:
            with open(${JSON.stringify(path.join(fixtureRoot, "base-state.json"))}, "w") as stream:
                json.dump(state, stream)
        return result
`);
  const baseVars = {
    lifecycle_profile: "inert", lifecycle_contract_host: "debian",
    debian: contract.debian, vm_100: { host_name: contract.vm_100.host_name },
    package_mutation_policy: { require_exact_lock_for_all_updates: true, automatic_apply: false },
    system_timezone: contract.system_timezone, debian_locale: groupVars.debian_locale,
    debian_base_hostname: groupVars.debian_base_hostname,
    base_packages: groupVars.base_packages, base_services: groupVars.base_services,
    ansible_facts: {
      distribution: "Debian", distribution_major_version: contract.debian.version,
      distribution_release: contract.debian.release, architecture: contract.debian.baseline.architecture,
      kernel: contract.debian.qualification.kernel_release,
    },
  };
  const freshBaseState = () => ({
    packages: Object.fromEntries(contract.debian.baseline.image_packages.map((name) => [name, "fixture-image-version"])),
    python_apt: true, timezone: "UTC", hostname: "fixture-first-contact", services: [], files: {},
  });
  const baselineLock = contract.debian.baseline.packages.map((name) => `${name}=1.0-fixture`);
  let baseRuns = 0;
  function runBase(label, { vars = {}, extraVars = {}, state = freshBaseState(), check = false,
    host = "fixture-inert" } = {}) {
    writeFixture("base-inventory", `${host} ansible_connection=local\n`);
    const { ansible_facts: seededFacts, ...playVars } = { ...baseVars, ...vars };
    writeFixture("base-play.yml", JSON.stringify([{
      name: "Base source fixture with controller-only synthetic endpoints", hosts: host,
      gather_facts: false, become: false, vars: playVars,
      pre_tasks: [{ name: "Seed synthetic platform facts without a connection",
        base_witness: { module: "fixture_facts", arguments: seededFacts } }],
      roles: [site.roles.find((item) => item.role === "base")],
    }]));
    writeFixture("base-extra.json", JSON.stringify(extraVars));
    writeFixture("base-state.json", JSON.stringify(state));
    writeFixture("base-events.jsonl", "");
    const result = spawnSync("ansible-playbook", ["-i", path.join(fixtureRoot, "base-inventory"),
      path.join(fixtureRoot, "base-play.yml"), "--extra-vars", `@${path.join(fixtureRoot, "base-extra.json")}`,
      ...(check ? ["--check"] : [])], { cwd: fixtureRoot, env, encoding: "utf8", timeout: 30000 });
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    writeFixture("base-last-output.txt", output);
    assert(!result.error, `${label}: ${result.error}\n${output}`);
    assert.notEqual(result.status, null, `${label}: ${result.signal}\n${output}`);
    const log = fs.readFileSync(path.join(fixtureRoot, "base-events.jsonl"), "utf8").trim();
    baseRuns++;
    return { label, status: result.status, output, events: log ? log.split("\n").map(JSON.parse) : [],
      state: JSON.parse(fs.readFileSync(path.join(fixtureRoot, "base-state.json"), "utf8")) };
  }
  const locked = { apt_packages_exact_lock_authorized: true, apt_packages_exact_locked_specs: baselineLock };
  const writeModules = new Set(["apt", "copy", "file", "hostname", "systemd_service"]);
  function baseSucceeded(result, zeroChange = false) {
    assert.equal(result.status, 0, `${result.label}: ${result.output}`);
    if (zeroChange) assert.match(result.output, /changed=0\s/, `${result.label}: ${result.output}`);
  }
  function baseRefused(result, original, beforeFacts = false) {
    assert.equal(result.status, 2, `${result.label}: ${result.output}`);
    assert.deepEqual(result.state, original, `${result.label}: state changed before refusal`);
    assert(!result.events.some((event) => writeModules.has(event.module)), `${result.label}: write endpoint reached`);
    if (beforeFacts) assert(!result.events.some((event) => event.module === "package_facts"));
  }
  for (const lifecycle_profile of ["inert", "recovery"]) {
    const first = runBase(`first ${lifecycle_profile}`, { vars: { lifecycle_profile, ...locked } });
    baseSucceeded(first);
    assert.match(first.output, /changed=[1-9]/);
    assert.equal(first.state.hostname, contract.vm_100.host_name);
    assert.equal(first.state.timezone, contract.system_timezone);
    assert.deepEqual(first.state.services, contract.debian.baseline.services);
    assert.equal(first.state.files["/etc/locale.conf"].content, "LANG=C.UTF-8\n");
    assert.equal(first.state.files["/etc/default/locale"].src, "../locale.conf");
    const aptEvent = first.events.find((event) => event.module === "apt");
    assert.deepEqual(aptEvent.args, { name: baselineLock, state: "present", update_cache: false,
      auto_install_module_deps: false, policy_rc_d: 101 });
    assert(first.events.findIndex((event) => event.module === "package_facts") >
      first.events.findLastIndex((event) => event.module === "command" && event.args.argv[0] === "/usr/bin/dpkg-query"));
    const second = runBase(`second ${lifecycle_profile}`, { vars: { lifecycle_profile }, state: first.state });
    baseSucceeded(second, true);
    assert.deepEqual(second.state, first.state);
    assert(!second.events.some((event) => event.module === "apt"));
    const state = freshBaseState();
    const checked = runBase(`check ${lifecycle_profile}`, { vars: { lifecycle_profile }, state, check: true });
    baseSucceeded(checked);
    assert.deepEqual(checked.state, state, "check mode mutated synthetic state");
    assert(!checked.events.some((event) => event.module === "apt"));
    assert(checked.events.filter((event) => writeModules.has(event.module)).every((event) => event.check));
    baseSucceeded(runBase(`converged check ${lifecycle_profile}`, {
      vars: { lifecycle_profile }, state: first.state, check: true,
    }), true);
  }
  const ordinary = runBase("ordinary inactive hostname", { vars: locked, host: "fixture-inert" });
  baseSucceeded(ordinary);
  assert.equal(ordinary.state.hostname, contract.vm_100.host_name);
  for (const check of [false, true]) {
    for (const [field, invalid] of Object.entries({ distribution: "Ubuntu", distribution_major_version: "12",
      distribution_release: "bookworm", architecture: "aarch64", kernel: "unapproved" })) {
      const state = freshBaseState();
      baseRefused(runBase(`wrong ${field}`, { state, check,
        vars: { ansible_facts: { ...baseVars.ansible_facts, [field]: invalid } } }), state, true);
    }
    for (const extraVars of [
      { debian_base_hostname: "unapproved-hostname" }, { apt_packages_requested: ["unapproved"] },
      { apt_packages_policy_rc_d: 0 }, { apt_packages_policy_rc_d: "101" },
      { base_services: ["docker.service"] }, { debian_locale: "en_US.UTF-8" },
    ]) {
      const state = freshBaseState();
      baseRefused(runBase("inactive binding override", { state, extraVars, check }), state, true);
    }
    for (const prerequisite of ["python_apt", ...contract.debian.baseline.image_packages]) {
      const state = freshBaseState();
      if (prerequisite === "python_apt") state.python_apt = false;
      else delete state.packages[prerequisite];
      baseRefused(runBase(`missing ${prerequisite}`, { state, check }), state, true);
    }
  }
  for (const vars of [
    {}, { ...locked, apt_packages_exact_lock_authorized: false },
    { ...locked, apt_packages_exact_locked_specs: baselineLock.slice(1) },
    { ...locked, apt_packages_exact_locked_specs: [...baselineLock, "extra=1.0-fixture"] },
    { ...locked, apt_packages_exact_locked_specs: baselineLock.map((spec, i) => i ? spec : "wrong=1.0-fixture") },
    { ...locked, apt_packages_exact_locked_specs: baselineLock.map((spec) => spec.split("=")[0]) },
    { ...locked, package_mutation_policy: { require_exact_lock_for_all_updates: true, automatic_apply: true } },
    { ...locked, package_mutation_policy: { require_exact_lock_for_all_updates: false, automatic_apply: false } },
  ]) {
    const state = freshBaseState();
    baseRefused(runBase("missing or invalid package authority", { vars, state }), state);
  }
  const productionVars = { lifecycle_profile: "production", apt_packages_exact_lock_authorized: true,
    apt_packages_exact_locked_specs: ["rsync=1.0-fixture"] };
  const production = runBase("production base unchanged", { vars: productionVars });
  baseSucceeded(production);
  assert.deepEqual(production.events.find((event) => event.module === "apt").args,
    { name: ["rsync=1.0-fixture"], state: "present", update_cache: false, auto_install_module_deps: false });
  assert(!production.events.some((event) => ["hostname", "systemd_service"].includes(event.module)));
  assert(!production.events.some((event) => event.module === "command" &&
    ["/usr/bin/python3", "/usr/bin/dpkg-query"].includes(event.args.argv[0])));
  baseSucceeded(runBase("production base zero-change", { vars: { lifecycle_profile: "production" }, state: production.state }), true);
  const state = freshBaseState();
  const productionCheck = runBase("production check unchanged", { vars: productionVars, state, check: true });
  baseSucceeded(productionCheck);
  assert.deepEqual(productionCheck.state, state);
  assert(!productionCheck.events.some((event) => event.module === "apt"));
  console.log(`debian_base_source=verified mocked_endpoints=true runs=${baseRuns} baseline_subschema=verified installed_first_boot=false`);

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
  fixtureSucceeded = true;
} finally {
  if (fixtureSucceeded) fs.rmSync(fixtureRoot, { recursive: true, force: true });
  else console.error(`Failed synthetic fixture retained at ${fixtureRoot}`);
}

console.log("debian_lifecycle_profiles=verified profiles=3");
