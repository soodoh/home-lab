#!/usr/bin/env node
"use strict";

// Real source task/import/condition/Jinja evaluation. All guest effects, including
// Python inactive-path and systemd observations, are controller-only JSON models.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");
const root = path.resolve(__dirname, "../..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const yaml = (p) => load(read(p));
const hash = (s) => crypto.createHash("sha256").update(s).digest("hex");
const contract = yaml("infrastructure/contract/home-lab.yml");
const site = yaml("ansible/playbooks/legacy-debian-site.yml")[0];
const tasks = yaml("ansible/roles/storage/tasks/inactive.yml");
const template = read("ansible/roles/storage/templates/inactive-mount.j2");
const helper = read("ansible/roles/debian_lifecycle_guard/files/debian-inactive-path.py");
const guard = yaml("ansible/roles/debian_lifecycle_guard/tasks/main.yml");
// Exact source startup check MUST precede any fixture creation. Never run helper.
const guardArgv = guard.find((t) => t.name === "Inspect inactive protected mountpoints without traversing them")["ansible.builtin.command"].argv;
assert.deepEqual(guardArgv, ["/usr/bin/python3", "-I", "-B", "-S", "-c",
  "{{ lookup('ansible.builtin.file', role_path ~ '/files/debian-inactive-path.py') }}", "{{ item }}"]);
assert.deepEqual(helper.match(/^(?:import |from ).*$/gm), ["import ctypes", "import errno", "import json", "import os",
  "import platform", "import stat", "import sys", "from contextlib import ExitStack", "from dataclasses import dataclass"]);
const schema = JSON.parse(read("infrastructure/contract/schema.json"));
const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema);
assert(validate(contract), JSON.stringify(validate.errors));
assert(schema.properties.debian.required.includes("storage"));
for (const storage of [undefined, {}, null, { local_mount_boot_options: [] }, { local_mount_boot_options: ["noatime"] },
  { local_mount_boot_options: ["nofail", "nofail"] }, { ...contract.debian.storage, automatic_activation: true }]) {
  const value = structuredClone(contract);
  if (storage === undefined) delete value.debian.storage;
  else value.debian.storage = storage;
  assert(!validate(value), "invalid storage schema accepted");
}
const roots = ["/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
  "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached", "/run/systemd/system",
  "/run/systemd/system.attached", "/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late"];
const parents = ["/", "/etc", "/etc/systemd", "/etc/home-lab", "/run", "/run/systemd", "/usr", "/usr/local",
  "/usr/local/lib", "/usr/local/lib/systemd", "/usr/lib", "/usr/lib/systemd"];
const unitName = (p) => p.slice(1).replaceAll("-", "\\x2d").replaceAll("/", "-") + ".mount";
const units = contract.debian.qualification.protected_mounts.map(unitName);
// Public systemd v257: dbus-unit.c Names is "as"; bus-print-properties.c
// uses shell_maybe_quote(str, 0), escape.c doubles backslashes inside quotes.
// Independent golden singletons, not a copy of the role's serialization expression.
// These are upstream compatibility facts, not installed-version observations.
const serializedNames = {
  [String.raw`srv-home\x2dlab\x2dstate.mount`]: String.raw`"srv-home\\x2dlab\\x2dstate.mount"`,
  "mnt-games.mount": "mnt-games.mount",
  "mnt-storage.mount": "mnt-storage.mount",
};
assert.deepEqual(units, Object.keys(serializedNames));
const targets = units.map((u) => `/etc/systemd/system/${u}`);
const token = contract.debian.transaction.storage_activation_path;
const legacy = Object.fromEntries(yaml("infrastructure/debian/cloud-init/user-data").write_files
  .filter((f) => targets.includes(f.path)).map((f) => [f.path, f.content]));
assert.equal(Object.keys(legacy).length, 3);
const dispatch = site.tasks.find((t) => t["ansible.builtin.import_role"].name === "storage");
assert.deepEqual(dispatch["ansible.builtin.import_role"], { name: "storage", tasks_from: "inactive" });
assert.equal(dispatch.when, "lifecycle_profile in ['inert', 'recovery']");
assert.deepEqual(dispatch.tags, ["storage"]);
for (const r of site.roles.filter((r) => r.role !== "base")) assert.equal(r.when, "lifecycle_profile == 'production'");
assert.deepEqual(site.pre_tasks.slice(1).map((t) => t["ansible.builtin.import_role"].name),
  ["debian_lifecycle_guard", "apply_guard", "lifecycle_state", "apply_lock"]);
assert.equal(site.pre_tasks.at(-1).vars.apply_lock_action, "acquire");
assert.equal(site.post_tasks[0].vars.apply_lock_action, "release");

const unitArg = "{{ item.path[1:] | replace('-', '\\x2d') | replace('/', '-') }}.mount";
const pathArgv = ["/usr/bin/python3", "-I", "-B", "-S", "-c",
  "{{ lookup('ansible.builtin.file', role_path ~ '/../debian_lifecycle_guard/files/debian-inactive-path.py') }}", "{{ item.path }}"];
const showArgv = ["/usr/bin/systemctl", "show", "--property=LoadState", "--property=ActiveState", "--property=SubState",
  "--property=UnitFileState", "--property=FragmentPath", "--property=DropInPaths", "--property=Names", "--property=Job", unitArg];
const pure = new Set(["assert", "set_fact"]);
const effects = new Set(["stat", "find", "command", "copy"]);
function adapt(source) {
  return source.map((task) => {
    const t = structuredClone(task);
    assert(!t.block && !t.always && !t.rescue, "unknown task block refused before dispatch");
    const keys = Object.keys(t).filter((k) => k.startsWith("ansible."));
    assert.equal(keys.length, 1);
    const module = keys[0].replace("ansible.builtin.", "");
    assert(pure.has(module) || effects.has(module), `unknown module/import refused before dispatch: ${keys[0]}`);
    if (module === "command") {
      const args = t[keys[0]];
      assert.deepEqual(Object.keys(args), ["argv"]);
      assert([pathArgv, showArgv, ["/usr/bin/systemctl", "show", "--property=UnitPath"]]
        .some((argv) => JSON.stringify(argv) === JSON.stringify(args.argv)), "unknown command refused before dispatch");
      assert.equal(t.changed_when, false);
      assert.equal(t.check_mode, false);
    }
    if (module === "copy") assert.deepEqual(t[keys[0]], {
      content: "{{ lookup('ansible.builtin.template', 'inactive-mount.j2') }}",
      dest: "/etc/systemd/system/" + unitArg, owner: "root", group: "root", mode: "0644", force: false, follow: false,
    });
    if (module === "find") {
      assert.equal(t[keys[0]].recurse, false);
      assert.equal(t[keys[0]].follow, false);
      assert.equal(t[keys[0]].file_type, "any");
      assert.equal(t[keys[0]].hidden, true);
    }
    if (effects.has(module)) {
      t.storage_witness = { module, arguments: t[keys[0]] };
      delete t[keys[0]];
    }
    return t;
  });
}
const adapted = adapt(tasks);
for (const module of ["shell", "template", "service", "include_role", "import_role", "import_tasks", "uri"])
  assert.throws(() => adapt([{ [`ansible.builtin.${module}`]: {} }]), assert.AssertionError);
assert.throws(() => adapt([{ "ansible.builtin.command": { argv: ["/usr/bin/systemctl", "daemon-reload"] } }]), assert.AssertionError);
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "storage-provisioning-"));
let success = false, runs = 0;
const write = (p, value) => fs.writeFileSync(path.join(fixture, p), typeof value === "string" ? value : JSON.stringify(value));
try {
  for (const d of ["home", "tmp", "collections", "action_plugins", "runs", "roles/storage/tasks", "roles/storage/templates",
    "roles/firewall_nfs_canary/tasks", "roles/debian_lifecycle_guard/files"])
    fs.mkdirSync(path.join(fixture, d), { recursive: true });
  write("inventory", "fixture-debian ansible_connection=local\n");
  write("ansible.cfg", `[defaults]\nroles_path = ${fixture}/roles\naction_plugins = ${fixture}/action_plugins\ncollections_path = ${fixture}/collections\nlocal_tmp = ${fixture}/tmp\nretry_files_enabled = False\nstdout_callback = default\n[privilege_escalation]\nbecome = False\n`);
  write("roles/storage/tasks/inactive.yml", adapted);
  write("roles/storage/templates/inactive-mount.j2", template);
  write("roles/debian_lifecycle_guard/files/debian-inactive-path.py", helper);
  for (const name of ["storage", "firewall_nfs_canary"])
    write(`roles/${name}/tasks/main.yml`, [{ name: `Production ${name} dispatch witness only`,
      "ansible.builtin.debug": { msg: "production body not executed" } }]);
  write("action_plugins/storage_witness.py", `import hashlib, json
from ansible.plugins.action import ActionBase
STATE = ${JSON.stringify(path.join(fixture, "state.json"))}
EVENTS = ${JSON.stringify(path.join(fixture, "events.jsonl"))}
ROOTS = ${JSON.stringify(roots)}
PARENTS = ${JSON.stringify(parents)}
UNITS = ${JSON.stringify(units)}
SERIALIZED_NAMES = ${JSON.stringify(serializedNames)}
TARGETS = ${JSON.stringify(targets)}
TOKEN = ${JSON.stringify(token)}
HELPER = ${JSON.stringify(helper.trimEnd())}
PROTECTED = ${JSON.stringify(contract.debian.qualification.protected_mounts)}

def directory():
    return dict(exists=True, isdir=True, islnk=False, uid=0, gid=0, mode='0755')
def body(content):
    return dict(exists=True, isreg=True, islnk=False, nlink=1, uid=0, gid=0, mode='0644',
                checksum=hashlib.sha256(content.encode()).hexdigest())
class ActionModule(ActionBase):
    _requires_connection = False
    def run(self, tmp=None, task_vars=None):
        module, args = self._task.args['module'], self._task.args['arguments']
        check = self._task.check_mode
        with open(STATE) as stream:
            state = json.load(stream)
        with open(EVENTS, 'a') as stream:
            stream.write(json.dumps(dict(module=module, args=args, check=check, task=self._task.get_name())) + '\\n')
        result = dict(changed=False)
        if module == 'facts':
            return dict(changed=False, ansible_facts=args)
        if module == 'admission':
            if state.get('refuse_admission') == args['name']:
                return dict(failed=True, msg='synthetic guard/lock admission refused')
        elif module == 'stat':
            target = args['path']
            assert args.get('follow') is False
            assert set(args) == {'path', 'follow', 'checksum_algorithm' if target in TARGETS else 'get_checksum'}
            if target in TARGETS:
                assert args['checksum_algorithm'] == 'sha256'
                result['stat'] = body(state['files'][target]) if target in state['files'] else dict(exists=False)
                result['stat'].update(state.get('dest_drift', {}).get(target, {}))
            elif target in ROOTS + PARENTS:
                result['stat'] = state.get('ancestry', {}).get(target, directory())
            elif target == '/lib':
                result['stat'] = state.get('lib_alias', dict(exists=True, islnk=True, uid=0, gid=0, lnk_target='usr/lib'))
            elif target == TOKEN:
                result['stat'] = dict(exists=state.get('token', False) or
                    (state.get('late_token', False) and 'Reinspect' in self._task.get_name()))
            else:
                raise AssertionError('unmodeled stat path refused')
        elif module == 'find':
            target = args['paths']
            assert args == dict(paths=target, recurse=False, file_type='any', hidden=True, follow=False)
            assert target in ROOTS or (target.rsplit('/', 1)[0] in ROOTS and target.endswith(('.wants', '.requires')))
            result.update(files=state.get('entries', {}).get(target, []), skipped_paths=state.get('skipped', {}).get(target, {}))
        elif module == 'command':
            argv = args['argv']
            assert set(args) == {'argv'} and not check
            if argv[:5] == ['/usr/bin/python3', '-I', '-B', '-S', '-c']:
                assert len(argv) == 7 and argv[5] == HELPER and argv[6] in PROTECTED
                if state.get('unsafe_path') == argv[6]:
                    return dict(failed=True, rc=1, msg='modeled inactive-path refusal; helper not executed')
                stdout = json.dumps(dict(exists=True, entry_count=1 if state.get('nonempty') == argv[6] else 0))
            elif argv == ['/usr/bin/systemctl', 'show', '--property=UnitPath']:
                stdout = state.get('unit_path', 'UnitPath=' + ' '.join(ROOTS))
            else:
                assert argv[:-1] == ${JSON.stringify(showArgv.slice(0, -1))} and argv[-1] in UNITS
                unit = argv[-1]
                values = dict(LoadState='not-found', ActiveState='inactive', SubState='dead', UnitFileState='',
                              FragmentPath='', DropInPaths='', Names=SERIALIZED_NAMES[unit], Job='')
                if state.get('loaded'):
                    values.update(LoadState='loaded', UnitFileState='disabled', FragmentPath='/etc/systemd/system/' + unit)
                values.update(state.get('unit_drift', {}).get(unit, {}))
                stdout = '\\n'.join(key + '=' + value for key, value in values.items())
            result.update(rc=0, stdout=stdout, stdout_lines=stdout.splitlines())
        elif module == 'copy':
            target = args['dest']
            assert target in TARGETS
            assert args == dict(content=args['content'], dest=target, owner='root', group='root', mode='0644', force=False, follow=False)
            assert target not in state['files'], 'existing destination must never be copied'
            result['changed'] = True
            if not check:
                state['files'][target] = args['content']
                with open(STATE, 'w') as stream:
                    json.dump(state, stream)
        else:
            raise AssertionError('unknown modeled endpoint refused')
        return result
`);
  const env = { PATH: process.env.PATH, HOME: path.join(fixture, "home"), TMPDIR: path.join(fixture, "tmp"),
    LANG: "C.UTF-8", ANSIBLE_CONFIG: path.join(fixture, "ansible.cfg"), ANSIBLE_NOCOLOR: "1", PYTHONDONTWRITEBYTECODE: "1" };
  const version = spawnSync("ansible-playbook", ["--version"], { cwd: fixture, env, encoding: "utf8", timeout: 30000 });
  write("ansible-version.txt", `${version.stdout || ""}${version.stderr || ""}`);
  assert.equal(version.status, 0, `Existing Ansible required; no install/skip: ${version.error || version.stderr}`);
  console.log(version.stdout.split("\n")[0]);
  const platform = { system: "Linux", architecture: "x86_64", distribution: "Debian",
    distribution_major_version: contract.debian.version, distribution_release: contract.debian.release };
  const fresh = () => ({ files: {} });
  const converged = () => ({ files: structuredClone(legacy) });
  const admission = (source) => {
    const t = structuredClone(source);
    if (t["ansible.builtin.assert"]) return t;
    delete t["ansible.builtin.import_role"];
    t.storage_witness = { module: "admission", arguments: { name: t.name } };
    return t;
  };
  function run(label, { state = fresh(), profile = "inert", extra = {}, check = false, direct = false, tag = "storage" } = {}) {
    // Only public storage bindings are fixture inputs; no credentials/receipts.
    const vars = { lifecycle_profile: profile, lifecycle_contract_host: "debian", debian: contract.debian,
      proxmox: { vm: { state_disk: contract.proxmox.vm.state_disk } }, vm_100: { storage: contract.vm_100.storage },
      network: { proxmox: contract.network.proxmox }, storage: { nfs: { export: contract.storage.nfs.export, mountpoint: contract.storage.nfs.mountpoint } } };
    write("play.yml", [{ name: "Source storage dispatch with synthetic guard/lock witnesses", hosts: "fixture-debian", gather_facts: false,
      become: false, vars,
      pre_tasks: [{ name: "Seed modeled platform", storage_witness: { module: "facts", arguments: platform }, tags: ["always"] },
        ...site.pre_tasks.map(admission)],
      roles: direct ? [] : site.roles.filter((r) => ["storage", "firewall_nfs_canary"].includes(r.role)),
      tasks: [direct ? { "ansible.builtin.import_role": { name: "storage", tasks_from: "inactive" }, tags: ["storage"] } : dispatch],
      post_tasks: site.post_tasks.map(admission) }]);
    write("extra.json", extra); write("state.json", state); write("events.jsonl", "");
    const result = spawnSync("ansible-playbook", ["-i", path.join(fixture, "inventory"), path.join(fixture, "play.yml"),
      "--extra-vars", `@${path.join(fixture, "extra.json")}`, "--tags", tag, ...(check ? ["--check"] : [])],
    { cwd: fixture, env, encoding: "utf8", timeout: 60000 });
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    const log = fs.readFileSync(path.join(fixture, "events.jsonl"), "utf8").trim();
    const observed = { label, status: result.status, output, events: log ? log.split("\n").map(JSON.parse) : [],
      state: JSON.parse(fs.readFileSync(path.join(fixture, "state.json"), "utf8")) };
    write(`runs/${String(++runs).padStart(3, "0")}.json`, observed);
    assert(!result.error && result.status !== null, `${label}: ${result.error || result.signal}\n${output}`);
    return observed;
  }
  const copies = (r) => r.events.filter((e) => e.module === "copy");
  function passed(r, noChange = false) {
    assert.equal(r.status, 0, `${r.label}: ${r.output}`);
    if (noChange) assert.match(r.output, /changed=0\s/);
    const names = r.events.map((e) => e.args.name);
    const acquire = names.indexOf(site.pre_tasks.at(-1).name), release = names.indexOf(site.post_tasks[0].name);
    assert(acquire >= 0 && release > acquire);
    for (const [i, e] of r.events.entries()) if (effects.has(e.module)) assert(i > acquire && i < release);
  }
  function refused(r, pattern, state) {
    assert.equal(r.status, 2, `${r.label}: ${r.output}`);
    assert.match(r.output, pattern, `${r.label}: ${r.output}`);
    assert.deepEqual(copies(r), [], `${r.label}: refusal must precede all writes`);
    if (state) assert.deepEqual(r.state, state);
    assert(!r.events.some((e) => e.args.name === site.post_tasks[0].name), "failed modeled apply released lock");
  }
  const descriptionBinding = "storage_inactive_mounts | map(attribute='description') | list == ['Home lab application state', 'Home lab games storage', 'Home lab shared NFS storage']";
  const pathRefusal = /Task failed: Action failed: Unsupported storage path or systemd graph binding; no arbitrary destination is accepted\./;
  const loadedRefusal = /Task failed: Action failed: Mount loaded state is unknown, foreign, aliased, enabled, masked, active or queued; disk declarations are not loaded readiness\./;
  const descriptors = contract.debian.qualification.protected_mounts.map((p, i) => ({
    kind: ["state", "games", "shared"][i], path: p,
    description: ["Home lab application state", "Home lab games storage", "Home lab shared NFS storage"][i],
  }));
  const injectedDescription = "Home lab application state\nRequires=unreviewed.service";
  const withDescription = (i, description) => ({ storage_inactive_mounts: descriptors.map((d, j) =>
    j === i ? { ...d, description } : { ...d }) });
  function descriptionRefused(r, state) {
    refused(r, pathRefusal, state);
    assert(r.output.includes(descriptionBinding), "refusal must identify the exact description binding");
    assert(!r.events.some((e) => effects.has(e.module)), "description refusal must precede all storage observations/effects");
  }
  for (const profile of ["inert", "recovery"]) {
    const first = run(`first ${profile}: quoted escaped Names singleton`, { profile }); passed(first);
    assert.deepEqual(first.state.files, legacy, "real Ansible rendered bytes must equal all cloud-init bodies");
    assert.equal(copies(first).length, 3);
    for (const event of copies(first)) assert.equal(hash(event.args.content), hash(legacy[event.args.dest]));
    const second = run(`second ${profile}`, { profile, state: first.state }); passed(second, true);
    assert.deepEqual(copies(second), []);
    for (const state of [fresh(), first.state]) {
      const checked = run(`check ${profile}`, { profile, state, check: true }); passed(checked, !!Object.keys(state.files).length);
      assert.deepEqual(checked.state, state);
      assert(copies(checked).every((e) => e.check));
      assert.equal(copies(checked).length, Object.keys(state.files).length ? 0 : 3);
    }
  }
  passed(run("loaded exact declarations", { state: { ...converged(), loaded: true } }), true);
  for (const check of [false, true]) {
    for (const target of targets) {
      const state = converged(); delete state.files[target];
      const r = run(`one missing ${target} check=${check}`, { state, check }); passed(r);
      assert.deepEqual(copies(r).map((e) => e.args.dest), [target]);
      assert.deepEqual(r.state.files, check ? state.files : legacy);
    }
    const production = run("production dispatch", { profile: "production", check }); passed(production, true);
    assert(!production.events.some((e) => effects.has(e.module)));
    assert.match(production.output, /production body not executed/);
    refused(run("direct production refused", { profile: "production", direct: true, check }), /production and activation are forbidden/);
    refused(run("unknown profile", { extra: { lifecycle_profile: "unknown" }, check }), /implicit production activation is forbidden/);
    const authorityRefusal = /Task failed: Action failed: Storage declarations require inactive Debian and direct contract bindings; production and activation are forbidden\./;
    for (const [label, extra, pattern] of [
      ["wrong host", { lifecycle_contract_host: "proxmox" }, authorityRefusal],
      ["missing authority", { debian: {} }, /Task failed: Error while evaluating conditional: object of type 'dict' has no attribute 'baseline'/],
      ["boot options", { debian: { ...contract.debian, storage: { local_mount_boot_options: [] } } }, authorityRefusal],
      ["NFS source", { vm_100: { storage: { ...contract.vm_100.storage, shared: { ...contract.vm_100.storage.shared, source: "foreign:/export" } } } }, authorityRefusal],
      ["graph", { debian: { ...contract.debian, transaction: { ...contract.debian.transaction,
        production_systemd_dependencies: { ...contract.debian.transaction.production_systemd_dependencies,
          "docker.service": { Requires: [], After: [] } } } } }, pathRefusal],
      ["redirected root", { storage_inactive_roots: ["/foreign"] }, /Task failed: Action failed: Overriding the supported systemd search topology is forbidden\./],
      ["redirected mounts", { storage_inactive_mounts: [{ kind: "state", description: "foreign", path: "/arbitrary" }] }, pathRefusal],
    ]) {
      const state = fresh();
      refused(run(`${label} check=${check}`, { check, extra, state }), pattern, state);
    }
    for (const [label, state, pattern] of [
      ["token", { ...fresh(), token: true }, /token must be absent/],
      ["late token", { ...fresh(), late_token: true }, /token appeared/],
      ["unsupported UnitPath", { ...fresh(), unit_path: "UnitPath=/etc/systemd/system /custom" }, /bounded scan cannot admit/],
      ["missing UnitPath", { ...fresh(), unit_path: "" }, /bounded scan cannot admit/],
      ["foreign alias", { ...fresh(), unit_path: "UnitPath=/etc/systemd/system /lib/systemd/system",
        lib_alias: { exists: true, islnk: true, uid: 0, gid: 0, lnk_target: "foreign" } }, /merged usr lib alias/],
      ["incomplete root", { ...fresh(), skipped: { [roots[0]]: { denied: "fixture" } } }, /Incomplete systemd root discovery/],
    ]) refused(run(`${label} check=${check}`, { check, state }), pattern, state);
    const alias = run("exact merged usr alias", { check, state: { ...fresh(), unit_path: "UnitPath=/etc/systemd/system /lib/systemd/system" } }); passed(alias);
    for (const p of contract.debian.qualification.protected_mounts) {
      for (const key of ["unsafe_path", "nonempty"]) {
        const state = { ...fresh(), [key]: p };
        refused(run(`${key} ${p}`, { check, state }), /inactive-path refusal|unmounted and empty/, state);
      }
    }
    for (const drift of [{ exists: false }, { exists: true, isdir: false, islnk: true, uid: 0, gid: 0, mode: "0755" },
      { exists: true, isdir: true, islnk: false, uid: 1, gid: 0, mode: "0755" },
      { exists: true, isdir: true, islnk: false, uid: 0, gid: 1, mode: "0755" },
      { exists: true, isdir: true, islnk: false, uid: 0, gid: 0, mode: "0775" }]) {
      const state = { ...fresh(), ancestry: { "/etc/systemd/system": drift } };
      refused(run(`unsafe ancestry ${JSON.stringify(drift)}`, { check, state }), /ancestry is absent or unsafe/, state);
    }
    const optional = { ...fresh(), ancestry: Object.fromEntries(roots.filter((p) => !["/etc/systemd/system", "/usr/lib/systemd/system"].includes(p))
      .map((p) => [p, { exists: false }])) };
    passed(run("optional roots absent", { check, state: optional }));
    for (const target of targets) {
      for (const drift of [{ checksum: "0".repeat(64) }, { mode: "0600" }, { uid: 1 }, { gid: 1 }, { nlink: 2 }, { isreg: false }, { islnk: true }]) {
        const state = { ...converged(), dest_drift: { [target]: drift } };
        refused(run(`destination ${target} ${JSON.stringify(drift)}`, { check, state }), /Existing storage declaration differs/, state);
      }
    }
    for (const [key, value] of Object.entries({ LoadState: "error", ActiveState: "active", SubState: "mounting",
      UnitFileState: "enabled", FragmentPath: "/foreign", DropInPaths: "/override.conf", Names: "alias.mount", Job: "42" })) {
      const state = { ...fresh(), unit_drift: { [units[0]]: { [key]: value } } };
      refused(run(`loaded ${key}`, { check, state }), /Mount loaded state is unknown/, state);
    }
    // Only the exact supported singleton representation is admitted, not
    // equivalent shell spellings, malformed escapes, aliases or multiple names.
    for (const [label, unit, value] of [
      ["raw escaped singleton", units[0], String.raw`srv-home\x2dlab\x2dstate.mount`],
      ["quoted undoubled escape", units[0], String.raw`"srv-home\x2dlab\x2dstate.mount"`],
      ["missing closing quote", units[0], String.raw`"srv-home\\x2dlab\\x2dstate.mount`],
      ["missing opening quote", units[0], String.raw`srv-home\\x2dlab\\x2dstate.mount"`],
      ["malformed escape", units[0], String.raw`"srv-home\\x2glab\\x2dstate.mount"`],
      ["mixed escape widths", units[0], String.raw`"srv-home\\x2dlab\x2dstate.mount"`],
      ["single quotes", units[0], String.raw`'srv-home\x2dlab\x2dstate.mount'`],
      ["POSIX quotes", units[0], String.raw`$'srv-home\\x2dlab\\x2dstate.mount'`],
      ["escaped multiple names", units[0], String.raw`"srv-home\\x2dlab\\x2dstate.mount" alias.mount`],
      ["raw multiple names", units[1], "mnt-games.mount alias.mount"],
      ["unnecessary quotes", units[1], '"mnt-games.mount"'],
      ["trailing whitespace", units[0], serializedNames[units[0]] + " "],
    ]) {
      const state = { ...fresh(), unit_drift: { [unit]: { Names: value } } };
      refused(run(`Names ${label} check=${check}`, { check, state }), loadedRefusal, state);
    }
    for (const i of [0, 1, 2]) {
      for (const description of ["Innocent different description", injectedDescription,
        "Home lab application state\n[Service]\nExecStart=/unreviewed"]) {
        const state = fresh();
        descriptionRefused(run(`description ${i} ${JSON.stringify(description)} check=${check}`,
          { check, state, extra: withDescription(i, description) }), state);
      }
    }
    const masked = { ...fresh(), unit_drift: { [units[0]]: { LoadState: "masked", UnitFileState: "masked" } } };
    refused(run("masked loaded state", { check, state: masked }), /Mount loaded state is unknown/, masked);
    // Every admitted search root is scanned, even if the manager omitted it.
    for (const r of roots) {
      const basename = r === "/etc/systemd/system" ? "mount.d" : units[0];
      const state = { ...fresh(), entries: { [r]: [{ path: `${r}/${basename}`, islnk: true }] } };
      refused(run(`foreign entry ${r}`, { check, state }), /Foreign mount definition/, state);
    }
    for (const basename of ["mount.d", "mnt-.mount.d", "srv-.mount.d", ...units.map((u) => `${u}.d`)]) {
      const state = { ...fresh(), entries: { [roots[0]]: [{ path: `${roots[0]}/${basename}`, islnk: true }] } };
      refused(run(`override ${basename}`, { check, state }), /Foreign mount definition/, state);
    }
    for (const suffix of ["wants", "requires"]) {
      const parent = `${roots[0]}/fixture.target.${suffix}`;
      const directory = { path: parent, isdir: true, islnk: false, uid: 0, gid: 0, mode: "0755" };
      for (const unit of units) {
        const state = { ...fresh(), entries: { [roots[0]]: [directory], [parent]: [{ path: `${parent}/${unit}`, islnk: true }] } };
        refused(run(`dangling ${suffix} ${unit}`, { check, state }), /Protected mount pull in entry/, state);
      }
      const state = { ...fresh(), entries: { [roots[0]]: [{ ...directory, islnk: true }] } };
      refused(run(`unsafe ${suffix}`, { check, state }), /Unsafe systemd pull in directory/, state);
      passed(run(`unrelated ${suffix}`, { check, state: { ...fresh(), entries: {
        [roots[0]]: [directory, { path: `${roots[0]}/unrelated.service`, islnk: true }],
        [parent]: [{ path: `${parent}/unrelated.service`, islnk: true }],
      } } }));
    }
    for (const task of [site.pre_tasks[1], site.pre_tasks[2], site.pre_tasks.at(-1)]) {
      const r = run("synthetic admission refusal", { check, state: { ...fresh(), refuse_admission: task.name } });
      refused(r, /synthetic guard\/lock admission refused/);
      assert(!r.events.some((e) => effects.has(e.module)));
    }
  }
  passed(run("unselected tag", { tag: "base" }), true);
  // Causal mutant: real template evaluation without the boot-only options must
  // reject the correct existing declarations. No missing-file pseudo-RED.
  const mutant = template.replace(" + debian.storage.local_mount_boot_options", "");
  assert.notEqual(mutant, template);
  write("roles/storage/templates/inactive-mount.j2", mutant);
  refused(run("nofail removal mutant", { state: converged() }), /Existing storage declaration differs/);
  write("roles/storage/templates/inactive-mount.j2", template);
  // One bounded synthetic counterfactual: remove ONLY the description binding
  // from the adapted fixture role. Keep paths, contract, template and every
  // other admission assertion fixed; no native unit is written or loaded.
  const descriptionMutant = structuredClone(adapted);
  const bindingTask = descriptionMutant.find((t) => t.name === "Require supported canonical paths and systemd graph names");
  const assertions = bindingTask["ansible.builtin.assert"].that;
  assert.equal(assertions.filter((a) => a === descriptionBinding).length, 1);
  bindingTask["ansible.builtin.assert"].that = assertions.filter((a) => a !== descriptionBinding);
  const restored = structuredClone(descriptionMutant);
  restored.find((t) => t.name === bindingTask.name)["ansible.builtin.assert"].that
    .splice(assertions.indexOf(descriptionBinding), 0, descriptionBinding);
  assert.deepEqual(restored, adapted, "mutant must remove only the description binding");
  write("roles/storage/tasks/inactive.yml", descriptionMutant);
  const counterfactualState = fresh();
  const counterfactual = run("description binding removal mutant: modeled directive publication only",
    { state: counterfactualState, extra: withDescription(0, injectedDescription) });
  passed(counterfactual);
  assert.equal(copies(counterfactual).length, 3);
  const injectedBody = legacy[targets[0]].replace("Description=Home lab application state\n",
    `Description=${injectedDescription}\n`);
  assert.notEqual(injectedBody, legacy[targets[0]]);
  assert.deepEqual(counterfactual.state, { files: { ...legacy, [targets[0]]: injectedBody } });
  assert(copies(counterfactual).some((e) => e.args.dest === targets[0] && e.args.content === injectedBody));
  assert.throws(() => descriptionRefused(counterfactual, counterfactualState),
    (error) => error instanceof assert.AssertionError && error.actual === 0 && error.expected === 2,
    "the intended description refusal assertion must fail on modeled publication");
  write("roles/storage/tasks/inactive.yml", adapted);
  console.log("description_binding_causal_mutant=verified removed_assertions=1 modeled_injected_directive_publication=true intended_refusal_assertion_failed=true native_publication=false");
  console.log(`debian_storage_declarations_source=verified runs=${runs} legacy_bodies=3 byte_parity=true full_public_schema=true real_ansible=true controller_only_effect_adapters=true native_helper=false native_installation=false loaded_boot_activation_acceptance=false`);
  success = true;
} finally {
  if (success) fs.rmSync(fixture, { recursive: true, force: true });
  else console.error(`Failed synthetic fixture retained at ${fixture}`);
}
