#!/usr/bin/env node
"use strict";

// Real Ansible evaluates the selected site dispatch, imports, loops, arguments and
// conditions. Controller action adapters model effects; no guest module executes.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");
const root = path.resolve(__dirname, "../..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const yaml = (p) => load(read(p));
const contract = yaml("infrastructure/contract/home-lab.yml");
const group = yaml("ansible/group_vars/docker_host.yml");
const site = yaml("ansible/playbooks/site.yml")[0];
const roles = ["sops_age", "restic_backup"];
const mains = Object.fromEntries(roles.map((r) => [r, yaml(`ansible/roles/${r}/tasks/main.yml`)]));
const tools = Object.fromEntries(roles.map((r) => [r, yaml(`ansible/roles/${r}/tasks/tools.yml`)]));
const sopsAliases = ["sops_version", "sops_download_url", "sops_sha256", "age_version", "age_download_url",
  "age_archive_sha256", "age_binary_sha256", "age_keygen_binary_sha256"];
const resticAliases = ["restic_version", "restic_download_url", "restic_archive_sha256", "restic_binary_sha256",
  "rclone_version", "rclone_download_url", "rclone_archive_sha256", "rclone_binary_sha256"];
const pins = { sops: contract.debian.tools.sops, age: contract.debian.tools.age,
  "age-keygen": { installed_sha256: contract.debian.tools.age.keygen_installed_sha256 },
  ...contract.backups.restic.tools };
const paths = Object.fromEntries(Object.keys(pins).map((name) => [`/usr/local/bin/${name}`, pins[name].installed_sha256]));
const schema = JSON.parse(read("infrastructure/contract/schema.json"));
assert(schema.properties.debian.required.includes("tools"));
const validateTools = new Ajv2020({ strict: true, allErrors: true }).compile(schema.properties.debian.properties.tools);
assert(validateTools(contract.debian.tools), JSON.stringify(validateTools.errors));
for (const tool of ["sops", "age"]) {
  for (const field of Object.keys(contract.debian.tools[tool])) {
    for (const value of [undefined, null, "unapproved"]) {
      const invalid = structuredClone(contract.debian.tools);
      if (value === undefined) delete invalid[tool][field];
      else invalid[tool][field] = value;
      assert(!validateTools(invalid), `tools subschema accepted invalid ${tool}.${field}`);
    }
  }
}
assert(!validateTools({ ...contract.debian.tools, automatic_install: true }));

// The production callers and admission/lock order stay intact. Only the two
// inactive imports are added; none of the full roles loses its production gate.
for (const role of site.roles.filter((r) => r.role !== "base")) assert.equal(role.when, "lifecycle_profile == 'production'");
assert.deepEqual(site.tasks.map((t) => t["ansible.builtin.import_role"]),
  roles.map((name) => ({ name, tasks_from: "tools" })));
for (const task of site.tasks) {
  assert.equal(task.when, "lifecycle_profile in ['inert', 'recovery']");
  assert.deepEqual(task.tags, [task["ansible.builtin.import_role"].name]);
  assert(group.apply_guard_allowed_tags.includes(task.tags[0]));
}
assert.deepEqual(site.pre_tasks.slice(1).map((t) => t["ansible.builtin.import_role"].name),
  ["debian_lifecycle_guard", "apply_guard", "lifecycle_state", "apply_lock"]);
assert.equal(site.pre_tasks.at(-1).vars.apply_lock_action, "acquire");
assert.equal(site.post_tasks[0].vars.apply_lock_action, "release");
assert.deepEqual(mains.sops_age[0]["ansible.builtin.import_tasks"], "tools.yml");
assert.equal(mains.sops_age[1].name, "Require the manually installed recovery identity");
assert.equal(mains.restic_backup[0].name, "Require the supported Restic host architecture");
assert.equal(mains.restic_backup[1].name, "Inspect exact Restic repository mount identities");
assert.equal(mains.restic_backup[2].name, "Require exact Restic repository mount identities");
assert.equal(mains.restic_backup[3]["ansible.builtin.import_tasks"], "tools.yml");
assert.equal(mains.restic_backup[4].name, "Inspect fixed restic-proton identity targets");

const pure = new Set(["assert", "set_fact", "debug", "import_tasks"]);
const effects = new Set(["stat", "get_url", "tempfile", "unarchive", "copy", "file", "command"]);
function adapt(tasks) {
  return tasks.map((source) => {
    const t = structuredClone(source);
    if (t.block) {
      assert(!Object.keys(t).some((k) => k.startsWith("ansible.")));
      t.block = adapt(t.block);
      if (t.always) t.always = adapt(t.always);
      assert(!t.rescue, "unreviewed rescue refused");
      return t;
    }
    const keys = Object.keys(t).filter((k) => k.startsWith("ansible."));
    assert.equal(keys.length, 1, `unclassified task: ${t.name}`);
    const module = keys[0].replace("ansible.builtin.", "");
    assert(pure.has(module) || effects.has(module), `unknown effect refused before dispatch: ${keys[0]}`);
    if (module === "import_tasks") assert.equal(t[keys[0]], "tools.yml", "unknown import refused before dispatch");
    if (effects.has(module)) {
      t.tool_witness = { module, arguments: t[keys[0]] };
      delete t[keys[0]];
    }
    return t;
  });
}
// Preflight the complete selected task closure before starting Ansible, including
// always blocks. Production Restic is deliberately bounded at its account seam:
// the remaining account/secret/unit body is not copied into the fixture at all.
const selectedMains = { sops_age: mains.sops_age, restic_backup: mains.restic_backup.slice(0, 4) };
const adaptedTools = Object.fromEntries(roles.map((r) => [r, adapt(tools[r])]));
const adaptedMains = Object.fromEntries(roles.map((r) => [r, adapt(selectedMains[r])]));
for (const module of ["shell", "service", "include_role", "uri", "unknown"]) {
  assert.throws(() => adapt([{ name: "unreviewed", [`ansible.builtin.${module}`]: {} }]), assert.AssertionError);
}
assert.throws(() => adapt([{ name: "unreviewed import", "ansible.builtin.import_tasks": "production.yml" }]), assert.AssertionError);
assert.throws(() => adapt([{ block: [], always: [{ "ansible.builtin.shell": "bad" }] }]), assert.AssertionError);

const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "tool-provisioning-"));
let success = false;
let runs = 0;
const write = (p, value) => fs.writeFileSync(path.join(fixture, p), typeof value === "string" ? value : JSON.stringify(value));
try {
  for (const d of ["home", "tmp", "collections", "action_plugins", "runs", ...roles.map((r) => `roles/${r}/tasks`)])
    fs.mkdirSync(path.join(fixture, d), { recursive: true });
  write("inventory", "fixture-debian ansible_connection=local\n");
  write("ansible.cfg", `[defaults]\nroles_path = ${fixture}/roles\naction_plugins = ${fixture}/action_plugins\ncollections_path = ${fixture}/collections\nlocal_tmp = ${fixture}/tmp\nretry_files_enabled = False\nstdout_callback = default\n[privilege_escalation]\nbecome = False\n`);
  for (const r of roles) {
    write(`roles/${r}/tasks/main.yml`, adaptedMains[r]);
    write(`roles/${r}/tasks/tools.yml`, adaptedTools[r]);
  }
  // This adapter never calls _execute_module, a connection, a subprocess, an
  // artifact URL or any tool path. Paths below describe only JSON model keys.
  write("action_plugins/tool_witness.py", `import json
from ansible.plugins.action import ActionBase

PINS = ${JSON.stringify(paths)}
TOOLS = json.loads(${JSON.stringify(JSON.stringify(pins))})
STATE = ${JSON.stringify(path.join(fixture, "state.json"))}
EVENTS = ${JSON.stringify(path.join(fixture, "events.jsonl"))}

def binary(checksum):
    return dict(exists=True, isreg=True, islnk=False, nlink=1, pw_name='root', gr_name='root', mode='0755', checksum=checksum)

class ActionModule(ActionBase):
    _requires_connection = False
    def run(self, tmp=None, task_vars=None):
        module = self._task.args['module']
        args = self._task.args['arguments']
        check = self._task.check_mode
        with open(STATE) as stream:
            state = json.load(stream)
        with open(EVENTS, 'a') as stream:
            stream.write(json.dumps(dict(module=module, args=args, check=check, task=self._task.get_name())) + '\\n')
        before = json.dumps(state, sort_keys=True)
        result = dict(changed=False)
        failure = state.get('failure') == self._task.get_name().split(' : ')[-1]
        if failure:
            return dict(failed=True, msg='injected synthetic endpoint failure')
        if module == 'fixture_facts':
            return dict(changed=False, ansible_facts=args)
        if module == 'admission':
            assert set(args) == {'name'}
            if state.get('refuse_admission') == args['name']:
                return dict(failed=True, msg='synthetic admission refused')
            return result
        if module == 'stat':
            target = args['path']
            if target == '/fixture/recovery-identity':
                assert args == dict(path=target)
                result['stat'] = state['identity']
            else:
                assert target in PINS, 'non-tool path inspection refused'
                assert args == dict(path=target, checksum_algorithm='sha256', follow=False)
                result['stat'] = state['binaries'].get(target, dict(exists=False))
                if state.get('post_corrupt') == target and state['workspaces_created']:
                    result['stat'] = binary('0' * 64)
        elif module == 'get_url':
            target = args['dest']
            if target == '/usr/local/bin/sops':
                assert args == dict(url=TOOLS['sops']['url'], dest=target, checksum='sha256:' + PINS[target], owner='root', group='root', mode='0755')
                state['binaries'][target] = binary(PINS[target])
            else:
                names = {'age.tar.gz': 'age', 'restic.bz2': 'restic', 'rclone.zip': 'rclone'}
                workspace, filename = target.rsplit('/', 1)
                assert workspace in state['workspaces'] and filename in names
                tool = TOOLS[names[filename]]
                assert args == dict(url=tool['url'], dest=target, checksum='sha256:' + tool['archive_sha256'], mode='0600')
                assert not check, 'archive download in check mode'
                state['archives'].append(target)
        elif module == 'tempfile':
            assert not check and args['state'] == 'directory' and args['path'] == '/var/tmp'
            assert args['prefix'] in ['age-install-', 'restic-tools-'] and len(args) == 3
            workspace = '/var/tmp/' + args['prefix'] + 'synthetic'
            state['workspaces'].append(workspace)
            state['workspaces_created'] += 1
            result['path'] = workspace
        elif module == 'unarchive':
            assert not check and args['remote_src'] is True
            workspace = args['dest']
            assert args == dict(src=workspace + '/age.tar.gz', dest=workspace, remote_src=True)
            assert args['src'] in state['archives']
            state['extracted'].extend([workspace + '/age/age', workspace + '/age/age-keygen'])
        elif module == 'command':
            argv = args['argv']
            assert set(args) == {'argv'}
            if argv[:3] == ['/usr/bin/findmnt', '--json', '--target']:
                assert len(argv) == 6 and argv[4:] == ['--output', 'TARGET,SOURCE,FSTYPE,UUID']
                assert argv[3] in ['/fixture/games', '/fixture/nfs']
                observed = dict(target=argv[3], fstype='ext4' if argv[3].endswith('games') else 'nfs4', uuid='fixture-uuid', source='fixture-server:/nfs')
                if not state['mounts_valid']:
                    observed['target'] = '/wrong'
                stdout = json.dumps(dict(filesystems=[observed]))
            elif argv in [['/usr/local/bin/restic', 'version'], ['/usr/local/bin/rclone', 'version']]:
                tool = argv[0].rsplit('/', 1)[1]
                assert state['binaries'][argv[0]] == binary(PINS[argv[0]])
                stdout = TOOLS[tool]['version_output' if tool == 'restic' else 'version_output_prefix']
                if state.get('bad_version') == tool:
                    stdout = 'wrong version'
            elif argv[:2] == ['/usr/bin/python3', '-c']:
                assert not check and len(argv) in [5, 6]
                assert argv[3] in state['archives']
                if len(argv) == 5:
                    assert argv[3].endswith('/restic.bz2') and argv[4] == argv[3].removesuffix('.bz2')
                    assert 'bz2.open' in argv[2] and "open(sys.argv[2], 'xb')" in argv[2]
                else:
                    assert argv[3].endswith('/rclone.zip') and argv[5] == argv[3].removesuffix('.zip')
                    assert argv[4] == 'rclone-v' + TOOLS['rclone']['version'] + '-linux-amd64/rclone'
                    assert 'symlink member refused' in argv[2] and "open(sys.argv[3], 'xb')" in argv[2]
                state['extracted'].append(argv[-1])
                stdout = ''
            else:
                raise AssertionError('unmodeled command refused: ' + repr(argv))
            result.update(rc=0, stdout=stdout, stdout_lines=stdout.splitlines())
        elif module == 'copy':
            assert not check and args['src'] in state['extracted']
            target = args['dest']
            assert target in PINS and target != '/usr/local/bin/sops'
            assert args == dict(src=args['src'], dest=target, remote_src=True, owner='root', group='root', mode='0755')
            assert args['src'].endswith('/' + target.rsplit('/', 1)[1])
            state['binaries'][target] = binary(PINS[target])
        elif module == 'file':
            workspace = args['path']
            assert not check and args == dict(path=workspace, state='absent') and workspace in state['workspaces']
            state['workspaces'].remove(workspace)
            state['archives'] = [p for p in state['archives'] if not p.startswith(workspace + '/')]
            state['extracted'] = [p for p in state['extracted'] if not p.startswith(workspace + '/')]
        else:
            raise AssertionError('unmodeled effect refused: ' + module)
        result['changed'] = before != json.dumps(state, sort_keys=True)
        if not check and result['changed']:
            with open(STATE, 'w') as stream:
                json.dump(state, stream)
        return result
`);
  const env = { PATH: process.env.PATH, HOME: path.join(fixture, "home"), TMPDIR: path.join(fixture, "tmp"),
    LANG: "C.UTF-8", ANSIBLE_CONFIG: path.join(fixture, "ansible.cfg"), ANSIBLE_NOCOLOR: "1", PYTHONDONTWRITEBYTECODE: "1" };
  const version = spawnSync("ansible-playbook", ["--version"], { cwd: fixture, env, encoding: "utf8" });
  write("ansible-version.txt", `${version.stdout || ""}${version.stderr || ""}`);
  assert.equal(version.status, 0, `Existing Ansible required; no install/skip: ${version.error || version.stderr}`);
  console.log(version.stdout.split("\n")[0]);
  const platform = { system: "Linux", architecture: "x86_64", distribution: "Debian",
    distribution_major_version: contract.debian.version, distribution_release: contract.debian.release };
  const variables = {
    lifecycle_profile: "inert", lifecycle_contract_host: "debian", ansible_python_interpreter: "/usr/bin/python3",
    debian: { version: contract.debian.version, release: contract.debian.release, tools: contract.debian.tools },
    backups: { restic: { tools: contract.backups.restic.tools } },
    ...Object.fromEntries([...sopsAliases, ...resticAliases].map((k) => [k, group[k]])),
  };
  const fresh = () => ({ binaries: {}, workspaces: [], archives: [], extracted: [], workspaces_created: 0,
    mounts_valid: true, identity: { exists: true, isreg: true, pw_name: "root", mode: "0600" } });
  const binary = (checksum) => ({ exists: true, isreg: true, islnk: false, nlink: 1, pw_name: "root", gr_name: "root", mode: "0755", checksum });
  const converged = () => ({ ...fresh(), binaries: Object.fromEntries(Object.entries(paths).map(([p, h]) => [p, binary(h)])) });
  const admission = (task) => {
    if (task["ansible.builtin.assert"]) return structuredClone(task);
    const t = structuredClone(task);
    delete t["ansible.builtin.import_role"];
    t.tool_witness = { module: "admission", arguments: { name: task.name } };
    return t;
  };
  function run(label, { profile = "inert", tag, state = fresh(), extra = {}, facts = platform, check = false } = {}) {
    const vars = { ...variables, lifecycle_profile: profile };
    if (profile === "production") {
      vars.compose_age_identity_path = "/fixture/recovery-identity";
      vars.backups = { restic: { tools: contract.backups.restic.tools, repositories: {
        games: { mountpoint: "/fixture/games", filesystem: "ext4", filesystem_uuid: "fixture-uuid" },
        nfs: { mountpoint: "/fixture/nfs", filesystem: "nfs4", mount_source: "fixture-server:/nfs" },
      } } };
    }
    // Source site pre/post admissions are explicit synthetic stand-ins, not proof
    // of their host invariants. Their tags/when/vars and relative placement remain.
    write("play.yml", [{ name: "Selected site tools dispatch with synthetic effects", hosts: "fixture-debian",
      gather_facts: false, become: false, vars,
      pre_tasks: [{ name: "Seed synthetic platform", tool_witness: { module: "fixture_facts", arguments: facts }, tags: ["always"] },
        ...site.pre_tasks.map(admission)],
      roles: site.roles.filter((r) => roles.includes(r.role)),
      tasks: site.tasks, post_tasks: site.post_tasks.map(admission),
    }]);
    write("extra.json", extra);
    write("state.json", state);
    write("events.jsonl", "");
    const result = spawnSync("ansible-playbook", ["-i", path.join(fixture, "inventory"), path.join(fixture, "play.yml"),
      "--extra-vars", `@${path.join(fixture, "extra.json")}`, ...(tag ? ["--tags", tag] : []), ...(check ? ["--check"] : [])],
    { cwd: fixture, env, encoding: "utf8", timeout: 30000 });
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    const log = fs.readFileSync(path.join(fixture, "events.jsonl"), "utf8").trim();
    const observed = { label, status: result.status, output, events: log ? log.split("\n").map(JSON.parse) : [],
      state: JSON.parse(fs.readFileSync(path.join(fixture, "state.json"), "utf8")) };
    const id = String(++runs).padStart(3, "0");
    write(`runs/${id}.json`, observed);
    assert(!result.error && result.status !== null, `${label}: ${result.error || result.signal}\n${output}`);
    return observed;
  }
  function passed(r, noChange = false) {
    assert.equal(r.status, 0, `${r.label}: ${r.output}`);
    if (noChange) assert.match(r.output, /changed=0\s/, `${r.label}: ${r.output}`);
    const names = r.events.map((e) => e.args.name);
    const acquire = names.indexOf(site.pre_tasks.at(-1).name), release = names.indexOf(site.post_tasks[0].name);
    assert(acquire >= 0 && release > acquire);
    for (const [i, e] of r.events.entries()) if (effects.has(e.module)) assert(i > acquire && i < release);
  }
  function refused(r, pattern) {
    assert.equal(r.status, 2, `${r.label}: ${r.output}`);
    if (pattern) assert.match(r.output, pattern);
    assert(!r.events.some((e) => e.args.name === site.post_tasks[0].name), "failed apply released lock");
  }
  const toolEvents = (r) => r.events.filter((e) => effects.has(e.module));
  const writes = (r) => toolEvents(r).filter((e) => ["get_url", "tempfile", "unarchive", "copy", "file"].includes(e.module));
  function beforeEffects(r) { refused(r); assert.deepEqual(toolEvents(r), []); }

  for (const profile of ["inert", "recovery", "production"]) {
    for (const tag of roles) {
      const first = run(`first ${profile} ${tag}`, { profile, tag });
      passed(first);
      assert.match(first.output, /changed=[1-9]/);
      assert.deepEqual(first.state.workspaces, []);
      const expected = tag === "sops_age" ? ["sops", "age", "age-keygen"] : ["restic", "rclone"];
      assert.deepEqual(Object.keys(first.state.binaries).sort(), expected.map((n) => `/usr/local/bin/${n}`).sort());
      const second = run(`second ${profile} ${tag}`, { profile, tag, state: first.state });
      passed(second, true);
      assert.deepEqual(second.state, first.state);
      assert(!second.events.some((e) => e.module === "tempfile"));
      const state = fresh();
      const checked = run(`missing check ${profile} ${tag}`, { profile, tag, state, check: true });
      passed(checked);
      assert.deepEqual(checked.state, state);
      assert(!checked.events.some((e) => ["tempfile", "copy", "unarchive", "file"].includes(e.module)));
      assert(!checked.events.some((e) => e.module === "command" && e.args.argv[0] === "/usr/local/bin/restic"));
      passed(run(`converged check ${profile} ${tag}`, { profile, tag, state: first.state, check: true }), true);
      for (const r of [first, second, checked]) {
        if (profile !== "production") {
          assert(!JSON.stringify(r.events).includes("/fixture/recovery-identity"));
          assert(!r.events.some((e) => e.module === "command" && e.args.argv[0] === "/usr/bin/findmnt"));
        } else if (tag === "restic_backup") {
          assert.equal(toolEvents(r)[0].args.argv[0], "/usr/bin/findmnt");
          assert.equal(toolEvents(r)[1].args.argv[0], "/usr/bin/findmnt");
        } else {
          assert.equal(toolEvents(r).at(-1).args.path, "/fixture/recovery-identity");
        }
      }
    }
  }
  // Every destination gets missing/checksum/metadata/type adversaries. Unsafe
  // destinations refuse before a download in both modes; drift is modeled repair.
  for (const [target, hash] of Object.entries(paths)) {
    const tag = /\/(restic|rclone)$/.test(target) ? "restic_backup" : "sops_age";
    for (const drift of [{ checksum: "0".repeat(64) }, { pw_name: "nobody" }, { gr_name: "nogroup" }, { mode: "0777" }]) {
      const state = converged(); Object.assign(state.binaries[target], drift);
      const checked = run(`drift check ${target} ${JSON.stringify(drift)}`, { tag, state, check: true });
      passed(checked); assert.deepEqual(checked.state, state); assert.match(checked.output, /changed=[1-9]/);
      const repaired = run(`repair ${target} ${JSON.stringify(drift)}`, { tag, state });
      passed(repaired); assert.deepEqual(repaired.state.binaries[target], binary(hash));
    }
    for (const unsafe of [{ isreg: false }, { islnk: true }, { nlink: 2 }]) {
      for (const check of [false, true]) {
        const state = converged(); Object.assign(state.binaries[target], unsafe);
        const r = run(`unsafe ${target} ${JSON.stringify(unsafe)} check=${check}`, { tag, state, check });
        refused(r, /Refusing to replace/); assert.deepEqual(writes(r), []); assert.deepEqual(r.state, state);
      }
    }
  }
  for (const tag of roles) {
    for (const check of [false, true]) {
      for (const [field, value] of Object.entries({ system: "Darwin", architecture: "aarch64", distribution: "Ubuntu",
        distribution_major_version: "12", distribution_release: "bookworm" }))
        beforeEffects(run(`platform ${tag} ${field}`, { tag, check, facts: { ...platform, [field]: value } }));
      for (const alias of tag === "sops_age" ? sopsAliases : resticAliases)
        beforeEffects(run(`binding ${alias}`, { tag, check, extra: { [alias]: "unapproved" } }));
      beforeEffects(run(`wrong host ${tag}`, { tag, check, extra: { lifecycle_contract_host: "proxmox" } }));
      beforeEffects(run(`missing contract ${tag}`, { tag, check, extra: { debian: {} } }));
    }
  }
  beforeEffects(run("interpreter binding", { tag: "restic_backup", extra: { ansible_python_interpreter: "/unapproved" } }));
  for (const tag of roles) {
    const extra = tag === "sops_age" ? { debian: { ...variables.debian, tools: { ...contract.debian.tools,
      sops: { ...contract.debian.tools.sops, installed_path: "/unapproved" } } } } :
      { backups: { restic: { tools: { ...contract.backups.restic.tools,
        restic: { ...contract.backups.restic.tools.restic, installed_path: "/unapproved" } } } } };
    beforeEffects(run(`fixed destination ${tag}`, { tag, extra }));
  }
  for (const check of [false, true]) {
    const mounts = run("production mount refusal", { profile: "production", tag: "restic_backup", check,
      state: { ...fresh(), mounts_valid: false } });
    refused(mounts, /exact contract repository mount/); assert.equal(toolEvents(mounts).length, 2); assert.deepEqual(writes(mounts), []);
    const architecture = run("production architecture refusal", { profile: "production", tag: "restic_backup", check,
      facts: { ...platform, architecture: "aarch64" } });
    beforeEffects(architecture);
    const identity = run("production identity refusal", { profile: "production", tag: "sops_age", check,
      state: { ...converged(), identity: { exists: false } } });
    refused(identity); assert.equal(toolEvents(identity).at(-1).args.path, "/fixture/recovery-identity");
    const unknown = run("invalid lifecycle", { tag: "sops_age", extra: { lifecycle_profile: "unknown" }, check });
    beforeEffects(unknown);
  }
  for (const task of [site.pre_tasks[1], site.pre_tasks[2], site.pre_tasks.at(-1)])
    beforeEffects(run("admission refusal", { tag: "sops_age", state: { ...fresh(), refuse_admission: task.name } }));

  // Explicit endpoint failures model archive/hash refusal and always cleanup, not
  // native decompression/checksum implementations or crash/transport interruption.
  for (const [tag, failures] of Object.entries({
    sops_age: ["Create a root-only age installation workspace", "Download the pinned age archive", "Extract the age archive", "Install age", "Install age-keygen"],
    restic_backup: ["Create a root-only Restic tool workspace", "Download the pinned Restic archive",
      "Extract the pinned Restic binary with the host Python standard library", "Download the pinned rclone archive",
      "Extract only the pinned rclone binary with the host Python standard library", "Install the pinned Restic binary", "Install the pinned rclone binary"],
  })) {
    for (const failure of failures) {
      const r = run(`failure ${failure}`, { tag, state: { ...fresh(), failure } });
      refused(r, /injected synthetic endpoint failure/);
      assert.deepEqual(r.state.workspaces, []);
      assert.equal(r.events.filter((e) => e.module === "file").length, failure.startsWith("Create") ? 0 : 1);
    }
    const cleanup = tag === "sops_age" ? "Remove the age installation workspace" : "Remove the Restic tool workspace";
    const r = run(`cleanup failure ${tag}`, { tag, state: { ...fresh(), failure: cleanup } });
    refused(r); assert.equal(r.state.workspaces.length, 1);
  }
  const sopsFailure = run("SOPS checksum/download failure", { tag: "sops_age", state: { ...fresh(), failure: "Install pinned SOPS binary" } });
  refused(sopsFailure); assert.equal(sopsFailure.state.workspaces_created, 0);
  for (const target of Object.keys(paths)) {
    const tag = /\/(restic|rclone)$/.test(target) ? "restic_backup" : "sops_age";
    const r = run(`post checksum ${target}`, { tag, state: { ...fresh(), post_corrupt: target } });
    refused(r, /Installed .* (differs|checksum)/); assert.deepEqual(r.state.workspaces, []);
  }
  for (const bad_version of ["restic", "rclone"])
    refused(run(`version ${bad_version}`, { tag: "restic_backup", state: { ...converged(), bad_version } }), /version output differs/);
  // Unselected tags cannot enter either tools path, even with malformed aliases.
  const unselected = run("unselected tools", { tag: "base", extra: { sops_download_url: "wrong", restic_download_url: "wrong" } });
  passed(unselected, true); assert.deepEqual(toolEvents(unselected), []);
  console.log(`debian_tool_provisioning_source=verified runs=${runs} real_ansible=true controller_only_effect_adapters=true native_installation=false production_restic_body=prefix_only`);
  success = true;
} finally {
  if (success) fs.rmSync(fixture, { recursive: true, force: true });
  else console.error(`Failed synthetic fixture retained at ${fixture}`);
}
