#!/usr/bin/env node
"use strict";

// Real Ansible evaluates the selected site dispatch, imports, loops, arguments and
// conditions. Controller action adapters model effects; no guest module executes.
// A separate bounded local stdlib regression uses only tiny synthetic archives.
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
const sharedRoles = ["sops_age", "restic_backup"];
const roles = [...sharedRoles, "tailscale"];
const mains = Object.fromEntries(roles.map((r) => [r, yaml(`ansible/roles/${r}/tasks/main.yml`)]));
const tools = Object.fromEntries(roles.map((r) => [r, yaml(`ansible/roles/${r}/tasks/tools.yml`)]));
// Expand only the fixed shared installer seam; both callers retain their guards.
const resticInstaller = yaml("ansible/roles/restic_backup/tasks/tools-install.yml");
function expandResticInstaller(tasks) {
  assert.equal(tasks.at(-1)["ansible.builtin.import_tasks"], "tools-install.yml");
  assert(!tasks.slice(0, -1).some((t) => t["ansible.builtin.import_tasks"]));
  return [...tasks.slice(0, -1), ...resticInstaller];
}
tools.restic_backup = expandResticInstaller(tools.restic_backup);
const nativeTools = expandResticInstaller(yaml("ansible/roles/restic_backup/tasks/tools-native.yml"));
const nativeHost = yaml("ansible/inventory/host_vars/docker-host.yml");
assert(!JSON.stringify(nativeTools).includes("backups."));
assert(!JSON.stringify(nativeTools).includes("lifecycle_contract_host"));
assert(!JSON.stringify(nativeTools).includes("lookup("));
for (const t of nativeTools.filter((t) => t["ansible.builtin.slurp"] || t.vars?.desired_tools)) assert.equal(t.no_log, true);
const tailscaleExtractor = tools.tailscale.flatMap((task) => task.block || [])
  .find((task) => task.name === "Extract only both regular Tailscale tool members")["ansible.builtin.command"].argv;
// Fail before fixture creation or Ansible dispatch if actual source startup drifts.
assert.deepEqual(tailscaleExtractor.slice(0, 5), ["{{ ansible_python_interpreter }}", "-I", "-B", "-S", "-c"],
  "Tailscale extractor requires isolated stdlib startup: -I -B -S");
const resticExtractors = Object.fromEntries([
  ["restic", "Extract the pinned Restic binary with the host Python standard library"],
  ["rclone", "Extract only the pinned rclone binary with the host Python standard library"],
].map(([name, taskName]) => [name, tools.restic_backup.flatMap((task) => task.block || [])
  .find((task) => task.name === taskName)["ansible.builtin.command"].argv]));
for (const [name, argv] of Object.entries(resticExtractors)) {
  assert.deepEqual(argv.slice(0, 5), ["{{ ansible_python_interpreter }}", "-I", "-B", "-S", "-c"],
    `${name} extractor requires isolated stdlib startup: -I -B -S`);
  assert.equal(argv.length, name === "restic" ? 8 : 9);
}
assert.deepEqual(resticExtractors.restic.slice(6), ["{{ restic_backup_workspace.path }}/restic.bz2",
  "{{ restic_backup_workspace.path }}/restic"]);
assert.deepEqual(resticExtractors.rclone.slice(6), ["{{ restic_backup_workspace.path }}/rclone.zip",
  "rclone-v{{ rclone_version }}-linux-amd64/rclone", "{{ restic_backup_workspace.path }}/rclone"]);
const sopsAliases = ["sops_version", "sops_download_url", "sops_sha256", "age_version", "age_download_url",
  "age_archive_sha256", "age_binary_sha256", "age_keygen_binary_sha256"];
const resticAliases = ["restic_version", "restic_download_url", "restic_archive_sha256", "restic_binary_sha256",
  "rclone_version", "rclone_download_url", "rclone_archive_sha256", "rclone_binary_sha256",
  "restic_version_output", "rclone_version_output"];
const tailscaleAliases = ["tailscale_client_path", "tailscale_client_sha256", "tailscale_daemon_path",
  "tailscale_daemon_sha256", "tailscale_expected_version"];
const tailscalePin = contract.tailscale.docker_host_client;
const tailscalePaths = { [tailscalePin.client_path]: tailscalePin.client_sha256, [tailscalePin.daemon_path]: tailscalePin.daemon_sha256 };
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

// The production callers and admission/lock order stay intact. Only the three
// tool imports plus storage/Docker/Compose declarations are inactive; full roles retain their production gate.
for (const role of site.roles.filter((r) => r.role !== "base")) assert.equal(role.when, "lifecycle_profile == 'production'");
assert.deepEqual(site.tasks.map((t) => t["ansible.builtin.import_role"]),
  [...roles.map((name) => ({ name, tasks_from: "tools" })),
    ...["storage", "docker", "compose"].map((name) => ({ name, tasks_from: "inactive" }))]);
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
const effects = new Set(["stat", "slurp", "get_url", "tempfile", "unarchive", "copy", "file", "command"]);
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
// Tailscale production behavior is NEVER evaluated: only the unchanged source
// dispatch is witnessed. No auth lookup, CLI, service or identity is fixture input.
const selectedMains = { sops_age: mains.sops_age, restic_backup: mains.restic_backup.slice(0, 4),
  tailscale: [{ name: "Production Tailscale dispatch witness only", "ansible.builtin.debug": { msg: "production body not executed" } }] };
const adaptedTools = Object.fromEntries(roles.map((r) => [r, adapt(tools[r])]));
const adaptedMains = Object.fromEntries(roles.map((r) => [r, adapt(selectedMains[r])]));
const adaptedNativeTools = adapt(nativeTools);
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
  // Native LOCAL stdlib only: no guest paths, official archives, ELF execution,
  // or installer dispatch. The helper and source extractor always disable site
  // startup/bytecode; each counterfactual removes only -I to expose poison.
  const localRoot = path.join(fixture, "native-local");
  for (const d of ["", "poison", "home", "tmp", "archives", "outputs"])
    fs.mkdirSync(path.join(localRoot, d), { recursive: true, mode: 0o700 });
  const poison = "TAILSCALE_FIXTURE_TARFILE_POISON_5B35A765";
  fs.writeFileSync(path.join(localRoot, "poison/tarfile.py"), `raise RuntimeError(${JSON.stringify(poison)})\n`, { mode: 0o600 });
  const localEnv = { PATH: process.env.PATH, HOME: path.join(localRoot, "home"), TMPDIR: path.join(localRoot, "tmp"),
    LANG: "C.UTF-8", PYTHONPATH: path.join(localRoot, "poison") };
  const localOptions = { cwd: path.join(localRoot, "poison"), env: localEnv, encoding: "utf8", timeout: 30000 };
  const memberPrefix = `tailscale_${tailscalePin.version}_amd64`;
  const localKinds = ["regular", ...["symlink", "hardlink", "directory", "fifo"].flatMap((kind) =>
    ["tailscale", "tailscaled"].map((name) => `${kind}-${name}`))];
  const localResult = (label, result) => {
    write(`native-local/${label}.json`, { status: result.status, stdout: result.stdout, stderr: result.stderr });
    assert(!result.error && result.status !== null, `${label}: ${result.error || result.signal}`);
  };
  const helper = spawnSync("python3", ["-I", "-B", "-S", "-c", `import io, os, sys, tarfile
root, prefix = sys.argv[1:]
kinds = ['regular'] + [kind + '-' + name for kind in ('symlink', 'hardlink', 'directory', 'fifo') for name in ('tailscale', 'tailscaled')]
for kind in kinds:
    with tarfile.open(os.path.join(root, 'archives', kind + '.tgz'), 'w:gz') as archive:
        for name, payload in (('tailscale', b'fixture-client\\n'), ('tailscaled', b'fixture-daemon\\n'), ('not-selected', b'ignored\\n')):
            member = tarfile.TarInfo(prefix + '/' + name)
            if kind.endswith('-' + name):
                member.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE, 'directory': tarfile.DIRTYPE, 'fifo': tarfile.FIFOTYPE}[kind.split('-')[0]]
                member.linkname = prefix + '/not-selected' if member.islnk() or member.issym() else ''
                archive.addfile(member)
            else:
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
`, localRoot, memberPrefix], localOptions);
  localResult("helper", helper);
  assert.equal(helper.status, 0, helper.stderr);
  assert.deepEqual(fs.readdirSync(path.join(localRoot, "archives")).sort(), localKinds.map((k) => `${k}.tgz`).sort());
  assert.equal(tailscaleExtractor.length, 9);
  assert.deepEqual(tailscaleExtractor.slice(6), ["{{ tailscale_tools_workspace.path }}/tailscale.tgz",
    "tailscale_{{ tailscale_expected_version }}_amd64", "{{ tailscale_tools_workspace.path }}"]);
  function localExtract(kind, mutant = false) {
    const label = mutant ? "without-isolation" : kind;
    const workspace = path.join(localRoot, "outputs", label);
    fs.mkdirSync(workspace, { mode: 0o700 });
    // Only interpreter and three input/output templates are substituted. The
    // program AND startup flags come from the actual parsed Ansible source argv.
    const substitutions = new Map([[tailscaleExtractor[0], "python3"],
      [tailscaleExtractor[6], path.join(localRoot, "archives", `${kind}.tgz`)],
      [tailscaleExtractor[7], memberPrefix], [tailscaleExtractor[8], workspace]]);
    const argv = tailscaleExtractor.map((value) => substitutions.get(value) ?? value);
    assert.deepEqual(argv.slice(1, 5), ["-I", "-B", "-S", "-c"]);
    if (mutant) argv.splice(1, 1); // Sole counterfactual: keep -B and -S.
    const result = spawnSync(argv[0], argv.slice(1), localOptions);
    localResult(label, result);
    if (mutant) {
      assert.equal(result.status, 1);
      assert.equal(result.stderr.trim().split("\n").at(-1), `RuntimeError: ${poison}`);
      assert.deepEqual(fs.readdirSync(workspace), []);
    } else if (kind !== "regular") {
      assert.equal(result.status, 1);
      assert.equal(result.stderr, "non-regular Tailscale member refused\n");
      assert.deepEqual(fs.readdirSync(workspace), [], "both members must be checked before extraction");
    } else {
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, "");
      assert.deepEqual(fs.readdirSync(workspace).sort(), ["tailscale", "tailscaled"]);
      for (const [name, payload] of [["tailscale", "fixture-client\n"], ["tailscaled", "fixture-daemon\n"]]) {
        const target = path.join(workspace, name), stat = fs.lstatSync(target);
        assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1);
        assert.deepEqual(fs.readFileSync(target), Buffer.from(payload));
      }
    }
  }
  for (const kind of localKinds) localExtract(kind);
  localExtract("regular", true);
  assert.deepEqual(fs.readdirSync(path.join(localRoot, "poison")), ["tarfile.py"], "bytecode must remain absent");
  console.log("tailscale_extractor_local_stdlib=verified cases=10 isolated_source_argv=true poison_counterfactual=verified native_installation=false");

  // These four local cases exercise the shared Restic extractor programs, not
  // guest installation or the modeled archive/hash refusal cases below.
  for (const [name, sourceArgv] of Object.entries(resticExtractors)) {
    const toolRoot = path.join(localRoot, name);
    for (const d of ["", "poison", "home", "tmp", "archives", "outputs"])
      fs.mkdirSync(path.join(toolRoot, d), { mode: 0o700 });
    const module = name === "restic" ? "bz2" : "zipfile";
    const marker = name === "restic" ? "RESTIC_FIXTURE_BZ2_POISON_A73184C2" : "RCLONE_FIXTURE_ZIPFILE_POISON_6E049AB1";
    fs.writeFileSync(path.join(toolRoot, "poison", `${module}.py`), `raise RuntimeError(${JSON.stringify(marker)})\n`, { mode: 0o600 });
    const options = { cwd: path.join(toolRoot, "poison"), encoding: "utf8", timeout: 30000,
      env: { PATH: process.env.PATH, HOME: path.join(toolRoot, "home"), TMPDIR: path.join(toolRoot, "tmp"),
        LANG: "C.UTF-8", PYTHONPATH: path.join(toolRoot, "poison") } };
    const archivePath = path.join(toolRoot, "archives", name === "restic" ? "restic.bz2" : "rclone.zip");
    const member = `rclone-v${pins.rclone.version}-linux-amd64/rclone`;
    const payload = Buffer.from(`fixture-${name}\n`);
    const helper = spawnSync("python3", ["-I", "-B", "-S", "-c", `import bz2, sys, zipfile
name, target, member, payload = sys.argv[1:]
if name == 'restic':
    with open(target, 'xb') as stream:
        stream.write(bz2.compress(payload.encode('ascii')))
else:
    with zipfile.ZipFile(target, 'x') as archive:
        archive.writestr(member, payload.encode('ascii'))
`, name, archivePath, member, payload.toString()], options);
    localResult(`${name}-helper`, helper);
    assert.equal(helper.status, 0, helper.stderr);
    assert.equal(helper.stdout, "");
    assert.equal(helper.stderr, "");
    assert.deepEqual(fs.readdirSync(path.join(toolRoot, "archives")), [path.basename(archivePath)]);
    // Snapshot only this newly constructed synthetic tree to detect extra output,
    // changed inputs, site/bytecode writes or effects outside the expected file.
    function snapshot(relative = "") {
      return Object.fromEntries(fs.readdirSync(path.join(toolRoot, relative)).sort().flatMap((entry) => {
        const key = relative ? `${relative}/${entry}` : entry;
        const target = path.join(toolRoot, key), stat = fs.lstatSync(target);
        assert(!stat.isSymbolicLink());
        if (stat.isDirectory()) return [[key, "directory"], ...Object.entries(snapshot(key))];
        assert(stat.isFile() && stat.nlink === 1);
        return [[key, fs.readFileSync(target).toString("hex")]];
      }));
    }
    for (const mutant of [false, true]) {
      const label = `${name}-${mutant ? "without-isolation" : "regular"}`;
      const workspace = path.join(toolRoot, "outputs", label);
      fs.mkdirSync(workspace, { mode: 0o700 });
      const target = path.join(workspace, name);
      const before = snapshot();
      // Only the installed local interpreter and fixture inputs/outputs replace
      // templates; the exact parsed source program and flags remain untouched.
      const substitutions = new Map([[sourceArgv[0], "python3"], [sourceArgv[6], archivePath],
        [sourceArgv.at(-1), target]]);
      if (name === "rclone") substitutions.set(sourceArgv[7], member);
      const argv = sourceArgv.map((value) => substitutions.get(value) ?? value);
      assert.deepEqual(argv.slice(1, 5), ["-I", "-B", "-S", "-c"]);
      if (mutant) argv.splice(1, 1); // Remove ONLY -I; retain -B/-S.
      const result = spawnSync(argv[0], argv.slice(1), options);
      localResult(label, result);
      assert.equal(result.stdout, "");
      if (mutant) {
        assert.equal(result.status, 1);
        assert.equal(result.stderr.trim().split("\n").at(-1), `RuntimeError: ${marker}`);
        assert.deepEqual(fs.readdirSync(workspace), []);
        assert.deepEqual(snapshot(), before, "poison must cause no unexpected effect or bytecode");
      } else {
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stderr, "");
        const stat = fs.lstatSync(target);
        assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1);
        assert.deepEqual(fs.readFileSync(target), payload);
        assert.deepEqual(snapshot(), { ...before, [`outputs/${label}/${name}`]: payload.toString("hex") });
      }
    }
  }
  console.log("restic_rclone_extractors_local_stdlib=verified cases=4 isolated_source_argv=true poison_counterfactuals=2 native_installation=false");

  write("inventory", "fixture-debian ansible_connection=local\n");
  write("ansible.cfg", `[defaults]\nroles_path = ${fixture}/roles\naction_plugins = ${fixture}/action_plugins\ncollections_path = ${fixture}/collections\nlocal_tmp = ${fixture}/tmp\nretry_files_enabled = False\nstdout_callback = default\n[privilege_escalation]\nbecome = False\n`);
  for (const r of roles) {
    write(`roles/${r}/tasks/main.yml`, adaptedMains[r]);
    write(`roles/${r}/tasks/tools.yml`, adaptedTools[r]);
  }
  write("roles/restic_backup/tasks/tools-native.yml", adaptedNativeTools);
  // This adapter never calls _execute_module, a connection, a subprocess, an
  // artifact URL or any tool path. Paths below describe only JSON model keys.
  write("action_plugins/tool_witness.py", `import base64, json
from ansible.plugins.action import ActionBase

PINS = ${JSON.stringify({ ...paths, ...tailscalePaths })}
TAILSCALE = json.loads(${JSON.stringify(JSON.stringify(tailscalePin))})
TOOLS = json.loads(${JSON.stringify(JSON.stringify(pins))})
STATE = ${JSON.stringify(path.join(fixture, "state.json"))}
EVENTS = ${JSON.stringify(path.join(fixture, "events.jsonl"))}

def binary(checksum):
    return dict(exists=True, isreg=True, islnk=False, nlink=1, pw_name='root', gr_name='root', mode='0755', checksum=checksum, dev=1, inode=42)

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
        task_name = self._task.get_name().split(' : ')[-1]
        failure = state.get('failure') == task_name and (not state.get('failure_dest') or args.get('dest') == state['failure_dest'])
        if failure:
            return dict(failed=True, msg='injected synthetic endpoint failure')
        if module == 'fixture_facts':
            return dict(changed=False, ansible_facts=args)
        if module == 'admission':
            assert set(args) == {'name'}
            if state.get('refuse_admission') == args['name']:
                return dict(failed=True, msg='synthetic admission refused')
            return result
        if module == 'slurp':
            assert args == dict(src='/etc/home-lab/restic-policy.json')
            policy = state.get('policy', dict(tools={name: TOOLS[name] for name in ['restic', 'rclone']}))
            result['content'] = base64.b64encode(json.dumps(policy).encode()).decode()
        elif module == 'stat':
            target = args['path']
            if target == '/fixture/recovery-identity':
                assert args == dict(path=target)
                result['stat'] = state['identity']
            elif target in ['/usr', '/usr/bin', '/usr/sbin', '/var', '/var/tmp']:
                assert args == dict(path=target, follow=False, get_checksum=False)
                result['stat'] = state.get('parents', {}).get(target, dict(exists=True, isdir=True, islnk=False,
                    pw_name='root', gr_name='root', mode='1777' if target == '/var/tmp' else '0755'))
            elif target in state['extracted'] and '/restic-tools-' in target:
                assert args == dict(path=target, checksum_algorithm='sha256', follow=False)
                name = target.rsplit('/', 1)[1]
                result['stat'] = binary(TOOLS[name]['installed_sha256'])
                if state.get('staged_target') == name:
                    result['stat'].update(state['staged_drift'])
            elif target in state['extracted'] and '/tailscale-tools-' in target:
                assert args == dict(path=target, checksum_algorithm='sha256', follow=False)
                name = target.rsplit('/', 1)[1]
                result['stat'] = binary(TAILSCALE['client_sha256' if name == 'tailscale' else 'daemon_sha256'])
                if state.get('staged_target') == name:
                    result['stat'].update(state['staged_drift'])
            else:
                assert target in PINS, 'non-tool path inspection refused'
                assert args == dict(path=target, checksum_algorithm='sha256', follow=False)
                result['stat'] = state['binaries'].get(target, dict(exists=False))
                if task_name == 'Reinspect Tailscale destinations before publication' and state.get('appeared_target') == target:
                    result['stat'] = {**binary(PINS[target]), **state.get('appeared_drift', {})}
                if state.get('post_corrupt') == target and state['workspaces_created'] and task_name != 'Reinspect Tailscale destinations before publication':
                    result['stat'] = binary('0' * 64)
        elif module == 'get_url':
            target = args['dest']
            if target == '/usr/local/bin/sops':
                assert args == dict(url=TOOLS['sops']['url'], dest=target, checksum='sha256:' + PINS[target], owner='root', group='root', mode='0755')
                state['binaries'][target] = binary(PINS[target])
            else:
                names = {'age.tar.gz': 'age', 'restic.bz2': 'restic', 'rclone.zip': 'rclone', 'tailscale.tgz': 'tailscale'}
                workspace, filename = target.rsplit('/', 1)
                assert workspace in state['workspaces'] and filename in names
                tool = {**TAILSCALE, 'url': TAILSCALE['archive_url']} if filename == 'tailscale.tgz' else TOOLS[names[filename]]
                assert args == dict(url=tool['url'], dest=target, checksum='sha256:' + tool['archive_sha256'], mode='0600')
                assert not check, 'archive download in check mode'
                state['archives'].append(target)
        elif module == 'tempfile':
            assert not check and args['state'] == 'directory' and args['path'] == '/var/tmp'
            assert args['prefix'] in ['age-install-', 'restic-tools-', 'tailscale-tools-'] and len(args) == 3
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
            elif argv[:5] == ['/usr/bin/python3', '-I', '-B', '-S', '-c'] and argv[5] == ${JSON.stringify(tailscaleExtractor[5])}:
                assert not check and len(argv) == 9
                assert argv[6] in state['archives'] and argv[6].endswith('/tailscale.tgz')
                assert argv[7] == 'tailscale_' + TAILSCALE['version'] + '_amd64'
                assert argv[8] == argv[6].removesuffix('/tailscale.tgz')
                assert argv[5] == ${JSON.stringify(tailscaleExtractor[5])}
                state['extracted'].extend([argv[8] + '/tailscale', argv[8] + '/tailscaled'])
                stdout = ''
            elif argv[:5] == ['/usr/bin/python3', '-I', '-B', '-S', '-c']:
                assert not check and len(argv) in [8, 9]
                assert argv[6] in state['archives']
                if len(argv) == 8:
                    assert argv[6].endswith('/restic.bz2') and argv[7] == argv[6].removesuffix('.bz2')
                    assert argv[5] == ${JSON.stringify(resticExtractors.restic[5])}
                else:
                    assert argv[6].endswith('/rclone.zip') and argv[8] == argv[6].removesuffix('.zip')
                    assert argv[7] == 'rclone-v' + TOOLS['rclone']['version'] + '-linux-amd64/rclone'
                    assert argv[5] == ${JSON.stringify(resticExtractors.rclone[5])}
                state['extracted'].append(argv[-1])
                stdout = ''
            else:
                raise AssertionError('unmodeled command refused: ' + repr(argv))
            result.update(rc=0, stdout=stdout, stdout_lines=stdout.splitlines())
        elif module == 'copy':
            assert not check and args['src'] in state['extracted']
            target = args['dest']
            assert target in PINS and target != '/usr/local/bin/sops'
            expected = dict(src=args['src'], dest=target, remote_src=True, owner='root', group='root', mode='0755')
            if target in [TAILSCALE['client_path'], TAILSCALE['daemon_path']]:
                expected.update(follow=False, force=False)
                assert target not in state['binaries'], 'existing Tailscale destination must never be copied'
            assert args == expected
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
    distribution_major_version: contract.debian.version, distribution_release: contract.debian.release,
    python: { version: { major: 3 } } };
  const variables = {
    lifecycle_profile: "inert", lifecycle_contract_host: "debian", ansible_python_interpreter: "/usr/bin/python3",
    debian: { version: contract.debian.version, release: contract.debian.release, tools: contract.debian.tools },
    backups: { restic: { tools: contract.backups.restic.tools } },
    tailscale: { docker_host_client: tailscalePin },
    ...Object.fromEntries([...sopsAliases, ...resticAliases, ...tailscaleAliases].map((k) => [k, group[k]])),
  };
  const fresh = () => ({ binaries: {}, workspaces: [], archives: [], extracted: [], workspaces_created: 0,
    mounts_valid: true, identity: { exists: true, isreg: true, pw_name: "root", mode: "0600" } });
  const binary = (checksum) => ({ exists: true, isreg: true, islnk: false, nlink: 1, pw_name: "root", gr_name: "root", mode: "0755", checksum, dev: 1, inode: 42 });
  const converged = () => ({ ...fresh(), binaries: Object.fromEntries(Object.entries(paths).map(([p, h]) => [p, binary(h)])) });
  const admission = (task) => {
    if (task["ansible.builtin.assert"]) return structuredClone(task);
    const t = structuredClone(task);
    delete t["ansible.builtin.import_role"];
    t.tool_witness = { module: "admission", arguments: { name: task.name } };
    return t;
  };
  function run(label, { profile = "inert", tag, state = fresh(), extra = {}, facts = platform, check = false, directTools = false, native = false } = {}) {
    // No legacy variables/admission tasks enter native tests.
    const vars = native ? { ...nativeHost, ansible_python_interpreter: "/usr/bin/python3" } : { ...variables, lifecycle_profile: profile };
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
        ...(native ? [] : site.pre_tasks.map(admission))],
      roles: native || directTools ? [] : site.roles.filter((r) => roles.includes(r.role)),
      tasks: native ? [{ "ansible.builtin.import_role": { name: "restic_backup", tasks_from: "tools-native" } }] : directTools ? [{ "ansible.builtin.import_role": { name: "tailscale", tasks_from: "tools" }, tags: ["tailscale"] }] : site.tasks.filter((t) => roles.includes(t["ansible.builtin.import_role"].name)), post_tasks: native ? [] : site.post_tasks.map(admission),
    }]);
    write("extra.json", extra);
    write("state.json", state);
    write("events.jsonl", "");
    const result = spawnSync("ansible-playbook", ["-i", path.join(fixture, "inventory"), path.join(fixture, "play.yml"),
      "--extra-vars", `@${path.join(fixture, "extra.json")}`, ...(tag ? ["--tags", tag] : []), ...(check ? ["--check"] : [])],
    { cwd: fixture, env, encoding: "utf8", timeout: 30000 });
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    const log = fs.readFileSync(path.join(fixture, "events.jsonl"), "utf8").trim();
    const observed = { label, native, status: result.status, output, events: log ? log.split("\n").map(JSON.parse) : [],
      state: JSON.parse(fs.readFileSync(path.join(fixture, "state.json"), "utf8")) };
    const id = String(++runs).padStart(3, "0");
    write(`runs/${id}.json`, observed);
    assert(!result.error && result.status !== null, `${label}: ${result.error || result.signal}\n${output}`);
    return observed;
  }
  function passed(r, noChange = false) {
    assert.equal(r.status, 0, `${r.label}: ${r.output}`);
    if (noChange) assert.match(r.output, /changed=0\s/, `${r.label}: ${r.output}`);
    if (r.native) {
      assert.equal(toolEvents(r)[0].module, "slurp");
      assert(!r.events.some((e) => e.module === "admission"));
      return;
    }
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

  // Native guard and drift behavior: real Ansible with synthetic module effects,
  // not a native module install or live preview. No contract is in native vars.
  const nativeRun = (label, options = {}) => run(`native ${label}`, { ...options, native: true });
  for (const check of [false, true]) {
    const exact = nativeRun("no drift", { state: converged(), check });
    passed(exact, true); assert.deepEqual(exact.state, converged()); assert.deepEqual(writes(exact), []);
    assert.equal(exact.events.filter((e) => e.module === "command").length, 2);
    for (const target of ["/usr/local/bin/restic", "/usr/local/bin/rclone"]) {
      for (const drift of [null, { checksum: "0".repeat(64) }, { mode: "0777" }]) {
        const state = converged();
        if (drift) Object.assign(state.binaries[target], drift); else delete state.binaries[target];
        const r = nativeRun(`drift ${target} ${JSON.stringify(drift)}`, { state, check });
        passed(r); assert.match(r.output, /changed=[1-9]/);
        if (check) {
          assert.deepEqual(r.state, state); assert.deepEqual(writes(r), []);
          assert(!r.events.some((e) => e.module === "command"), "never execute drifted tools in check mode");
        } else {
          assert.deepEqual(r.state.binaries, converged().binaries);
          assert.deepEqual(r.state.workspaces, []);
          const staged = r.events.filter((e) => e.task.endsWith("Inspect both staged Restic tool checksums before installation"));
          assert.equal(staged.length, 2);
          assert(r.events.indexOf(staged[1]) < r.events.findIndex((e) => e.module === "copy"));
        }
      }
      for (const unsafe of [{ islnk: true }, { nlink: 2 }]) {
        const state = converged(); Object.assign(state.binaries[target], unsafe);
        const r = nativeRun("unsafe destination", { state, check });
        refused(r, /Refusing to replace/); assert.deepEqual(r.state, state); assert.deepEqual(writes(r), []);
      }
    }
    for (const tool of ["restic", "rclone"]) {
      for (const field of Object.keys(pins[tool])) {
        const policy = { tools: structuredClone(contract.backups.restic.tools), unrelated: "NATIVE_POLICY_PRIVATE_MARKER" };
        policy.tools[tool][field] = "mismatch";
        const state = { ...converged(), policy };
        const r = nativeRun(`policy mismatch ${tool}.${field}`, { state, check });
        refused(r); assert.deepEqual(r.state, state);
        assert.deepEqual(toolEvents(r).map((e) => e.module), ["slurp"], "policy refuses before any binary inspection or effect");
        assert(!r.output.includes("NATIVE_POLICY_PRIVATE_MARKER"));
      }
    }
    const unrelated = nativeRun("unrelated policy ignored", { check, state: { ...converged(),
      policy: { tools: contract.backups.restic.tools, unrelated: "NATIVE_POLICY_PRIVATE_MARKER" } } });
    passed(unrelated, true); assert(!unrelated.output.includes("NATIVE_POLICY_PRIVATE_MARKER"));
    beforeEffects(nativeRun("opt-in absent", { check, extra: { restic_tools_existing_host: false } }));
    beforeEffects(nativeRun("wrong platform", { check, facts: { ...platform, architecture: "aarch64" } }));
    beforeEffects(nativeRun("wrong Python", { check, facts: { ...platform, python: { version: { major: 2 } } } }));
    const missingPolicy = nativeRun("missing policy", { check, state: { ...fresh(),
      failure: "Read the existing Restic runtime policy without exposing its contents" } });
    refused(missingPolicy); assert.deepEqual(writes(missingPolicy), []);
  }
  for (const native of [false, true]) {
    for (const staged_target of ["restic", "rclone"]) {
      for (const staged_drift of [{ checksum: "0".repeat(64) }, { isreg: false }, { islnk: true }, { nlink: 2 }]) {
        const r = run("staged Restic refusal", { native, ...(native ? {} : { tag: "restic_backup" }),
          state: { ...fresh(), staged_target, staged_drift } });
        refused(r, /no binary may be installed/);
        assert(!r.events.some((e) => e.module === "copy"));
        assert.deepEqual(r.state.binaries, {}); assert.deepEqual(r.state.workspaces, []);
      }
    }
    for (const failure of ["Download the pinned Restic archive", "Download the pinned rclone archive"]) {
      const r = run("modeled archive checksum failure", { native, ...(native ? {} : { tag: "restic_backup" }),
        state: { ...fresh(), failure } });
      refused(r); assert(!r.events.some((e) => e.module === "copy")); assert.deepEqual(r.state.workspaces, []);
    }
  }

  for (const profile of ["inert", "recovery", "production"]) {
    for (const tag of sharedRoles) {
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
  for (const tag of sharedRoles) {
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
  for (const tag of sharedRoles) {
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
  // Tailscale is missing-only, unlike the shared standalone tools. Parent layout
  // here is an explicit conservative prerequisite, NOT evidence about the image.
  const exactTailscale = () => ({ ...fresh(), binaries: Object.fromEntries(Object.entries(tailscalePaths).map(([p, h]) => [p, binary(h)])) });
  const tsRun = (label, options = {}) => run(label, { tag: "tailscale", ...options });
  const tsCopies = (r) => r.events.filter((e) => e.module === "copy");
  for (const profile of ["inert", "recovery"]) {
    const first = tsRun(`Tailscale first ${profile}`, { profile });
    passed(first);
    assert.deepEqual(first.state.binaries, exactTailscale().binaries);
    assert.deepEqual(first.state.workspaces, []);
    assert.equal(tsCopies(first).length, 2);
    const staged = first.events.filter((e) => e.task.endsWith("Inspect both staged Tailscale tool identities before publication"));
    assert.equal(staged.length, 2);
    assert(first.events.indexOf(staged[1]) < first.events.indexOf(tsCopies(first)[0]));
    const second = tsRun(`Tailscale second ${profile}`, { profile, state: first.state });
    passed(second, true); assert.deepEqual(second.state, first.state); assert.deepEqual(writes(second), []);
    for (const state of [fresh(), first.state]) {
      const checked = tsRun(`Tailscale check ${profile}`, { profile, state, check: true });
      passed(checked, !!Object.keys(state.binaries).length);
      assert.deepEqual(checked.state, state); assert.deepEqual(writes(checked), []);
      assert(!checked.events.some((e) => e.module === "command"));
    }
  }
  for (const check of [false, true]) {
    const production = tsRun("Tailscale production dispatch only", { profile: "production", check,
      extra: { tailscale_client_path: "invalid" } });
    passed(production, true); assert.deepEqual(toolEvents(production), []);
    assert.match(production.output, /production body not executed/);
    beforeEffects(tsRun("Tailscale direct production tools refused", { profile: "production", directTools: true, check }));
    beforeEffects(tsRun("Tailscale invalid lifecycle", { check, extra: { lifecycle_profile: "unknown" } }));
    for (const [field, value] of Object.entries({ system: "Darwin", architecture: "aarch64", distribution: "Ubuntu",
      distribution_major_version: "12", distribution_release: "bookworm" }))
      beforeEffects(tsRun(`Tailscale platform ${field}`, { check, facts: { ...platform, [field]: value } }));
    for (const alias of [...tailscaleAliases, "ansible_python_interpreter", "lifecycle_contract_host"])
      beforeEffects(tsRun(`Tailscale binding ${alias}`, { check, extra: { [alias]: "unapproved" } }));
    for (const [field, value] of Object.entries({ installation: "package", architecture: "linux_arm64",
      client_path: "/unapproved", daemon_path: "/unapproved" }))
      beforeEffects(tsRun(`Tailscale contract ${field}`, { check,
        extra: { tailscale: { docker_host_client: { ...tailscalePin, [field]: value } } } }));
    beforeEffects(tsRun("Tailscale missing contract", { check, extra: { tailscale: {} } }));
    for (const parent of ["/usr", "/usr/bin", "/usr/sbin", "/var", "/var/tmp"]) {
      for (const drift of [{ exists: false, isdir: false }, { isdir: false }, { islnk: true },
        { pw_name: "nobody" }, { gr_name: "nogroup" }, { mode: parent === "/var/tmp" ? "0777" : "0775" }]) {
        const state = { ...fresh(), parents: { [parent]: { exists: true, isdir: true, islnk: false,
          pw_name: "root", gr_name: "root", mode: parent === "/var/tmp" ? "1777" : "0755", ...drift } } };
        const r = tsRun(`Tailscale parent ${parent} ${JSON.stringify(drift)} check=${check}`, { check, state });
        refused(r, /topology changes require separate review/); assert.deepEqual(writes(r), []); assert.deepEqual(r.state, state);
      }
    }
    for (const target of Object.keys(tailscalePaths)) {
      for (const drift of [{ checksum: "0".repeat(64) }, { pw_name: "nobody" }, { gr_name: "nogroup" },
        { mode: "0777" }, { isreg: false }, { islnk: true }, { nlink: 2 }]) {
        const state = exactTailscale(); Object.assign(state.binaries[target], drift);
        const r = tsRun(`Tailscale refuse drift ${target} ${JSON.stringify(drift)} check=${check}`, { check, state });
        refused(r, /separately approved access-critical recovery/); assert.deepEqual(writes(r), []); assert.deepEqual(r.state, state);
      }
      const state = exactTailscale(); delete state.binaries[target];
      const r = tsRun(`Tailscale one missing ${target} check=${check}`, { state, check });
      passed(r);
      if (check) { assert.deepEqual(r.state, state); assert.deepEqual(writes(r), []); }
      else {
        assert.deepEqual(r.state.binaries, exactTailscale().binaries);
        assert.deepEqual(tsCopies(r).map((e) => e.args.dest), [target]);
      }
    }
  }
  for (const task of [site.pre_tasks[1], site.pre_tasks[2], site.pre_tasks.at(-1)])
    beforeEffects(tsRun("Tailscale admission refusal", { state: { ...fresh(), refuse_admission: task.name } }));
  for (const staged_target of ["tailscale", "tailscaled"]) {
    for (const staged_drift of [{ checksum: "0".repeat(64) }, { isreg: false }, { islnk: true },
      { nlink: 2 }, { pw_name: "nobody" }, { gr_name: "nogroup" }]) {
      const r = tsRun(`Tailscale staged refusal ${staged_target} ${JSON.stringify(staged_drift)}`, {
        state: { ...fresh(), staged_target, staged_drift } });
      refused(r, /no binary may be published/); assert.deepEqual(tsCopies(r), []);
      assert.deepEqual(r.state.binaries, {}); assert.deepEqual(r.state.workspaces, []);
    }
  }
  // Model only an appearance/replacement BEFORE the recheck, not a privileged
  // pathname race. force:false and ancestry stats are not descriptor guarantees.
  for (const appeared_target of Object.keys(tailscalePaths)) {
    for (const replacement of [false, true]) {
      const state = replacement ? exactTailscale() : fresh();
      if (replacement) delete state.binaries[Object.keys(tailscalePaths).find((p) => p !== appeared_target)];
      Object.assign(state, { appeared_target, appeared_drift: replacement ? { inode: 43 } : {} });
      const r = tsRun(`Tailscale destination changed ${appeared_target} replacement=${replacement}`, { state });
      refused(r, /destination changed during staging/); assert.deepEqual(tsCopies(r), []); assert.deepEqual(r.state.workspaces, []);
    }
  }
  for (const failure of ["Create a root-only Tailscale tool workspace", "Download the exact contracted Tailscale archive",
    "Extract only both regular Tailscale tool members", "Inspect both staged Tailscale tool identities before publication",
    "Reinspect Tailscale destinations before publication"]) {
    const r = tsRun(`Tailscale failure ${failure}`, { state: { ...fresh(), failure } });
    refused(r, /injected synthetic endpoint failure/); assert.deepEqual(tsCopies(r), []);
    assert.deepEqual(r.state.workspaces, []); assert.deepEqual(r.state.binaries, {});
  }
  // A loop can continue after a failed copy. Either member can be left installed;
  // there is no pair transaction, automatic retry, rollback or crash cleanup.
  for (const failure_dest of Object.keys(tailscalePaths)) {
    const r = tsRun(`Tailscale partial publication ${failure_dest}`, {
      state: { ...fresh(), failure: "Publish only missing Tailscale tools", failure_dest } });
    refused(r); assert.deepEqual(r.state.workspaces, []);
    assert.deepEqual(Object.keys(r.state.binaries), Object.keys(tailscalePaths).filter((p) => p !== failure_dest));
  }
  const cleanup = tsRun("Tailscale cleanup failure", { state: { ...fresh(), failure: "Remove the Tailscale tool workspace" } });
  refused(cleanup); assert.equal(cleanup.state.workspaces.length, 1);
  assert.deepEqual(cleanup.state.binaries, exactTailscale().binaries);
  for (const post_corrupt of Object.keys(tailscalePaths)) {
    const r = tsRun(`Tailscale final identity refusal ${post_corrupt}`, { state: { ...fresh(), post_corrupt } });
    refused(r, /Installed Tailscale tool identity differs/); assert.deepEqual(r.state.workspaces, []);
  }
  // Unselected tags cannot enter any tools path, even with malformed aliases.
  const unselected = run("unselected tools", { tag: "base", extra: { sops_download_url: "wrong", restic_download_url: "wrong", tailscale_client_path: "wrong" } });
  passed(unselected, true); assert.deepEqual(toolEvents(unselected), []);
  console.log(`debian_tool_provisioning_source=verified runs=${runs} real_ansible=true controller_only_effect_adapters=true native_installation=false production_restic_body=prefix_only production_tailscale_body=not_executed process_boot_closure=not_proven`);
  success = true;
} finally {
  if (success) fs.rmSync(fixture, { recursive: true, force: true });
  else console.error(`Failed synthetic fixture retained at ${fixture}`);
}
