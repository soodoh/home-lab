#!/usr/bin/env node
"use strict";

// Actual Ansible imports/tags/conditions/Jinja; every guest effect is replaced
// before dispatch. Only controller JSON metadata/events change. Never run guard.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { load } = require("js-yaml");
const Ajv = require("ajv/dist/2020");
const phase = process.argv[2] || "full";
assert(process.argv.length <= 3 && ["full", "red-guard", "red-vendor", "permutations"].includes(phase), "unknown fixture phase refused");
const root = path.resolve(__dirname, "../..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const yaml = (p) => load(read(p));
const hash = (s) => crypto.createHash("sha256").update(s).digest("hex");
const contract = yaml("infrastructure/contract/home-lab.yml");
const schema = JSON.parse(read("infrastructure/contract/schema.json"));
const site = yaml("ansible/playbooks/site.yml")[0];
const group = yaml("ansible/group_vars/docker_host.yml");
const guardTasks = yaml("ansible/roles/debian_lifecycle_guard/tasks/main.yml");
const prefix = "ansible/roles/debian_lifecycle_transaction/tasks/";
const admission = yaml(prefix + "inactive-unit-admission.yml");
const publication = yaml(prefix + "inactive-units.yml");
const wrappers = Object.fromEntries(["docker", "compose"].map((r) => [r, yaml(`ansible/roles/${r}/tasks/inactive.yml`)]));
const assets = contract.debian.systemd.assets;
const paths = Object.values(assets).map((a) => a.path);
const units = ["home-lab-production-guard.service", "home-lab-compose.service", "docker.service", "docker.socket"];
const vendorPaths = Object.values(contract.debian.systemd.vendor_units);
const gates = [contract.debian.transaction.storage_activation_path, "/var/lib/home-lab/debian-production-activation.json", "/run/home-lab-production-transaction"];
const roots = ["/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
  "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached", "/run/systemd/system",
  "/run/systemd/system.attached", "/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late"];
const parents = ["/", "/etc", "/etc/systemd", "/etc/home-lab", "/run", "/run/systemd", "/var", "/var/lib", "/var/lib/home-lab",
  "/usr", "/usr/local", "/usr/local/sbin", "/usr/local/lib", "/usr/local/lib/systemd", "/usr/lib", "/usr/lib/systemd"];
const dropdir = "/etc/systemd/system/docker.service.d";
const helper = read("ansible/roles/" + assets.guard_helper.source);
assert.equal(Buffer.byteLength(helper), 234);
assert.equal(hash(helper), "ebaef168ef89defe8806237272d77a5c0dee4f62749896cc7a1955d2f6201be6");
assert.equal(hash(helper), contract.debian.systemd.guard.sha256);
assert.equal(fs.statSync(path.join(root, "ansible/roles/" + assets.guard_helper.source)).mode & 0o777, 0o755);
const validate = new Ajv({ strict: true, allErrors: true }).compile(schema);
assert(validate(contract), JSON.stringify(validate.errors));
assert(schema.properties.debian.required.includes("systemd"));
for (const replacement of [undefined, null, {}, { ...contract.debian.systemd, extra: true }]) {
  const candidate = structuredClone(contract);
  if (replacement === undefined) delete candidate.debian.systemd;
  else candidate.debian.systemd = replacement;
  assert(!validate(candidate), "closed systemd schema accepted drift");
}
for (const [key, value] of Object.entries(assets)) {
  for (const field of Object.keys(value)) {
    const candidate = structuredClone(contract);
    candidate.debian.systemd.assets[key][field] += "\nExecStart=/unapproved";
    assert(!validate(candidate));
  }
  const candidate = structuredClone(contract);
  candidate.debian.systemd.assets[key].extra = true;
  assert(!validate(candidate));
}
for (const [section, field, replacement] of [["guard", "sha256", "0".repeat(64)], ["guard", "before", []],
  ["compose", "home", "%h"], ["compose", "start", ["up", "--pull", "always"]], ["compose", "timeout_stop", 0]]) {
  const candidate = structuredClone(contract);
  candidate.debian.systemd[section][field] = replacement;
  assert(!validate(candidate));
}
const dispatches = ["docker", "compose"].map((r) => site.tasks.find((t) => t["ansible.builtin.import_role"].name === r));
for (const [i, r] of ["docker", "compose"].entries()) {
  assert.deepEqual(dispatches[i]["ansible.builtin.import_role"], { name: r, tasks_from: "inactive" });
  assert.equal(dispatches[i].when, "lifecycle_profile in ['inert', 'recovery']");
  assert.deepEqual(dispatches[i].tags, [r]);
  assert.deepEqual(wrappers[r][0]["ansible.builtin.assert"].that, [`(ansible_run_tags | list) == ['${r}']`]);
}
for (const r of site.roles.filter((r) => r.role !== "base")) assert.equal(r.when, "lifecycle_profile == 'production'");
assert.deepEqual(site.pre_tasks.slice(1).map((t) => t["ansible.builtin.import_role"].name),
  ["debian_lifecycle_guard", "apply_guard", "lifecycle_state", "apply_lock"]);
for (const unit of units) assert(group.debian_lifecycle_inactive_units.includes(unit));
const identityStat = guardTasks.find((t) => t.name === "Inspect secret identity and Tailscale state boundaries");
assert.deepEqual(identityStat["ansible.builtin.stat"], { path: "{{ item }}", follow: false, get_checksum: false, get_mime: false, get_attributes: false });
const guardAudit = guardTasks.filter((t) => ["Inspect services forbidden from running before production activation",
  "Require protected services and timers to remain absent or disabled and inactive"].includes(t.name));
assert.equal(guardAudit.length, 2);
const show = ["/usr/bin/systemctl", "show", "--property=LoadState", "--property=ActiveState", "--property=SubState",
  "--property=UnitFileState", "--property=FragmentPath", "--property=DropInPaths", "--property=Names", "--property=Job", "{{ item }}"];
const auditShow = ["/usr/bin/systemctl", "show", "--property=LoadState", "--property=ActiveState", "--property=UnitFileState", "{{ item }}"];
const pure = new Set(["assert", "set_fact"]);
const effects = new Set(["stat", "find", "command", "copy", "file"]);
function adapt(tasks) {
  return tasks.map((source) => {
    const t = structuredClone(source);
    assert(!t.block && !t.rescue && !t.always && !t.notify && !t.delegate_to, "unreviewed task structure");
    const keys = Object.keys(t).filter((k) => k.startsWith("ansible."));
    assert.equal(keys.length, 1);
    const module = keys[0].replace("ansible.builtin.", "");
    const a = t[keys[0]];
    if (module === "import_tasks") assert.equal(a, "inactive-unit-admission.yml", "unknown task import refused before dispatch");
    else if (module === "import_role") assert.deepEqual(a, { name: "debian_lifecycle_transaction", tasks_from: "inactive-units" }, "unknown role import refused before dispatch");
    else assert(pure.has(module) || effects.has(module), `unknown module refused before dispatch: ${module}`);
    if (module === "stat") {
      assert.equal(a.follow, false); assert.equal(a.get_mime, false); assert.equal(a.get_attributes, false);
      assert.deepEqual(Object.keys(a).sort(), ["path", "follow", "get_mime", "get_attributes",
        a.checksum_algorithm ? "checksum_algorithm" : "get_checksum"].sort());
      if (a.checksum_algorithm) assert.equal(a.checksum_algorithm, "sha256");
      else assert.equal(a.get_checksum, false);
    }
    if (module === "command") {
      assert.deepEqual(Object.keys(a), ["argv"]);
      assert([show, auditShow, ["/usr/bin/systemctl", "show", "--property=UnitPath"]]
        .some((v) => JSON.stringify(v) === JSON.stringify(a.argv)), "unknown command refused before dispatch");
      assert.equal(t.changed_when, false); assert.equal(t.check_mode, false);
    }
    if (module === "find") assert.deepEqual(a, { paths: a.paths, recurse: false, file_type: "any", hidden: true, follow: false });
    if (module === "file") assert.deepEqual(a, { path: dropdir, state: "directory", owner: "root", group: "root", mode: "0755" });
    if (module === "copy") assert.deepEqual(a, {
      content: "{{ lookup('ansible.builtin.file' if item.key == 'guard_helper' else 'ansible.builtin.template', role_path ~ '/../' ~ item.value.source, rstrip=False) }}",
      dest: "{{ item.value.path }}", owner: "root", group: "root", mode: "{{ item.value.mode }}", force: false, follow: false,
    });
    if (effects.has(module)) { t.unit_witness = { module, arguments: a }; delete t[keys[0]]; }
    return t;
  });
}
const adaptedAdmission = adapt(admission), adaptedPublication = adapt(publication);
for (const tasks of Object.values(wrappers)) adapt(tasks);
adapt(guardAudit);
for (const module of ["shell", "template", "systemd_service", "include_role", "uri", "package_facts"])
  assert.throws(() => adapt([{ [`ansible.builtin.${module}`]: {} }]), assert.AssertionError);
for (const task of [{ "ansible.builtin.command": { argv: ["/usr/bin/systemctl", "daemon-reload"] } },
  { "ansible.builtin.command": { argv: [assets.guard_helper.path] } },
  { "ansible.builtin.import_tasks": "main.yml" }, { "ansible.builtin.import_role": { name: "docker" } }])
  assert.throws(() => adapt([task]), assert.AssertionError);
const mimeMutant = structuredClone(identityStat); delete mimeMutant["ansible.builtin.stat"].get_mime;
assert.throws(() => adapt([mimeMutant]), assert.AssertionError, "MIME-only mutant must fail before dispatch");

// Independent synthetic golden declarations, not a copy of production files or
// cat framing. Canonical dependency order is intentional; compare semantics below.
const golden = {
  [paths[0]]: helper,
  [paths[1]]: `[Unit]\nDescription=Fail-closed guard for Home Lab production activation\nAfter=local-fs.target\nBefore=docker.service tailscaled.service home-lab-compose.service\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/home-lab-production-guard\nRemainAfterExit=yes\n`,
  [paths[2]]: String.raw`[Unit]
Description=Home lab production Compose stack
Requires=docker.service home-lab-production-guard.service mnt-games.mount mnt-storage.mount srv-home\x2dlab\x2dstate.mount
After=docker.service home-lab-production-guard.service mnt-games.mount mnt-storage.mount srv-home\x2dlab\x2dstate.mount network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=HOME=/root
WorkingDirectory=/srv/docker-compose/current
ExecStart=/usr/bin/docker compose --project-name docker-compose --project-directory /srv/docker-compose/current --env-file /etc/docker-compose/production.env --file /srv/docker-compose/current/docker-compose.yml --file /var/lib/home-lab/production-image-override.json up --detach --pull never --remove-orphans
ExecStop=/usr/bin/docker compose --project-name docker-compose --project-directory /srv/docker-compose/current --env-file /etc/docker-compose/production.env --file /srv/docker-compose/current/docker-compose.yml --file /var/lib/home-lab/production-image-override.json stop --timeout 120
TimeoutStartSec=1200
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
`,
  [paths[3]]: String.raw`[Unit]
Requires=home-lab-production-guard.service mnt-games.mount mnt-storage.mount srv-home\x2dlab\x2dstate.mount
After=home-lab-production-guard.service mnt-games.mount mnt-storage.mount srv-home\x2dlab\x2dstate.mount network-online.target
Wants=network-online.target
`,
};
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "unit-provisioning-"));
let success = false, runs = 0;
const write = (p, value) => fs.writeFileSync(path.join(fixture, p), typeof value === "string" ? value : JSON.stringify(value));
try {
  for (const p of ["home", "tmp", "collections", "action_plugins", "runs", "ansible/playbooks", "infrastructure/contract",
    "ansible/roles/docker/tasks", "ansible/roles/docker/templates", "ansible/roles/compose/tasks", "ansible/roles/compose/templates",
    "ansible/roles/debian_lifecycle_transaction/tasks", "ansible/roles/debian_lifecycle_transaction/files", "ansible/roles/debian_lifecycle_transaction/templates"])
    fs.mkdirSync(path.join(fixture, p), { recursive: true });
  write("inventory", "fixture-debian ansible_connection=local\n");
  write("ansible.cfg", `[defaults]\nroles_path = ${fixture}/ansible/roles\naction_plugins = ${fixture}/action_plugins\ncollections_path = ${fixture}/collections\nlocal_tmp = ${fixture}/tmp\nretry_files_enabled = False\nstdout_callback = default\n[privilege_escalation]\nbecome = False\n`);
  write("infrastructure/contract/schema.json", schema);
  write(prefix + "inactive-unit-admission.yml", adaptedAdmission);
  write(prefix + "inactive-units.yml", adaptedPublication);
  for (const [r, tasks] of Object.entries(wrappers)) {
    write(`ansible/roles/${r}/tasks/inactive.yml`, adapt(tasks));
    write(`ansible/roles/${r}/tasks/main.yml`, [{ name: "Production dispatch witness; body never executed", "ansible.builtin.debug": { msg: `production ${r} body excluded from fixture` } }]);
  }
  for (const asset of Object.values(assets)) write("ansible/roles/" + asset.source, read("ansible/roles/" + asset.source));
  write("action_plugins/unit_witness.py", `import hashlib, json
from ansible.plugins.action import ActionBase
STATE = ${JSON.stringify(path.join(fixture, "state.json"))}
EVENTS = ${JSON.stringify(path.join(fixture, "events.jsonl"))}
ROOTS = ${JSON.stringify(roots)}
PARENTS = ${JSON.stringify(parents)}
PATHS = ${JSON.stringify(paths)}
UNITS = ${JSON.stringify(units)}
VENDORS = ${JSON.stringify(vendorPaths)}
GATES = ${JSON.stringify(gates)}
DROP = ${JSON.stringify(dropdir)}
AUDIT_UNITS = ${JSON.stringify(group.debian_lifecycle_inactive_units)}
SHOW = ${JSON.stringify(show.slice(0, -1))}
AUDIT_SHOW = ${JSON.stringify(auditShow.slice(0, -1))}
def directory():
    return dict(exists=True, isdir=True, islnk=False, uid=0, gid=0, mode='0755')
def regular(content=None, mode='0644'):
    data = dict(exists=True, isreg=True, islnk=False, uid=0, gid=0, nlink=1, mode=mode)
    if content is not None:
        data.update(size=len(content.encode()), checksum=hashlib.sha256(content.encode()).hexdigest())
    return data
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
        vendors = state.get('vendors', [])
        assert vendors is True or vendors is False or (isinstance(vendors, list) and len(vendors) == len(set(vendors)) and all(p in VENDORS for p in vendors)), 'unmodeled vendor presence refused'
        present_vendors = VENDORS if vendors is True else [] if vendors is False else vendors
        if module == 'facts':
            return dict(changed=False, ansible_facts=args)
        if module == 'admission':
            if state.get('refuse_admission') == args['name']:
                return dict(failed=True, msg='synthetic guard or lock refusal')
        elif module == 'stat':
            target = args['path']
            assert args['follow'] is False and args['get_mime'] is False and args['get_attributes'] is False
            assert set(args) == {'path', 'follow', 'get_mime', 'get_attributes', 'checksum_algorithm' if target in PATHS else 'get_checksum'}
            if target in PATHS:
                assert args['checksum_algorithm'] == 'sha256'
                result['stat'] = regular(state['files'][target], '0755' if target == PATHS[0] else '0644') if target in state['files'] else dict(exists=False)
                result['stat'].update(state.get('asset_drift', {}).get(target, {}))
            else:
                assert args['get_checksum'] is False
                if target in ROOTS + PARENTS:
                    result['stat'] = state.get('ancestry', {}).get(target, directory())
                elif target in VENDORS:
                    result['stat'] = regular() if target in present_vendors else dict(exists=False)
                    result['stat'].update(state.get('vendor_drift', {}).get(target, {}))
                elif target in GATES:
                    result['stat'] = dict(exists=target in state.get('gates', []))
                elif target == DROP:
                    result['stat'] = state.get('drop_metadata', directory() if state.get('dropdir') else dict(exists=False))
                elif target == '/lib':
                    result['stat'] = state.get('lib_alias', dict(exists=True, islnk=True, uid=0, gid=0, lnk_target='usr/lib'))
                else:
                    assert target in state.get('aliases', {}), 'unmodeled stat path refused'
                    result['stat'] = state['aliases'][target]
        elif module == 'find':
            target = args['paths']
            assert args == dict(paths=target, recurse=False, file_type='any', hidden=True, follow=False)
            assert target in ROOTS or target == DROP or (target.rsplit('/', 1)[0] in ROOTS and target.endswith(('.wants', '.requires', '.upholds')))
            entries = []
            for name in list(state['files']) + present_vendors:
                if name.rsplit('/', 1)[0] == target:
                    entries.append(dict(path=name, isreg=True, islnk=False))
            if target == '/etc/systemd/system' and state.get('dropdir'):
                entries.append(dict(path=DROP, **directory()))
            entries += state.get('entries', {}).get(target, [])
            result.update(files=entries, skipped_paths=state.get('skipped', {}).get(target, {}))
        elif module == 'command':
            argv = args['argv']
            assert set(args) == {'argv'} and not check
            if argv == ['/usr/bin/systemctl', 'show', '--property=UnitPath']:
                stdout = state.get('unit_path', 'UnitPath=' + ' '.join(ROOTS))
            else:
                audit = argv[:-1] == AUDIT_SHOW
                assert argv[:-1] == SHOW or audit, 'unmodeled command refused'
                unit = argv[-1]
                assert unit in (AUDIT_UNITS if audit else UNITS)
                values = dict(LoadState='not-found', ActiveState='inactive', SubState='dead', UnitFileState='', FragmentPath='', DropInPaths='', Names=unit, Job='')
                if unit in UNITS[2:] and VENDORS[UNITS.index(unit) - 2] in present_vendors:
                    values.update(LoadState='loaded', UnitFileState='disabled', FragmentPath=VENDORS[UNITS.index(unit) - 2])
                if unit in UNITS[:2] and state.get('loaded') and PATHS[UNITS.index(unit) + 1] in state['files']:
                    values.update(LoadState='loaded', UnitFileState='static' if unit == UNITS[0] else 'disabled', FragmentPath=PATHS[UNITS.index(unit) + 1])
                if unit == 'docker.service' and state.get('loaded_dropin'):
                    values['DropInPaths'] = PATHS[3]
                values.update(state.get('unit_drift', {}).get(unit, {}))
                if audit:
                    values = {k: values[k] for k in ['LoadState', 'ActiveState', 'UnitFileState']}
                stdout = '\\n'.join(k + '=' + v for k, v in values.items())
            result.update(rc=state.get('command_rc', 0), stdout=stdout, stdout_lines=stdout.splitlines())
        elif module == 'file':
            assert args == dict(path=DROP, state='directory', owner='root', group='root', mode='0755')
            assert not state.get('dropdir'), 'existing directory must never be repaired'
            result['changed'] = True
            if not check:
                state['dropdir'] = True
        elif module == 'copy':
            target = args['dest']
            assert target in PATHS
            assert args == dict(content=args['content'], dest=target, owner='root', group='root', mode='0755' if target == PATHS[0] else '0644', force=False, follow=False)
            assert target not in state['files'], 'existing destination must never be copied'
            assert target != PATHS[3] or state.get('dropdir') or check
            if state.get('fail_copy') == target:
                return dict(failed=True, msg='modeled copy interruption; no native interruption')
            result['changed'] = True
            if not check:
                state['files'][target] = args['content']
        else:
            raise AssertionError('unknown effect adapter refused')
        if module in ['copy', 'file'] and not check:
            with open(STATE, 'w') as stream:
                json.dump(state, stream)
        return result
`);
  const env = { PATH: process.env.PATH, HOME: path.join(fixture, "home"), TMPDIR: path.join(fixture, "tmp"), LANG: "C.UTF-8",
    ANSIBLE_CONFIG: path.join(fixture, "ansible.cfg"), ANSIBLE_NOCOLOR: "1", PYTHONDONTWRITEBYTECODE: "1" };
  const version = spawnSync("ansible-playbook", ["--version"], { cwd: fixture, env, encoding: "utf8", timeout: 30000 });
  write("ansible-version.txt", `${version.stdout || ""}${version.stderr || ""}`);
  assert.equal(version.status, 0, `Existing Ansible required, no repair/install/skip: ${version.error || version.stderr}`);
  console.log(version.stdout.split("\n")[0]);
  const platform = { system: "Linux", architecture: "x86_64", distribution: "Debian", distribution_major_version: contract.debian.version, distribution_release: contract.debian.release };
  const fresh = () => ({ files: {}, dropdir: false });
  const complete = () => ({ files: structuredClone(golden), dropdir: true });
  function admissionWitness(source) {
    const t = structuredClone(source);
    if (t["ansible.builtin.assert"]) return t;
    assert(["debian_lifecycle_guard", "apply_guard", "lifecycle_state", "apply_lock"].includes(t["ansible.builtin.import_role"].name));
    delete t["ansible.builtin.import_role"];
    t.unit_witness = { module: "admission", arguments: { name: t.name } };
    return t;
  }
  function run(label, { state = fresh(), tag = "compose", profile = "inert", check = false, extra = {}, direct = false, audit = false } = {}) {
    const play = { name: "Actual declaration source with controller-only effects", hosts: "fixture-debian", gather_facts: false, become: false,
      vars: { lifecycle_profile: profile, lifecycle_contract_host: "debian", debian: contract.debian,
        debian_lifecycle_inactive_units: group.debian_lifecycle_inactive_units },
      pre_tasks: [{ name: "Seed synthetic platform", unit_witness: { module: "facts", arguments: platform }, tags: ["always"] }, ...site.pre_tasks.map(admissionWitness)],
      roles: audit || direct ? [] : site.roles.filter((r) => ["docker", "compose"].includes(r.role)),
      tasks: audit ? adapt(guardAudit).map((t) => ({ ...t, tags: ["always"] })) : direct ? [{ "ansible.builtin.import_role": { name: "debian_lifecycle_transaction", tasks_from: "inactive-units" }, tags: ["always"] }] : dispatches,
      post_tasks: site.post_tasks.map(admissionWitness) };
    write("ansible/playbooks/play.yml", [play]); write("extra.json", extra); write("state.json", state); write("events.jsonl", "");
    const result = spawnSync("ansible-playbook", ["-i", path.join(fixture, "inventory"), path.join(fixture, "ansible/playbooks/play.yml"),
      "--extra-vars", `@${path.join(fixture, "extra.json")}`, "--tags", tag, ...(check ? ["--check"] : [])],
    { cwd: fixture, env, encoding: "utf8", timeout: 60000 });
    const log = fs.readFileSync(path.join(fixture, "events.jsonl"), "utf8").trim();
    const observed = { label, status: result.status, output: `${result.stdout || ""}${result.stderr || ""}`,
      events: log ? log.split("\n").map(JSON.parse) : [], state: JSON.parse(fs.readFileSync(path.join(fixture, "state.json"), "utf8")) };
    write(`runs/${String(++runs).padStart(3, "0")}.json`, observed);
    assert(!result.error && result.status !== null, `${label}: ${result.error || result.signal}\n${observed.output}`);
    return observed;
  }
  const writes = (r) => r.events.filter((e) => ["file", "copy"].includes(e.module));
  function passed(r, zero = false) {
    assert.equal(r.status, 0, `${r.label}: ${r.output}`);
    if (zero) assert.match(r.output, /changed=0\s/);
    const names = r.events.map((e) => e.args.name), acquire = names.indexOf(site.pre_tasks.at(-1).name), release = names.indexOf(site.post_tasks[0].name);
    assert(acquire >= 0 && release > acquire);
    for (const [i, e] of r.events.entries()) if (effects.has(e.module)) assert(i > acquire && i < release);
  }
  function refused(r, pattern, state) {
    assert.equal(r.status, 2, `${r.label}: ${r.output}`); assert.match(r.output, pattern);
    assert.deepEqual(writes(r), [], "admission refusal must precede directory and file writes");
    if (state) assert.deepEqual(r.state, state);
    assert(!r.events.some((e) => e.args.name === site.post_tasks[0].name), "failed apply released modeled lock");
  }
  const permuted = (assetOrder, vendorOrder) => {
    const d = structuredClone(contract.debian);
    if (assetOrder) d.systemd.assets = Object.fromEntries(Object.entries(d.systemd.assets).reverse());
    if (vendorOrder) d.systemd.vendor_units = Object.fromEntries(Object.entries(d.systemd.vendor_units).reverse());
    return d;
  };
  function staleGuard() {
    const debian = structuredClone(contract.debian);
    debian.systemd.assets = Object.fromEntries(["guard_helper", "compose_unit", "guard_unit", "docker_dependencies"].map((k) => [k, debian.systemd.assets[k]]));
    const state = complete(); delete state.files[paths[1]]; delete state.files[paths[3]];
    state.unit_drift = { [units[0]]: { LoadState: "loaded", UnitFileState: "static", FragmentPath: paths[1] } };
    const r = run("permuted stale guard fragment", { tag: "docker", state, extra: { debian } });
    console.log(`permutation_guard_case_status=${r.status} writes=${writes(r).length} root=${fixture}`);
    refused(r, /Unit is active cached/, state);
    assert.match(r.output, /failed: \[fixture-debian\].*home-lab-production-guard.service/);
  }
  function staleVendor() {
    const debian = permuted(false, true);
    const state = { ...complete(), vendors: [vendorPaths[1]], unit_drift: {
      [units[2]]: { LoadState: "loaded", UnitFileState: "disabled", FragmentPath: vendorPaths[0] },
      // Counterpart observation is swapped too: positional admission otherwise
      // refuses socket first and masks the missing Docker-fragment association.
      [units[3]]: { LoadState: "not-found", UnitFileState: "", FragmentPath: "" },
    } };
    delete state.files[paths[3]];
    const r = run("permuted stale vendor fragment", { tag: "docker", state, extra: { debian } });
    console.log(`permutation_vendor_case_status=${r.status} writes=${writes(r).length} root=${fixture}`);
    refused(r, /Unit is active cached/, state);
    assert.match(r.output, /failed: \[fixture-debian\].*docker.service/);
  }
  if (phase === "red-guard") { staleGuard(); throw new Error("RED no longer reproduces; run permutations GREEN instead"); }
  if (phase === "red-vendor") { staleVendor(); throw new Error("RED no longer reproduces; run permutations GREEN instead"); }
  if (phase === "permutations" || phase === "full") {
    staleGuard(); staleVendor();
    for (const [assetOrder, vendorOrder] of [[true, false], [false, true], [true, true]]) {
      const debian = permuted(assetOrder, vendorOrder);
      for (const tag of ["docker", "compose"]) for (const check of [false, true]) {
        const state = complete();
        // Partial asset and vendor presence make an index mix-up observable.
        delete state.files[paths[1]]; delete state.files[paths[3]];
        state.vendors = [vendorPaths[1]];
        const r = run(`permuted partial ${assetOrder}/${vendorOrder} ${tag} check=${check}`, { tag, check, state, extra: { debian } });
        passed(r);
        assert.deepEqual(writes(r).map((e) => e.args.dest), [tag === "docker" ? paths[3] : paths[1]]);
        if (check) assert.deepEqual(r.state, state);
        const loaded = { ...complete(), vendors: [vendorPaths[0]], loaded: true, loaded_dropin: true };
        passed(run(`permuted loaded ${assetOrder}/${vendorOrder} ${tag} check=${check}`, { tag, check, state: loaded, extra: { debian } }), true);
      }
    }
    console.log(`keyed_observation_permutations=verified runs=${runs} phase=${phase}`);
  }
  if (phase === "full") {
  for (const tag of ["compose", "docker"]) {
    for (const profile of ["inert", "recovery"]) {
      const first = run(`first ${tag} ${profile}`, { tag, profile }); passed(first);
      const selected = Object.entries(assets).filter(([, a]) => a.tag === tag).map(([, a]) => a.path);
      assert.deepEqual(Object.keys(first.state.files).sort(), selected.sort());
      for (const p of selected) assert.equal(first.state.files[p], golden[p], "real template bytes differ from independent golden");
      assert.equal(first.state.dropdir, tag === "docker");
      const second = run(`second ${tag} ${profile}`, { tag, profile, state: first.state }); passed(second, true);
      assert.deepEqual(writes(second), []);
      const checked = run(`check missing ${tag} ${profile}`, { tag, profile, check: true }); passed(checked);
      assert.deepEqual(checked.state, fresh()); assert(writes(checked).every((e) => e.check));
      passed(run(`check exact ${tag} ${profile}`, { tag, profile, state: first.state, check: true }), true);
      const effectsBeforeWrite = first.events.slice(0, first.events.findIndex((e) => e.module === "copy" || e.module === "file"));
      assert.deepEqual(effectsBeforeWrite.filter((e) => e.module === "stat" && gates.includes(e.args.path)).map((e) => e.args.path), gates);
      assert.equal(effectsBeforeWrite.filter((e) => e.module === "command" && e.args.argv.length === show.length).length, 4);
    }
    const adopted = { ...complete(), vendors: true, loaded: true, loaded_dropin: true };
    passed(run(`loaded exact ${tag}`, { tag, state: adopted }), true);
    passed(run(`vendor-only ${tag}`, { tag, state: { ...fresh(), vendors: true } }));
    for (const target of Object.values(assets).filter((a) => a.tag === tag).map((a) => a.path)) {
      const state = complete(); delete state.files[target];
      const r = run(`one missing ${target}`, { tag, state }); passed(r);
      assert.deepEqual(writes(r).map((e) => e.args.dest), [target]);
    }
    passed(run(`production dispatch ${tag}`, { tag, profile: "production" }), true);
  }
  passed(run("unselected tag", { tag: "base" }), true);
  for (const [label, options, pattern] of [
    ["broad check", { tag: "all", check: true }, /require only the docker tag/],
    ["multiple tags", { tag: "docker,compose" }, /require only the docker tag/],
    ["direct production", { direct: true, profile: "production" }, /require inactive Debian/],
    ["direct unknown tag", { direct: true, tag: "base" }, /require inactive Debian/],
    ["wrong host", { extra: { lifecycle_contract_host: "proxmox" } }, /require inactive Debian/],
    ["redirected roots", { extra: { unit_declaration_roots: ["/foreign"] } }, /Overriding the bounded/],
  ]) refused(run(label, options), pattern);
  const policyRefusal = /Unsupported declaration policy/;
  for (const [label, change] of [
    ["descriptor extra", (d) => { d.systemd.assets.guard_unit.extra = true; }],
    ["redirected path", (d) => { d.systemd.assets.guard_helper.path = "/unapproved"; }],
    ["redirected tag", (d) => { d.systemd.assets.docker_dependencies.tag = "compose"; }],
    ["description newline", (d) => { d.systemd.compose.description += "\nRequires=unreviewed.service"; }],
    ["specifier", (d) => { d.systemd.compose.home = "%h"; }],
    ["unbound argv", (d) => { d.transaction.compose_command.push("$UNAPPROVED"); }],
    ["working directory", (d) => { d.transaction.compose_artifact_path = "/foreign/docker-compose.yml"; }],
    ["weakened graph", (d) => { d.transaction.production_systemd_dependencies["docker.service"].Requires = []; }],
  ]) {
    const debian = structuredClone(contract.debian); change(debian);
    const r = run(label, { extra: { debian } }); refused(r, policyRefusal);
    assert(!r.events.some((e) => effects.has(e.module)), "binding failed after observations");
  }
  for (const target of gates) {
    const state = { ...fresh(), gates: [target] };
    refused(run(`gate ${target}`, { state }), /Activation gate metadata exists/, state);
  }
  for (const [label, state, pattern] of [
    ["unknown roots", { ...fresh(), unit_path: "UnitPath=/etc/systemd/system /foreign" }, /Unsupported UnitPath/],
    ["absent UnitPath", { ...fresh(), unit_path: "" }, /Unsupported UnitPath/],
    ["incomplete discovery", { ...fresh(), skipped: { [roots[0]]: { denied: "synthetic" } } }, /Incomplete unit root/],
    ["missing sbin", { ...fresh(), ancestry: { "/usr/local/sbin": { exists: false } } }, /ancestry is absent or unsafe/],
    ["unsafe ancestry", { ...fresh(), ancestry: { "/var/lib/home-lab": { exists: true, isdir: true, islnk: false, uid: 0, gid: 0, mode: "0777" } } }, /ancestry is absent or unsafe/],
    ["unsafe drop directory", { ...fresh(), drop_metadata: { exists: true, isdir: false, islnk: true } }, /Unsafe Docker drop/],
    ["capability Docker", { ...complete(), entries: { [dropdir]: [{ path: `${dropdir}/50-home-lab-production-dependencies.conf` }] } }, /Foreign or capability Docker/],
  ]) refused(run(label, { state, tag: "docker" }), pattern, state);
  const commandFailureState = { ...fresh(), command_rc: 1 };
  const commandFailure = run("command failure", { state: commandFailureState, tag: "docker" });
  refused(commandFailure, /TASK \[debian_lifecycle_transaction : Inspect manager unit search roots\]/, commandFailureState);
  assert.equal([...commandFailure.output.matchAll(/^TASK \[([^\]]+)\]/gm)].at(-1)[1],
    "debian_lifecycle_transaction : Inspect manager unit search roots");
  const fatal = commandFailure.output.match(/^fatal: \[fixture-debian\]: FAILED! => (\{.*\})$/m);
  assert(fatal, "expected exact command failure fatal record");
  assert.equal(JSON.parse(fatal[1]).rc, 1);
  assert.equal(JSON.parse(fatal[1]).changed, false);
  assert.deepEqual(commandFailure.events.at(-1), { module: "command", args: { argv: ["/usr/bin/systemctl", "show", "--property=UnitPath"] },
    check: false, task: "debian_lifecycle_transaction : Inspect manager unit search roots" });
  passed(run("merged usr", { state: { ...fresh(), unit_path: "UnitPath=/etc/systemd/system /lib/systemd/system" } }));
  refused(run("foreign merged usr", { state: { ...fresh(), unit_path: "UnitPath=/etc/systemd/system /lib/systemd/system",
    lib_alias: { exists: true, islnk: true, uid: 0, gid: 0, lnk_target: "foreign" } } }), /exact root owned merged usr/);
  const optional = roots.filter((r) => !["/etc/systemd/system", "/usr/lib/systemd/system"].includes(r));
  passed(run("optional roots absent", { state: { ...fresh(), ancestry: Object.fromEntries(optional.map((p) => [p, { exists: false }])) } }));
  for (const p of paths) for (const drift of [{ checksum: "0".repeat(64) }, { mode: "0600" }, { uid: 1 }, { gid: 1 }, { nlink: 2 }, { isreg: false }, { islnk: true }]) {
    const state = { ...complete(), asset_drift: { [p]: drift } };
    refused(run(`asset drift ${p} ${JSON.stringify(drift)}`, { state, tag: "docker" }), /Existing Home Lab declaration differs/, state);
  }
  for (const p of vendorPaths) {
    const state = { ...fresh(), vendors: true, vendor_drift: { [p]: { nlink: 2 } } };
    refused(run(`unsafe vendor ${p}`, { state }), /Unsafe designated vendor/, state);
  }
  for (const [unit, drift] of [
    [units[0], { LoadState: "loaded", ActiveState: "active", SubState: "exited", UnitFileState: "static", FragmentPath: paths[1] }],
    [units[1], { ActiveState: "active", SubState: "exited" }], [units[2], { ActiveState: "active", SubState: "running" }],
    [units[3], { ActiveState: "active", SubState: "listening" }], [units[0], { Job: "42" }], [units[3], { UnitFileState: "enabled" }],
    [units[1], { LoadState: "masked", UnitFileState: "masked" }], [units[0], { Names: units[0] + " alias.service" }],
    [units[3], { Names: '"docker.socket"' }], [units[2], { FragmentPath: "/foreign/docker.service" }],
    [units[1], { DropInPaths: "/override.conf" }], [units[2], { LoadState: "not-found", UnitFileState: "", FragmentPath: "" }],
  ]) {
    const state = { ...complete(), vendors: true, loaded: true, unit_drift: { [unit]: drift } };
    refused(run(`loaded ${unit} ${JSON.stringify(drift)}`, { state }), /Unit is active cached/, state);
  }
  refused(run("absent vendor with loaded observation", { state: { ...fresh(), unit_drift: { [units[3]]: {
    LoadState: "loaded", UnitFileState: "disabled", FragmentPath: vendorPaths[1] } } } }), /Unit is active cached/);
  for (const basename of ["service.d", "socket.d", "home-.service.d", "home-lab-.service.d", "home-lab-production-.service.d",
    "home-lab-production-guard.service.d", "home-lab-compose.service.d", "docker.socket.d"]) {
    const state = { ...fresh(), entries: { [roots[0]]: [{ path: `${roots[0]}/${basename}` }] } };
    refused(run(`applicable override ${basename}`, { state }), /Foreign fragment or applicable override/, state);
  }
  for (const r of roots) {
    const name = r === "/etc/systemd/system" ? "docker.socket" : "home-lab-compose.service";
    const state = { ...fresh(), entries: { [r]: [{ path: `${r}/${name}` }] } };
    refused(run(`foreign fragment ${r}`, { state }), /Foreign fragment or applicable override/, state);
  }
  for (const suffix of ["wants", "requires", "upholds"]) {
    const parent = `${roots[0]}/fixture.target.${suffix}`;
    const directory = { path: parent, isdir: true, islnk: false, uid: 0, gid: 0, mode: "0755" };
    for (const u of units) {
      const state = { ...fresh(), entries: { [roots[0]]: [directory], [parent]: [{ path: `${parent}/${u}`, islnk: true }] } };
      refused(run(`dangling ${suffix} ${u}`, { state }), /pull in entry exists/, state);
    }
    refused(run(`unsafe ${suffix}`, { state: { ...fresh(), entries: { [roots[0]]: [{ ...directory, islnk: true }] } } }), /Unsafe systemd pull in/);
    refused(run(`incomplete ${suffix}`, { state: { ...fresh(), entries: { [roots[0]]: [directory] }, skipped: { [parent]: { denied: "fixture" } } } }), /Incomplete pull in/);
  }
  const alias = `${roots[0]}/alias.service`;
  refused(run("differently named alias", { state: { ...fresh(), entries: { [roots[0]]: [{ path: alias, islnk: true }] },
    aliases: { [alias]: { exists: true, islnk: true, lnk_target: paths[2], lnk_source: paths[2] } } } }), /Workload alias/);
  for (const task of [site.pre_tasks[1], site.pre_tasks[2], site.pre_tasks.at(-1)]) {
    const r = run("guard/lock refusal", { state: { ...fresh(), refuse_admission: task.name } });
    refused(r, /synthetic guard or lock refusal/); assert(!r.events.some((e) => effects.has(e.module)));
  }
  // Actual existing audit tasks, not a shadow implementation: cached static guard
  // and vendor socket are both explicitly in the default inactive audit list.
  passed(run("audit absent", { audit: true }), true);
  for (const u of [units[0], units[3]]) {
    const state = { ...complete(), vendors: true, loaded: true, unit_drift: { [u]: { ActiveState: "active" } } };
    refused(run(`audit active ${u}`, { state, audit: true }), /is enabled or active/, state);
  }
  const interrupted = run("modeled partial copy interruption", { state: { ...fresh(), fail_copy: paths[2] } });
  assert.equal(interrupted.status, 2, interrupted.output); assert.match(interrupted.output, /modeled copy interruption/);
  assert.deepEqual(Object.keys(interrupted.state.files), paths.slice(0, 2));
  assert(!interrupted.events.some((e) => e.args.name === site.post_tasks[0].name));
  // Causal counterfactuals only change temporary adapted tasks, never repository
  // source. Removing the descriptor assertion permits modeled directive injection.
  const policyTask = adaptedAdmission.findIndex((t) => t.name.startsWith("Bind every declaration field"));
  const mutant = structuredClone(adaptedAdmission);
  const binding = mutant[policyTask]["ansible.builtin.assert"].that.shift();
  assert(binding.startsWith("debian.systemd =="));
  write(prefix + "inactive-unit-admission.yml", mutant);
  const debian = structuredClone(contract.debian); debian.systemd.compose.description += "\nRequires=unreviewed.service";
  const escaped = run("descriptor guard removal causal mutant", { extra: { debian } }); passed(escaped);
  assert(escaped.state.files[paths[2]].includes("\nRequires=unreviewed.service\n"));
  assert.throws(() => refused(escaped, policyRefusal), assert.AssertionError);
  write(prefix + "inactive-unit-admission.yml", adaptedAdmission);
  refused(run("restored descriptor guard", { extra: { debian } }), policyRefusal);
  // Moving the gate assertion past publication must defeat the no-write oracle.
  const lateAdmission = structuredClone(adaptedAdmission);
  const gateAssert = lateAdmission.pop();
  assert.equal(gateAssert.name, "Require all activation gates absent without reading or manufacturing them");
  write(prefix + "inactive-unit-admission.yml", lateAdmission);
  write(prefix + "inactive-units.yml", [...adaptedPublication, gateAssert]);
  const lateState = { ...fresh(), gates: [gates[2]] };
  const late = run("gate assertion after publication causal mutant", { state: lateState, tag: "docker" });
  assert.equal(late.status, 2, late.output); assert.equal(writes(late).length, 2);
  assert.throws(() => refused(late, /Activation gate metadata exists/, lateState), assert.AssertionError);
  write(prefix + "inactive-unit-admission.yml", adaptedAdmission); write(prefix + "inactive-units.yml", adaptedPublication);
  refused(run("restored prepublication gate assertion", { state: lateState, tag: "docker" }), /Activation gate metadata exists/, lateState);
  console.log(`debian_unit_declarations_source=verified runs=${runs} full_schema=true real_ansible=true controller_only_effect_adapters=true causal_mutants=3 tag_scoped_writes=true guard_executed=false vendor_body_read=false native_installation=false first_start_boot_interruption_acceptance=false`);
  }
  success = true;
} finally {
  if (success) fs.rmSync(fixture, { recursive: true, force: true });
  else console.error(`Failed synthetic fixture retained at ${fixture}`);
}
