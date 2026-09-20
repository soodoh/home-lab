#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load, dump } = require("js-yaml");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "../..");
const readYaml = (relative) => load(fs.readFileSync(path.join(root, relative), "utf8"));
const tasks = readYaml("ansible/roles/lifecycle_state/tasks/main.yml");
const observePlaybook = readYaml("ansible/playbooks/lifecycle-observe.yml");
const assertPlaybook = readYaml("ansible/playbooks/lifecycle-assert.yml");
const inventory = readYaml("ansible/inventory/production.yml");
const sitePlaybook = readYaml("ansible/playbooks/legacy-debian-site.yml")[0];
const contract = readYaml("infrastructure/contract/home-lab.yml");

function task(name) {
  const matches = tasks.filter((item) => item.name === name);
  assert.equal(matches.length, 1, `expected one lifecycle task named ${name}`);
  return matches[0];
}

const allowedModules = new Set([
  "ansible.builtin.assert",
  "ansible.builtin.command",
  "ansible.builtin.debug",
  "ansible.builtin.find",
  "ansible.builtin.set_fact",
  "ansible.builtin.stat",
]);
for (const item of tasks) {
  const modules = Object.keys(item).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1, `${item.name} must use exactly one builtin module`);
  assert(allowedModules.has(modules[0]), `${item.name} uses mutation-capable module ${modules[0]}`);
}

for (const item of tasks.filter((entry) => entry["ansible.builtin.command"])) {
  assert.equal(item.changed_when, false, `${item.name} must report no change`);
  assert.equal(item.check_mode, false, `${item.name} must remain observable in check mode`);
  const argv = item["ansible.builtin.command"].argv;
  assert(Array.isArray(argv) && argv[0] === "/usr/bin/python3" && argv[1] === "-c", `${item.name} must use fixed Python argv`);
}

const markerTask = task("Inspect and validate the lifecycle marker without changing it");
const markerScript = markerTask["ansible.builtin.command"].argv[2];
for (const required of ["os.lstat", "metadata.st_nlink != 1", "metadata.st_size > 4096", "raw == canonical", "expected_keys"]) {
  assert(markerScript.includes(required), `marker observer omits ${required}`);
}

const keyTask = task("Discover conventional authorized-key files");
assert.deepEqual(keyTask["ansible.builtin.find"].patterns, ["authorized_keys", "authorized_keys2"]);
assert.equal(keyTask["ansible.builtin.find"].follow, false);
assert.equal(keyTask["ansible.builtin.find"].get_checksum, false);

const tailscaleTask = task("Inspect reduced Tailscale node state and preferences");
assert.equal(tailscaleTask.no_log, true);
const tailscaleScript = tailscaleTask["ansible.builtin.command"].argv[2];
for (const required of ["status", "--json", "debug", "prefs", "RunSSH", "WantRunning"]) {
  assert(tailscaleScript.includes(required), `Tailscale observer omits ${required}`);
}

const lockScript = task("Inspect lifecycle lock conflicts")["ansible.builtin.command"].argv[2];
for (const required of ["lslocks", "--json", "--notruncate", "os.path.lexists", "monitored_paths"]) {
  assert(lockScript.includes(required), `lock observer omits ${required}`);
}

const invariants = task("Evaluate lifecycle invariants")["ansible.builtin.set_fact"];
// Execute the actual role expressions, not a reimplementation of their policy.
const disabled = Object.fromEntries(["pubkey_authentication", "password_authentication", "kbd_interactive_authentication", "permit_root_login"].map((field) => [field, "no"]));
const authenticationCases = [{ sshd: disabled, expected: true }];
for (const field of Object.keys(disabled)) {
  for (const value of ["yes", null]) authenticationCases.push({ sshd: { ...disabled, [field]: value }, expected: false });
}
const fixtureDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "home-lab-lifecycle-auth-"));
try {
  const fixture = path.join(fixtureDirectory, "authentication.yml");
  fs.writeFileSync(fixture, dump([{
    name: "Test lifecycle authentication policy offline",
    hosts: "localhost", gather_facts: false,
    vars: { lifecycle_state_policy: { current_mutation_owner: "ansible" } },
    tasks: ["lifecycle_state_sshd_matches", "lifecycle_state_target_sshd_matches"].map((name) => ({
      name,
      "ansible.builtin.assert": {
        that: [`(${invariants[name].trim().slice(2, -2).replaceAll("lifecycle_state_sshd.", "item.sshd.")}) == item.expected`],
      },
      loop: authenticationCases,
    })),
  }]), { mode: 0o600 });
  const result = spawnSync("ansible-playbook", ["-i", "localhost,", "-c", "local", "--check", fixture], {
    cwd: root, encoding: "utf8", env: { ...process.env, ANSIBLE_CONFIG: path.join(root, "ansible/ansible.cfg") },
  });
  assert.equal(result.status, 0, `lifecycle authentication fixtures failed: ${result.error || ""}\n${result.stdout}\n${result.stderr}`);
} finally {
  fs.rmSync(fixtureDirectory, { recursive: true, force: true });
}
for (const name of ["lifecycle_state_sshd_matches", "lifecycle_state_target_sshd_matches"]) {
  for (const field of ["pubkey_authentication", "password_authentication", "kbd_interactive_authentication", "permit_root_login"]) {
    assert(invariants[name].includes(`lifecycle_state_sshd.${field} == 'no'`), `${name} must require disabled ${field}`);
  }
}

const enforcement = task("Enforce lifecycle invariants when explicitly requested");
assert.equal(enforcement.when, "lifecycle_state_enforce | bool");
assert.deepEqual(enforcement["ansible.builtin.assert"].that, ["lifecycle_state_observation.compliant"]);

assert.equal(observePlaybook[0].hosts, "docker_host:proxmox_host");
assert.equal(observePlaybook[0].gather_facts, false);
assert.equal(observePlaybook[0].roles[0].vars.lifecycle_state_enforce, false);
assert.equal(assertPlaybook[0].roles[0].vars.lifecycle_state_enforce, true);

const dockerHost = inventory.all.children.docker_host.hosts["docker-host-production"];
const proxmoxHost = inventory.all.children.proxmox_host.hosts["proxmox-host-production"];
assert.equal(dockerHost.lifecycle_contract_host, "debian");
assert.equal(proxmoxHost.lifecycle_contract_host, "proxmox");
assert.equal(proxmoxHost.ansible_host, "proxmox");
assert.equal(proxmoxHost.ansible_user, "proxmox");
assert.equal(dockerHost.lifecycle_profile, "production");
for (const host of [dockerHost, proxmoxHost]) {
  for (const required of ["-F /dev/null", "BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "UserKnownHostsFile=", "IdentitiesOnly=yes", "ClearAllForwardings=yes", "PermitLocalCommand=no", "RequestTTY=no"]) {
    assert(host.ansible_ssh_common_args.includes(required), `inventory SSH policy omits ${required}`);
  }
}
assert(dockerHost.ansible_ssh_common_args.includes("HOME_LAB_DEBIAN_PRODUCTION_KNOWN_HOSTS"));
for (const required of ["GlobalKnownHostsFile=/dev/null", "IdentityAgent=none", "IdentityFile=none", "PreferredAuthentications=none", "PubkeyAuthentication=no", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "GSSAPIAuthentication=no"]) {
  assert(dockerHost.ansible_ssh_common_args.includes(required), `protected Debian transaction SSH policy omits ${required}`);
}
assert(proxmoxHost.ansible_ssh_common_args.includes("HOME_LAB_PROXMOX_PRODUCTION_KNOWN_HOSTS"));

const profileGuard = sitePlaybook.pre_tasks.find((item) => item.name === "Require an explicit Debian lifecycle profile");
assert(profileGuard, "site.yml must require a lifecycle profile");
assert(profileGuard["ansible.builtin.assert"].that.includes("lifecycle_profile in ['inert', 'recovery', 'production']"));
const baseRole = sitePlaybook.roles.find((item) => item.role === "base");
assert(baseRole && baseRole.when === undefined, "safe base must run for every lifecycle profile");
for (const role of sitePlaybook.roles.filter((item) => item.role !== "base")) {
  assert.equal(role.when, "lifecycle_profile == 'production'", `${role.role} must remain production-only`);
}

assert.deepEqual(contract.lifecycle.states, ["inert", "bootstrap", "production", "maintenance", "recovery", "retired"]);
assert.equal(contract.lifecycle.hosts.proxmox.current_mutation_owner, "ansible");
assert.equal(contract.lifecycle.hosts.debian.current_mutation_owner, "ansible");
for (const host of Object.values(contract.lifecycle.hosts)) {
  assert.equal(host.desired_state, "production");
  assert.equal(host.target_mutation_owner, "ansible");
  assert.equal(host.steady_transport, "tailscale-ssh");
  assert.equal(host.break_glass, "physical-console");
  assert.equal(host.marker.path, "/var/lib/home-lab/lifecycle-state.json");
  assert.equal(host.marker.adoption_state, "complete");
}

console.log("lifecycle_state=verified");
