#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const { planProxmoxAccessCutover } = require("./proxmox-access-cutover");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const contract = load(read("infrastructure/contract/home-lab.yml"));
const sources = {
  tailnet: read("infrastructure/tofu/tailscale/main.tf"),
  inventory: read("ansible/inventory/production.yml"),
  firewallController: read("scripts/controller/proxmox-firewall.py"),
  firewallTransport: read("infrastructure/proxmox-firewall/host/proxmox-firewall-transport"),
  planTransport: read("infrastructure/proxmox-access/host/proxmox-ansible-plan-transport"),
};
const currentEvidence = {
  accounts: [
    { name: "proxmox", exists: true },
    { name: "root", exists: true, groups: ["apex", "root"] },
    { name: "firewall-apply", exists: true },
    { name: "tofu-plan", exists: true },
    { name: "tofu-apply", exists: true },
    { name: "ansible-plan", exists: true },
    { name: "ansible-deploy", exists: true },
  ],
  conventional_key_files: ["tofu-plan", "tofu-apply", "firewall-apply", "root"],
  pubkey_authentication: "yes",
  permit_root_login: "without-password",
  plan_observer_proven: false,
  canaries_proven: false,
  root_keys_attributed: false,
  console_attested: false,
};

const current = planProxmoxAccessCutover(contract, sources, currentEvidence);
assert.equal(current.ready, false);
assert.equal(current.authorized, false);
for (const blocker of [
  "access-cutover-state-not-ready",
  "tailnet-ssh-tests-incomplete",
  "conventional-authorized-keys-present",
  "openssh-pubkey-authentication-enabled",
  "openssh-root-login-enabled",
  "transitional-tofu-identities-present",
  "unexpected-root-supplementary-groups",
  "root-key-owner-attribution-required",
]) {
  assert(current.blockers.includes(blocker), `current access plan omits ${blocker}`);
}
assert.match(current.plan_sha256, /^[0-9a-f]{64}$/);

const readyContract = structuredClone(contract);
readyContract.lifecycle.hosts.proxmox.access_cutover.state = "ready";
const readyTailnet = `
ssh = [
  {
    dst = [local.tags.proxmox]
    users = ["proxmox", "ansible-plan", "ansible-deploy", "firewall-apply"]
  },
]
tests = []
sshTests = [
  {
    dst = [local.tags.proxmox]
    accept = ["proxmox", "ansible-plan", "ansible-deploy", "firewall-apply"]
    deny = ["root", "tofu-plan", "tofu-apply"]
  },
]
`;
const readyEvidence = {
  accounts: [
    { name: "proxmox", exists: true },
    { name: "root", exists: true, groups: ["root"] },
    { name: "firewall-apply", exists: true },
    { name: "ansible-plan", exists: true },
    { name: "ansible-deploy", exists: true },
    { name: "tofu-plan", exists: false },
    { name: "tofu-apply", exists: false },
  ],
  conventional_key_files: [],
  pubkey_authentication: "no",
  permit_root_login: "no",
  plan_observer_proven: true,
  canaries_proven: true,
  root_keys_attributed: true,
  console_attested: true,
};
const ready = planProxmoxAccessCutover(readyContract, {
  tailnet: readyTailnet,
  inventory: "ansible_user: ansible-plan\n",
  firewallController: 'PVE_SSH_TARGET = "firewall-apply@proxmox"\n',
  firewallTransport: sources.firewallTransport,
  planTransport: sources.planTransport,
}, readyEvidence);
assert.equal(ready.ready, true);
assert.equal(ready.authorized, false);
assert.deepEqual(ready.blockers, ["saved-access-cutover-plan-required", "separate-access-cutover-authorization-required"]);

const tasks = load(read("ansible/roles/access_cutover_plan/tasks/main.yml"));
const allowedModules = new Set([
  "ansible.builtin.assert",
  "ansible.builtin.command",
  "ansible.builtin.debug",
  "ansible.builtin.set_fact",
]);
for (const item of tasks) {
  const modules = Object.keys(item).filter((key) => key.startsWith("ansible.builtin."));
  assert.equal(modules.length, 1, `${item.name} must use one builtin module`);
  assert(allowedModules.has(modules[0]), `${item.name} uses mutation-capable module ${modules[0]}`);
}
const observer = tasks.find((item) => item.name === "Observe reduced Proxmox account and transport metadata");
assert.equal(observer.changed_when, false);
assert.equal(observer.check_mode, false);
const script = observer["ansible.builtin.command"].argv[2];
for (const required of ['pwd.getpwnam', '"/usr/bin/passwd", "--status"', 'os.lstat', '"evidence_sha256"']) {
  assert(script.includes(required), `access observer omits ${required}`);
}
for (const forbidden of ["useradd", "userdel", "usermod", "set-timezone", "systemctl", "authorized_keys\", \"w"]) {
  assert(!script.includes(forbidden), `access observer contains mutation path ${forbidden}`);
}
const publish = tasks.find((item) => item.name === "Publish pending access cutover readiness");
assert.equal(publish["ansible.builtin.set_fact"].access_cutover_plan_observation.ready, false);
assert.equal(publish["ansible.builtin.set_fact"].access_cutover_plan_observation.authorized, false);

const playbook = load(read("ansible/playbooks/proxmox-access-cutover-plan.yml"))[0];
assert.equal(playbook.hosts, "proxmox_host");
assert.equal(playbook.gather_facts, false);
assert.equal(playbook.serial, 1);
assert.equal(playbook.roles[0].vars.lifecycle_state_enforce, false);
assert.equal(playbook.roles[1].role, "access_cutover_plan");

const policy = contract.lifecycle.hosts.proxmox.access_cutover;
assert.equal(policy.state, "pending");
assert.deepEqual(policy.required_tailnet_users, ["proxmox", "ansible-plan", "ansible-deploy", "firewall-apply"]);
assert.deepEqual(policy.forbidden_tailnet_users, ["root", "tofu-plan", "tofu-apply"]);
assert.equal(policy.plan_privilege_model, "fixed-reduced-observer");
assert.equal(policy.firewall_magicdns_target, "firewall-apply@proxmox");
assert.equal(policy.remove_conventional_keys_last, true);

const accessEvidence = read("scripts/controller/proxmox-access-evidence.py");
for (const required of ["PROXMOX_CONSOLE_ATTESTATION_CONFIRMED", "StrictHostKeyChecking=yes", "live_plan_noop", "root_keys", "os.O_EXCL", "os.O_NOFOLLOW"]) {
  assert(accessEvidence.includes(required), `access evidence capture omits ${required}`);
}
assert(!accessEvidence.includes("StrictHostKeyChecking=no"));
const readinessSource = read("scripts/controller/proxmox-access-readiness.js");
for (const required of ["home-lab-proxmox-access-evidence-v1", "planProxmoxAccessCutover", "receipt_sha256", "live_evidence_sha256", "O_EXCL"]) {
  assert(readinessSource.includes(required), `access readiness planner omits ${required}`);
}
assert(read("ansible/playbooks/proxmox-access-cutover-plan.yml").includes("rstrip=False"));

console.log("proxmox_access_cutover=verified");
