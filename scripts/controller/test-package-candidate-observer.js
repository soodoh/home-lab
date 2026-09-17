#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "../..");
const observer = fs.readFileSync(path.join(root, "infrastructure/maintenance/host/package-candidate-observer"), "utf8");
const nativeRole = fs.readFileSync(path.join(root, "ansible/roles/proxmox_package_observe/tasks/main.yml"), "utf8");
const packagePlay = fs.readFileSync(path.join(root, "ansible/playbooks/maintain-proxmox-packages.yml"), "utf8");
assert.match(observer, /apt-get/);
assert.match(observer, /--simulate/);
assert.match(observer, /@EXPECTED_PACKAGES_BASE64@/);
assert.match(nativeRole, /ansible\.builtin\.package_facts/);
assert.doesNotMatch(nativeRole, /package-candidate-observer|apt-get|response adapter/i);
assert.match(packagePlay, /proxmox_package_maintenance/);
assert.doesNotMatch(packagePlay, /ansible_check_mode/);
for (const retired of [
  "infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator",
  "scripts/controller/proxmox-package-activation.py",
]) {
  assert.equal(fs.existsSync(path.join(root, retired)), false, retired);
}
console.log("package_candidate_observer=debian-only proxmox=native-ansible");
