#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const debian = contract.debian;

assert.equal(debian.release, "trixie");
assert.equal(debian.version, "13");
assert.equal(debian.image.variant, "generic");
assert.equal(debian.image.format, "qcow2");
assert.match(debian.image.sha512, /^[0-9a-f]{128}$/);
assert.deepEqual(debian.os_disk.qualification_boot_order, ["scsi3", "net0"]);
assert.deepEqual(debian.qualification.kernel_modules, ["amdgpu", "uhid", "uinput"]);

const inputs = [
  ["user_data", "user-data"],
  ["network_data", "network-data"],
  ["meta_data", "meta-data"],
];
const parsed = new Map();
for (const [contractKey, name] of inputs) {
  const expected = debian.cloud_init[contractKey];
  const source = path.join(root, expected.source_path);
  const body = fs.readFileSync(source);
  assert.equal(path.basename(source), name);
  assert.equal(body.length, expected.size);
  assert.equal(crypto.createHash("sha256").update(body).digest("hex"), expected.sha256);
  parsed.set(name, load(body.toString("utf8")));
}

const userData = parsed.get("user-data");
const dockerUser = userData.users.find((user) => user.name === "docker");
assert.equal(userData.groups, undefined);
assert.deepEqual(dockerUser.groups, ["adm", "sudo", "video", "render", "input", "dialout"]);
assert.equal(dockerUser.uid, 1000);
assert.equal(dockerUser.lock_passwd, true);
assert.equal(dockerUser.ssh_authorized_keys.length, 1);
assert.match(dockerUser.ssh_authorized_keys[0], /^ssh-ed25519 /);
assert.equal(userData.ssh_pwauth, false);
assert.equal(userData.disable_root, true);
assert.equal(userData.package_upgrade, false);
for (const requiredPackage of ["firmware-amd-graphics", "qemu-guest-agent", "unattended-upgrades", "usbutils", "vainfo"]) {
  assert.ok(userData.packages.includes(requiredPackage));
}
for (const prohibitedPackage of ["docker-ce", "docker.io", "docker-compose", "tailscale"]) {
  assert.equal(userData.packages.includes(prohibitedPackage), false);
}
const fileByPath = new Map(userData.write_files.map((file) => [file.path, file]));
const debianSources = fileByPath.get("/etc/apt/sources.list.d/debian.sources").content;
assert.match(debianSources, /Components: main contrib non-free-firmware/);
assert.match(debianSources, /Signed-By: \/usr\/share\/keyrings\/debian-archive-keyring\.gpg/);
assert.equal(fileByPath.get("/etc/modules-load.d/home-lab-hardware.conf").content, "amdgpu\nuhid\nuinput\n");
for (const mountPath of [
  "/etc/systemd/system/srv-home\\x2dlab\\x2dstate.mount",
  "/etc/systemd/system/mnt-games.mount",
  "/etc/systemd/system/mnt-storage.mount",
]) {
  assert.ok(fileByPath.has(mountPath));
  assert.match(fileByPath.get(mountPath).content, /ConditionPathExists=\/etc\/home-lab\/allow-storage-activation/);
}
const commands = userData.runcmd.map((command) => command.join(" ")).join("\n");
assert.match(commands, /modprobe amdgpu/);
assert.match(commands, /modprobe uhid/);
assert.match(commands, /modprobe uinput/);
assert.doesNotMatch(commands, /(?:docker|tailscale|home-lab-compose|enable .*\.mount|mount )/);
assert.equal(Object.hasOwn(userData, "power_state"), false);
assert.match(fileByPath.get("/etc/apt/apt.conf.d/52home-lab-unattended-upgrades").content, /Automatic-Reboot "false"/);

const networkData = parsed.get("network-data");
const ens18 = networkData.ethernets.ens18;
assert.equal(ens18.match.macaddress, contract.vm_100.networking.match_mac.toLowerCase());
assert.deepEqual(ens18.addresses, [contract.vm_100.networking.ipv4]);
assert.equal(ens18.routes[0].via, contract.vm_100.networking.gateway);
assert.deepEqual(ens18.nameservers.addresses, contract.vm_100.networking.dns);

const metaData = parsed.get("meta-data");
assert.equal(metaData["local-hostname"], contract.vm_100.network_identity);
assert.match(metaData["instance-id"], /^vm-100-debian-13-/);

process.stdout.write("debian cloud-init tests passed\n");
