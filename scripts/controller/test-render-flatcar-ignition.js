#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { load } = require("js-yaml");
const { buildButaneConfig, collectArtifactFiles, mountUnit, parseArgs } = require("./render-flatcar-ignition.js");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const inputs = {
  sshAuthorizedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfakedeterministictestkeyonly flatcar-test\n",
  runtimeEnvironment: "COMPOSE_PROJECT_NAME=home-lab\nHOME=/home/docker\n",
  zigbeeSerial: "zigbee-test",
  zwaveSerial: "zwave-test",
  composeFiles: [
    { relative: "docker-compose.yml", mode: 0o644, content: "services: {}\n" },
    { relative: "scripts/backup", mode: 0o755, content: "#!/bin/sh\n" },
  ],
};

const config = buildButaneConfig(contract, inputs);
assert.equal(config.variant, "flatcar");
assert.equal(config.version, "1.1.0");
assert.deepEqual(config.passwd.users[0].ssh_authorized_keys, [inputs.sshAuthorizedKey.trim()]);

const unitByName = new Map(config.systemd.units.map((unit) => [unit.name, unit]));
for (const name of ["srv-home\\x2dlab\\x2dstate.mount", "mnt-games.mount", "mnt-storage.mount", "home-lab-compose.service"]) {
  assert.equal(unitByName.get(name).enabled, false, `${name} must require guarded activation`);
}
assert.equal(unitByName.get("docker.service").enabled, true);
assert.equal(unitByName.get("home-lab-runtime-tools.service").enabled, true);
assert.match(unitByName.get("tailscaled.service").contents, /Requires=home-lab-runtime-tools\.service/);
assert.match(unitByName.get("srv-home\\x2dlab\\x2dstate.mount").contents, new RegExp(contract.proxmox.vm.state_disk.filesystem_uuid));
assert.match(unitByName.get("mnt-games.mount").contents, new RegExp(contract.vm_100.storage.games.filesystem_uuid));
assert.match(unitByName.get("home-lab-compose.service").contents, /RequiresMountsFor=\/srv\/home-lab-state \/mnt\/games \/mnt\/storage/);

const fileByPath = new Map(config.storage.files.map((file) => [file.path, file]));
assert.equal(fileByPath.get("/etc/hostname").overwrite, true);
assert.equal(fileByPath.get("/etc/flatcar/update.conf").overwrite, true);
assert.equal(fileByPath.get("/etc/docker-compose/production.env").mode, 0o600);
assert.equal(fileByPath.get("/etc/docker-compose/production.env").contents.inline, inputs.runtimeEnvironment);
const installer = fileByPath.get("/opt/bin/home-lab-install-runtime-tools");
assert.equal(fileByPath.has("/usr/local/sbin/home-lab-install-runtime-tools"), false);
assert.match(unitByName.get("home-lab-runtime-tools.service").contents, /ExecStart=\/opt\/bin\/home-lab-install-runtime-tools/);
assert.equal(installer.mode, 0o700);
assert.match(installer.contents.inline, new RegExp(contract.flatcar.compose.sha256));
assert.match(installer.contents.inline, new RegExp(contract.flatcar.tailscale.sha256));
assert.match(installer.contents.inline, /--proto '=https' --tlsv1\.2/);
assert.equal(fileByPath.has("/opt/bin/docker-compose"), false);
assert.equal(fileByPath.has("/opt/tailscale/tailscale.tgz"), false);
assert.equal(fileByPath.get("/opt/home-lab/compose/scripts/backup").mode, 0o755);
assert.doesNotMatch(JSON.stringify(config), /A678E17443DBD7A4|AGE-SECRET-KEY/);

assert.throws(() => buildButaneConfig(contract, { ...inputs, zwaveSerial: inputs.zigbeeSerial }), /must be distinct/);
assert.throws(() => buildButaneConfig(contract, { ...inputs, runtimeEnvironment: "NO-NEWLINE" }), /must end with a newline/);
assert.throws(() => parseArgs(["--ssh-key-file", "key"]), /missing --runtime-env-file/);
assert.match(mountUnit({ description: "test", what: "/dev/test", where: "/mnt/test", type: "ext4", options: ["noatime"] }), /Options=noatime/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "flatcar-artifact-test-"));
try {
  fs.writeFileSync(path.join(temporary, "docker-compose.yml"), "services: {}\n");
  fs.mkdirSync(path.join(temporary, "scripts"));
  fs.writeFileSync(path.join(temporary, "scripts", "run"), "#!/bin/sh\n", { mode: 0o755 });
  const files = collectArtifactFiles(temporary);
  assert.deepEqual(files.map((entry) => entry.relative), ["docker-compose.yml", path.join("scripts", "run")]);
  assert.equal(files[1].mode, 0o755);
  fs.symlinkSync(path.join(temporary, "docker-compose.yml"), path.join(temporary, "unsafe-link"));
  assert.throws(() => collectArtifactFiles(temporary), /contains a symlink/);
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}

process.stdout.write("flatcar ignition renderer tests passed\n");
