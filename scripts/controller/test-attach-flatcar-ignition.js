#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "scripts/attach-flatcar-ignition"), "utf8");
const runner = fs.readFileSync(path.join(root, "scripts/run-flatcar-ignition-attach"), "utf8");
const disk = contract.flatcar.os_disk;

assert.ok(script.includes(`readonly VMID=${contract.proxmox.vm.vmid}`));
assert.ok(script.includes(`readonly INTERFACE=${disk.ignition_drive_interface}`));
assert.ok(script.includes(`readonly DATASTORE=${disk.ignition_drive_datastore}`));
assert.ok(script.includes(`readonly CICUSTOM=${disk.snippet_storage}:snippets/${path.basename(disk.snippet_path)}`));
assert.ok(script.includes("readonly CONFIRMATION=attach-reviewed-vm-100-flatcar-ignition"));
assert.match(script, /ps -o tty= -p "\$\$"/);
assert.match(script, /flock -n 9/);
assert.match(script, /flock -n 7/);
assert.match(script, /qm set "\$VMID" --ide2 "\$DATASTORE:cloudinit"/);
assert.match(script, /qm set "\$VMID" --cicustom "user=\$CICUSTOM"/);
assert.match(script, /order=scsi0;net0/);
assert.match(script, /configurationActivation/);
assert.match(script, /cloud-init drive is preserved for explicit reconciliation/);
assert.doesNotMatch(script, /qm (?:stop|start|shutdown|destroy)|qm disk (?:import|resize|unlink)|pvesm free|--delete|--boot|--scsi[0-9]\b/);
assert.ok(runner.includes("HOME_LAB_FLATCAR_IGNITION_ATTACH_CONFIRMED=attach-reviewed-vm-100-flatcar-ignition"));
assert.match(runner, /exec "\$root\/scripts\/attach-flatcar-ignition"/);

process.stdout.write("flatcar Ignition attachment tests passed\n");
