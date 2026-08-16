#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "scripts/import-flatcar-disk"), "utf8");
const flatcar = contract.flatcar;
const disk = flatcar.os_disk;

assert.ok(script.includes(`readonly VMID=${contract.proxmox.vm.vmid}`));
assert.ok(script.includes(`readonly IMAGE=/var/lib/vz/import/flatcar-${flatcar.version}-proxmoxve.img`));
assert.ok(script.includes(`readonly STORAGE=${disk.datastore}`));
assert.ok(script.includes(`readonly INTERFACE=${disk.interface}`));
assert.ok(script.includes(`readonly SERIAL=${disk.serial}`));
assert.ok(script.includes(`readonly SIZE=${disk.size_gb}G`));
assert.ok(script.includes("readonly CONFIRMATION=import-reviewed-vm-100-flatcar-scsi3"));
assert.match(script, /ps -o tty= -p "\$\$"/);
assert.match(script, /flock -n 9/);
assert.match(script, /flock -n 7/);
assert.match(script, /qm disk import "\$VMID" "\$IMAGE" "\$STORAGE" --format raw --target-disk "\$INTERFACE"/);
assert.match(script, /qm disk resize "\$VMID" "\$INTERFACE" "\$SIZE"/);
assert.match(script, /order=scsi0;net0/);
assert.match(script, /the new disk is preserved for explicit reconciliation/);
assert.doesNotMatch(script, /qm (?:stop|start|shutdown|destroy)|qm disk unlink|pvesm free|--delete|--boot|--ide2|--scsi[012]\b/);

process.stdout.write("flatcar disk import tests passed\n");
