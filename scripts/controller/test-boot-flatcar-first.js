#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "scripts/boot-flatcar-first"), "utf8");
const runner = fs.readFileSync(path.join(root, "scripts/run-flatcar-first-boot"), "utf8");
const disk = contract.flatcar.os_disk;

assert.equal(contract.flatcar.qualification_stage, "ready-for-first-boot");
assert.ok(script.includes(`readonly VMID=${contract.proxmox.vm.vmid}`));
assert.ok(script.includes(`readonly FLATCAR_IP=${contract.network.arch.ipv4.split("/")[0]}`));
assert.ok(script.includes(`readonly FLATCAR_BOOT='order=${disk.qualification_boot_order.join(";")}'`));
assert.ok(script.includes("readonly ARCH_BOOT='order=scsi0;net0'"));
assert.ok(script.includes("readonly CONFIRMATION=boot-reviewed-vm-100-flatcar-inert"));
assert.ok(script.includes("readonly VFIO_CONFIRMATION=recover-vm-100-vfio-group-14"));
assert.match(script, /ps -o tty= -p "\$\$"/);
assert.match(script, /qm shutdown "\$VMID" --timeout 180/);
assert.match(script, /qm set "\$VMID" --boot "\$FLATCAR_BOOT"/);
assert.match(script, /home-lab-vfio-recover recover --confirm "\$VFIO_CONFIRMATION"/);
assert.match(script, /\[\[ \$\(os_id\) == flatcar \]\]/);
assert.match(script, /restore_arch \|\| true/);
assert.match(script, /qm set "\$VMID" --boot "\$ARCH_BOOT"/);
assert.match(script, /\[\[ \$\(os_id\) == arch \]\]/);
assert.match(script, /qm stop "\$VMID" \|\| restored=false/);
assert.match(script, /"composeActivation":"disabled"/);
assert.match(script, /"mountActivation":"disabled"/);
assert.doesNotMatch(script, /systemctl (?:enable|start)|docker compose|docker-compose|\bmount\b|mkfs|wipefs|qm disk (?:import|resize|unlink)|pvesm free|--delete/);
assert.ok(runner.includes("HOME_LAB_FLATCAR_FIRST_BOOT_CONFIRMED=boot-reviewed-vm-100-flatcar-inert"));
assert.match(runner, /exec "\$root\/scripts\/boot-flatcar-first"/);

process.stdout.write("flatcar first-boot tests passed\n");
