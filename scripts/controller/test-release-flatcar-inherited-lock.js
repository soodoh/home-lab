#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const script = fs.readFileSync(path.join(root, "scripts/release-flatcar-inherited-lock"), "utf8");
const transitionLibrary = fs.readFileSync(path.join(root, "scripts/lib/vm-100-os-transition"), "utf8");
const combined = `${script}\n${transitionLibrary}`;
const runner = fs.readFileSync(path.join(root, "scripts/run-flatcar-lock-release"), "utf8");

assert.match(script, /ps -o tty= -p "\$\$"/);
assert.match(script, /\/run\/qemu-server\/100\.pid/);
assert.match(script, /\/proc\/\$pid\/cmdline/);
assert.match(script, /\$executable == \/usr\/bin\/kvm/);
assert.match(script, /\[\[ \$value == -id \]\]/);
assert.match(script, /lock_owners "\$OPERATION_LOCK"/);
assert.match(script, /lock_owners "\$FIRST_BOOT_LOCK"/);
assert.match(script, /qm shutdown "\$VMID" --timeout 180/);
assert.match(combined, /home-lab-vfio-recover recover --confirm "\$VFIO_CONFIRMATION"/);
assert.match(combined, /\[\[ \$\(os_id\) == arch \]\]/);
assert.match(script, /flock -n "\$OPERATION_LOCK" true/);
assert.match(script, /operation lock ownership differs after restart/);
assert.match(combined, /exec 8>&-/);
assert.match(combined, /exec 9>&-/);
assert.ok(script.indexOf("restart_required=true") < script.indexOf('qm shutdown "$VMID"'));
assert.doesNotMatch(script, /qm stop|qm set|--boot|qm disk|pvesm free|--delete|kill /);
assert.ok(runner.includes("HOME_LAB_FLATCAR_LOCK_RELEASE_CONFIRMED=restart-reviewed-vm-100-release-inherited-locks"));
assert.match(runner, /exec "\$root\/scripts\/release-flatcar-inherited-lock"/);

process.stdout.write("Flatcar inherited-lock release tests passed\n");
