#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "scripts/stage-flatcar-ignition"), "utf8");
const expected = contract.flatcar.production_ignition;
const target = contract.flatcar.os_disk.snippet_path;

assert.ok(script.includes(`readonly IGNITION_VERSION=${expected.version}`));
assert.ok(script.includes(`readonly EXPECTED_SHA256=${expected.sha256}`));
assert.ok(script.includes(`readonly EXPECTED_SIZE=${expected.size}`));
assert.match(script, /readonly PREVIOUS_SHA256=[0-9a-f]{64}/);
assert.match(script, /readonly PREVIOUS_SIZE=[0-9]+/);
assert.ok(script.includes(`readonly TARGET=$STORAGE_ROOT/${path.basename(target)}`));
assert.ok(script.includes("readonly STORAGE_ROOT=$STORAGE_PARENT/snippets"));
assert.ok(script.includes("readonly CONFIRMATION=stage-reviewed-vm-100-flatcar-ignition"));
assert.match(script, /ps -o tty= -p "\$\$"/);
assert.match(script, /head -c "\$\(\(EXPECTED_SIZE \+ 1\)\)"/);
assert.match(script, /sha256sum "\$PENDING"/);
assert.match(script, /chmod 0600 "\$PENDING"/);
assert.match(script, /ln "\$PENDING" "\$TARGET"/);
assert.match(script, /previous_actual=\$\(sha256sum "\$TARGET"/);
assert.match(script, /mv -f -- "\$PENDING" "\$TARGET"/);
assert.match(script, /refusing replacement/);
assert.doesNotMatch(script, /\b(qm|pvesm|pvesh)\b|\/sys\/|\/dev\/disk|scsi[0-9]/);
assert.doesNotMatch(script, /rm[^\n]*"\$TARGET"/);
assert.doesNotMatch(script, /cat "?\$PENDING|jq .*\$PENDING|echo .*\$PENDING/);

process.stdout.write("flatcar Ignition staging tests passed\n");
