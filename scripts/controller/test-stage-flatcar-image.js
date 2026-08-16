#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const script = fs.readFileSync(path.join(root, "scripts/stage-flatcar-image"), "utf8");
const flatcar = contract.flatcar;

assert.match(script, new RegExp(`readonly VERSION=${flatcar.version.replaceAll(".", "\\.")}`));
assert.ok(script.includes(`readonly IMAGE_URL=${flatcar.image.url}`));
assert.ok(script.includes(`readonly IMAGE_SHA512=${flatcar.image.sha512}`));
assert.ok(script.includes("readonly STORAGE_PARENT=/var/lib/vz"));
assert.ok(script.includes("readonly STORAGE_ROOT=$STORAGE_PARENT/import"));
assert.ok(script.includes("install -d -o root -g root -m 0755 \"$STORAGE_ROOT\""));
assert.ok(script.includes("readonly CONFIRMATION=stage-reviewed-flatcar-4593.2.5-image"));
assert.match(script, /\[\[ \$\(tty\) =~ \^\/dev\/tty\[0-9\]\+\$ \]\]/);
assert.match(script, /curl --fail --location --silent --show-error --proto '=https' --tlsv1\.2/);
assert.match(script, /sha512sum "\$PENDING"/);
assert.match(script, /ln "\$PENDING" "\$TARGET"/);
assert.match(script, /refusing replacement/);
assert.doesNotMatch(script, /\b(qm|pvesm|pvesh)\b|\/sys\/|\/dev\/disk|scsi[0-9]/);
assert.doesNotMatch(script, /rm[^\n]*"\$TARGET"|mv[^\n]*"\$TARGET"/);

process.stdout.write("flatcar image staging tests passed\n");
