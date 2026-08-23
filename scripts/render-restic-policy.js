#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const policy = contract.backups.restic;
const outputs = new Map([
  [path.join(root, "services/data/restic/files-from"), `${policy.sources.map((entry) => entry.path).join("\n")}\n`],
  [path.join(root, "services/data/restic/excludes"), `${policy.excludes.join("\n")}\n`],
]);
const check = process.argv.length === 3 && process.argv[2] === "--check";
if (!check && process.argv.length !== 2) {
  console.error("usage: scripts/render-restic-policy.js [--check]");
  process.exit(64);
}
let failed = false;
for (const [destination, expected] of outputs) {
  if (check) {
    if (!fs.existsSync(destination) || fs.readFileSync(destination, "utf8") !== expected) {
      console.error(`restic_policy=failed path=${path.relative(root, destination)}`);
      failed = true;
    }
  } else {
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, expected, { encoding: "utf8", mode: 0o644 });
  }
}
if (failed) process.exit(1);
console.log(check ? "restic_policy=verified" : "restic_policy=rendered");
