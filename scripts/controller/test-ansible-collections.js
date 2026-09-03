#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const ansibleRoot = path.join(root, "ansible");
const requirements = load(fs.readFileSync(path.join(ansibleRoot, "collections/requirements.yml"), "utf8"));
assert.deepEqual(requirements, { collections: [{ name: "community.general", version: "13.2.0" }] });
const installed = JSON.parse(execFileSync("ansible-galaxy", ["collection", "list", "--format", "json"], { encoding: "utf8" }));
const installedCollections = Object.values(installed).flatMap((value) => Object.entries(value));
for (const requirement of requirements.collections) {
  const matches = installedCollections.filter(([name, metadata]) => name === requirement.name && metadata.version === requirement.version);
  assert(matches.length > 0, `missing exact Ansible collection ${requirement.name} ${requirement.version}`);
}

const files = [];
function visit(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) visit(candidate);
    else if (entry.isFile() && /\.ya?ml$/.test(entry.name)) files.push(candidate);
  }
}
visit(ansibleRoot);

const modules = new Set();
const modulePattern = /^\s+([a-z][a-z0-9_]+\.[a-z][a-z0-9_]+\.[a-z][a-z0-9_]+):(?:\s|$)/gm;
for (const file of files) {
  const source = fs.readFileSync(file, "utf8");
  for (const match of source.matchAll(modulePattern)) modules.add(match[1]);
}
assert(modules.size > 0, "Ansible module inventory must not be empty");
const pinnedCollections = new Set(requirements.collections.map((item) => item.name));
for (const module of modules) {
  if (module.startsWith("ansible.builtin.")) continue;
  const collection = module.split(".").slice(0, 2).join(".");
  assert(pinnedCollections.has(collection), `unpinned external Ansible collection module: ${module}`);
}

console.log(`ansible_collections=verified pinned=${requirements.collections.length} modules=${modules.size}`);
