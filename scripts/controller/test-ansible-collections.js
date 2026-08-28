#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");

const root = path.resolve(__dirname, "../..");
const ansibleRoot = path.join(root, "ansible");
const requirements = load(fs.readFileSync(path.join(ansibleRoot, "collections/requirements.yml"), "utf8"));
assert.deepEqual(requirements, { collections: [] });

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
for (const module of modules) {
  assert(module.startsWith("ansible.builtin."), `unpinned external Ansible collection module: ${module}`);
}

console.log(`ansible_collections=verified external=0 builtin_modules=${modules.size}`);
