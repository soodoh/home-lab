#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { load } = require("js-yaml");
const Ajv2020 = require("ajv/dist/2020");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const schema = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/contract/schema.json"), "utf8"));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

function check(value, expected, label) {
  const actual = validate(value);
  if (actual !== expected) {
    throw new Error(`${label}: expected valid=${expected}, got ${actual}: ${JSON.stringify(validate.errors)}`);
  }
}

check(structuredClone(contract), true, "current contract");

const missing = structuredClone(contract);
delete missing.arch.packages.kernel;
check(missing, false, "missing required package");

const unknown = structuredClone(contract);
unknown.arch.packages.parallel_runtime = "1.2.3-1";
check(unknown, false, "unknown package");

for (const key of ["kernel", "docker", "docker_compose", "tailscale"]) {
  const malformed = structuredClone(contract);
  malformed.arch.packages[key] = "latest";
  check(malformed, false, `malformed ${key} version`);
}

console.log("contract_package_schema=verified");
