#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const Ajv2020 = require("ajv/dist/2020");

if (process.argv.length !== 3) {
  throw new Error("usage: validate-vm-100-gate-c-schema.js MANIFEST.json");
}
const root = path.resolve(__dirname, "../..");
const schema = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/vm-100/gate-c-manifest.schema.json"), "utf8"));
const document = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
if (!validate(document)) {
  throw new Error(`Gate C manifest failed schema validation: ${JSON.stringify(validate.errors)}`);
}
console.log("vm_100_gate_c_schema=structurally-valid");
