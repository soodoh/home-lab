#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const Ajv2020 = require("ajv/dist/2020");

const schemas = {
  "isolated-restore": "isolated-restore-evidence.schema.json",
  "candidate-daemon-stop": "candidate-daemon-stop-evidence.schema.json",
  "source-daemon-stability": "source-daemon-stability-evidence.schema.json",
  "data-transfer": "data-transfer-evidence.schema.json",
};
if (process.argv.length !== 4 || !Object.hasOwn(schemas, process.argv[2])) {
  throw new Error("usage: validate-vm-100-execution-schema.js <isolated-restore|candidate-daemon-stop|source-daemon-stability|data-transfer> EVIDENCE.json");
}
const root = path.resolve(__dirname, "../..");
const schema = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/vm-100", schemas[process.argv[2]]), "utf8"));
const document = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
if (!validate(document)) throw new Error(`VM 100 execution evidence failed schema validation: ${JSON.stringify(validate.errors)}`);
if (process.argv[2] === "source-daemon-stability" && document.exactEquality && document.beforeInventorySha256 !== document.afterInventorySha256) {
  throw new Error("source stability exactEquality contradicts its inventory digests");
}
if (process.argv[2] === "data-transfer") {
  for (const entry of document.entries) {
    const capacity = entry.capacityBefore;
    if (capacity !== null && (capacity.availableBytes < capacity.reserveBytes + capacity.requiredWriteBytes || capacity.availableInodes < capacity.requiredInodes)) throw new Error("transfer capacity evidence is incoherent");
    if (entry.status === "failed" && entry.exitCode === 0 && entry.before !== null && entry.after !== null && entry.observationError === null) throw new Error("failed transfer entry is success-shaped");
  }
  if (document.status === "succeeded") {
    if (document.entries.length !== 34 || JSON.stringify(document.candidateBefore) !== JSON.stringify(document.candidateAfter)) throw new Error("successful transfer lacks exact cardinality or stable candidate identity");
    if (document.entries.some((entry, index) => entry.index !== index || entry.status !== "succeeded" || entry.exitCode !== 0 || entry.stdout === null || entry.stderr === null || entry.before === null || entry.after === null || entry.observationError !== null || entry.capacityBefore === null)) throw new Error("successful transfer contains a failed, duplicate, logless, or unobserved entry");
  }
}
console.log("vm_100_execution_evidence_schema=structurally-and-semantically-valid");
