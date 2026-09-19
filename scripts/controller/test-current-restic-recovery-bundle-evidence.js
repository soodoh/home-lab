#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const Ajv2020 = require("ajv/dist/2020");

const root = path.resolve(__dirname, "../..");
const evidence = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/evidence/current-restic-recovery-bundles-2026-09-19.json"), "utf8"));
const schema = JSON.parse(fs.readFileSync(path.join(root, "infrastructure/evidence/current-restic-recovery-bundles.schema.json"), "utf8"));
const validate = new Ajv2020({allErrors: true, strict: true}).compile(schema);
if (!validate(evidence)) {
  throw new Error(JSON.stringify(validate.errors));
}
if (evidence.bundle_a.ciphertext_sha256 === evidence.bundle_b.ciphertext_sha256) {
  throw new Error("current recovery bundle ciphertexts are not distinct");
}
if (evidence.scope.publication_performed || evidence.scope.bundle_decrypted || evidence.scope.restore_performed) {
  throw new Error("current recovery bundle evidence overstates executed scope");
}
console.log("current_restic_recovery_bundle_evidence=pass");
