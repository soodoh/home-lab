#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import Ajv2020 from "ajv/dist/2020.js";

function fail(reason) {
  process.stderr.write(`offen_retirement_evidence=failed reason=${reason}\n`);
  process.exit(1);
}

if (process.argv.length < 5 || (process.argv.length - 5) % 2 !== 0) fail("usage");
const [schemaPath, evidencePath, manifestPath, ...bindings] = process.argv.slice(2);
const load = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
let schema;
let evidence;
let manifest;
try {
  schema = load(schemaPath);
  evidence = load(evidencePath);
  manifest = load(manifestPath);
} catch {
  fail("json_invalid");
}
const ajv = new Ajv2020({allErrors: true, strict: true});
if (!ajv.compile(schema)(evidence)) fail("schema_invalid");
if (evidence.manifest_sha256 !== sha256(manifestPath)) fail("manifest_hash_differs");
if (evidence.state === "retired") {
  if (JSON.stringify(evidence.preserved) !== JSON.stringify(manifest.preserve)
      || evidence.aws.version_id_sha256 !== manifest.aws.version_id_sha256
      || evidence.aws.bundle_b_before_head_sha256 !== evidence.aws.bundle_b_after_head_sha256
      || evidence.restic.restore_proof_sha256 !== manifest.restic_evidence.restore_proof_sha256) {
    fail("manifest_semantics_differ");
  }
} else if (evidence.phase === "retirement-finalizing") {
  if (evidence.bundle_b_before_head_sha256 !== evidence.bundle_b_after_head_sha256) fail("bundle_b_changed");
} else {
  fail("evidence_phase_invalid");
}
const allowed = new Map([
  ["--aws-owner", ["aws", "transaction_owner_sha256"]],
  ["--aws-journal", ["aws", "journal_sha256"]],
  ["--local-owner", ["local", "transaction_owner_sha256"]],
  ["--local-plan", ["local", "action_plan_sha256"]],
  ["--local-journal", ["local", "journal_sha256"]],
  ["--local-result", ["local", "final_result_sha256"]],
]);
const seen = new Set();
for (let index = 0; index < bindings.length; index += 2) {
  const option = bindings[index];
  const file = bindings[index + 1];
  if (!allowed.has(option) || seen.has(option)) fail("binding_arguments_invalid");
  seen.add(option);
  const [section, field] = allowed.get(option);
  if (!path.isAbsolute(file) || evidence[section][field] !== sha256(file)) fail("artifact_binding_differs");
}
process.stdout.write("offen_retirement_evidence=verified\n");
