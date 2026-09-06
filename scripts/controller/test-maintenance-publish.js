#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { aggregate, canonicalJson, sha } = require("./maintenance-report");
const { planPublication } = require("./maintenance-publish");
const { context, fixture, now, expiry, seal } = require("./test-maintenance-report");
const { buildCandidateLock } = require("./package-transaction-lock");
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const pem = publicKey.export({type:"spki",format:"pem"});
const trust = {repository:"soodoh/home-lab",source_commit:context.source_commit,contract_sha256:context.contract_sha256,public_key_pem:pem,public_key_sha256:sha(pem)};
function signed(report,registry=[],issued=now) {
  const provenance={format:"home-lab-maintenance-publication-provenance-v1",repository:trust.repository,source_commit:trust.source_commit,contract_sha256:trust.contract_sha256,issued_at:issued,expires_at:new Date(Date.parse(issued)+86400000).toISOString().replace('.000Z','Z'),collector:"existing-mac",workflow_artifact:false,report_sha256:sha(canonicalJson(report)),registry_sha256:sha(canonicalJson(registry))};
  return {report,registry,provenance,signature:crypto.sign(null,Buffer.from(canonicalJson(provenance)),privateKey).toString("base64")};
}
const report=aggregate(context,fixture(),now), input=signed(report);
const plan=planPublication(input,trust,now);
assert.equal(plan.live_send_enabled,false); assert.equal(plan.requests.length,12);
for (const r of plan.requests) { assert.equal(r.method,"POST"); assert.equal(r.path,"/repos/soodoh/home-lab/issues"); assert(!r.body.body.includes("ansible-")); }
const registry=plan.requests.map((r,i)=>({dedup_key:r.dedup_key,issue_number:i+1,content_sha256:r.content_sha256}));
assert.equal(planPublication(signed(report,registry),trust,now).requests.length,0,"unchanged content must not spam issues");
const later = new Date(Date.parse(now)+60000).toISOString().replace('.000Z','Z');
const freshRecords = fixture();
function reseal(record) {
  if (record.topic === "package") record.payload.candidate = buildCandidateLock({host:record.host,lifecycle:"production",proposal:record.payload.proposal,
    bindings:{git_commit:context.source_commit,contract_sha256:context.contract_sha256,...context.hosts[record.host],max_metadata_age_seconds:86400},
    generatedAt:record.observed_at,expiresAt:record.expires_at});
  record.payload_sha256=sha(canonicalJson(record.payload));
}
for (const record of freshRecords) {
  record.observed_at=later; record.expires_at=new Date(Date.parse(later)+86400000).toISOString().replace('.000Z','Z');
  record.evidence_sha256="a".repeat(64);
  if (record.topic === "package") { record.payload.proposal.observed_at=later; record.payload.proposal.metadata_age_seconds+=60; }
  if (record.topic === "release") { record.payload.source_generated_at=later; record.payload.source_sha256="a".repeat(64); }
  reseal(record);
}
const freshReport=aggregate(context,freshRecords,later);
assert.notEqual(freshReport.report_sha256,report.report_sha256);
assert.notEqual(freshReport.entries[0].values.transaction_sha256,report.entries[0].values.transaction_sha256);
assert.equal(planPublication(signed(freshReport,registry,later),trust,later).requests.length,0,"fresh observations of unchanged state must not PATCH");
freshRecords[0].payload.proposal.changes[0].candidate_version="3";seal(freshRecords[0].payload.proposal);reseal(freshRecords[0]);
const changedState=planPublication(signed(aggregate(context,freshRecords,later),registry,later),trust,later);
assert.equal(changedState.requests.length,1,"same counts but new candidate version must update");
assert.equal(changedState.requests[0].path,"/repos/soodoh/home-lab/issues/1");
registry[0].content_sha256="0".repeat(64);
const update=planPublication(signed(report,registry),trust,now); assert.equal(update.requests.length,1); assert.equal(update.requests[0].method,"PATCH"); assert.equal(update.requests[0].path,"/repos/soodoh/home-lab/issues/1");
for (const mutate of [i=>i.signature="A".repeat(86)+"==",i=>i.provenance.workflow_artifact=true,i=>i.provenance.collector="github",i=>i.provenance.source_commit="f".repeat(40),i=>i.provenance.repository="evil/repo",i=>i.report.automatic_apply=true,i=>i.registry.push({dedup_key:"1".repeat(64),issue_number:1,content_sha256:"2".repeat(64)})]) {
  const bad=structuredClone(input); mutate(bad); assert.throws(()=>planPublication(bad,trust,now));
}
assert.throws(()=>planPublication(input,trust,expiry),"expired attestation");
assert.throws(()=>planPublication(input,{...trust,public_key_sha256:"0".repeat(64)},now));
const stale=planPublication(signed(report,[],expiry),trust,expiry); assert(stale.requests.every(r=>r.body.body.includes("Status: stale")),"offline Mac becomes stale at consumption");
for (const mutate of [r=>r.entries[0].values={token:"private"},r=>r.entries[0].values={latest:"https://untrusted.invalid"},r=>r.entries[0].authorized=true,r=>r.entries[0].detail="@everyone",r=>r.extra="secret",r=>r.entries[0].values={latest:"0".repeat(100000)}]) {
  const bad=structuredClone(report); mutate(bad); const {report_sha256,...material}=bad; bad.report_sha256=sha(canonicalJson(material));
  assert.throws(()=>planPublication(signed(bad),trust,now));
}
assert.throws(()=>planPublication(signed(report,[registry[0],registry[0]]),trust,now));
console.log("maintenance_publish=verified signature/provenance/stale/dedup/sanitization/no-live-send");
