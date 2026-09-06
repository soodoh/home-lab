#!/usr/bin/env node
"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const {buildLocalInputs}=require("./maintenance-local-inputs");
const {buildReport}=require("./release-eol-report");
const {context,now}=require("./test-maintenance-report");
const {aggregate,sha,canonicalJson}=require("./maintenance-report");
const {load}=require("js-yaml");
const root=path.resolve(__dirname,"../..");
const contract=load(fs.readFileSync(path.join(root,"infrastructure/contract/home-lab.yml"),"utf8"));
const manifest=JSON.parse(fs.readFileSync(path.join(root,contract.proxmox.packages.manifest.path),"utf8"));
const sources=Object.fromEntries(["debian","proxmox"].map(host=>[host,{raw:fs.readFileSync(path.join(root,`infrastructure/maintenance/fixtures/endoflife-${host === "proxmox" ? "proxmox-ve" : host}.json`))}]));
const dashboard={format:"home-lab-maintenance-dashboard-v1",git_commit:context.source_commit,inputs:{contract_sha256:context.contract_sha256,package_manifest_sha256:contract.proxmox.packages.manifest.sha256},automatic_apply:false,authorized:false,coverage:Object.fromEntries(["cloud_image","standalone_tools","ansible_collections","opentofu_providers"].map(k=>[k,true])),generated_at:now};
const release=buildReport(contract,manifest,sources,now,{source_commit:context.source_commit,source_clean:true,contract_sha256:context.contract_sha256,package_manifest_sha256:contract.proxmox.packages.manifest.sha256});
const migrations={source_commit:context.source_commit,contract_sha256:context.contract_sha256,observed_at:now,hosts:{debian:[{major:14,issue_number:12}],proxmox:[]}};
const records=buildLocalInputs(context,dashboard,release,migrations);
assert.equal(records.length,6);assert(records.every(r=>r.provenance==="reviewed-local-input"));
assert.equal(records[0].evidence_sha256,sha(canonicalJson(release)));
const report=aggregate(context,records,now);assert.equal(report.complete,false);assert.equal(report.entries[0].status,"missing");
assert.throws(()=>buildLocalInputs(context,{...dashboard,git_commit:"f".repeat(40)},release,migrations));
assert.throws(()=>buildLocalInputs(context,dashboard,release,{...migrations,hosts:{debian:[{major:14,issue_number:12,title:"secret"}],proxmox:[]}}));
const hostile=structuredClone(release);hostile.sources.debian.latest_version="https://untrusted.invalid";assert.throws(()=>buildLocalInputs(context,dashboard,hostile,migrations));
for (const [key,value] of [["source_commit","f".repeat(40)],["contract_sha256","f".repeat(64)],["package_manifest_sha256","f".repeat(64)],["source_clean",false],["format","home-lab-release-eol-report-v1"],["version",1]]) {
  assert.throws(()=>buildLocalInputs(context,dashboard,{...release,[key]:value},migrations),key);
}
const refreshed=buildLocalInputs(context,{...dashboard,generated_at:new Date(Date.parse(now)+60000).toISOString().replace('.000Z','Z')},release,migrations);
assert.deepEqual(refreshed[1].payload,records[1].payload,"clock-only refresh must not change pin semantics");
assert.notEqual(refreshed[1].evidence_sha256,records[1].evidence_sha256,"exact observation identity must still change");
console.log("maintenance_local_inputs=verified existing-release-and-pin-bridge/no-host-promotion");
