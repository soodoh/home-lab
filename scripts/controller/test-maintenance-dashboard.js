#!/usr/bin/env node
"use strict";
const assert=require("node:assert/strict"); const fs=require("node:fs"); const path=require("node:path"); const {spawnSync}=require("node:child_process");
const root=path.resolve(__dirname,"../.."); const renovate=JSON.parse(fs.readFileSync(path.join(root,"renovate.json"))); const workflow=fs.readFileSync(path.join(root,".github/workflows/maintenance-dashboard.yml"),"utf8");
const result=spawnSync("node",[path.join(root,"scripts/controller/maintenance-dashboard.js")],{cwd:root,encoding:"utf8",env:{...process.env,MAINTENANCE_DASHBOARD_GENERATED_AT:"2026-09-03T12:00:00Z"}});
assert.equal(result.status,0,result.stderr); const report=JSON.parse(result.stdout); assert.equal(report.automatic_apply,false); assert.equal(report.authorized,false); assert.equal(report.credentials_present,false); assert(Object.values(report.coverage).every(Boolean)); assert(report.inputs.tofu_lockfiles.length>=5);
assert.equal(workflow.match(/^permissions:\n  contents: read$/m)?.[0],"permissions:\n  contents: read");
for(const forbidden of ["secrets.","ansible-playbook","ssh ","TAILSCALE","AWS_"]) assert(!workflow.includes(forbidden),`dashboard workflow contains ${forbidden}`);
assert(renovate.customManagers.some((manager)=>JSON.stringify(manager).includes("debian-trixie-generic-cloud"))); assert(renovate.packageRules.some((rule)=>JSON.stringify(rule).includes("tofu-provider")&&rule.automerge===false));
console.log("maintenance_dashboard=verified candidate_only=true");
