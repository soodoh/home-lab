#!/usr/bin/env node
"use strict";
const crypto=require("node:crypto"); const fs=require("node:fs"); const path=require("node:path"); const {execFileSync}=require("node:child_process");
const root=path.resolve(__dirname,"../..");
const sha=(raw)=>crypto.createHash("sha256").update(raw).digest("hex");
const read=(name)=>fs.readFileSync(path.join(root,name));
const renovate=JSON.parse(read("renovate.json"));
const managerText=JSON.stringify(renovate.customManagers); const rulesText=JSON.stringify(renovate.packageRules);
const coverage={
  ansible_collections:managerText.includes("ansible/collections/requirements"),
  cloud_image:managerText.includes("debian-trixie-generic-cloud")&&JSON.stringify(renovate.customDatasources||{}).includes("cloud.debian.org"),
  opentofu_providers:rulesText.includes("tofu-provider")&&fs.readdirSync(path.join(root,"infrastructure/tofu"),{recursive:true}).some((name)=>String(name).endsWith(".terraform.lock.hcl")),
  standalone_tools:["tailscale/tailscale","getsops/sops","FiloSottile/age","restic/restic"].every((name)=>read("infrastructure/contract/home-lab.yml").includes(name)||read("ansible/group_vars/docker_host.yml").includes(name)),
};
if(Object.values(coverage).includes(false)) throw new Error("maintenance candidate coverage is incomplete");
const generated=process.env.MAINTENANCE_DASHBOARD_GENERATED_AT;
if(!generated||Number.isNaN(Date.parse(generated))) throw new Error("MAINTENANCE_DASHBOARD_GENERATED_AT is required");
const report={format:"home-lab-maintenance-dashboard-v1",generated_at:new Date(generated).toISOString().replace(".000Z","Z"),git_commit:execFileSync("git",["rev-parse","HEAD"],{cwd:root,encoding:"utf8"}).trim(),automatic_apply:false,automatic_reboot:false,automatic_retry_allowed:false,authorized:false,credentials_present:false,host_collection:{status:"missing",trusted_mac_report_required:true,workflow_artifact_promotion_allowed:false},coverage,inputs:{contract_sha256:sha(read("infrastructure/contract/home-lab.yml")),renovate_sha256:sha(read("renovate.json")),tofu_lockfiles:fs.readdirSync(path.join(root,"infrastructure/tofu"),{recursive:true}).filter((name)=>String(name).endsWith(".terraform.lock.hcl")).sort().map(String)},blockers:["candidate-review-required","separate-exact-authorization-required"]};
const contract=require("js-yaml").load(read("infrastructure/contract/home-lab.yml").toString("utf8"));
report.inputs.package_manifest_sha256=sha(read(contract.proxmox.packages.manifest.path));
if(report.inputs.package_manifest_sha256!==contract.proxmox.packages.manifest.sha256) throw new Error("package manifest binding differs");
report.inputs.ansible_collections_sha256=sha(read("ansible/collections/requirements.yml"));
report.inputs.standalone_tools_sha256=sha(read("ansible/group_vars/docker_host.yml"));
report.inputs.tofu_lockfile_sha256=Object.fromEntries(report.inputs.tofu_lockfiles.map(name=>[name,sha(read("infrastructure/tofu/"+name))]));
const sort=(value)=>Array.isArray(value)?value.map(sort):value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map((key)=>[key,sort(value[key])])):value;
process.stdout.write(JSON.stringify(sort(report),null,2)+"\n");
