#!/usr/bin/env node
"use strict";
// Offline bridge from the existing coverage/release reports. Only reviewed local inputs;
// never use a downloaded workflow artifact as this program's trusted input.
const { canonicalJson, sha, keys, hash, time, aggregate, HOSTS } = require("./maintenance-report");
function buildLocalInputs(context, dashboard, release, migrations) {
  hash(release?.package_manifest_sha256);
  if (release.version !== 2) throw Error("release schema rejected");
  if (dashboard.format !== "home-lab-maintenance-dashboard-v1" || dashboard.git_commit !== context.source_commit || dashboard.inputs?.contract_sha256 !== context.contract_sha256 || dashboard.automatic_apply !== false || dashboard.authorized !== false || release.format !== "home-lab-release-eol-report-v2" || release.source_commit !== context.source_commit || release.source_clean !== true || release.contract_sha256 !== context.contract_sha256 || release.package_manifest_sha256 !== dashboard.inputs.package_manifest_sha256 || release.automatic_apply !== false) throw Error("local source binding rejected");
  keys(migrations, ["source_commit", "contract_sha256", "observed_at", "hosts"]);
  if (migrations.source_commit !== context.source_commit || migrations.contract_sha256 !== context.contract_sha256) throw Error("migration source binding rejected");
  keys(migrations.hosts,HOSTS);
  const records=[];
  function add(host,topic,payload,observedAt,evidence) {
    const epoch=time(observedAt);
    const record={format:"home-lab-maintenance-input-v1",source_commit:context.source_commit,contract_sha256:context.contract_sha256,host,topic,host_key_fingerprint:context.hosts[host].host_key_fingerprint,observed_at:observedAt,expires_at:new Date(epoch+86400000).toISOString().replace('.000Z','Z'),provenance:"reviewed-local-input",evidence_sha256:sha(canonicalJson(evidence)),payload_sha256:sha(canonicalJson(payload)),payload};
    // Reuse the aggregator's strict topic validators rather than accepting free text.
    const result=aggregate(context,[record],observedAt).entries.find(e=>e.host===host&&e.topic===topic);
    if (result.status==="invalid") throw Error("local topic rejected");
    records.push(record);
  }
  for (const host of HOSTS) {
    const source=release.sources?.[host];
    if (source) add(host,"release",{current:source.current_version,latest:source.latest_version,major:Number(source.cycle),maintained:source.maintained,eol:source.eol,source_sha256:source.source_sha256,source_generated_at:new Date(source.source_generated_at).toISOString().replace('.000Z','Z')},release.observed_at,release);
    const pinSemantics = {coverage: dashboard.coverage, inputs: dashboard.inputs};
    add(host,"pins",Object.fromEntries(["cloud_image","standalone_tools","ansible_collections","opentofu_providers"].map(name=>[name,{covered:dashboard.coverage[name],sha256:sha(canonicalJson(pinSemantics))}])),dashboard.generated_at,dashboard);
    add(host,"migrations",{items:migrations.hosts[host]},migrations.observed_at,migrations);
  }
  return records;
}
if(require.main===module){
  let raw="";process.stdin.setEncoding("utf8");process.stdin.on("data",chunk=>{raw+=chunk;if(Buffer.byteLength(raw)>1048576)process.exit(65);});
  process.stdin.on("end",()=>{try{const input=JSON.parse(raw);if(raw!==canonicalJson(input))throw Error();keys(input,["context","dashboard","release","migrations"]);process.stdout.write(canonicalJson(buildLocalInputs(input.context,input.dashboard,input.release,input.migrations)));}catch{process.stderr.write("maintenance local inputs rejected\n");process.exitCode=65;}});
}
module.exports={buildLocalInputs};
