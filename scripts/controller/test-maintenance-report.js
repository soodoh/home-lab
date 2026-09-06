#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { aggregate, canonicalJson, sha, FLAGS, HOSTS, TOPICS } = require("./maintenance-report");
const { buildCandidateLock } = require("./package-transaction-lock");
const now = "2026-09-05T12:00:00Z", expiry = "2026-09-06T12:00:00Z";
const context = { source_commit: "a".repeat(40), contract_sha256: "b".repeat(64), hosts: Object.fromEntries(HOSTS.map(h => [h, { inventory_sha256: "c".repeat(64), host_key_fingerprint: `SHA256:${"A".repeat(43)}` }])) };
function proposal(host) {
  const p = { version: 2, host, observed_at: now, metadata_refresh_performed: false, metadata_newest_path: "/var/lib/apt/lists/fixture", metadata_mtime_epoch: Date.parse(now)/1000 - 120, metadata_age_seconds: 120,
    installed_inventory_format: "dpkg-query-status-tsv-v1", installed_records: 100, installed_inventory_sha256: "d".repeat(64), installed_package_records: 100, installed_status_sha256: "e".repeat(64), expected_manifest_records: 100, expected_manifest_sha256: "f".repeat(64), manifest_matches: true,
    solver: { command: "apt-get-simulate", returncode: 0, stdout_sha256: "1".repeat(64), stderr_sha256: "2".repeat(64) }, holds: [], kept_back: [], download_bytes: 1024, disk_delta_bytes: 512, apt_tree_safe: true, apt_unsafe_paths: [], size_parse_complete: true, active_lifecycle_locks: [],
    apt_state_hashes: { configuration_sha256: "3".repeat(64), keyrings_sha256: "4".repeat(64), sources_sha256: "5".repeat(64) }, change_counts: { install: 0, upgrade: 1, downgrade: 0, remove: 0 }, security_changes: 1,
    changes: [{ action: "upgrade", name: "fixture", previous_version: "1", candidate_version: "2", origin: "Debian-Security", policy_sha256: "6".repeat(64), security: true }] };
  seal(p); return p;
}
function seal(p) {
  const names = ["host", "installed_inventory_sha256", "metadata_mtime_epoch", "holds", "changes", "installed_status_sha256", "expected_manifest_sha256", "manifest_matches", "apt_state_hashes", "apt_tree_safe", "apt_unsafe_paths", "active_lifecycle_locks", "kept_back", "download_bytes", "disk_delta_bytes", "size_parse_complete"];
  const m = Object.fromEntries(names.map(n => [n,p[n]])); m.solver_stdout_sha256 = p.solver.stdout_sha256;
  p.proposal_sha256 = sha(canonicalJson(m, false).trimEnd());
}
function record(host, topic, payload, provenance = "reviewed-local-input") {
  return { format: "home-lab-maintenance-input-v1", source_commit: context.source_commit, contract_sha256: context.contract_sha256, host, topic, host_key_fingerprint: context.hosts[host].host_key_fingerprint, observed_at: now, expires_at: expiry, provenance, evidence_sha256: "9".repeat(64), payload_sha256: sha(canonicalJson(payload)), payload };
}
function fixture() {
  return HOSTS.flatMap(host => {
    const p = proposal(host), candidate = buildCandidateLock({host, lifecycle:"production", proposal:p, bindings:{git_commit:context.source_commit,contract_sha256:context.contract_sha256,...context.hosts[host],max_metadata_age_seconds:86400},generatedAt:now,expiresAt:expiry});
    return [record(host,"package",{proposal:p,candidate},"challenge-verified"), record(host,"reboot",{required:true,backup_proven:false},"challenge-verified"),
      record(host,"release",{current:"13.1",latest:"13.2",major:13,maintained:true,eol:"2028-01-01",source_sha256:"8".repeat(64),source_generated_at:now}),
      record(host,"pins",Object.fromEntries(["cloud_image","standalone_tools","ansible_collections","opentofu_providers"].map(k=>[k,{covered:true,sha256:"7".repeat(64)}]))),
      record(host,"migrations",{items:[{major:14,issue_number:42}]})];
  });
}
function run() {
  const records = fixture(), report = aggregate(context,records,now);
  assert.equal(report.complete,true); assert.equal(report.entries.length,12);
  for (const entry of [report,...report.entries]) for (const key of Object.keys(FLAGS)) assert.equal(entry[key],false);
  for (const host of HOSTS) for (const topic of TOPICS) {
    const result = aggregate(context, records.filter(r => !(r.host===host&&r.topic===topic)), now);
    assert.equal(result.complete,false); assert.equal(result.entries.find(e=>e.host===host&&e.topic===topic).status,"missing");
  }
  for (const [field,value] of [["source_commit","f".repeat(40)],["contract_sha256","f".repeat(64)],["host_key_fingerprint",`SHA256:${"B".repeat(43)}`],["observed_at","2026-09-05T12:00:01Z"],["payload_sha256","0".repeat(64)],["expires_at","2026-09-08T12:00:00Z"]]) {
    const bad=structuredClone(records); bad[0][field]=value;
    assert.equal(aggregate(context,bad,now).entries[0].status,"invalid",field);
  }
  const wrongHost=structuredClone(records); wrongHost[0].payload.proposal.host="proxmox"; wrongHost[0].payload_sha256=sha(canonicalJson(wrongHost[0].payload));
  assert.equal(aggregate(context,wrongHost,now).entries[0].status,"invalid");
  assert.equal(aggregate(context,records,expiry).entries[0].status,"stale");
  const stale=structuredClone(records); stale[0].payload.proposal.metadata_mtime_epoch-=86400; stale[0].payload.proposal.metadata_age_seconds+=86400; seal(stale[0].payload.proposal); stale[0].payload.candidate=null; stale[0].payload_sha256=sha(canonicalJson(stale[0].payload));
  assert.equal(aggregate(context,stale,now).entries[0].detail,"apt-metadata-stale");
  const failed=structuredClone(records); failed[0]=record("debian","package",{failure:"transport-failed"},"failed-collection");
  assert.equal(aggregate(context,failed,now).entries[0].status,"failed");
  for (const inject of [p=>p.password="private", p=>p.changes[0].origin="https://token@example.invalid", p=>p.metadata_refresh_performed=true]) {
    const bad=structuredClone(records); inject(bad[0].payload.proposal); bad[0].payload_sha256=sha(canonicalJson(bad[0].payload));
    assert.equal(aggregate(context,bad,now).entries[0].status,"invalid");
  }
  const unknown=structuredClone(records); unknown[1].payload.required=null; unknown[1].payload_sha256=sha(canonicalJson(unknown[1].payload));
  assert.equal(aggregate(context,unknown,now).entries[1].detail,"reboot-observation-unknown");
  assert.throws(()=>aggregate(context,[...records,records[0]],now));
  assert.throws(()=>aggregate(context,[record("debian","pins",{x:"x".repeat(1048576)})],now));
  const changed=structuredClone(records); changed[4].payload.items[0].major=15; changed[4].payload_sha256=sha(canonicalJson(changed[4].payload));
  const changedReport=aggregate(context,changed,now);
  assert.equal(changedReport.entries[4].dedup_key,report.entries[4].dedup_key);
  assert.notEqual(changedReport.entries[5].dedup_key,report.entries[5].dedup_key);
  const input=canonicalJson({context,records,observed_at:now});
  let process=spawnSync("node",[require.resolve("./maintenance-report")],{input,encoding:"utf8"}); assert.equal(process.status,0,process.stderr);
  process=spawnSync("node",[require.resolve("./maintenance-report")],{input:input.replace('"observed_at":','"observed_at":"duplicate","observed_at":'),encoding:"utf8"}); assert.notEqual(process.status,0);
  console.log("maintenance_report=verified fresh/missing/stale/partial/binding/dedup/non-authorizing");
}
if (require.main === module) run();
module.exports={context,fixture,now,expiry,proposal,record,seal};
