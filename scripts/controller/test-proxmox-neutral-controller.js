#!/usr/bin/env node
"use strict";
// End-to-end local check path: ssh/git are confined fixtures; no host is contacted.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync, spawnSync } = require("node:child_process");
const { canonicalJson } = require("./proxmox-host-projection");
const { fixture } = require("./test-proxmox-check-evidence");
const { sha } = require("./proxmox-check-evidence");
const ROOT = path.resolve(__dirname, "../..");
const reconcile = path.join(ROOT, ".reconcile");
fs.mkdirSync(reconcile, { recursive: true, mode: 0o700 });
const directory = fs.mkdtempSync(path.join(reconcile, "neutral-controller-test-"));
const records = [];
try {
  const template = fixture(directory);
  const key = Buffer.from("synthetic-ed25519-host-key");
  template.snapshot.host_key = "SHA256:" + crypto.createHash("sha256").update(key).digest("base64").replace(/=+$/, "");
  const snapshot = path.join(directory, "snapshot.json"); fs.writeFileSync(snapshot, canonicalJson(template.snapshot));
  const hosts = path.join(directory, "known_hosts"); fs.writeFileSync(hosts, `proxmox ssh-ed25519 ${key.toString("base64")}\n`, { mode: 0o600 });
  const bin = path.join(directory, "bin"); fs.mkdirSync(bin);
  const realGit = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\nif [ "$1" = status ]; then exit 0; fi\nexec '${realGit}' "$@"\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "ssh"), `#!/usr/bin/env python3
import datetime,json,os,sys
assert sys.argv[-2:] == ['ansible-plan@proxmox','observe-controller']
for required in ['StrictHostKeyChecking=yes','GlobalKnownHostsFile=/dev/null','UpdateHostKeys=no','HostKeyAlgorithms=ssh-ed25519']:
 assert required in sys.argv
value=json.load(open(os.environ['NEUTRAL_TEST_SNAPSHOT']))
value['nonce']=sys.stdin.read().strip()
value['observed_at']=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
if os.environ.get('NEUTRAL_TEST_DRIFT'):
 value['observation']['domains']['protectedHardware']['matches']=False
print(json.dumps(value,sort_keys=True,separators=(',',':')))
`, { mode: 0o755 });
  for (const name of ["nix", "nix-store"]) fs.writeFileSync(path.join(bin, name), "#!/bin/sh\necho forbidden-Nix-call >&2\nexit 99\n", { mode: 0o755 });
  const environment = { ...process.env, PATH: bin + path.delimiter + process.env.PATH,
    RECONCILE_PROXMOX_KNOWN_HOSTS: hosts, RECONCILE_PROXMOX_HOST_KEY_SHA256: template.snapshot.host_key, NEUTRAL_TEST_SNAPSHOT: snapshot };
  const cli = path.join(ROOT, "scripts/controller/proxmox-check-evidence.js");
  const command = (args, env = environment) => spawnSync(process.execPath, [cli, ...args], { cwd: ROOT, env, encoding: "utf8", timeout: 120000 });
  const planned = command(["collect"]);
  assert.equal(planned.status, 0, planned.stderr);
  const record = JSON.parse(planned.stdout); records.push(record.file);
  const evidence = JSON.parse(fs.readFileSync(path.join(ROOT, record.file)));
  assert.equal(evidence.scope.recap.changed, 0); assert.equal(evidence.scope.recap.ok, 2);
  const manifest = { version: 6, commit: template.commit, phase: "steady", stage: "converge", backend_bucket: "fixture",
    compose_artifact_sha256: "a".repeat(64), ansible_extra_vars_file_sha256: "", recovery_backup_identity_sha256: "",
    recovery_expectations_sha256: "", offen_retirement_operation: "", proxmox_host_check: record, plans: [] };
  for (const root of ["aws-foundation", "proxmox"]) {
    const raw = Buffer.from(`saved-binary-fixture:${root}\n`); fs.writeFileSync(path.join(directory, root + ".tfplan"), raw, { mode: 0o600 });
    manifest.plans.push({ root, file: root + ".tfplan", sha256: sha(raw), changed: false,
      tailscale_policy_before_sha256: "", tailscale_policy_after_sha256: "", tailscale_policy_etag: "" });
  }
  const manifestFile = path.join(directory, "manifest.json");
  const write = value => fs.writeFileSync(manifestFile, canonicalJson(value), { mode: 0o600 });
  write(manifest);
  assert.equal(command(["verify", manifestFile]).status, 0);
  const checked = command(["recheck", manifestFile]); assert.equal(checked.status, 0, checked.stderr);
  records.push(JSON.parse(checked.stdout).file);
  assert.equal(command(["recheck", manifestFile], { ...environment, NEUTRAL_TEST_DRIFT: "true" }).status, 66);
  for (const change of [v => { v.version = 5; }, v => { v.stage = "vm-start-prerequisite"; },
    v => { v.stage = "external-owner-prerequisite"; }, v => { v.proxmox_host_plan = { actions: 0 }; },
    v => { v.plans[0].file = "../../outside"; }, v => { v.proxmox_host_check.sha256 = "0".repeat(64); }]) {
    const invalid = structuredClone(manifest); change(invalid); write(invalid);
    assert.equal(command(["verify", manifestFile]).status, 66);
  }
  // The public wrapper's second reader invokes the same semantic validator BEFORE
  // any provider binary display/hash traversal or loading apply credentials.
  write(manifest);
  const wrapper = fs.readFileSync(path.join(ROOT, "scripts/local-controller"), "utf8");
  const start = wrapper.indexOf("verify_proxmox_host_check() {"), end = wrapper.indexOf("show_saved_plans() {", start);
  const shell = `set -euo pipefail\ncd '${ROOT}'\nmanifest='${manifestFile}'\nplan_dir='${directory}'\ncommit='${manifest.commit}'\noperation=steady\n${wrapper.slice(start, end)}\nverify_saved_plans\n`;
  const wrapperResult = spawnSync("bash", ["-c", shell], { cwd: ROOT, env: environment, encoding: "utf8" });
  assert.equal(wrapperResult.status, 0, wrapperResult.stderr);
  const invalid = structuredClone(manifest); invalid.version = 5; write(invalid);
  assert.notEqual(spawnSync("bash", ["-c", shell], { cwd: ROOT, env: environment }).status, 0);
  console.log("neutral_controller=passed real_ansible_check_both_readers_recheck_no_nix_no_hosts=true");
} finally {
  for (const file of records) fs.rmSync(path.join(ROOT, file), { force: true });
  fs.rmSync(directory, { recursive: true, force: true });
}
