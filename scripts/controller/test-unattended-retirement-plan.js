#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { load } = require("js-yaml");
const { buildPlan, canonicalJson } = require("./save-unattended-retirement-plan");

const root = path.resolve(__dirname, "../..");
const contract = load(fs.readFileSync(path.join(root, "infrastructure/contract/home-lab.yml"), "utf8"));
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const files = [
  { content_base64: Buffer.from('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n').toString("base64"),
    exists: true, gid: 0, mode: "0644", path: "/etc/apt/apt.conf.d/20auto-upgrades", safe: true,
    sha256: "a".repeat(64), size: 90, uid: 0 },
  { content_base64: "", exists: true, gid: 0, mode: "0644", path: "/etc/apt/apt.conf.d/52home-lab-unattended-upgrades",
    safe: true, sha256: "b".repeat(64), size: 0, uid: 0 },
];
const units = [
  { active_state: "inactive", load_state: "loaded", name: "apt-daily.timer", unit_file_state: "enabled" },
  { active_state: "active", load_state: "loaded", name: "apt-daily-upgrade.timer", unit_file_state: "enabled" },
  { active_state: "active", load_state: "loaded", name: "unattended-upgrades.service", unit_file_state: "enabled" },
];
const material = { files, locks: [], processes: [], units };
const observation = { format: "home-lab-unattended-retirement-observation-v1", version: 1, host: "debian",
  observed_at: "2026-09-03T10:00:00Z", ...material, observation_sha256: sha(canonicalJson(material).trimEnd()) };
const bindings = { git_commit: "1".repeat(40), contract_sha256: "2".repeat(64), inventory_sha256: "3".repeat(64),
  host_key_fingerprint: `SHA256:${"A".repeat(43)}`, max_observation_age_seconds: 1800 };
const plan = buildPlan({ observation, contract, bindings, nowEpoch: Date.parse("2026-09-03T10:01:00Z") / 1000 });
assert.equal(plan.actionable, true);
assert.equal(plan.authorized, false);
assert.equal(plan.automatic_apply, false);
assert.equal(plan.package_removal, false);
assert.deepEqual(plan.blockers, ["separate-exact-authorization-required"]);
assert(plan.desired.units.every((unit) => unit.active_state === "inactive" && unit.unit_file_state === "masked"));
assert.equal(Buffer.from(plan.desired.periodic_file.content_base64, "base64").toString(), contract.lifecycle.maintenance.unattended_upgrade_retirement.periodic_file.content);
assert.deepEqual(plan.rollback.files, files);
assert.match(plan.plan_sha256, /^[0-9a-f]{64}$/);
const active = structuredClone(observation);
active.processes.push({ command: "apt-get", pid: 42 });
active.observation_sha256 = sha(canonicalJson({ files: active.files, locks: active.locks, processes: active.processes, units: active.units }).trimEnd());
assert(buildPlan({ observation: active, contract, bindings, nowEpoch: Date.parse("2026-09-03T10:01:00Z") / 1000 }).blockers.includes("active-package-process"));
const tampered = structuredClone(observation);
tampered.units[0].active_state = "active";
assert.throws(() => buildPlan({ observation: tampered, contract, bindings, nowEpoch: Date.parse("2026-09-03T10:01:00Z") / 1000 }), /hash differs/);
assert.throws(() => buildPlan({ observation, contract, bindings, nowEpoch: Date.parse("2026-09-03T11:00:00Z") / 1000 }), /stale/);
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "unattended-transaction-"));
try {
  const planPath = path.join(temporary, "plan.json");
  fs.writeFileSync(planPath, canonicalJson(plan));
  const transactionPath = path.join(root, "infrastructure/maintenance/host/unattended-retirement-transaction");
  const python = String.raw`import datetime as dt,importlib.machinery,importlib.util,json,pathlib,sys
loader=importlib.machinery.SourceFileLoader("transaction",sys.argv[1]); spec=importlib.util.spec_from_loader("transaction",loader); module=importlib.util.module_from_spec(spec); loader.exec_module(module)
plan=json.loads(pathlib.Path(sys.argv[2]).read_bytes()); raw=module.canonical(plan)
module.validate_plan(plan,raw,plan["plan_sha256"],dt.datetime.fromisoformat("2026-09-03T10:02:00+00:00"))
try: module.validate_plan({**plan,"authorized":True},raw,plan["plan_sha256"],dt.datetime.fromisoformat("2026-09-03T10:02:00+00:00")); raise AssertionError("accepted")
except RuntimeError: pass
print("transaction_validation=verified")`;
  const result = spawnSync("python3", ["-c", python, transactionPath, planPath], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "transaction_validation=verified");
  const transaction = fs.readFileSync(transactionPath, "utf8");
  for (const required of ["fcntl.LOCK_EX | fcntl.LOCK_NB", "status\": \"applying", "status\"] = \"rolled-back\"",
    "os.O_EXCL | os.O_NOFOLLOW", "os.fsync", "stop_and_mask", "restore_unit", "live precondition differs",
    "retirement postcondition differs", "separate-exact-authorization-required"]) {
    assert(transaction.includes(required), `retirement transaction omits ${required}`);
  }
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
const source = fs.readFileSync(path.join(root, "infrastructure/maintenance/host/unattended-retirement-observer"), "utf8");
for (const required of ["os.O_NOFOLLOW", "os.fstat", "st_nlink != 1", "apt-daily-upgrade.timer", "unattended-upgrades.service", "lslocks", "processes"]) {
  assert(source.includes(required), `retirement observer omits ${required}`);
}
for (const forbidden of ["systemctl\", \"stop", "systemctl\", \"disable", "systemctl\", \"mask", "apt-get\", \"remove", "os.unlink", "os.replace"]) {
  assert(!source.includes(forbidden), `retirement observer contains mutation ${forbidden}`);
}
console.log("unattended_retirement_plan=verified transaction=verified");
