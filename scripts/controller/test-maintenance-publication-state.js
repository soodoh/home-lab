#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const Ajv = require("ajv");
const { modelPublication, MODEL_FLAGS } = require("./maintenance-publication-state");
const schema = require("../../infrastructure/maintenance/publication-state.schema.json");
const { aggregate, canonicalJson, sha } = require("./maintenance-report");
const { planPublication } = require("./maintenance-publish");
const { context, fixture, now, expiry, record } = require("./test-maintenance-report");
const validSchema = new Ajv({ strict: true }).compile(schema);
const sourcePath = require.resolve("./maintenance-publication-state");
const source = fs.readFileSync(sourcePath, "utf8");
const localRequire = createRequire(sourcePath);
const clone = v => JSON.parse(canonicalJson(v));
const hash = v => sha(canonicalJson(v));
const fmt = name => `synthetic-only-non-operational-${name}-v1`;
// Keys never leave this process; they are unrelated to operational custody.
const publicationKeys = crypto.generateKeyPairSync("ed25519");
const stateKeys = crypto.generateKeyPairSync("ed25519");
const pem = key => key.export({ type: "spki", format: "pem" });
const sign = (value, key = stateKeys.privateKey) => crypto.sign(null, Buffer.from(canonicalJson(value)), key).toString("base64");
const base = Date.parse(now), end = Date.parse(expiry);
const trust = { repository: "soodoh/home-lab", source_commit: context.source_commit, contract_sha256: context.contract_sha256,
  public_key_pem: pem(publicationKeys.publicKey), public_key_sha256: sha(pem(publicationKeys.publicKey)) };
const report = aggregate(context, fixture(), now);
let serial = 0, tick = base + 1000;
function clock(stage, execution, predecessor, at = (tick += 10)) {
  return { format: fmt("time-check"), profile: "fixture-profile", epoch: "fixture-clock-epoch", execution,
    challenge: sha(`challenge-${++serial}`), stage, predecessor, independent: true, elapsed_supported: true,
    reset: false, resumed: false, lower_ms: at - 1, upper_ms: at - 1, elapsed_start_ms: 10, elapsed_end_ms: 11 };
}
function eventRow(type, payload, input = null) {
  const generation = input ? input.store.current_generation + 1 : 0;
  const event = { format: fmt("publication-event"), flags: MODEL_FLAGS, epoch: "fixture-journal-epoch", generation,
    predecessor: input?.store.current_head ?? null, type, payload };
  return { key: String(generation).padStart(3,"0"), event, signature: sign(event), execution: null, initiation: null };
}
const profile = { format: fmt("elapsed-profile"), identity: "fixture-profile", epoch: "fixture-clock-epoch", independent: true,
  elapsed_supported: true, max_width_ms: 1000, max_elapsed_ms: 1000, drift_ms: 0 };
function initial(registry = []) {
  const row = eventRow("genesis", { registry: clone(registry), heartbeat_issue_number: 999, clock_floor_ms: base, profile_sha256: hash(profile) });
  return { format: fmt("publication-model"), flags: MODEL_FLAGS,
    pins: { epoch: "fixture-journal-epoch", store_identity: "fixture-store", genesis_sha256: hash(row.event), publication_trust: trust,
      state_public_key_pem: pem(stateKeys.publicKey), state_public_key_sha256: sha(pem(stateKeys.publicKey)),
      profile },
    store: { format: fmt("store-assertion"), identity: "fixture-store", complete: true, single_version: true,
      current_generation: 0, current_head: hash(row.event), current_journal_sha256: hash([row]), rows: [row] }, attempt: null };
}
function envelope(r, registry) {
  const provenance = { format: "home-lab-maintenance-publication-provenance-v1", repository: trust.repository,
    source_commit: trust.source_commit, contract_sha256: trust.contract_sha256, issued_at: r.observed_at, expires_at: r.expires_at,
    collector: "existing-mac", workflow_artifact: false, report_sha256: hash(r), registry_sha256: hash(registry) };
  return { report: clone(r), registry: clone(registry), provenance, signature: sign(provenance, publicationKeys.privateKey) };
}
function propose(input, row, append = "won") {
  return { ...clone(input), attempt: { format: fmt("conditional-append"), append_result: append, row } };
}
function candidate(input, r = report, overrides = {}) {
  const projected = modelPublication({ ...input, attempt: null });
  assert.notEqual(projected.status, "rejected", projected.reason);
  const execution = `execution-${++serial}`, predecessor = input.store.current_head;
  const env = envelope(r, projected.registry);
  const material = { format: fmt("publication-companion"), flags: MODEL_FLAGS, repository: trust.repository,
    source_commit: trust.source_commit, contract_sha256: trust.contract_sha256, epoch: input.pins.epoch,
    generation: input.store.current_generation, state_sha256: predecessor, registry_sha256: hash(env.registry),
    provenance_sha256: hash(env.provenance), signature_sha256: sha(env.signature), intake_id: `intake-${hash(r).slice(0,16)}`,
    admission_expires_ms: Date.parse(r.expires_at), expires_ms: Date.parse(r.expires_at), ...overrides };
  const payload = { execution, checks: ["admission", "provenance-sign", "companion-sign", "plan"].map(s => clock(s, execution, predecessor)),
    envelope: env, companion: { material, signature: sign(material) } };
  return propose(input, eventRow("candidate", payload, input));
}
function installed(input, result = modelPublication(input)) {
  assert(result.journal.length > 0);
  return { ...clone(input), attempt: null, store: { ...clone(input.store), rows: clone(result.journal),
    current_generation: result.generation, current_head: result.head, current_journal_sha256: hash(result.journal) } };
}
function progress(input) {
  const intentRow = input.store.rows.at(-1), intent = intentRow.event, execution = intent.payload.execution;
  let request;
  if (intent.type === "candidate") {
    request = planPublication(intent.payload.envelope, trust, new Date(tick).toISOString().replace(/\.\d{3}Z$/, "Z")).requests[0];
  } else {
    const body = { title: "[maintenance] synthetic publisher heartbeat",
      body: `SYNTHETIC ONLY / NON-OPERATIONAL. Historical candidate issues are not fresh authority.\n${canonicalJson(intent.payload.statement)}` };
    request = { method: "PATCH", path: "/repos/soodoh/home-lab/issues/999", body, content_sha256: hash(body) };
  }
  const row = eventRow("progress", { execution, checks: [clock("progress-sign", execution, input.store.current_head)],
    intent_sha256: hash(intent), request_sha256: hash(request) }, input);
  row.execution = { id: execution, started_at_head: intent.predecessor, running: true, reconstructed: false,
    intent_ack: hash(intent), progress_ack: hash(row.event) };
  row.initiation = clock("initiation", execution, hash(row.event));
  return propose(input, row);
}
function outcome(input, dispatch, number = 1) {
  const execution = input.store.rows.at(-1).event.payload.execution;
  return propose(input, eventRow("outcome", { execution, checks: [clock("outcome-sign", execution, input.store.current_head)],
    intent_sha256: dispatch.intent_sha256, response: { format: fmt("response"), authenticated_in_model: true,
      repository: "soodoh/home-lab", request_sha256: hash(dispatch.request), content_sha256: dispatch.request.content_sha256,
      issue_number: number, completion: "confirmed" } }, input));
}
function heartbeat(input, at = null) {
  const s = modelPublication(input), execution = `monitor-${++serial}`;
  const c = clock("heartbeat-sign", execution, s.head, at ?? (tick += 10));
  const later = clock("heartbeat-plan", execution, s.head, c.lower_ms + 11);
  const a = s.last_acceptance, upper = c.upper_ms + 1;
  const stale = a && (upper >= Date.parse(a.expires_at) || a.slots.some(slot => slot.expires_at !== null && upper >= Date.parse(slot.expires_at)));
  const classification = !a ? "never-received" : stale ? "stale" : a.slots.some(slot => slot.freshness !== "fresh" || slot.status !== "blocked") ? "partial/failed" : "within-recorded-deadline";
  const statement = { format: fmt("publisher-heartbeat"), flags: MODEL_FLAGS, epoch: input.pins.epoch,
    generation: s.generation, state_sha256: s.head, checked_at_ms: c.lower_ms + 1, expires_ms: c.lower_ms + 1 + 7200000,
    last_acceptance_sha256: a?.event_sha256 ?? null, classification, slots: a?.slots ?? [] };
  return propose(input, eventRow("heartbeat", { execution, checks: [c,later], statement }, input));
}
function reseal(input) {
  const row = input.attempt.row;
  if (row.event.type === "candidate") {
    const p = row.event.payload, env = p.envelope;
    const { report_sha256, ...r } = env.report;
    env.report.report_sha256 = hash(r);
    env.provenance.report_sha256 = hash(env.report); env.provenance.registry_sha256 = hash(env.registry);
    env.signature = sign(env.provenance, publicationKeys.privateKey);
    p.companion.material.provenance_sha256 = hash(env.provenance);
    p.companion.material.signature_sha256 = sha(env.signature);
    p.companion.signature = sign(p.companion.material);
  }
  row.signature = sign(row.event);
  if (row.event.type === "progress") {
    row.execution.progress_ack = hash(row.event);
    if (row.initiation) row.initiation.predecessor = hash(row.event);
  }
  return input;
}
const focused = [];
function negative(name, positive, mutate, reason, mutant = true) {
  const good = modelPublication(positive);
  assert.equal(good.reason, null, `${name}: positive control: ${good.reason}`);
  const bad = clone(positive); mutate(bad);
  if (reason !== "store-journal-binding") bad.store.current_journal_sha256 = hash(bad.store.rows);
  assert.equal(modelPublication(bad).reason, reason, name);
  focused.push({ name, positive: clone(positive), bad, reason, mutant });
  return bad;
}
const genesis = initial(), candidateInput = candidate(genesis);
const reservedResult = modelPublication(candidateInput);
assert.equal(reservedResult.status, "retained");
assert(reservedResult.last_acceptance && reservedResult.retained_intent);
assert.equal(reservedResult.modeled_dispatch, null);
const reserved = installed(candidateInput, reservedResult);
const progressInput = progress(reserved), sent = modelPublication(progressInput);
assert.equal(sent.status, "modeled-dispatch", sent.reason);
assert.equal(sent.modeled_dispatch.request.method, "POST");
assert(sent.clock_floor_ms > reservedResult.clock_floor_ms);
const dispatched = installed(progressInput, sent);
assert.equal(modelPublication(dispatched).modeled_dispatch, null, "reconstruction only projects; never sends");
const outcomeInput = outcome(dispatched, sent.modeled_dispatch), confirmed = modelPublication(outcomeInput);
assert.equal(confirmed.status, "committed", confirmed.reason);
assert.equal(confirmed.registry.length, 1); assert.equal(confirmed.registry[0].issue_number, 1);
assert.equal(confirmed.retained_intent, null);
const completed = installed(outcomeInput, confirmed);
// Complete the actual fixture through the old planner, one binding per generation.
let all = completed;
for (let i = 2; i <= 12; i++) {
  const c = candidate(all), reserved = installed(c);
  const p = progress(reserved), sent = modelPublication(p); assert.equal(sent.status, "modeled-dispatch", sent.reason);
  const o = outcome(installed(p, sent), sent.modeled_dispatch, i), done = modelPublication(o);
  assert.equal(done.status, "committed", done.reason); all = installed(o, done);
}
const dedup = candidate(all), dedupResult = modelPublication(dedup);
assert.equal(dedupResult.status, "committed", dedupResult.reason);
assert.equal(dedupResult.registry.length, 12); assert.equal(dedupResult.retained_intent, null);
assert.equal(dedupResult.modeled_dispatch, null);
assert.equal(planPublication(dedup.attempt.row.event.payload.envelope, trust, now).requests.length, 0);
all = installed(dedup, dedupResult);
const monitoring = heartbeat(all), hbResult = modelPublication(monitoring);
assert.equal(hbResult.status, "retained", hbResult.reason);
assert.equal(monitoring.attempt.row.event.payload.statement.classification, "within-recorded-deadline");
const hp = progress(installed(monitoring, hbResult)), hs = modelPublication(hp);
assert.equal(hs.status, "modeled-dispatch", hs.reason);
assert.equal(hs.modeled_dispatch.request.path, "/repos/soodoh/home-lab/issues/999");
const ho = outcome(installed(hp, hs), hs.modeled_dispatch, 999), hd = modelPublication(ho);
assert.equal(hd.status, "committed", hd.reason); assert.deepEqual(hd.registry, dedupResult.registry);
assert.equal(heartbeat(genesis).attempt.row.event.payload.statement.classification, "never-received");
assert.equal(modelPublication(heartbeat(genesis)).status, "retained");
const sleeping = heartbeat(all, end + 86400000);
assert.equal(modelPublication(sleeping).status, "retained");
assert.equal(sleeping.attempt.row.event.payload.statement.classification, "stale");
assert(!canonicalJson(sleeping.attempt.row.event.payload.statement).includes("candidate_semantics"));
assert.deepEqual(sleeping.attempt.row.event.payload.statement.slots, modelPublication(all).last_acceptance.slots);

// Companion and slot horizons are independently shorter than whole-report
// authority. Re-sign each proposal so expiry refusals cannot be signature failures.
const shortDeadline = base + 60000;
const shortCompanion = candidate(genesis, report, { expires_ms: shortDeadline });
negative("short companion exact expiry with current envelope", shortCompanion, b => {
  const c = b.attempt.row.event.payload.checks[3];
  c.lower_ms = shortDeadline - 1; c.upper_ms = shortDeadline - 1; reseal(b);
}, "admission-expiry");
const cappedAdmission = clone(shortCompanion);
cappedAdmission.attempt.row.event.payload.envelope.provenance.expires_at = "2026-09-05T12:02:00Z";
cappedAdmission.attempt.row.event.payload.companion.material.admission_expires_ms = base + 120000;
reseal(cappedAdmission);
negative("admission cannot outlive current report", cappedAdmission, b => {
  const p = b.attempt.row.event.payload;
  p.envelope.provenance.issued_at = "2026-09-05T12:00:01Z";
  p.envelope.provenance.expires_at = "2026-09-06T12:00:01Z";
  p.companion.material.admission_expires_ms = end + 1000; reseal(b);
}, "admission-cap");
const shortRecords = fixture();
const shortRecord = shortRecords.find(r => r.host === "debian" && r.topic === "reboot");
shortRecord.expires_at = "2026-09-05T12:01:00Z";
const shortReport = aggregate(context, shortRecords, now);
assert.equal(shortReport.entries[1].observed_at, shortRecord.observed_at);
assert.equal(shortReport.entries[1].expires_at, shortRecord.expires_at);
const shortSlot = candidate(genesis, shortReport);
negative("short fresh slot exact expiry with current envelope", shortSlot, b => {
  const c = b.attempt.row.event.payload.checks[3];
  c.lower_ms = shortDeadline - 1; c.upper_ms = shortDeadline - 1; reseal(b);
}, "slot-expiry");

// Binding negatives are re-signed when necessary to reach the intended guard.
negative("alternate predecessor", candidateInput, b => { b.attempt.row.event.predecessor = "0".repeat(64); reseal(b); }, "event-predecessor");
negative("alternate generation", candidateInput, b => { b.attempt.row.event.generation++; reseal(b); }, "event-generation");
negative("alternate epoch", candidateInput, b => { b.attempt.row.event.epoch = "another"; reseal(b); }, "event-epoch");
negative("journal key", candidateInput, b => { b.attempt.row.key = "002"; }, "event-generation");
negative("event signature", candidateInput, b => { b.attempt.row.signature = "A".repeat(86) + "=="; }, "signature");
negative("state key", candidateInput, b => { b.pins.state_public_key_pem = trust.public_key_pem; }, "key-pin", false);
negative("different pinned key", candidateInput, b => { const k = crypto.generateKeyPairSync("ed25519"); b.pins.state_public_key_pem = pem(k.publicKey); b.pins.state_public_key_sha256 = sha(b.pins.state_public_key_pem); }, "signature");
negative("companion original predecessor", candidateInput, b => { b.attempt.row.event.payload.companion.material.state_sha256 = "0".repeat(64); reseal(b); }, "companion-predecessor");
negative("companion generation", candidateInput, b => { b.attempt.row.event.payload.companion.material.generation++; reseal(b); }, "companion-predecessor");
negative("companion source", candidateInput, b => { b.attempt.row.event.payload.companion.material.source_commit = "f".repeat(40); reseal(b); }, "companion-source");
negative("companion signature", candidateInput, b => { b.attempt.row.event.payload.companion.signature = "A".repeat(86) + "=="; b.attempt.row.signature = sign(b.attempt.row.event); }, "signature");
negative("companion envelope", candidateInput, b => { b.attempt.row.event.payload.companion.material.signature_sha256 = "0".repeat(64); b.attempt.row.event.payload.companion.signature = sign(b.attempt.row.event.payload.companion.material); b.attempt.row.signature = sign(b.attempt.row.event); }, "companion-envelope");
negative("registry binding", candidateInput, b => { b.attempt.row.event.payload.companion.material.registry_sha256 = "0".repeat(64); reseal(b); }, "companion-registry");
negative("future observation at each boundary", candidateInput, b => {
  const c = b.attempt.row.event.payload.checks[0]; c.lower_ms = base - 2; c.upper_ms = base - 2;
  b.store.rows[0].event.payload.clock_floor_ms = base - 100;
  const g = b.store.rows[0]; g.signature = sign(g.event); b.pins.genesis_sha256 = hash(g.event); b.store.current_head = hash(g.event);
  b.attempt.row.event.predecessor = b.store.current_head;
  b.attempt.row.event.payload.companion.material.state_sha256 = b.store.current_head;
  for (const c of b.attempt.row.event.payload.checks) c.predecessor = b.store.current_head;
  for (const e of b.attempt.row.event.payload.envelope.report.entries) {
    e.observed_at = new Date(base - 1000).toISOString().replace(".000Z", "Z");
    if (e.values.source_generated_at) e.values.source_generated_at = e.observed_at;
    e.expires_at = new Date(end - 1000).toISOString().replace(".000Z", "Z");
  }
  reseal(b);
}, "time-future");
for (const index of [0,1,2,3]) {
  negative(`independent check stage ${index}`, candidateInput, b => { b.attempt.row.event.payload.checks[index].independent = false; reseal(b); }, "time-qualification");
}
negative("missing external profile", candidateInput, b => { b.pins.profile = null; }, "time-profile", false);
negative("unqualified elapsed profile", candidateInput, b => { b.pins.profile.elapsed_supported = false; }, "time-profile", false);
negative("same-name profile parameter change", candidateInput, b => { b.pins.profile.max_elapsed_ms = 999; }, "genesis-profile");
negative("profile rotation", candidateInput, b => { b.attempt.row.event.payload.checks[0].profile = "other"; reseal(b); }, "time-profile-binding");
negative("clock epoch reset", candidateInput, b => { b.attempt.row.event.payload.checks[0].epoch = "other"; reseal(b); }, "time-profile-binding");
negative("resume", candidateInput, b => { b.attempt.row.event.payload.checks[0].resumed = true; reseal(b); }, "time-qualification");
negative("reset", candidateInput, b => { b.attempt.row.event.payload.checks[0].reset = true; reseal(b); }, "time-qualification");
negative("frozen elapsed", candidateInput, b => { b.attempt.row.event.payload.checks[0].elapsed_end_ms = 10; reseal(b); }, "time-elapsed");
negative("slow elapsed", candidateInput, b => { b.attempt.row.event.payload.checks[3].elapsed_end_ms = 2000; reseal(b); }, "time-elapsed");
negative("unsupported drift width", candidateInput, b => { b.attempt.row.event.payload.checks[3].upper_ms += 1001; reseal(b); }, "time-uncertainty");
negative("challenge replay", candidateInput, b => { const c = b.attempt.row.event.payload.checks; c[1].challenge = c[0].challenge; reseal(b); }, "time-replay");
negative("foreign clock execution", candidateInput, b => { b.attempt.row.event.payload.checks[0].execution = "foreign"; reseal(b); }, "time-context");
negative("wrong clock predecessor", candidateInput, b => { b.attempt.row.event.payload.checks[0].predecessor = "0".repeat(64); reseal(b); }, "time-context");
negative("ordered provisional checks", candidateInput, b => { const c = b.attempt.row.event.payload.checks; c[1].lower_ms = c[0].lower_ms - 1; c[1].upper_ms = c[0].upper_ms - 1; reseal(b); }, "time-rollback");
negative("fresh-run rollback against durable floor", candidate(completed), b => {
  for (const [i,c] of b.attempt.row.event.payload.checks.entries()) { c.lower_ms = base + 100 + i * 10; c.upper_ms = c.lower_ms; } reseal(b);
}, "time-rollback");
// Isolate expiry from the unchanged planner's own refusal using the final check:
// progress is still valid and committed; only post-persistence initiation expires.
negative("exact final expiry", progressInput, b => { const c = b.attempt.row.initiation; c.lower_ms = end - 1; c.upper_ms = end - 1; }, "time-expiry", false);
negative("uncertainty crossing final expiry", progressInput, b => { const c = b.attempt.row.initiation; c.lower_ms = end - 11; c.upper_ms = end; }, "time-expiry", false);
negative("slow/frozen runner independent time beyond expiry", progressInput, b => { const c = b.attempt.row.initiation; c.lower_ms = end + 1000; c.upper_ms = end + 1000; }, "time-expiry", false);
negative("missing final check retains committed progress", progressInput, b => { b.attempt.row.initiation = null; }, "time-missing-initiation", false);
negative("post-persistence stalled elapsed", progressInput, b => { b.attempt.row.initiation.elapsed_end_ms = 10; }, "time-elapsed");
negative("post-persistence restart", progressInput, b => { b.attempt.row.initiation.resumed = true; }, "time-qualification");
negative("post-persistence clock replay", progressInput, b => { b.attempt.row.initiation.challenge = b.attempt.row.event.payload.checks[0].challenge; }, "time-replay");
negative("foreign owner", progressInput, b => { b.attempt.row.execution.id = "foreign"; }, "execution-owner");
negative("reconstructed runner", progressInput, b => { b.attempt.row.execution.reconstructed = true; }, "execution-continuity");
negative("stopped originating runner", progressInput, b => { b.attempt.row.execution.running = false; }, "execution-continuity");
negative("lost winning intent acknowledgement", progressInput, b => { b.attempt.row.execution.intent_ack = null; }, "execution-ack");
negative("lost progress acknowledgement", progressInput, b => { b.attempt.row.execution.progress_ack = null; }, "execution-ack");
negative("rebound origin head", progressInput, b => { b.attempt.row.execution.started_at_head = b.store.current_head; }, "execution-owner");
negative("progress intent", progressInput, b => { b.attempt.row.event.payload.intent_sha256 = "0".repeat(64); reseal(b); }, "progress-intent");
negative("progress exact body", progressInput, b => { b.attempt.row.event.payload.request_sha256 = "0".repeat(64); reseal(b); }, "progress-request");
negative("unknown POST outcome", outcomeInput, b => { b.attempt.row.event.payload.response.completion = "unknown"; reseal(b); }, "outcome-unknown");
negative("unauthenticated outcome", outcomeInput, b => { b.attempt.row.event.payload.response.authenticated_in_model = false; reseal(b); }, "outcome-unknown");
negative("outcome body", outcomeInput, b => { b.attempt.row.event.payload.response.content_sha256 = "0".repeat(64); reseal(b); }, "outcome-content");
negative("outcome request", outcomeInput, b => { b.attempt.row.event.payload.response.request_sha256 = "0".repeat(64); reseal(b); }, "outcome-content");
negative("outcome alternate intent", outcomeInput, b => { b.attempt.row.event.payload.intent_sha256 = "0".repeat(64); reseal(b); }, "outcome-intent");
negative("outcome foreign execution", outcomeInput, b => { b.attempt.row.event.payload.execution = "other"; b.attempt.row.event.payload.checks[0].execution = "other"; reseal(b); }, "outcome-intent");
negative("heartbeat issue ownership", outcomeInput, b => { b.attempt.row.event.payload.response.issue_number = 999; reseal(b); }, "registry-number-or-heartbeat");
negative("heartbeat historical binding", monitoring, b => { b.attempt.row.event.payload.statement.last_acceptance_sha256 = null; reseal(b); }, "heartbeat-binding");
negative("heartbeat issue response", ho, b => { b.attempt.row.event.payload.response.issue_number = 998; reseal(b); }, "outcome-issue");

const savedTick = tick;
const nearDeadlineHeartbeat = heartbeat(all, end - 1000);
assert.equal(modelPublication(nearDeadlineHeartbeat).status, "retained");
tick = end - 900;
const nearDeadlineProgress = progress(installed(nearDeadlineHeartbeat));
negative("heartbeat classification remains current at dispatch", nearDeadlineProgress, b => {
  b.attempt.row.initiation.lower_ms = end - 1; b.attempt.row.initiation.upper_ms = end - 1;
}, "heartbeat-classification");
tick = savedTick;

// Causal expiry controls isolate the lifetime guard from the old planner and
// candidate slot deadlines using the separately typed heartbeat dispatch.
for (const [name, lower, upper] of [
  ["heartbeat exact expiry", 0, 0], ["heartbeat expiry uncertainty", -10, 1],
  ["heartbeat independent time beyond expired frozen runner", 1000, 1000]
]) {
  negative(name, hp, b => {
    const deadline = b.store.rows.at(-1).event.payload.statement.expires_ms;
    b.attempt.row.initiation.lower_ms = deadline + lower - 1;
    b.attempt.row.initiation.upper_ms = deadline + upper - 1;
  }, "time-expiry");
}
negative("post-persistence independent qualification", hp, b => { b.attempt.row.initiation.independent = false; }, "time-qualification");
negative("future slot only", candidateInput, b => {
  b.attempt.row.event.payload.envelope.report.entries[0].observed_at = "2026-09-05T12:00:02Z"; reseal(b);
}, "slot-future");
negative("future release source only", candidateInput, b => {
  b.attempt.row.event.payload.envelope.report.entries.find(e => e.topic === "release").values.source_generated_at = "2026-09-05T12:00:02Z"; reseal(b);
}, "source-future");
negative("unsigned replay annotation substitution", dispatched, b => {
  b.store.rows.at(-1).initiation.upper_ms++;
}, "store-journal-binding");
assert.equal(sent.clock_floor_ms, progressInput.attempt.row.event.payload.checks[0].upper_ms + 1,
  "only winning signed progress commits a floor, final initiation is provisional");

// An altered candidate creates a real PATCH through the unchanged planner.
const changed = clone(report); changed.entries[0].values.upgrade++;
const { report_sha256: oldHash, ...changedMaterial } = changed; changed.report_sha256 = hash(changedMaterial);
const patchCandidate = candidate(all, changed), patchReserved = installed(patchCandidate);
const patchProgress = progress(patchReserved), patchSent = modelPublication(patchProgress);
assert.equal(patchSent.modeled_dispatch.request.method, "PATCH");
const patchNumber = Number(patchSent.modeled_dispatch.request.path.split("/").at(-1));
const patchOutcome = outcome(installed(patchProgress, patchSent), patchSent.modeled_dispatch, patchNumber);
assert.equal(modelPublication(patchOutcome).status, "committed");
negative("unknown PATCH completion", patchOutcome, b => { b.attempt.row.event.payload.response.completion = "unknown"; reseal(b); }, "outcome-unknown");
negative("wrong PATCH issue", patchOutcome, b => { b.attempt.row.event.payload.response.issue_number = 998; reseal(b); }, "outcome-issue");
for (const positive of [candidateInput, progressInput, outcomeInput, patchProgress, patchOutcome, monitoring, hp, ho]) {
  for (const append of ["lost", "unknown", "failed"]) {
    const b = clone(positive); b.attempt.append_result = append;
    const r = modelPublication(b);
    assert.equal(r.reason, `append-${append}`); assert.equal(r.status, "manual-reconciliation");
    assert.equal(r.modeled_dispatch, null); assert.deepEqual(r.registry, modelPublication({ ...b, attempt: null }).registry);
    assert(r.retained_intent, "lost ack/concurrent loser/persistence failure never releases possible ownership");
  }
}
const delayed = clone(progressInput); delayed.attempt.row.initiation.lower_ms = end; delayed.attempt.row.initiation.upper_ms = end;
const delayResult = modelPublication(delayed);
assert.equal(delayResult.journal.length, reserved.store.rows.length + 1);
assert(delayResult.retained_intent.progress_sha256); assert.equal(delayResult.modeled_dispatch, null);
assert.equal(modelPublication(installed(delayed, delayResult)).status, "retained");
const repeatProgress = clone(progressInput), delayedState = installed(delayed, delayResult);
repeatProgress.store = delayedState.store;
repeatProgress.attempt.row.event.generation++; repeatProgress.attempt.row.key = "003";
repeatProgress.attempt.row.event.predecessor = repeatProgress.store.current_head;
repeatProgress.attempt.row.event.payload.checks[0].predecessor = repeatProgress.store.current_head;
reseal(repeatProgress);
assert.equal(modelPublication(repeatProgress).reason, "progress-lineage", "no second progress/resend, even when first did not dispatch");
negative("second owned progress cannot reset dispatch step", progressInput, b => {
  Object.assign(b, clone(repeatProgress));
  const p = b.attempt.row.event.payload;
  p.checks = [clock("progress-sign", p.execution, b.store.current_head)];
  b.attempt.row.initiation = clock("initiation", p.execution, hash(b.attempt.row.event)); reseal(b);
}, "progress-lineage");
negative("confirmed response cannot invent dispatch", outcomeInput, b => {
  b.store.rows.at(-1).initiation = null;
}, "outcome-dispatch");
negative("new contender cannot replace retained ownership", candidateInput, b => {
  Object.assign(b, candidate(reserved));
}, "retained-intent");
assert.equal(modelPublication(candidate(reserved)).reason, "retained-intent", "one global intent also blocks heartbeat");
assert.equal(modelPublication(heartbeat(reserved)).reason, "retained-intent");
assert.equal(modelPublication({ ...dispatched, attempt: null }).status, "retained", "crash after POST remains retained");
assert.equal(modelPublication({ ...installed(patchProgress, patchSent), attempt: null }).status, "retained", "crash after PATCH remains retained");

// Complete/current synthetic listing is a separate premise, not signed-snapshot proof.
negative("partial listing", completed, b => { b.store.complete = false; }, "store-qualification");
negative("alternate storage version", completed, b => { b.store.single_version = false; }, "store-qualification");
negative("wrong store identity", completed, b => { b.store.identity = "another"; }, "store-qualification");
negative("old signed snapshot", completed, b => { b.store.rows = b.store.rows.slice(0,1); }, "store-current-head");
negative("missing journal tail", completed, b => { b.store.rows.pop(); }, "store-current-head");
negative("reordered journal", completed, b => { [b.store.rows[1], b.store.rows[2]] = [b.store.rows[2], b.store.rows[1]]; }, "event-generation", false);
const absent = clone(genesis); absent.store.rows = [];
assert.equal(modelPublication(absent).reason, "schema");
const noGenesis = clone(completed); noGenesis.store.rows.shift();
assert.notEqual(modelPublication(noGenesis).reason, null);
negative("genesis pin", genesis, b => { b.pins.genesis_sha256 = "0".repeat(64); }, "genesis-pin");
const sampleRegistry = dedupResult.registry.slice(0,2);
const duplicateKey = initial([sampleRegistry[0], sampleRegistry[0]]);
assert.equal(modelPublication(duplicateKey).reason, "registry-order-or-duplicate");
const duplicateNumber = initial(sampleRegistry.map(e => ({ ...e, issue_number: 1 })));
assert.equal(modelPublication(duplicateNumber).reason, "registry-number-or-heartbeat");
assert.equal(modelPublication(initial([...sampleRegistry].reverse())).reason, "registry-order-or-duplicate");
assert.equal(modelPublication(initial([{ ...sampleRegistry[0], issue_number: 999 }])).reason, "registry-number-or-heartbeat");
const fullRegistry = Array.from({ length: 50 }, (_,i) => ({ dedup_key: sha(`registry-${i}`), issue_number: i + 100, content_sha256: "0".repeat(64) })).sort((a,b) => a.dedup_key < b.dedup_key ? -1 : 1);
assert.equal(modelPublication(initial(fullRegistry)).status, "projected");
assert.equal(modelPublication(candidate(initial(fullRegistry))).reason, "registry-capacity");
assert.equal(modelPublication(initial([...fullRegistry, { dedup_key: "f".repeat(64), issue_number: 500, content_sha256: "0".repeat(64) }])).reason, "schema");
negative("initial admission cap survives rebinding", candidate(all), b => {
  b.attempt.row.event.payload.companion.material.admission_expires_ms--; reseal(b);
}, "admission-reset", false);
negative("original intake identity survives registry rebinding", candidate(all), b => {
  b.attempt.row.event.payload.companion.material.intake_id = "replacement"; reseal(b);
}, "admission-reset");
// A valid current report can preserve expired slots only as stale historical facts.
const later = new Date(base + 86400000).toISOString().replace(".000Z", "Z");
const historical = aggregate(context, fixture(), later);
const historicalCandidate = candidate(genesis, historical);
for (const [i,c] of historicalCandidate.attempt.row.event.payload.checks.entries()) { c.lower_ms = end + 100 + i * 10; c.upper_ms = c.lower_ms; }
reseal(historicalCandidate);
assert.equal(modelPublication(historicalCandidate).status, "retained");
assert(historical.entries.every(e => e.status === "stale" && Object.keys(e.values).length === 0));
for (const entry of historical.entries) {
  const original = fixture().find(r => r.host === entry.host && r.topic === entry.topic);
  assert.equal(entry.observed_at, original.observed_at);
  assert.equal(entry.expires_at, original.expires_at);
}
negative("historical slot requires stale status", historicalCandidate, b => {
  b.attempt.row.event.payload.envelope.report.entries[0].status = "blocked"; reseal(b);
}, "historical-slot");
negative("historical slot cannot retain candidate values", historicalCandidate, b => {
  b.attempt.row.event.payload.envelope.report.entries[1].values = { required: true, backup_proven: false }; reseal(b);
}, "historical-slot");
negative("unexpired original slot cannot claim historical expiry", shortSlot, b => {
  const r = b.attempt.row.event.payload.envelope.report, e = r.entries[1];
  e.freshness = "stale"; e.status = "stale"; e.detail = "input-stale"; e.values = {}; r.complete = false;
  assert.equal(e.observed_at, shortRecord.observed_at); assert.equal(e.expires_at, shortRecord.expires_at);
  reseal(b);
}, "historical-slot");
negative("future historical observation", historicalCandidate, b => {
  b.attempt.row.event.payload.envelope.report.entries[0].observed_at = "2026-09-07T12:00:00Z"; reseal(b);
}, "slot-future", false);
const partial = fixture().filter(r => r.topic !== "release");
partial[0] = record("debian", "package", { failure: "transport-failed" }, "failed-collection");
const partialCandidate = candidate(genesis, aggregate(context, partial, now));
const partialState = installed(partialCandidate);
// Finish this candidate once; heartbeat sees historical partial/failed acceptance.
const pp = progress(partialState), ps = modelPublication(pp), po = outcome(installed(pp, ps), ps.modeled_dispatch, 1);
const ph = heartbeat(installed(po));
assert.equal(ph.attempt.row.event.payload.statement.classification, "partial/failed");
assert.equal(modelPublication(ph).status, "retained");
const missingCandidate = candidate(genesis, aggregate(context, [], now));
assert.equal(modelPublication(missingCandidate).status, "retained");

// Shape parity: implementation uses the same cached Ajv schema, with additional
// semantic checks. Schema-valid must not be confused with valid state/authority.
for (const good of [genesis, candidateInput, progressInput, outcomeInput, monitoring, historicalCandidate]) {
  assert(validSchema(good), JSON.stringify(validSchema.errors)); assert.equal(modelPublication(good).reason, null);
}
for (const mutate of [
  b => { b.flags.authorized = true; }, b => { b.flags.admission_enabled = true; }, b => { b.flags.live_send_enabled = true; },
  b => { b.attempt.row.event.flags.automatic_retry_allowed = true; }, b => { b.attempt.row.event.payload.envelope.report.automatic_apply = true; },
  b => { b.attempt.row.event.payload.envelope.report.entries[0].values.latest = "@everyone https://evil.invalid"; },
  b => { b.attempt.row.event.payload.envelope.report.entries[0].values.token = "private"; },
  b => { b.pins.profile.max_elapsed_ms = true; }, b => { b.attempt.row.event.generation = true; },
  b => { b.attempt.row.event.payload.checks[0].lower_ms = "0"; }, b => { b.extra = "unknown"; },
  b => { b.attempt.row.event.payload.envelope.provenance.workflow_artifact = true; },
  b => { b.attempt.row.event.payload.statement = {}; }, b => { b.attempt.row.event.type = "resume"; },
  b => { b.attempt.row.event.payload.checks = []; }
]) {
  const bad = clone(candidateInput); mutate(bad);
  assert.equal(validSchema(bad), false); assert.equal(modelPublication(bad).reason, "schema");
}
for (const flag of Object.keys(MODEL_FLAGS)) {
  const b = clone(candidateInput); b.flags[flag] = true; assert.equal(modelPublication(b).reason, "schema");
}
for (const value of [NaN, Infinity, 1.5, undefined, () => {}, new Date(0)]) {
  const b = clone(candidateInput); b.extra = value; assert.notEqual(modelPublication(b).reason, null);
}
let proxyInvoked = false;
const proxy = new Proxy({}, { getPrototypeOf() { proxyInvoked = true; throw Error("proxy"); } });
assert.equal(modelPublication(proxy).reason, "input-object"); assert.equal(proxyInvoked, false);
const hostileId = clone(candidateInput); hostileId.attempt.row.event.payload.execution = "id\n";
assert.equal(modelPublication(hostileId).reason, "input-string");
const accessor = clone(genesis); let invoked = false;
Object.defineProperty(accessor, "extra", { enumerable: true, get() { invoked = true; throw Error("getter"); } });
assert.equal(modelPublication(accessor).reason, "input-accessor"); assert.equal(invoked, false);
const cycle = clone(genesis); cycle.extra = cycle; assert.equal(modelPublication(cycle).reason, "input-object");
const deep = clone(genesis); deep.extra = {}; let cursor = deep.extra; for (let i = 0; i < 30; i++) { cursor.next = {}; cursor = cursor.next; }
assert.equal(modelPublication(deep).reason, "input-bound");
const large = clone(genesis); large.extra = "x".repeat(262145); assert.equal(modelPublication(large).reason, "input-bound");
const sparse = clone(genesis); sparse.store.rows = new Array(1); assert.equal(modelPublication(sparse).reason, "input-array");
function assertUncommittedProgress(input, reason) {
  const r = modelPublication(input);
  assert.equal(r.reason, reason); assert.equal(r.status, "manual-reconciliation");
  for (const field of ["generation", "head", "clock_floor_ms", "journal", "retained_intent", "last_acceptance", "registry"])
    assert.deepEqual(r[field], reservedResult[field], `no progress manufactured: ${field}`);
  assert.equal(r.modeled_dispatch, null);
}
let malformedFinalCases = 0;
function assertMalformedFinal(mutate, reason) {
  malformedFinalCases++;
  const bad = clone(progressInput); mutate(bad);
  const descriptor = Object.getOwnPropertyDescriptor(bad.attempt.row, "initiation");
  const signedBefore = canonicalJson([bad.attempt.row.event, bad.attempt.row.signature, bad.attempt.row.execution]);
  const r = modelPublication(bad), committedRow = { ...clone(progressInput.attempt.row), initiation: null };
  const check = committedRow.event.payload.checks[0];
  assert.equal(r.reason, reason); assert.equal(r.status, "manual-reconciliation");
  assert.equal(r.generation, reservedResult.generation + 1);
  assert.equal(r.head, hash(committedRow.event));
  assert.equal(r.clock_floor_ms, check.upper_ms + check.elapsed_end_ms - check.elapsed_start_ms + profile.drift_ms);
  assert.deepEqual(r.journal, [...reservedResult.journal, committedRow]);
  assert.deepEqual(r.retained_intent, { ...reservedResult.retained_intent, progress_sha256: r.head });
  assert.equal(r.retained_intent.modeled_dispatched, false); assert.equal(r.modeled_dispatch, null);
  assert.deepEqual(r.registry, reservedResult.registry); assert.deepEqual(r.last_acceptance, reservedResult.last_acceptance);
  for (const flag of Object.keys(MODEL_FLAGS)) assert.equal(r[flag], false);
  assert.equal(r.format, fmt("publication-model-result"));
  const after = Object.getOwnPropertyDescriptor(bad.attempt.row, "initiation");
  for (const field of ["value", "get", "set", "enumerable", "configurable", "writable"])
    assert.equal(after?.[field], descriptor?.[field], `annotation descriptor unchanged: ${field}`);
  assert.equal(canonicalJson([bad.attempt.row.event, bad.attempt.row.signature, bad.attempt.row.execution]), signedBefore);
  assert.deepEqual(modelPublication(bad), r, "deterministic malformed-final evaluation");

  const reconstructed = installed(progressInput, r), replayed = modelPublication(reconstructed);
  assert.equal(replayed.reason, null); assert.equal(replayed.status, "retained");
  for (const field of ["generation", "head", "clock_floor_ms", "journal", "retained_intent"])
    assert.deepEqual(replayed[field], r[field], `reconstruction retains committed ${field}`);
  assert.equal(replayed.modeled_dispatch, null);
  const repeat = clone(progressInput); repeat.store = reconstructed.store;
  assert.equal(modelPublication(repeat).reason, "event-generation", "same signed append cannot replay");
  repeat.attempt.row.event.generation = r.generation + 1;
  repeat.attempt.row.key = String(r.generation + 1).padStart(3, "0");
  repeat.attempt.row.event.predecessor = r.head;
  repeat.attempt.row.event.payload.checks[0] = clock("progress-sign", repeat.attempt.row.event.payload.execution, r.head);
  reseal(repeat);
  const refused = modelPublication(repeat);
  assert.equal(refused.reason, "progress-lineage", "no second progress after malformed final time");
  assert.deepEqual(refused.journal, r.journal); assert.equal(refused.clock_floor_ms, r.clock_floor_ms);
  assert.deepEqual(refused.retained_intent, r.retained_intent); assert.equal(refused.modeled_dispatch, null);

  for (const append of ["lost", "unknown", "failed"]) {
    bad.attempt.append_result = append; assertUncommittedProgress(bad, `append-${append}`);
  }
  bad.attempt.append_result = "won"; bad.attempt.row.signature = "A".repeat(86) + "==";
  assertUncommittedProgress(bad, "signature");
}
assertMalformedFinal(b => { b.attempt.row.initiation.lower_ms = true; }, "schema");
assertMalformedFinal(b => { delete b.attempt.row.initiation; }, "schema");
for (const [value, reason] of [
  [true, "schema"], [0, "schema"], ["invalid", "schema"], [NaN, "input-number"],
  [Infinity, "input-number"], [1.5, "input-number"], [undefined, "input-object"],
  [() => {}, "input-object"], [new Date(0), "input-prototype"], [proxy, "input-object"],
  [{ nested: deep.extra }, "input-bound"], ["x".repeat(262145), "input-bound"],
  [cycle, "input-object"], [null, "time-missing-initiation"]
]) assertMalformedFinal(b => { b.attempt.row.initiation = value; }, reason);
let finalInvoked = false;
const finalGetter = () => { finalInvoked = true; throw Error("untrusted-final-getter"); };
assertMalformedFinal(b => { Object.defineProperty(b.attempt.row, "initiation", { enumerable: true, get: finalGetter }); }, "input-accessor");
assertMalformedFinal(b => { Object.defineProperty(b.attempt.row.initiation, "lower_ms", { enumerable: true, get: finalGetter }); }, "input-accessor");
assertMalformedFinal(b => { b.attempt.row.initiation = new Proxy({}, {
  get: finalGetter, ownKeys: finalGetter, getPrototypeOf: finalGetter, getOwnPropertyDescriptor: finalGetter
}); }, "input-object");
assert.equal(finalInvoked, false); assert.equal(proxyInvoked, false);
// The exclusion must never extend into signed data, acknowledgements or ancestors.
for (const [mutate, reason] of [
  [b => { delete b.attempt; }, "schema"],
  [b => { b.attempt.row.event.generation = true; }, "schema"],
  [b => { b.attempt.row.event.payload.checks = undefined; }, "input-object"],
  [b => { b.attempt.row.event.payload.extra = deep.extra; }, "input-bound"],
  [b => { b.attempt.row.event = proxy; }, "input-object"],
  [b => { b.attempt.row.execution = proxy; }, "input-object"],
  [b => { b.attempt.row = proxy; }, "input-object"],
  [b => { b.attempt = proxy; }, "input-object"],
  [b => { Object.defineProperty(b.attempt.row, "execution", { enumerable: true, get: finalGetter }); }, "input-accessor"],
  [b => { Object.defineProperty(b.attempt, "row", { enumerable: true, get: finalGetter }); }, "input-accessor"]
]) {
  const b = clone(progressInput); b.attempt.row.initiation = undefined; mutate(b);
  assertUncommittedProgress(b, reason);
}
assert.equal(finalInvoked, false); assert.equal(proxyInvoked, false);
for (const mutate of [
  b => { delete b.attempt.row.initiation; },
  b => { b.attempt.row.initiation = true; },
  b => { Object.defineProperty(b.attempt.row, "initiation", { enumerable: true, get: finalGetter }); }
]) {
  const b = clone(candidateInput); mutate(b);
  const r = modelPublication(b);
  assert.equal(r.status, "rejected"); assert.equal(r.generation, 0);
  assert.deepEqual(r.journal, genesis.store.rows); assert.equal(r.retained_intent, null);
  assert.equal(r.modeled_dispatch, null);
}
assert.equal(finalInvoked, false, "non-progress annotations are still rejected without invocation");

// Guard-removal mutants execute the actual module entrypoint. Each has its own
// valid control, reaches its named guard in the original, and must become accepted
// after that guard is removed (not merely fail at an unrelated guard).
let mutants = 0;
for (const test of focused.filter(t => t.mutant)) {
  const text = source.replace('if (!ok) throw Error(reason);', `if (!ok && reason !== ${JSON.stringify(test.reason)}) throw Error(reason);`);
  assert.notEqual(text, source);
  // Inputs must have the realm's plain prototypes: JSON.parse inside the realm
  // is used by the wrapper, not an extracted/bypassed state-machine function.
  const run = value => {
    const sandbox = { require: localRequire, module: { exports: {} }, Buffer, console, raw: canonicalJson(value) };
    vm.runInNewContext(`${text}\nmodule.exports.testResult = modelPublication(JSON.parse(raw));`, sandbox, { filename: sourcePath });
    return sandbox.module.exports.testResult;
  };
  assert.equal(run(test.positive).reason, null, `${test.name}: mutant positive`);
  const result = run(test.bad);
  assert.equal(result.reason, null, `${test.name}: removal must causally defeat focused refusal, got ${result.reason}`);
  assert.notEqual(result.status, "rejected"); mutants++;
}

// Conservative quantization is observable in the unchanged planner. All four
// synthetic intervals remain strictly before expiry; ceil(U) reaches it.
const quantized = clone(candidateInput);
for (const [i,c] of quantized.attempt.row.event.payload.checks.entries()) {
  c.lower_ms = end - 100 + i * 10; c.upper_ms = c.lower_ms;
}
reseal(quantized);
assert.equal(modelPublication(quantized).reason, "maintenance publication rejected");
const quantizedSandbox = { require: localRequire, module: { exports: {} }, Buffer, raw: canonicalJson(quantized) };
const quantizedMutant = source.replace("Math.ceil(clocks[3].upper / 1000)", "Math.floor(clocks[3].upper / 1000)");
assert.notEqual(quantizedMutant, source);
vm.runInNewContext(`${quantizedMutant}\nmodule.exports.result = modelPublication(JSON.parse(raw));`, quantizedSandbox, { filename: sourcePath });
assert.equal(quantizedSandbox.module.exports.result.reason, null, "round-down mutant must defeat quantization refusal");
mutants++;

// Tripwires surround actual entrypoints, including the unchanged planner call.
// Date construction with explicit data is allowed; wall clock and all I/O are not.
const tripwires = [];
function trap(object, name) {
  const original = object[name]; if (typeof original !== "function") return;
  tripwires.push(() => { object[name] = original; }); object[name] = () => { throw Error(`forbidden-${name}`); };
}
for (const name of ["readFileSync","openSync","readSync","writeFileSync","appendFileSync","statSync","lstatSync","readdirSync","createReadStream","createWriteStream"]) trap(fs, name);
for (const name of ["exec","execSync","spawn","spawnSync","execFile","execFileSync","fork"]) trap(require("node:child_process"), name);
for (const mod of ["node:http","node:https","node:net","node:tls","node:dgram","node:dns"]) {
  const object = require(mod); for (const name of ["request","get","connect","createConnection","createSocket","lookup","resolve"]) trap(object, name);
}
trap(global, "fetch"); trap(Date, "now"); trap(process, "hrtime"); trap(process, "uptime"); trap(crypto, "sign"); trap(crypto, "randomBytes");
const OriginalDate = Date, originalEnv = process.env;
global.Date = class extends OriginalDate { constructor(...args) { assert(args.length > 0, "ambient Date"); super(...args); } };
process.env = new Proxy({}, { get() { throw Error("environment-read"); } });
try {
  for (const input of [genesis, candidateInput, progressInput, outcomeInput, monitoring, historicalCandidate, ...focused.map(t => t.bad)]) {
    const before = canonicalJson(input), a = modelPublication(input), b = modelPublication(input);
    assert.deepEqual(a, b); assert.equal(canonicalJson(input), before);
    for (const flag of Object.keys(MODEL_FLAGS)) assert.equal(a[flag], false);
    assert(!String(a.reason).includes("forbidden") && !String(a.reason).includes("environment-read"), a.reason);
    if (a.modeled_dispatch) for (const flag of Object.keys(MODEL_FLAGS)) assert.equal(a.modeled_dispatch[flag], false);
  }
} finally { process.env = originalEnv; global.Date = OriginalDate; for (const restore of tripwires.reverse()) restore(); }
const detached = modelPublication(candidateInput); detached.last_acceptance.slots[0].status = "changed";
assert.equal(modelPublication(candidateInput).last_acceptance.slots[0].status, "blocked");
console.log(`maintenance_publication_state=verified synthetic-only full-chain/intent/progress/one-dispatch/outcome/dedup/heartbeat; ${focused.length} focused negatives; ${mutants} causal guard-removal mutants; ${malformedFinalCases} malformed-final committed-progress/replay controls; schema/purity/tripwires`);
