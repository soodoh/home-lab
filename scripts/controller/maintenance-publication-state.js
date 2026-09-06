"use strict";
// Counterfactual JSON trace evaluator only. No CLI, signer, clock, store or sender.
const crypto = require("node:crypto");
const { isProxy } = require("node:util").types;
const Ajv = require("ajv");
const schema = require("../../infrastructure/maintenance/publication-state.schema.json");
const { planPublication } = require("./maintenance-publish");
const { canonicalJson, sha, time, FLAGS } = require("./maintenance-report");
const validate = new Ajv({ strict: true }).compile(schema);
const MODEL_FLAGS = Object.freeze({ ...FLAGS, admission_enabled: false, live_send_enabled: false });
const format = name => `synthetic-only-non-operational-${name}-v1`;
const digest = value => sha(canonicalJson(value));
const equal = (a, b) => canonicalJson(a) === canonicalJson(b);
function guard(ok, reason) { if (!ok) throw Error(reason); }

// Bound before serialization/schema recursion. Accessors, cycles, sparse arrays and
// exotic prototypes are not JSON-like data; never invoke a getter or toJSON hook.
function bounded(value, omitAttempt = false, omitInitiation = false) {
  let nodes = 0, bytes = 0;
  const seen = new Set();
  function walk(v, depth, path) {
    guard(++nodes <= 200000 && depth <= 24, "input-bound");
    if (v === null || typeof v === "boolean") return v;
    if (typeof v === "number") { guard(Number.isSafeInteger(v), "input-number"); return v; }
    if (typeof v === "string") {
      guard(/^[\x20-\x7e]*$/.test(v) || /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n$/.test(v), "input-string");
      bytes += Buffer.byteLength(v);
      guard(v.length <= 262144 && bytes <= 4194304, "input-bound"); return v;
    }
    guard(typeof v === "object" && !seen.has(v) && !isProxy(v), "input-object");
    guard(Object.getPrototypeOf(v) === (Array.isArray(v) ? Array.prototype : Object.prototype), "input-prototype");
    seen.add(v);
    const descriptors = Object.getOwnPropertyDescriptors(v), names = Reflect.ownKeys(descriptors);
    guard(names.length <= (Array.isArray(v) ? 129 : 64), "input-bound");
    if (Array.isArray(v)) guard(names.length === v.length + 1, "input-array");
    const copy = Array.isArray(v) ? [] : {};
    if (omitAttempt && depth === 0) copy.attempt = null;
    const excludeInitiation = omitInitiation && path.length === 2 && path[0] === "attempt" && path[1] === "row";
    if (excludeInitiation) copy.initiation = null;
    for (const name of names) {
      if (Array.isArray(v) && name === "length") continue;
      guard(typeof name === "string" && name.length <= 64 && !["__proto__", "constructor", "prototype", "toJSON"].includes(name), "input-key");
      // Exclude only the separate final annotation, even its descriptor, until
      // signed progress wins. All ancestors and other properties remain checked.
      if (excludeInitiation && name === "initiation") continue;
      const d = descriptors[name];
      guard(d.enumerable && Object.hasOwn(d, "value"), "input-accessor");
      if (Array.isArray(v)) guard(/^(0|[1-9][0-9]*)$/.test(name) && Number(name) < v.length, "input-array");
      copy[name] = omitAttempt && depth === 0 && name === "attempt" ? null : walk(d.value, depth + 1, [...path, name]);
    }
    seen.delete(v);
    return copy;
  }
  const copy = walk(value, 0, []);
  guard(Buffer.byteLength(canonicalJson(copy)) <= 4194304, "input-bound");
  return copy;
}
function publicKey(pem, hash) {
  guard(sha(pem) === hash, "key-pin");
  const key = crypto.createPublicKey(pem);
  guard(key.asymmetricKeyType === "ed25519", "key-type");
  guard(key.export({ type: "spki", format: "pem" }) === pem, "key-canonical"); return key;
}
function signed(material, signature, key) {
  guard(crypto.verify(null, Buffer.from(canonicalJson(material)), key, Buffer.from(signature, "base64")), "signature");
}
function registryCheck(registry, heartbeatNumber) {
  let previous = "";
  const numbers = new Set([heartbeatNumber]);
  for (const item of registry) {
    guard(item.dedup_key > previous, "registry-order-or-duplicate");
    guard(!numbers.has(item.issue_number), "registry-number-or-heartbeat");
    previous = item.dedup_key; numbers.add(item.issue_number);
  }
  guard(registry.length <= 50, "registry-capacity");
}
function interval(check, stage, execution, predecessor, state, pins) {
  const p = pins.profile;
  guard(p !== null && p.independent && p.elapsed_supported, "time-profile");
  guard(check.profile === p.identity && check.epoch === p.epoch, "time-profile-binding");
  guard(check.independent && check.elapsed_supported && !check.reset && !check.resumed, "time-qualification");
  guard(check.execution === execution && check.stage === stage && check.predecessor === predecessor, "time-context");
  guard(!state.challenges.includes(check.challenge), "time-replay");
  const elapsed = check.elapsed_end_ms - check.elapsed_start_ms;
  guard(elapsed > 0 && elapsed <= p.max_elapsed_ms, "time-elapsed");
  guard(check.lower_ms <= check.upper_ms, "time-interval");
  const lower = check.lower_ms + elapsed - p.drift_ms;
  const upper = check.upper_ms + elapsed + p.drift_ms;
  guard(upper - lower <= p.max_width_ms && upper <= 4102444800000, "time-uncertainty");
  guard(lower >= state.floor, "time-rollback");
  state.floor = upper; state.challenges.push(check.challenge);
  return { lower, upper };
}
function checks(payload, stages, predecessor, state, pins) {
  guard(payload.checks.length === stages.length, "time-stages");
  return payload.checks.map((check, i) => interval(check, stages[i], payload.execution, predecessor, state, pins));
}
function lifetime(issued, expires, clock) {
  guard(issued <= clock.lower, "time-future");
  guard(clock.upper < expires && issued < expires && expires - issued <= 86400000, "time-expiry");
}
function candidateLifetime(payload, clock) {
  const { report, provenance } = payload.envelope, c = payload.companion.material;
  lifetime(time(report.observed_at), time(report.expires_at), clock);
  lifetime(time(provenance.issued_at), time(provenance.expires_at), clock);
  guard(clock.upper < c.expires_ms && c.expires_ms <= c.admission_expires_ms, "admission-expiry");
  guard(c.admission_expires_ms <= time(report.expires_at) && c.expires_ms <= time(provenance.expires_at) && time(provenance.expires_at) <= c.admission_expires_ms, "admission-cap");
  for (const e of report.entries) {
    if (e.observed_at !== null) guard(time(e.observed_at) <= clock.lower, "slot-future");
    if (e.values.source_generated_at !== undefined) guard(time(e.values.source_generated_at) <= clock.lower, "source-future");
    if (e.freshness === "fresh" || e.freshness === "stale") {
      guard(e.observed_at !== null && e.expires_at !== null, "slot-times");
      const observed = time(e.observed_at), expires = time(e.expires_at);
      guard(expires > observed && expires - observed <= 86400000, "slot-lifetime");
      if (e.freshness === "fresh") guard(clock.upper < expires, "slot-expiry");
      else {
        guard(expires <= clock.lower && e.status === "stale" && equal(e.values, {}), "historical-slot");
      }
    }
  }
  guard(report.complete === report.entries.every(e => e.freshness === "fresh" && e.status === "blocked"), "report-complete");
}
function acceptance(payload, clock, eventHash) {
  const r = payload.envelope.report;
  return { event_sha256: eventHash, report_sha256: digest(r), envelope_sha256: digest(payload.envelope),
    accepted_at_ms: clock.lower, observed_at: r.observed_at, expires_at: r.expires_at,
    slots: r.entries.map(e => ({ dedup_key: e.dedup_key, observed_at: e.observed_at, expires_at: e.expires_at, freshness: e.freshness, status: e.status })) };
}
function heartbeat(state, pins, clock, expires) {
  lifetime(clock.lower, expires, clock);
  // Two hours is only a bounded fixture horizon, not an operational cadence/SLA.
  guard(expires - clock.lower <= 7200000, "heartbeat-lifetime");
  const a = state.acceptance;
  let classification = "never-received";
  if (a) {
    const stale = clock.upper >= time(a.expires_at) || a.slots.some(s => s.expires_at !== null && clock.upper >= time(s.expires_at));
    classification = stale ? "stale" : a.slots.some(s => s.freshness !== "fresh" || s.status !== "blocked") ? "partial/failed" : "within-recorded-deadline";
  }
  return { format: format("publisher-heartbeat"), flags: MODEL_FLAGS, epoch: pins.epoch, generation: state.generation,
    state_sha256: state.head, checked_at_ms: clock.lower, expires_ms: expires,
    last_acceptance_sha256: a?.event_sha256 ?? null, classification, slots: a?.slots ?? [] };
}
function requestForHeartbeat(statement, issueNumber) {
  const body = { title: "[maintenance] synthetic publisher heartbeat",
    body: `SYNTHETIC ONLY / NON-OPERATIONAL. Historical candidate issues are not fresh authority.\n${canonicalJson(statement)}` };
  return { method: "PATCH", path: `/repos/soodoh/home-lab/issues/${issueNumber}`, body, content_sha256: digest(body) };
}
function owns(execution, intent, progressHash) {
  guard(execution !== null && execution.id === intent.execution && execution.started_at_head === intent.predecessor, "execution-owner");
  guard(execution.running && !execution.reconstructed, "execution-continuity");
  guard(execution.intent_ack === intent.hash && execution.progress_ack === progressHash, "execution-ack");
}
function intentLifetime(intent, clock, state, pins) {
  if (intent.kind === "candidate") candidateLifetime(intent.payload, clock);
  else {
    const statement = intent.payload.statement;
    lifetime(statement.checked_at_ms, statement.expires_ms, clock);
    guard(heartbeat(state, pins, clock, statement.expires_ms).classification === statement.classification, "heartbeat-classification");
  }
}
function applyRow(state, row, pins, key) {
  const e = row.event, p = e.payload, eventHash = digest(e);
  guard(Buffer.byteLength(canonicalJson(row)) <= 65536, "event-bound");
  guard(e.epoch === pins.epoch, "event-epoch");
  guard(e.generation === state.generation + 1 && row.key === String(e.generation).padStart(3, "0"), "event-generation");
  guard(e.predecessor === state.head, "event-predecessor");
  signed(e, row.signature, key);
  if (e.type !== "progress") guard(row.execution === null && row.initiation === null, "unexpected-execution");
  if (e.type === "genesis") {
    guard(e.generation === 0 && eventHash === pins.genesis_sha256, "genesis-pin");
    registryCheck(p.registry, p.heartbeat_issue_number);
    guard(pins.profile !== null && pins.profile.independent && pins.profile.elapsed_supported, "time-profile");
    guard(p.profile_sha256 === digest(pins.profile), "genesis-profile");
    state.registry = p.registry; state.heartbeatNumber = p.heartbeat_issue_number; state.floor = p.clock_floor_ms;
    state.committedFloor = state.floor;
  } else {
    guard(state.generation >= 0, "missing-genesis");
    if (e.type === "candidate" || e.type === "heartbeat") {
      guard(state.intent === null, "retained-intent");
      guard(!state.executions.includes(p.execution), "execution-reuse");
      state.executions.push(p.execution);
      let request;
      if (e.type === "candidate") {
        const clocks = checks(p, ["admission", "provenance-sign", "companion-sign", "plan"], state.head, state, pins);
        const c = p.companion.material, trust = pins.publication_trust;
        signed(c, p.companion.signature, key);
        guard(c.epoch === pins.epoch && c.generation === state.generation && c.state_sha256 === state.head, "companion-predecessor");
        guard(c.repository === trust.repository && c.source_commit === trust.source_commit && c.contract_sha256 === trust.contract_sha256, "companion-source");
        guard(equal(p.envelope.registry, state.registry) && c.registry_sha256 === digest(state.registry), "companion-registry");
        guard(c.provenance_sha256 === digest(p.envelope.provenance) && c.signature_sha256 === sha(p.envelope.signature), "companion-envelope");
        const reportHash = digest(p.envelope.report), admitted = state.admissions.find(a => a.report === reportHash);
        guard(!admitted || (c.admission_expires_ms === admitted.expires && c.intake_id === admitted.intake), "admission-reset");
        guard(admitted || !state.admissions.some(a => a.intake === c.intake_id), "intake-reuse");
        guard(admitted || c.admission_expires_ms === time(p.envelope.provenance.expires_at), "initial-admission-cap");
        for (const clock of clocks) candidateLifetime(p, clock);
        // This is the original planner, not a replacement. Quantize U upward.
        const plannerTime = new Date(Math.ceil(clocks[3].upper / 1000) * 1000).toISOString().replace(".000Z", "Z");
        const plan = planPublication(p.envelope, trust, plannerTime);
        request = plan.requests[0] ?? null;
        if (request?.method === "POST") guard(state.registry.length < 50, "registry-capacity");
        if (!admitted) state.admissions.push({ report: reportHash, expires: c.admission_expires_ms, intake: c.intake_id });
        state.acceptance = acceptance(p, clocks[0], eventHash);
      } else {
        const clocks = checks(p, ["heartbeat-sign", "heartbeat-plan"], state.head, state, pins);
        const expected = heartbeat(state, pins, clocks[0], p.statement.expires_ms);
        guard(equal(p.statement, expected), "heartbeat-binding");
        lifetime(p.statement.checked_at_ms, p.statement.expires_ms, clocks[1]);
        // Classification must still be valid at planning, not just signing.
        guard(heartbeat(state, pins, clocks[1], p.statement.expires_ms).classification === p.statement.classification, "heartbeat-classification");
        request = requestForHeartbeat(p.statement, state.heartbeatNumber);
      }
      if (request) state.intent = { hash: eventHash, predecessor: e.predecessor, execution: p.execution,
        kind: e.type, payload: p, request, progress: null, dispatched: false };
    } else if (e.type === "progress") {
      const intent = state.intent;
      guard(intent !== null && p.intent_sha256 === intent.hash && p.execution === intent.execution, "progress-intent");
      guard(intent.progress === null && state.head === intent.hash, "progress-lineage");
      guard(p.request_sha256 === digest(intent.request), "progress-request");
      owns(row.execution, intent, eventHash);
      const [clock] = checks(p, ["progress-sign"], state.head, state, pins);
      intentLifetime(intent, clock, state, pins);
      intent.progress = eventHash;
      state.committedFloor = state.floor;
      if (row.initiation !== null) {
        // The progress append does not freshen its sample. A separate fresh
        // independent check after persistence is required at modeled initiation.
        const final = interval(row.initiation, "initiation", p.execution, eventHash, state, pins);
        intentLifetime(intent, final, state, pins);
        intent.dispatched = true;
      }
    } else if (e.type === "outcome") {
      const intent = state.intent;
      guard(intent !== null && p.intent_sha256 === intent.hash && p.execution === intent.execution, "outcome-intent");
      guard(intent.dispatched && state.head === intent.progress, "outcome-dispatch");
      checks(p, ["outcome-sign"], state.head, state, pins);
      const r = p.response;
      guard(r.authenticated_in_model && r.completion === "confirmed", "outcome-unknown");
      guard(r.request_sha256 === digest(intent.request) && r.content_sha256 === intent.request.content_sha256, "outcome-content");
      if (intent.request.method === "PATCH") guard(intent.request.path === `/repos/soodoh/home-lab/issues/${r.issue_number}`, "outcome-issue");
      if (intent.kind === "candidate") {
        const entry = { dedup_key: intent.request.dedup_key, issue_number: r.issue_number, content_sha256: r.content_sha256 };
        state.registry = [...state.registry.filter(item => item.dedup_key !== entry.dedup_key), entry].sort((a,b) => a.dedup_key < b.dedup_key ? -1 : 1);
        registryCheck(state.registry, state.heartbeatNumber);
      }
      state.intent = null;
    } else guard(false, "event-type");
  }
  if (e.type !== "progress") state.committedFloor = state.floor;
  state.generation = e.generation; state.head = eventHash;
}
function result(state, status, reason, rows, dispatch = null) {
  return { format: format("publication-model-result"), ...MODEL_FLAGS, status, reason,
    generation: state?.generation ?? null, head: state?.head ?? null,
    registry: state?.registry ?? [], last_acceptance: state?.acceptance ?? null,
    retained_intent: state?.intent ? { sha256: state.intent.hash, kind: state.intent.kind, progress_sha256: state.intent.progress, modeled_dispatched: state.intent.dispatched } : null,
    clock_floor_ms: state?.committedFloor ?? null, journal: rows, modeled_dispatch: dispatch };
}
function modelPublication(input) {
  let state = null, rows = [];
  try {
    const existing = bounded(input, true); guard(validate(existing), "schema");
    // Verify the existing store before inspecting a potentially malformed new
    // attempt. Even malformed final time cannot erase verified retained intent.
    const { pins, store } = existing;
    const key = publicKey(pins.state_public_key_pem, pins.state_public_key_sha256);
    publicKey(pins.publication_trust.public_key_pem, pins.publication_trust.public_key_sha256);
    guard(pins.state_public_key_sha256 !== pins.publication_trust.public_key_sha256, "purpose-key-separation");
    guard(store.identity === pins.store_identity && store.complete && store.single_version, "store-qualification");
    guard(store.current_generation === store.rows.length - 1 && store.current_head === digest(store.rows.at(-1).event), "store-current-head");
    // This separately supplied synthetic complete-store digest binds unsigned
    // append/execution/initiation assertions too. It is not a storage verifier.
    guard(store.current_journal_sha256 === digest(store.rows), "store-journal-binding");
    const verified = { generation: -1, head: null, registry: [], acceptance: null, intent: null, floor: 0, committedFloor: 0, challenges: [], admissions: [], executions: [] };
    for (const row of store.rows) applyRow(verified, row, pins, key);
    state = verified; rows = store.rows;
    let proposal = bounded(input, false, true); guard(validate(proposal), "schema");
    if (proposal.attempt && proposal.attempt.row.event.type !== "progress") {
      proposal = bounded(input); guard(validate(proposal), "schema");
    }
    const attempt = proposal.attempt;
    if (!attempt) return result(state, state.intent ? "retained" : "projected", null, rows);
    guard(rows.length < 128, "journal-capacity");
    const proposed = JSON.parse(canonicalJson(state)), row = attempt.row;
    // Validate the proposal provisionally. Unknown/losing appends never commit
    // time floors, observations, registry transitions or a modeled dispatch.
    if (row.event.type === "progress") {
      const withoutInitiation = { ...row, initiation: null };
      applyRow(proposed, withoutInitiation, pins, key);
    } else applyRow(proposed, row, pins, key);
    if (attempt.append_result !== "won") {
      const out = result(state, "manual-reconciliation", `append-${attempt.append_result}`, rows);
      if (!out.retained_intent && row.event.type === "candidate" && proposed.intent) out.retained_intent = {
        sha256: proposed.intent.hash, kind: "candidate", progress_sha256: null, modeled_dispatched: false };
      if (!out.retained_intent && row.event.type === "heartbeat") out.retained_intent = {
        sha256: digest(row.event), kind: "heartbeat", progress_sha256: null, modeled_dispatched: false };
      return out;
    }
    if (row.event.type === "progress") {
      // Confirmed owned clock progress survives invalid/delayed final time. It
      // consumes the sole progress step; there is no resume/retry transition.
      const committedRow = { ...row, initiation: null };
      state = proposed; rows = [...rows, committedRow];
      try {
        const complete = bounded(input); guard(validate(complete), "schema");
        const finalRow = complete.attempt.row;
        guard(finalRow.initiation !== null, "time-missing-initiation");
        const finalState = JSON.parse(canonicalJson(state));
        const clock = interval(finalRow.initiation, "initiation", state.intent.execution, state.head, finalState, pins);
        intentLifetime(finalState.intent, clock, finalState, pins);
        finalState.intent.dispatched = true;
        state = finalState; rows[rows.length - 1] = finalRow;
        return result(state, "modeled-dispatch", null, rows,
          { format: format("dispatch-step"), ...MODEL_FLAGS, intent_sha256: state.intent.hash, request: state.intent.request });
      } catch (error) { return result(state, "manual-reconciliation", error.message, rows); }
    }
    state = proposed; rows = [...rows, row];
    return result(state, state.intent ? "retained" : "committed", null, rows);
  } catch (error) {
    // A verified existing intent is never discarded by a bad new proposal.
    return result(state, state?.intent ? "manual-reconciliation" : "rejected", error.message, rows);
  }
}
module.exports = { modelPublication, MODEL_FLAGS };
