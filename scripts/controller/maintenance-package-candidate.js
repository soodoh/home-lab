#!/usr/bin/env node
"use strict";
const { buildCandidateLock, canonicalJson } = require("./package-transaction-lock");
const { validateMaintenanceProposal } = require("./maintenance-report");
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => { raw += chunk; if (Buffer.byteLength(raw) > 1048576) process.exit(65); });
process.stdin.on("end", () => {
  try {
    const input = JSON.parse(raw);
    if (raw !== canonicalJson(input) || Object.keys(input).sort().join() !== "context,expires_at,proposal") throw Error();
    const p = input.proposal, c = input.context;
    if (!["debian", "proxmox"].includes(p.host)) throw Error();
    validateMaintenanceProposal(p, p.host);
    if (p.metadata_refresh_performed !== false) throw Error();
    // Stale metadata remains evidence, never grounds for an automatic refresh.
    const candidate = p.metadata_age_seconds > 86400 ? null : buildCandidateLock({ host: p.host, lifecycle: "production", proposal: p,
      generatedAt: p.observed_at, expiresAt: input.expires_at,
      bindings: { git_commit: c.source_commit, contract_sha256: c.contract_sha256, ...c.hosts[p.host], max_metadata_age_seconds: 86400 } });
    process.stdout.write(canonicalJson({ proposal: p, candidate }));
  } catch { process.stderr.write("maintenance candidate rejected\n"); process.exitCode = 65; }
});
