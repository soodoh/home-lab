# ADR 0002: Ordinary advisory maintenance reporting

- Status: Accepted
- Decision owner: home-lab operator
- Scope: reporting only; ADR 0001 remains mutation/recovery authority

## Decision

Scheduled/daily collection, automatic issue publication and external missed-report monitoring are **deferred and are not migration or acceptance blockers**. Daily collection is not a requirement. Keep the offline advisory command for optional manual use; no reporting installation or replacement collector profile is required now. Revisit automation only through a separate decision.

Use ordinary trusted Mac/OS-managed UTC and original per-topic observations for advisory maintenance reports. Recheck freshness when read, using existing at-most-24-hour reporting bounds as display heuristics, not a requirement to collect daily. Stale, failed, missing, invalid or future observations are unknown; old successes are never restamped. Current observations mean needs-review or observation-only, never host health, backup admission or authorization. Reports cannot authorize deployment, packages, reboot, recovery, credentials or ownership changes.

Supersede the selected high-assurance **reporting** design: Roughtime/qualified `[L,U]` time, purpose-specific signatures and separate signing custody, authenticated CAS/append-only journals/Object Lock, durable time floors, retained publication intents and exactly-once sending are not requirements of this advisory path. A fresh complete host-lifecycle audit every day is not a prerequisite merely to publish an advisory. Separately reviewed installation identity and safe read-only collection must be designed and implemented before replacing the existing setup-gated collection path. Full audits for mutation/recovery remain unchanged.

## Rationale and trust tradeoff

An advisory helps the owner notice maintenance; it is not an admission capability. Accept ordinary platform/time trust, including no protection against compromised owner/root, adversarial clock freezing or malicious storage rollback. A report's self-hash checks structural integrity, not authenticated source authority. Fewer reporting mechanisms and fewer hidden prerequisites are preferable to synthetic assurance claims.

## Reporting-only consequences

The first implementation is a small offline renderer/CLI for existing bounded reports or explicit absence. It needs no signatures, keys or registry and sends nothing. Legacy signed planner and synthetic publication model remain unchanged offline alternatives, not invoked or required by the advisory path (only the existing structural report validator is reused).

If reporting automation is resumed, publication may best-effort update a known issue using a stable key and a least-privilege issues-only token, separate from Mac-only host credentials. Duplicates/lost updates need ordinary reconciliation, not permanent global publication locks. Preserve scheduled-check attempts separately from last successful collection, original observation deadlines and stale display. An external ordinary missed-report check is separately configured work: a Mac-only timer cannot alert when the Mac is off. No provider, token, issue or schedule is selected or provisioned here.

Existing collectors, launchers, admission/expiry checks and mutation/recovery guards are unchanged. Expired attestations remain rejected by old code. This decision neither installs collection nor completes publication, monitoring or host-lifecycle qualification.
