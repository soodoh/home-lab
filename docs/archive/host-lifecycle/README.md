# Host-lifecycle archive

Use the [operational Nix retirement checklist](../../host-lifecycle-completion-plan.md) and [ADR 0004](../../adr/0004-operational-nix-retirement.md) for current scope. These moved snapshots preserve historical evidence and failed-run lineage; they do not renew observations, grant operations or add acceptance gates.

## Historical

- [Phase 0 baseline](host-lifecycle-phase-0.md): original ownership/access/storage discovery.
- [Phase 1](host-lifecycle-phase-1.md): observation and maintenance-plan fixtures.
- [Phase 2](host-lifecycle-phase-2.md): additive access and attended transaction history, including package-parser/transport failure and recovery.
- [2026-09-03 rebaseline](host-lifecycle-rebaseline-2026-09-03.md): pre-cutover observations and the old full-lifecycle backlog.
- [2026-09-05 completion review and continuations](host-lifecycle-completion-review-2026-09-05.md): source hardening, failed VM9900 lineage and qualification limits. Its old completion sequence is superseded, not its failures reclassified.

## Deferred

- [Qualification-controller artifact research](qualification-controller-artifact-research.md): proposed VM9901/controller/CPython and Bun/OpenTofu metadata detour. Published metadata is not authenticated artifacts or native qualification; the failed research and unresolved OpenTofu manifest remain recorded.
- [Debian predecessor-observer experiment](../../../archive/lifecycle-experiments/debian-predecessor-observer/README.md): two fixture-only source candidates archived together, with no native Adapter or installed authority.

Active recovery, access, firewall and Nix-retirement runbooks remain in `docs/`. The [capability candidate](../../proxmox-controller-capability-candidate.md) remains there because it documents still-binding installation and recovery gates; it is not proof that those gates have closed.
