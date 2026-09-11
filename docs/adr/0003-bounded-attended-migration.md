# Finish the host migration through bounded, attended operations

- Status: Accepted
- Decision owner: home-lab operator
- Accepted by: operator instruction to proceed with the recommended scope and complexity reductions
- Amends: [ADR 0001](0001-ansible-host-lifecycle.md); [ADR 0002](0002-advisory-maintenance-reporting.md) remains unchanged

The migration accumulated requirements for a new orchestration platform beyond reproducible host configuration and recovery. We will finish a smaller, maintainable lifecycle using Ansible, systemd and existing guarded transactions, with attended migration and explicit recovery after ambiguous failure. This exchanges unattended continuity and universal failure-atomicity ambitions for operator availability and explicitly planned downtime; it does not exchange production data or access safety for speed.

## Completion boundary

**Superseded only in completion scope by [ADR 0004](0004-operational-nix-retirement.md).** The original boundary below is retained as decision history, not current acceptance requirements. The native attended method, executable guards and per-operation safety/approval rules elsewhere in this ADR remain binding. A future clean rebuild is now explicitly uncertified.

The original migration completion boundary was:

1. Both hosts' durable configuration has a clear Ansible owner, with OpenTofu retaining its infrastructure boundary and minimal cloud-init providing first contact.
2. A fresh disposable Debian guest converges inertly, converges a second time without changes, restores synthetic state through Restic, and reaches the production profile through an approved activation.
3. Relevant interruption, reboot, access, storage and recovery behaviors pass on supported native infrastructure; unsafe activation refuses and an operator can recover.
4. Separately approved production operations finish with current host audits, Compose/Restic checks and enabled OpenTofu roots at no-op on one reviewed revision.
5. Remaining Nix dependencies and migration-only assets are retired through an explicit consumer/retention review, without losing required recovery assets.

Ansible already owns both hosts. Do not repeat the aggregate cutover. The [completion plan](../host-lifecycle-completion-plan.md) tracks remaining work; this ADR does not declare any outstanding native proof complete.

## Supported migration route

Attended maintenance is the selected design route for enrollment/activation changes that cannot safely be performed live. Uninterrupted live enrollment is not a migration completion requirement.

Each actual operation still needs its own reviewed target, exact change/effect scope, fresh preconditions, confirmation, access/console route, backup and recovery plan. The operator must separately approve the affected workloads, interruption/session-loss expectations, downtime budget and abort point **before** shutdown or other effects. This ADR authorizes no maintenance window, connection, stop, freeze, restart, reboot or data loss.

Use documented native behavior and focused inspection/testing of the actual operation. Identify the running predecessor and relevant effective configuration before relying on shutdown behavior, but do not require a bespoke observer merely to obtain ordinary bounded evidence safely. A quiet state reached after stopping cannot retroactively authorize that stop. Unknown writable-layer, volume or dynamic-helper persistence must be resolved or the affected operation stays blocked; it is not presumed disposable.

## Prefer native mechanisms, keep necessary exceptions

Use Ansible modules, handlers and lifecycle profiles, systemd ordering and per-start checks, and the existing controller/host exclusion mechanisms. Retain narrow custom transactions where supported primitives cannot provide a required outcome, notably the PVE firewall recovery transaction and existing data/access-critical operations.

The proposed controller/bridge/broker/finalizer protocol, permanent mediation of every engine/API writer, and a complete joined Docker-restoration readset are **not universal migration prerequisites**. Comprehensive Docker-internals modeling, new native-observer infrastructure and stronger exactly-once controller/host commit-acknowledgement protocols are deferred unless a specific required operation demonstrates that they are necessary. Source investigation must answer that concrete gap rather than recursively expand a global proof obligation.

This changes the future design and acceptance scope, not installed behavior. Existing guards, fixed capability boundaries, locks and executable contracts remain enforced until an explicit reviewed replacement is implemented and qualified. Do not bypass a gate to make an existing command work. If a required operation still needs a stronger mechanism, either implement the minimum necessary mechanism or leave that operation blocked.

## Failure and startup guarantees

An attended operation need not automatically restore every partially changed resource or preserve workload sessions after failure. It must report partial/unknown outcomes honestly, retain ownership and recovery information, and prevent another cooperating operation from proceeding until outstanding effects are resolved. Configuration rollback is not data rollback.

A lost controller connection/result is unknown, not evidence that the host stopped, rolled back or committed. Do not retry, clear ownership, adopt another actor's transaction or assume callbacks ended. Resolve outstanding native jobs/processes and transaction state through the documented, separately authorized recovery route before new mutation. No replacement bridge or cached exited-unit result manufactures completion authority.

Preserve the startup policies already selected:

- Inert/recovery preparation must not unexpectedly activate production workloads or write below an inactive protected mountpoint.
- A failed/interrupted **precommit** activation grants no subsequent boot permission. Do not publish an early activation marker or use the legacy guard as a bypass.
- Successful activation permits freshly verified full boot, reconciling the complete declared stack, including services previously stopped manually.
- Daemon-only restart preserves native restart-policy/manual-stop behavior; do not replace it with whole-project `up`/`stop`, `restart: no`, or a blanket prohibition on survivors.
- Cached `RemainAfterExit` success or marker presence alone is not fresh admission.

The trust model remains cooperative local/root administration, not protection against arbitrary privileged writers or indistinguishable rollback of all local identity and authority state. No external monotonic verifier is introduced.

## Safety controls that remain

Preserve protected disk/UUID/boot-order identities, including VM100 `scsi3`, `scsi3;net0` and absent retired `scsi0`; existing persistence; strict independently established host trust; separate plan/apply authority; exact reviewed plans/artifact/image identities; secrets boundaries; controller/host locks; fixed firewall recovery; and native Restic staging verification. Retain `C.UTF-8` and the contract's declared host settings.

Packages and reboots remain separately authorized, not unattended. Supported native qualification and missing-package gates remain mandatory; no automatic dependency installation, unsupported-platform success, or synthetic evidence promoted to installed proof. Production data/disks/credentials are not rehearsal inputs. The failed VM9900 qualification remains failed and requires fresh observation, a new exact plan and separate approval before recovery or another attempt.

## Deferred work is not a completion gate

- Scheduled collection, reporting/publication and missed-report monitoring remain deferred under ADR 0002.
- New release/maintenance automation and optional Compose simplification are separate projects. Existing package/reboot controls and the operations needed for bootstrap/recovery still require qualification.
- The fixture-only predecessor observer and unimplemented broker designs are optional retained candidates, not production capabilities or required next steps. The later owner-approved source cleanup archived the [Debian observer pair](../../archive/lifecycle-experiments/debian-predecessor-observer/README.md) without changing its bytes or discarding evidence. This ADR itself grants no installation or deletion.
- Broad optimization, protocol replacement and exhaustive fault-model expansion are not required merely because a more elaborate design could exist.

## Bounded development recovery

Replace approval-per-mechanical-error with bounded recovery **inside an already approved local source/test scope**:

1. Stop the failed action; record its exact error, command and source/worktree state. Preserve any partial diff and distinguish setup failure, causal RED, coverage and success.
2. The supervising parent may make one understood mechanical correction and retry the affected local step once without a new owner prompt: use an already supplied path, verify an existing private directory instead of recreating it, correct a local wrapper invocation, or compare exact source/mode coverage when patch serialization differs.
3. Do not overwrite historical evidence, chmod unrelated/source inputs to fit a snapshot, suppress failing checks, change the expected safety outcome, or label a failed attempt successful. Use a new attempt/verification record.
4. If the cause is unclear, repeats, or needs new permissions, dependencies, execution mode, targets or protected inputs, stop and ask the owner. Subagent infrastructure failures still require their native stop/report/state-capture and same-protocol recovery procedures; no external/foreground fallback or environment repair is implied.

Ordinary source-review fixes within the agreed behavior/edit scope can proceed with causal tests and fresh review without reopening the whole project decision. New guarantees, expanded effects and operational actions still require a new decision. This local development allowance never retries a host operation, failed rehearsal, uncertain remote transaction, credential action or public publication.

## Consequences

We accept planned downtime, operator-led recovery and deferral of optional automation in exchange for fewer custom protocols and a finite completion target. We still require real evidence for data/access safety and the native behavior we actually rely on. The next implementation must close a named acceptance gap; producing another non-authorizing model alone does not advance production readiness.
