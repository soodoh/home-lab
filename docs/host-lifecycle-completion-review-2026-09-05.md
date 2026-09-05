# Host lifecycle completion review — 2026-09-05

Status: **incomplete; repository hardening only, not production acceptance**.

Reviewed the Desktop plan `ansible-debian-cloud-init-refactor.md` (SHA-256 `1e74b68607cc3ee940059e6e8363b9cd05f970b5690ef2666fa52424fe352d7b`) against clean starting revision `d0b085212199605478cab9ccb91214629ae76ad0`, the current contract, ADR amendments, implementation, committed evidence and selected private qualification receipts. No production or disposable-host mutation was performed in this review. Historical evidence is not a fresh host observation.

## Current authority, not the original assumptions

- Ansible already owns both hosts. The [aggregate Proxmox cutover](proxmox-aggregate-authority-cutover-2026-09-04.md) records 17-domain parity and five no-op OpenTofu roots. Do not repeat that cutover.
- The steady controller still builds, validates and consumes Nix compatibility material. Ansible ownership does **not** mean Nix-free controller acceptance or runtime retirement is complete.
- [ADR 0001 §6](adr/0001-ansible-host-lifecycle.md) supersedes automatic Debian security updates, merge-authorized package installation and automatic reboot. Every mutation requires a separately reviewed exact transaction. Do not add the original unattended apply lanes.
- The accepted qualification route uses production PVE plus disposable VM9900, not an independent physical PVE host. Production VM100, its disks, guest credentials and application state remain prohibited rehearsal inputs.
- The adopted contract uses `C.UTF-8`, not the original proposed `en_US.UTF-8`. Current role/tests preserve that declared policy.
- OpenTofu still does not represent the existing `scsi3` root as a disk block. Its contract/audit protection must remain; no production adoption is authorized.
- Compose artifact identity, image locks, Restic staging verification, fixed firewall transactions and all apply guards remain required.

## Requirement / evidence / next gate

| Original phase | Current implementation/evidence | Still needed |
| --- | --- | --- |
| 0–1 discovery and design | Ownership/access/retirement matrices, accepted ADR, contract and collection pin exist | Fresh revision-bound live baseline before any new operation; historical matrices need current-status annotations |
| 2–3 Proxmox Ansible and cutover | Domain handoffs and aggregate Ansible ownership recorded | Nix-free controller/manifests, reusable-asset migration, separately approved runtime/rollback retirement |
| 4 Debian profiles | Explicit inert/recovery/production role gates; base ownership and strict access boundaries | Descriptor-safe inactive-mount observer; complete disposable base convergence and second-run zero change |
| 5 root behavior/cloud-init | Minimal first-contact template and VM9900 controllers exist; warm-repair proof recorded | Clean first-boot chain, installed observer/booted-template provenance, exact-image prerequisites, synthetic disk topology/adoption proof |
| 6 lifecycle transactions | Storage/identity/enrollment/activation/replacement-disk executors and fault fixtures; inert canary and lock recovery recorded | Contract-bound per-property systemd graph; all substantive transactions rehearsed without production state or credentials |
| 7 maintenance | Exact package/reboot capabilities, candidate generators, Renovate managers, weekly release artifact, monthly coverage artifact | Attended installation/rehearsal and unattended-upgrade retirement proof; trusted scheduled candidate collection; useful deduplicated issue/PR and dashboard aggregation |
| 8 Compose | Existing artifact/image/rollback safeguards retained | Preserve them; optional simplification is not a prerequisite and must not be used to bypass recovery proof |
| 9 cold recovery | Restic staging/recovery tools and authority receipts exist | Complete minimal-image → inert → synthetic restore/storage/access → production-profile recovery proof, including interruption/reboot |
| 10 retirement | Nix mutation frozen; some account/domain retirement evidence exists | Finish consumer inventory, retention/terminal-session gates, source/runtime/schema/attestation migration; do not delete API principals |
| 11 acceptance | Local checks below pass within stated limits | Full authoritative validation, current host audits, exact Compose runtime equality and all enabled OpenTofu roots at no-op on one reviewed revision |

## Fixes in this review

1. Registered the existing first-boot and offline-diagnostic suites in `scripts/reconcile-infrastructure validate`. Added a security regression assertion for their registration and the existing indirect policy-suite coverage of tailnet policy, Ansible-plan normalization and Omada host aliases.
2. Storage activation now encloses exclusive token creation, writes/fsync, daemon reload and mount starts in its rollback scope. The open descriptor binds token ownership; rollback preserves preexisting tokens, refuses inode/content replacement observed before deletion, revokes owned partial publication, fsyncs removal, stops only attempted mounts and checks mount absence. This assumes cooperating writers under the host lock and a trusted root-owned parent: pathname unlink after the identity check is not an atomic inode CAS against a racing privileged writer. Failed cleanup remains an explicit failure with no automatic retry.
3. Storage and production unit admission/rollback require successful named `LoadState=loaded`, `ActiveState=inactive`, `SubState=dead` observations. Nonzero `is-active` status or an observer failure is no longer accepted as proof of inactivity. Inactive mount checks reject unexpected `findmnt` errors/output.
4. Added fault injection for reload/interruption, fsync/short-write failures, token replacement/content drift, partial starts, cleanup/observer failures and mount-observation errors. Registered this suite in authoritative validation.
5. Inert/recovery unit checks now include `docker.socket` and all existing Restic targets/workers, with coverage tied to the declared Restic unit inventory.
6. The maintenance dashboard workflow now stamps actual UTC execution time, not repository `updated_at`, and runs its regression test before publication. It remains credential-free and non-authorizing.
7. Corrected stale gate/automation prose and documented persistent descriptor-lock semantics. No evidence artifact was upgraded to a stronger qualification claim.

Changed executor bytes are **not installed or live-qualified**. Existing evidence bound to executor SHA-256 `94689348c8195a14c509cb90d2a35ad07afe068a96a541af7e6eba830773e494` remains historical. A fresh capability install/check and disposable proof are mandatory before the new executor is used.

## Open safety/implementation blockers

### P1: production dependency graph

`scripts/controller/debian-lifecycle-transactions.py` checks the selected unit names and request/observation equality but does not bind minimum dependency edges to the contract. The host executor checks the union of `Requires` and `After`, so an ordering edge alone can appear to satisfy a requirement; empty lists also pass. Derive and bind the required per-property graph from durable unit policy, then reject empty/weakened graphs and wrong-property edges in both controller and host fixtures. Do not activate production using the present dependency proof.

### P1: inactive protected path observation

`ansible/roles/debian_lifecycle_guard/tasks/main.yml` still uses `os.path.ismount` and path-based enumeration. Same-filesystem bind mounts, symlinked ancestors and inspection/open races are not reliably excluded. Replace this with exact Linux mount identity plus component-safe descriptor-based observation, and test no traversal for unsafe/mounted paths. Rehearse actual bind mounts only on an approved disposable Linux target.

### P2: clean-first-boot provenance

`scripts/controller/debian-qualification-first-boot.py` records local helper/transport hashes without independently proving the installed producers emitted the result. Return/validate a locked installed-producer and snippet envelope, bind it to the foundation/start chain and distinguish observer revision from booted-template provenance. Add behavioral stale-producer, template-mismatch, source-change and receipt-publication tests. Add uptime boundary tests matching the implemented -2..120-second bound; this review did not change that policy.

### Nix-free controller and retirement

Replace the compatibility stage with versioned neutral check evidence while preserving commit/dependency/host/protected-fact binding, freshness, immediate recheck, one-tag scope and zero-change audit. Reject old or weakened manifests rather than treating Ansible check output as a consumable saved plan. Move shared controller/host lock code, firewall/VFIO assets and retained package evidence before removing Nix sources. Runtime deletion remains blocked on consumer, terminal-session, retention and rollback proofs.

### Maintenance and recovery completion

The monthly dashboard reports configuration coverage, not fresh host package candidates, pending reboot state and open migration issues. Complete non-authorizing collection/aggregation/publication with explicit stale/missing-input tests and a reviewed trusted runner. Package/reboot executors being present is not evidence of installation or successful rehearsal. Obtain fresh proof of the unattended-upgrade retirement state rather than assuming the old drift record still describes the host.

The substantive Debian recovery operations currently route to the recovery/production inventory, whereas the VM9900 canary is deliberately narrow. A synthetic recovery qualification route must be reviewed and identity-bound; simply redirecting a production transaction or copying production secrets into VM9900 is not acceptable.

## Interrupted qualification investigation

The controller mutex file is persistent by design. A read-only nonblocking descriptor probe found no exclusive holder and left its bytes unchanged; the recorded PID was absent. Neither an old PID nor file existence justifies unlinking it.

The latest selected private invocation-failure record was created at `2026-09-05T19:34:17Z`, SHA-256 `6b342c840fdb4accc80dbb54ff933a6e43ec1711fedf298c514e649bea884dce`. It records:

- plan `09f7429ea9d5a0bf9d059470c8eb16fe10faf56b81e87fcfbaa942081f9c2976`;
- reason `incorrect-snippet-receipt-path`;
- post-failure VM9900 status `stopped`;
- `automatic_retry_allowed: false`;
- fresh observed admission and a separately authorized new plan required.

No current VM state is inferred from this historical file. Preserve all failed/recovery receipts and private state. Before resuming, independently verify current host keys, VM9900 and VM100 state, shared locks and console readiness. A clean-first-boot acceptance chain ultimately needs new foundation/start evidence, not a repaired/restarted guest passed off as first boot.

## Validation and limits

Passing local checks in this review:

- contract/schema and pinned collection validation;
- provider-lock coverage and recursive OpenTofu formatting;
- Ansible lint across roles/playbooks and syntax checks for every playbook;
- lifecycle/profile/transaction/authority, package/reboot fixture, release/dashboard, first-boot/diagnostic/transition, controller-lock and reconciliation-security suites;
- newly added storage rollback fault injection;
- `shellcheck scripts/reconcile-infrastructure` and `git diff --check`;
- `docker compose config --no-interpolate --quiet` and pinned-image checks (38 declared services).

`scripts/reconcile-infrastructure validate` exits 69 immediately: `nix` is not installed in this controller environment. The Nix-dependent build/closure checks were **not** run or bypassed. A plain interpolated `docker compose config --quiet` also fails because production `.env` values are unavailable; the no-interpolation check verifies declarations only, not deployable environment or runtime health. No production environment was decrypted, no services started, and no fresh live-host/OpenTofu no-op acceptance was claimed.

## Safe next order

1. Review and commit the repository hardening; complete the open P1/provenance fixes with failure tests.
2. Restore a supported full validation environment, or finish and prove the Nix-free validation/controller migration without deleting retained rollback evidence prematurely.
3. Re-establish fresh read-only target admission and obtain exact approval for any failed-operation recovery, capability install, VM9900 restart/destruction or replacement qualification chain.
4. Perform complete synthetic cold-recovery and maintenance rehearsals, then separately reviewed production convergence/retirement.
5. Publish one revision-bound acceptance set covering both hosts, Compose/Restic and every enabled OpenTofu root. Until then, do not mark the original plan complete.
