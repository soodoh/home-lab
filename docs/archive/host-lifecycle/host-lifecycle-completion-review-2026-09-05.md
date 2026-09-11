# Host lifecycle completion review — 2026-09-05

> Historical snapshot; not current runtime evidence or a current acceptance checklist. See the [current operational plan](../../host-lifecycle-completion-plan.md) and [archive index](README.md). Historical failures and evidence limits below remain unchanged.

Status: **incomplete; repository hardening only, not production acceptance**.

Historical review and evidence below remain unchanged apart from navigation. Current completion scope and sequencing are defined by [ADR 0004](../../adr/0004-operational-nix-retirement.md) and the [operational checklist](../../host-lifecycle-completion-plan.md); do not treat deferred reporting, full-rebuild qualification or superseded framework proposals below as new operational acceptance gates.

Reviewed the Desktop plan `ansible-debian-cloud-init-refactor.md` (SHA-256 `1e74b68607cc3ee940059e6e8363b9cd05f970b5690ef2666fa52424fe352d7b`) against clean starting revision `d0b085212199605478cab9ccb91214629ae76ad0`, the current contract, ADR amendments, implementation, committed evidence and selected private qualification receipts. No production or disposable-host mutation was performed in this review. Historical evidence is not a fresh host observation.

## Current authority, not the original assumptions

- Ansible already owns both hosts. The [aggregate Proxmox cutover](../../proxmox-aggregate-authority-cutover-2026-09-04.md) records 17-domain parity and five no-op OpenTofu roots. Do not repeat that cutover.
- The steady controller still builds, validates and consumes Nix compatibility material. Ansible ownership does **not** mean Nix-free controller acceptance or runtime retirement is complete.
- [ADR 0001 §6](../../adr/0001-ansible-host-lifecycle.md) supersedes automatic Debian security updates, merge-authorized package installation and automatic reboot. Every mutation requires a separately reviewed exact transaction. Do not add the original unattended apply lanes.
- The accepted qualification route uses production PVE plus disposable VM9900, not an independent physical PVE host. Production VM100, its disks, guest credentials and application state remain prohibited rehearsal inputs.
- The adopted contract uses `C.UTF-8`, not the original proposed `en_US.UTF-8`. Current role/tests preserve that declared policy.
- OpenTofu still does not represent the existing `scsi3` root as a disk block. Its contract/audit protection must remain; no production adoption is authorized.
- Compose artifact identity, image locks, Restic staging verification, fixed firewall transactions and all apply guards remain required.

## Requirement / evidence / next gate

| Original phase | Current implementation/evidence | Still needed |
| --- | --- | --- |
| 0–1 discovery and design | Ownership/access/retirement matrices, accepted ADR, contract and collection pin exist | Fresh revision-bound live baseline before any new operation; historical matrices need current-status annotations |
| 2–3 Proxmox Ansible and cutover | Domain handoffs and aggregate Ansible ownership recorded | Nix-free controller/manifests, reusable-asset migration, separately approved runtime/rollback retirement |
| 4 Debian profiles | Explicit inert/recovery/production role gates; descriptor-safe inactive-path observer and hostile synthetic tests | Native Linux bind-mount/namespace proof; complete disposable base convergence and second-run zero change |
| 5 root behavior/cloud-init | Minimal first-contact template; VM9900 controllers; strict v2 installed-producer/booted-cache provenance and consumer tests | New clean first-boot chain with installed bytes; exact-image prerequisites; synthetic disk topology/adoption proof |
| 6 lifecycle transactions | Rollback fault fixtures; contract-bound per-property production graph and installed-policy/drop-in path; historical inert canary | Installed-policy/activation proof; durable Docker/Compose/production-guard unit-body ownership; all substantive transactions rehearsed without production state or credentials |
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

## Safety implementation and remaining qualification gates

### Production dependency graph — repository fix integrated

Controller requests/observations now use a production-only v2 graph bound independently to the contract; the host additionally verifies installed policy and separate live `Requires`/`After` properties. Docker and Compose retain guard/mount requirements. Timers gain ordering after Compose but do not implicitly start it. Capability installation writes additive drop-ins without starting/restarting units and reloads on every non-check installation, including a separately authorized reinstall after interrupted reload. Hostile graph and interrupted-installation fixtures pass. Installed proof and durable Docker/Compose/guard unit-body ownership remain necessary before complete cold recovery.

### Inactive protected path observation — repository fix integrated

The role now invokes a separately tested Linux x86_64 helper using `openat2` no-symlink/no-mount-crossing traversal, `statx` mount identities, descriptor-only enumeration and identity/namespace rechecks. Every inactive-path entry is refused. Unsupported kernels and separate-filesystem ancestors fail closed. The 29 synthetic tests do not replace native x86_64 bind-mount/namespace and two-run inert-convergence qualification.

### Clean-first-boot provenance — repository fix integrated

The first-boot controller independently renders and binds the exact snippet, challenges the locked installed producer, and requires the guest's cached user-data hash to match the snippet/start/source chain. The strict v2 host-key consumer revalidates producer/source/envelope/stopped-chain bindings and rejects v1 evidence. Producer, consumer and inclusive -2..120-second boundary fixtures pass. Actual embedded cache-reader code also passed confined Linux filesystem tests, including FIFO, symlink, ownership, hardlink, short-read and content/mode/replacement races, inside the local Colima development environment with no network or production input. These are not clean-first-boot or VM9900 deployment proofs.

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

## Continuation after review

The operator instructed the controller to continue through completion without stopping for routine authorization prompts and explicitly reaffirmed the **current ADR maintenance policy**. This standing direction does not change exact-plan, target trust, lock, no-retry, protected-disk, backup or console prerequisites, and does not authorize unattended package/reboot workflows.

- Repository hardening was committed as `601147a`; complete lifecycle SSH checks and offline behavioral fixtures followed in `72035ef`. Lifecycle compliance now explicitly requires password and keyboard-interactive authentication disabled as well as public-key/root login disabled.
- Fresh pinned-key read-only observations from `601147a` passed both hosts' lifecycle checks, Debian's complete audit (`57` tasks, `changed=0`) and Proxmox's complete 17-domain audit (`parity: true`, `changed=0`). The strengthened lifecycle check also passed on both hosts without changes.
- At `2026-09-05T22:16:10Z`, VM100 was running and VM9900 was stopped. No failed qualification operation was retried. These observations do not replace fresh admission immediately before an operation.
- Package observation refreshed **no** metadata and installed nothing. Debian reported zero changes and a valid candidate observation. Proxmox reported two installs/six upgrades, but candidate admission correctly remained blocked on unsafe keyring-path and incomplete package-size evidence. No package apply was attempted.
- Private reduced logs are retained under `.local/completion-601147a/`. These are intermediate baseline observations, not final revision-bound acceptance or disposable cold-recovery qualification.
- Isolated implementation/review lanes completed for the inactive-path observer, contract dependency graph and first-boot provenance. Parent integration addresses their test-registration, consumer-version and interrupted-reload findings. Nix-free controller and maintenance publication work remains open; the overall status above is unchanged.
- The operator selected this existing Mac controller for scheduled read-only collection. Sleeping/offline periods must surface as stale/missing observations; no host credentials will be added to GitHub reporting workflows.

### Recovered neutral-controller and maintenance integration (not acceptance)

- Both timed-out implementation candidates were recovered as exact patches and independently reviewed. The maintenance candidate also had a completed commit (`69887df`); timeout did not mean its changes were absent. Review findings block deployment, not preservation of the recovered work.
- Parent source integration now passes the complete Nix-free `scripts/reconcile-infrastructure validate` entry point, including registered maintenance aggregation, publication planning, launcher, read-only capability and explicit plan-generation suites. Retained AWS first-run proof was available in the parent checkout; it was not fabricated or waived to obtain this pass.
- Ignored unchecked-hash bytecode execution was reproduced and closed for the maintenance controller-lock import. Malformed local inputs now fail per slot while preserving other observations. Release v2 reports bind clean source, contract and package-manifest identities; consumers reject legacy, dirty or mismatched reports.
- Freshness-only changes no longer force public issue updates. Regression tests rebuild fresh package locks and report timestamps, require zero PATCH requests for unchanged state, and require an update for a different candidate version with unchanged package counts. Exact changing evidence remains private and hash-bound.
- Public controller calls require an explicit immutable plan generation so failed/expired attempts survive a fresh plan at the same revision. The host audit observer no longer creates missing mutex files and releases partially acquired descriptors on failure.
- Read-only reporting capability fixtures pass on this Mac (native filesystem case explicitly skipped) and all ten pass inside a network-disabled, read-only local Linux container with only disposable fixture files. This tests native descriptor reads, not installed host capability or real package-producer integration.
- **Still open:** Proxmox operation-descriptor lifetime migration and capability/sudo/installer wiring; dedicated reporting identity/policy/ACL installation; reviewed attestation renewal; bounded live publication/signing setup; durable Debian unit/bootstrap/storage ownership; substantive disposable cold recovery; and revision-bound live acceptance. A local Debian container has root-owned sticky mode-1777 `/run/lock`; target locking must handle legitimate platform topology without changing shared directory permissions or weakening unsafe-ancestry checks.
- No host mutation, schedule enablement, public publication, failed-qualification retry or Nix evidence retirement is justified by these source checks. The original completion status remains **incomplete**.

### Shared reboot ownership follow-up

- Compatibility inventory showed that legacy Nix, firewall and Ansible writers honor `reconciliation/apply.lock`, not merely `owner.lock`. Offline implementation of a distinct versioned reboot record at that shared path was approved, with operation-first locking, exact ownership, durable pre-side-effect retention and narrowly authorized postboot verification. Installer compatibility remains a hard gate; no live installation/reboot was approved.
- Parent maintenance and package observers now detect retained `apply.lock` even when no descriptor holder remains. Regressions first failed on the old source, then passed for actual regular-file, dangling-symlink and FIFO fixtures with empty lock listings. `operation.lock` remains descriptor-only; no retained records are read, removed or repaired by collection.
- An intermittent launcher test exposed access-time changes being mistaken for file replacement. Explicit device/inode/ownership/mode/link/size and nanosecond modification/change-time comparisons now ignore access time only; deterministic tests reject changes to every protected field at both descriptor and pathname boundaries.
- Full authoritative Nix-free validation passes after these changes. Launcher: 15 tests; read-only capability: 11 tests (one native skip on Mac, all 11 passing in confined Linux); package producer and report/publication suites pass. These parent changes postdate frozen review snapshot `d72c3fc` and need inclusion in the final integrated review, not attribution to that earlier snapshot.

### Capability candidate integration and review recovery

- Final PVE capability candidate is `4c19305` (superseding intermediate `b6547e8`), with exact retained patch verified against `d72c3fc`. Parent applied it only as unaccepted working-tree integration; main HEAD remains `8b5706f`. The intended independent PVE review was skipped because the orchestration ref check rejected a full `refs/heads/` name. A fresh integrated review is required; successful worker completion is not review approval.
- Candidate installer and new reboot application remain unconditionally blocked on missing VFIO queued-reboot coordination. Legacy package-observer and inert-plan apply installers also refuse; this candidate does not supply a replacement inert bootstrap. No gate may be bypassed to claim recovery completion.
- Maintenance follow-up confirmed the four original fixes, but found ignored unknown absolute lock paths and buffered host command capture. Parent now rejects unknown paths and drains subprocess stdout/stderr under one combined byte bound, deadline and failure cleanup. The scheduled wrapper also routes the pinned package producer's commands through that bounded runner; standalone package command capture remains a separate implementation. Real subprocess fixtures cover exact-bound output, stdout/stderr/combined overflow, timeout and interrupted cleanup.
- Full Nix-free authoritative validation passes with the new PVE suites registered. Parent reproduced all 14 PVE protocol tests in a network-disabled, read-only-image child-chroot container. Its first reduced-capability attempt failed three fixtures; the passing reproduction explicitly includes DAC_OVERRIDE, needed for synthetic read-only boot-ID rewrites and root metadata probes. Read-only capability now has 13 tests, all passing in confined Linux (one native skip on Mac). No tests ran real package mutation, workload stop, reboot or host contact, and these passes do not qualify target topology or installed bytes.


### Durable cleanup, strict admission and source-bound dispatch repairs

- Recovered independent review of `6fab729` identified four P1 source defects: missing directory durability, incomplete access admission, interruption-obstructed terminal cleanup, and implicitly refreshed remote source bindings. A separate reporting review identified a SIGALRM spawn-boundary cleanup gap. Those reviews did not grant integrated or operational acceptance.
- Durability candidate `8441eaae0e6557b0c1e7bd398a93d84ac6f6e4f9`, retained at `pi-durable-journal-candidate-8bb20983010c`, passed independent source review with no findings in its lane. Parent verified exact baseline-to-commit patch bytes and SHA256 `9fba447635c4dcdfc8dd4a742075046d88b7d56668d4e82fec2ed0d9138af3d8` before integrating. Actual directory/file fsync ordering, unique temporary publication, inode-bound terminal detachment, abrupt child exits and foreign-owner refusal are covered by 20 passing confined native protocol cases; these do not simulate physical storage power loss.
- Durable committed installation permits only separately confirmed `cleanup-committed`, never rollback of installed bytes or an apply retry. Rolled-back state permits its own cleanup. Parent wired the exact controller route without audit substitution or installation authority; fresh unchanged prerequisites and recorded ownership remain mandatory.
- Parent implemented strict access v1 shape/source/host/time/positive-negative proof validation and captured both inventories in the saved plan. Remote phases now retain approved commit/bindings and hash-checked transaction bytes, refuse observed changes and never replace those identities at dispatch. Twelve controller tests pass, including the actual attestation producer-to-consumer fixture, the former incomplete 2099 receipt, malformed/boundary proofs, revision substitution and separately confirmed cleanup. Console/source bindings and host behavior in these tests are synthetic, not live admission.
- The reporting runner now defers SIGALRM exceptions only through process creation until cleanup is armed, without masking inherited signals. Real spawn-boundary interruption and spawn-failure fixtures check child termination, pipe closure and handler restoration. All 14 reporting capability tests pass in confined Linux; one native test is intentionally skipped on Mac.
- Full parent Nix-free validation passes after the integrated repairs, using legitimate retained AWS evidence. Diagnostics, diff whitespace and declaration-only Compose validation also pass. At review freeze, main remained uncommitted integration at `8b5706f`; no frozen snapshot was attributed to installed hosts.
- The old access capture command still lacks the newly required explicit controller generation. A reviewed generation-aware capture and predecessor/bootstrap admission path remain outstanding; no receipt is fabricated or gate relaxed to work around this. VFIO coordination, target mutex provisioning, reporting setup/renewal/publication, durable Debian recovery, new independently admitted disposable qualification and revision-bound live acceptance remain open. No production mutation, schedule/publication enablement, push or automatic retry occurred.
- Fresh independent review of frozen candidate `eb35c42b61e5c0c5b213d9606aa208199d51997c` (tree `f6a78b283c111020a8888f6cbf4b2c806433596e`) found no issues in the combined admission/source-binding/cleanup/reporting changes and approved bounded source integration. Review SHA256: `56864b6ab82954cf34764a240d3274324e1e8e73f3d44fa962f4787285908ab3`. Parent verified exact checkout equality before committing, with only these subsequent review-status documentation updates. This closes the four identified P1 source findings and the reporting P2; it does not close the operational gaps above or establish live acceptance.


### VFIO shared-coordination source migration

- The reviewed neutral/reporting/capability checkpoint was committed as `85ea056d10bb84c862aa05cc676c1898d04e1717`; commitlint and full post-commit validation passed with a clean checkout. No push or deployment followed.
- Source-grounded design found no normal guest-startup call to the explicit stopped-VM VFIO recovery CLI. Installed hooks/callers remain unknown. The bounded migration adds operation-first exclusion, blanket retained ownership refusal, protected policy reads, preexisting VFIO/QEMU descriptors and fixed isolated execution without inventing a postboot handoff or automatic recovery. Retained Nix source and all installer/controller/reboot gates remain unchanged.
- Candidate `2594ed479ae0310527fb9112e316a7efebcd8833` is retained at `pi-vfio-coordination-candidate-a4e62c98`; its sole parent is `85ea056`. Exact five-file patch SHA256 is `6d69ee7b24cbaa5e8a277e3c115527f6ace35b4182a33791747baa0b9e722bfa`. Parent verified the ref, parent, diff bytes and source-only archive before integration.
- The implementation workflow failed on unsupported `acceptanceReport.nativeEvidence`, so its planned review never ran. The failed report remains preserved and unapproved. A separately launched independent review of the recovered exact candidate found no issues and approved bounded source integration; review SHA256 is `96766b17f9e3dc56eaf971d4b18751fa59a29aee7808fcd484d30ba0ba188801`.
- An earlier recursive archive accidentally included one locally generated source-derived `.pyc`. The deviation was disclosed; those native passes are superseded, not counted. Parent independently verified the final archive's exact nine regular files against candidate Git blobs, checked its hash/membership before extraction into empty disposable storage, and reran all 15 VFIO, 21 protocol and 14 maintenance tests without skips. Before/after cache scans passed. Archive SHA256: `8c83c35edf3dbbc066e37c53a234a03eb19ea690cfd56eda3b2109b2324a6310`; parent native log SHA256: `20c1616240dabe3a4a3dbe424ea013fce2c6ab65dfd45c701892e5e645cbddf6`.
- Full parent Nix-free validation, syntax/diagnostics, diff checks and secret-free declaration-only Compose validation pass after integration. The cached Linux image lacks `/usr/bin/python3`; explicit interpreter/backend/native-command substitutions are not installed qualification. No actual VM/device/package/reboot operation occurred.
- This closes the bounded VFIO source-coordination implementation, not its installation or qualification. Exact helper/policy/interpreter/import/native dependency closure, actual callers/startup, mutex metadata and boot provisioning, bootstrap/admission, reporting setup, durable Debian recovery and live acceptance remain open. No owner adoption/removal exemption, source-hash-only enablement or gate bypass is authorized.


### Predecessor-path decision and offline policy diagnostic

- VFIO source integration was committed as `6509c4bbf0897191982ff0157bbace52e653e1e7`; post-commit full validation passed. Operator selected development of a versioned capability-only predecessor admission path, preserving strict v1 and refusing missing assets, without deployment or gate removal.
- Source analysis established the cycle: existing access capture needs a complete steady neutral check, while installing that capability needs fresh access evidence. A generation flag alone would also expose legacy trust/stdout-proof weaknesses. A later specification run was aborted; its output remains a draft, not acceptance. Parent confirmed firewall inspection can create missing runtime ancestry before validation, though `ensure_dir` does not chmod/chown existing directories. Full fixed-asset/runtime evidence and retained-recovery expiry rules remain unresolved; no new collector or receipt issuer is enabled.
- The deliberately narrower first implementation is the imported Tailscale content diagnostic, retained as candidate `74d637c57ff5282e8c305b0cbaf6267ed02802af` at `pi-tailscale-diagnostic-candidate-31c17ba5-final`. Parent verified exact parent/ref/patch bytes before integration; patch SHA256 is `da950f7292b2c89934db28d7974bc2008e9a72aa5f55379307014730cbcba5e5`.
- Independent review approved bounded offline diagnostic integration, with a P2 finding that structural-policy negative tests could reject on unrelated mismatches. Parent applied the prescribed exact-error assertions and separated substitution tests. Disabling the structural validator reproduces a passing old matrix and a failing strengthened matrix. Review SHA256 is `d3377769f05e0a58c0ad454801d53923dbcc97e703d051ba545dd3094e13ab46`.
- All 15 focused diagnostic tests pass, including actual isolated CLI, unchanged v1 rejection with flags flipped, and real local OpenTofu 1.12.5 builtin-only init/plan/show under network denial with synthetic unchanged state. No apply/import/backend/provider download or live planning occurred. Existing policy tests, authoritative registration guard and full parent Nix-free validation pass; syntax, diff and secret-free Compose declaration checks pass.
- Every diagnostic remains `authorized:false`, `admission_eligible:false`, `origin:unqualified-import`, with explicit binary-linkage, live-origin, execution and independent-policy-review blockers. The exact unused Tailscale provider metadata exception is opaque/unverified and only synthetically exercised; no resource may reference it. No host/API/collector execution, console attestation, receipt issuance, consumer/schema change or operational gate removal is introduced. Predecessor admission and overall completion remain open.


### Console-only fixed-asset measurement source

- The offline Tailscale diagnostic was committed as `c8ed8e7bc2aa44ba93f9191e21fc3e48647bed00`; full post-commit validation passed. Operator then explicitly approved offline development/testing of a console-only read-only fixed nonsensitive asset/metadata collector, without secrets dumps, new SSH/sudo verbs, installation or live execution.
- The writer failed on a WebSocket error after preserving `c69d8d5b57c2f56ec4345abf0306fbba88176e7f`. Parent recovered its durable ref/patch, verified exact source/archive provenance and reran 12 confined Linux tests. The following review was aborted; its findings were retained, but its apparent verdict was not counted as approval.
- Parent closed two test gaps: exact startup refusal reasons and collection tripwires prevent unrelated interpreter/root/PTY/non-TTY failures from masking broken guards; 128/129-byte signing-key and 4096/4097-byte mutex cases establish their separate metadata limits without content reads or secret hashes. Five in-memory mutation probes detect removed interpreter/root/console checks and widened key/mutex limits. Mutation log SHA256: `1e7b2b74129c0cf51c330b6858f0f54fe6439acac7995d9175fc1517f54da904`.
- Completed review of `6f517fed53bbac2b772bfed70a8f493a014a23ed` closed those gaps but found a P1 registration defect: plain Python lacked required startup flags and inherited the reconciler's forbidden `PYTHONDONTWRITEBYTECODE`. Parent reproduced the native failure, then changed only registration and its guard/regression to use a sanitized environment and actual `-I -B -S` flags. The regression executes the exact extracted registered command under synthetic SSH/PYTHON contamination, with no native skips allowed on Linux/root.
- Final candidate `779a2d493d8382fe30733058c3b921d2d4e0f0ea` is retained at `pi-predecessor-console-candidate-registration-01`. Combined patch SHA256: `964d7f83ce41bb30858b4964ef3b79a79141f0930148c92a8830d6b5d0f2b8e9`. Completed targeted review closed the P1 with no new findings; review SHA256: `81ef6f39e9b6b639287a525a0ee310541d8cc38ffc77aba066d055e3bd875323`. Collector bytes are unchanged from the original recovered candidate.
- Parent verified all nine explicitly enumerated regular source archive members against final candidate Git blobs, archive hash/membership before extraction into empty tmpfs, and cache absence before/after execution. The actual registered-entry regression and all 13 collector tests pass in the cached aarch64 Linux container without network or host/repository/secret mounts. Archive SHA256: `840a8df06fa9fce42b7f0b994bc03941549715bcd2c2f1066015f3290e33d994`; native log SHA256: `2b72c8f68eff441064502c32904269cd4bc85b55b98ee801574d541238e1ddff`. Hardware-terminal and interpreter-path substitutions remain explicitly synthetic, not installed/physical-console/x86_64 qualification.
- Full parent Nix-free validation, 17 security/registration tests, syntax/diff checks and secret-free Compose declaration validation pass. Mac native skips are not counted as Linux evidence. A worktree hook dependency failure was resolved by linking existing cached dependencies, without installation/download; normal hook then passed.
- This closes only the reviewed measurement source slice: fixed public helper/transport/sudoers hashes, protected metadata-only signing-key inspection, existing operation flock, blanket retained-owner refusal and no-create/no-repair semantics. Every result is non-authorizing with explicit profile, host-binding, account/key/runtime coverage, execution/console-origin and freshness/recovery blockers. No target collection, activation, receipt issuance, consumer change, privilege grant or operational gate removal occurred. Independently approved predecessor profiles, attended execution/console qualification, expiry-safe recovery, reporting installation and durable Debian/live acceptance remain open.


### Legacy transition design and synthetic classifier

- Console measurement source was committed as `f9829528d98b2be1303414a01a00ab0d93acc63a`. Subsequent source mapping established that the legacy private-preparer is not the neutral protected collector: the current nine-asset measurement slice cannot inventory a legacy-only host. Operator selected a distinct legacy-to-neutral transition design, not missing-file allowances or opportunistic installation.
- The recovered advisory outline and completed independent critique distinguish nine required legacy inputs (five replacement/no-op and four preserved roles) from two explicitly absent new outputs. The original aborted advisory run remains failed. A completed validation/recovery addendum maps all seventeen audit domains plus supplemental requirements; it proposes a non-public same-process checker, without claiming privileged collection authority, complete equivalence or execution qualification. Releasing retained ownership to obtain an audit remains prohibited.
- Operator selected fresh, separately confirmed action-specific console recovery plans tied to immutable original transactions. Eligible preterminal rollback needs complete restored-before validation; matching already-terminal cleanup verifies authentic original completion/audit evidence and exact ownership without manufacturing a new terminal audit or claiming current live health. Existing prerequisite/expiry rules are unchanged. Selected profiles, private/owner-compatible evidence, complete support coverage, freshness/compatibility policy and crash-safe identity remain unresolved; no operational recovery protocol is implemented.
- Operator separately approved only the pure offline classifier and synthetic tests. Candidate `11c8a042cf150aebf460f38fd0da894104fc6281` is preserved at `pi-legacy-transition-classifier-candidate-01`; exact five-file patch SHA256 is `94f2deae1a1aa2a54fb4cb94e702d48b6329db87a2bfeaf8c7e9be4444318077`. Completed independent review found no issues and approved bounded offline integration only; review SHA256 is `1bfff404f474de714a1c792dffc12b0aeca1588e1f01afd39e676ada6a15b30f`. Parent verified both frozen handoffs and patch/source equality; subsequent parent changes are review-status/ledger documentation only.
- The import-free classifier checks bounded synthetic role/object references and five fixed checkpoint/action shapes. Every result has literal false authorization/admission flags and eight permanent qualification blockers. Coherently substituted assertions cannot be authenticated; unsupported mixed/interrupted, failed, detached or cleaned states refuse. There is no filesystem, environment, clock, network, helper execution, receipt issuer, collector or dispatcher in the classifier, and no current consumer/v1/gate change.
- Parent reran all 13 focused tests and 18 default security regressions, including the exact registered synthetic invocation under Python/SSH contamination and three detected in-memory guard mutations. Python/shell syntax, diff checks, secret-free declaration-only Compose and full Nix-free repository validation pass. This is source/grammar validation, not installed/native/console/crash/live qualification. No host collection, deployment, push, publication enablement, failed-qualification retry or operational gate removal occurred; overall lifecycle completion remains incomplete.
