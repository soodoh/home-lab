# Legacy Nix runtime retirement assessment

## First slice: source boundary, not host retirement

The first slice documented dependencies and added offline refusal regressions;
the separately authorized September 16 inventory below establishes a bounded
installed-state observation. Neither slice removed runtime source or installed
components. The [supported scope](operations.md#what-is-available-now) is unchanged.

Even `fixture-observation.json` belongs to the retained planner's exact source
allowlist. Those bindings protect existing generations, **not perpetual residence
of every subsystem in the active checkout**. Preserve historical source/bundles
and retire individual consumers before changing the active source boundary; never
rewrite old plans or hashes. Completed one-shot workflows need not be reimplemented.
Native SSH observation alone does not replace still-required hardware, backup or
firewall recovery. Historical forward ceremonies are not current setup guidance.

## Traced dependency boundary

| Source / entrypoint | Callers, installation and retained dependency |
| --- | --- |
| [`nix/flake.nix`](../nix/flake.nix), [`bundle.py`](../nix/proxmox/bundle.py) | The flake builds the controller-side bundle and wraps `planner.py`. The bundle renders the observer, private preparer and activator from templates, projection, schemas, package manifest and flake-lock bindings. PVE receives copied Python helpers, not a Nix daemon/store. |
| [`planner.py`](../nix/proxmox/planner.py), `prepare.py`, `apply.py`, `controller_lock.py` | `APPROVED_SOURCE_FILES` and `sanitized_source_binding` require the complete `nix/` file set and byte equality with the fixed application source. Bundle verification checks canonical content, schemas and rendered helper bytes; plans/sidecars additionally bind Git commit/tree and helper identities. The controller lock protocol and retained status/rollback logic remain dependencies. |
| [`bootstrap-proxmox-nix-host`](../scripts/bootstrap-proxmox-nix-host) | Imports `bundle.py` even for recovery. Installs the three Nix helpers plus access/deploy transports and activator, firewall transaction/transport/boot helper, policy, five units and backend drop-ins from its fixed target map. Installation enables boot recovery and the persistent watchdog. Recovery consumes `install-journal.json`, `previous-generation.json`, captured bytes and exact ownership. `recover_previous_active` requires the previous activator hash to match the retained apply owner before restoring that generation. |
| [`bootstrap-proxmox-nix-access`](../scripts/bootstrap-proxmox-nix-access) | Imports the host bootstrap utilities and loads the Nix projection. Separate access, convergence, role, VM9900 ACL and import-storage journals drive distinct gated rollback branches. Source identity checks and exact captured keys/sudo/account/API before-state remain required; current projection is not proof that an old journal is compatible. |
| Protected input and key helpers | [`collect-proxmox-protected-inputs`](../scripts/collect-proxmox-protected-inputs) produces `/root/home-lab-hardware.env`, consumed by [`prepare-proxmox-nix-protected-inputs`](../scripts/prepare-proxmox-nix-protected-inputs). Preparation, [refresh](../scripts/refresh-proxmox-nix-protected-inputs) and [session-key rotation](../scripts/rotate-proxmox-nix-session-key) import bootstrap utilities. Runtime protected inputs/MAC and session key are consumed by the private preparer/activator; rotation explicitly validates retained terminal journals/manifests. Do not regenerate identities or rotate keys as cleanup. |
| Physical-console upgrades | The deploy, observer and private-preparer console writers are [retired below](#live-state-boundary-and-console-source-retirement--september-16-2026). They advanced the host checkout and replaced helpers; their shell traps were not standalone recovery tools. Installed generations, host checkout and before-images remain untouched. Missing historical receipts are not a prerequisite for unrelated source retirement. |
| Other legacy installers and executors | The controller deploy-upgrade producer, its direct Nix bundle-renderer import and the console writers are retired below. Current [`proxmox-ansible-deploy-activator`](../infrastructure/proxmox-access/host/proxmox-ansible-deploy-activator) and low-risk controller source now read native maintenance inputs; the package-ownership binding uses the canonical non-Nix manifest. Installed older generations still read their old checkout's Nix inputs. This source migration is not deployed. Existing low-risk observation and saved-plan/recovery consumers remain; no historical hashes were rewritten. |
| Observer and VFIO succession | The neutral builder and `infrastructure/host-lifecycle/proxmox/` supply a separate observer/protected collector and guarded VFIO implementation. Neutral tests distinguish the intended active-source VFIO from retained Nix VFIO; the latter is embedded in the retained projection and is still installed. Both generations remain source consumers. Shared installed names such as `proxmox-observer` do not identify which generation is present. Legacy boot/network roles, remaining audits and the plan transport still invoke that installed name; the obsolete timezone parity consumer is retired below. |
| Access and Restic recovery | [`proxmox-ansible-plan-transport`](../infrastructure/proxmox-access/host/proxmox-ansible-plan-transport) dispatches fixed observers. [`proxmox-ansible-deploy-transport`](../infrastructure/proxmox-access/host/proxmox-ansible-deploy-transport) retains package/boot recovery and Restic network identity plus hash-bound snippet staging/removal, consumed by [`prove-restic-recovery-vm`](../scripts/prove-restic-recovery-vm). Native SSH does not retire these consumers or their capability transaction state. |
| Autonomous firewall | The [firewall protocol](legacy-host-recovery.md#autonomous-firewall-recovery) has its own transaction key/journal, shared operation mutex, continuously active rollback timer and two boot phases. It is not an ordinary Nix action or replaceable by controller-side Ansible rescue. Retain the required autonomous runtime. Its completed historical installer can be considered separately once its own transactions and recovery generation are accounted for. |

The contract, retained runtime schemas, surviving source-hash checks, historical
evidence receipts and bundle bindings are unchanged. No historical hash was regenerated. Whole-Git bindings may still
reject a future checkout even after documentation-only commits; use the exact
reviewed recovery generation rather than rewriting a retained plan for new HEAD.

## Recovery invocation gaps

The retained planner accepts only `plan`, `prepare`, `apply`. Current
`projection.json` has `nixMutationFrozen=true`: `prepare` and `apply` reject after
bundle validation, **before reading the saved plan/sidecar or reaching session
status/rollback**. The older expired-plan recovery branches in `apply.py` therefore
do not provide a usable recovery command under current policy. Do not unfreeze it,
retry `apply`, or substitute a sidecar to inspect an old session.

Host-session `status` is itself a reconciliation transition under a live mutex:
it can finish initialization, action or release checkpoints. It is not a passive
journal read. Firewall `status` is a different, read-only protocol. An unresolved
session needs its exact generation and a separately reviewed invocation; released
zero-action sessions do not justify building a new general recovery CLI.

Likewise, bootstrap `check` and `verify` create/permission directories, acquire
locks and reconcile pending files before their named operation. Do not use them
as read-only inventory. The narrower `diagnose-recovery` branch is not a complete
journal inventory, compatibility proof or recovery qualification; invoking it on
a host still requires separate inspection approval.

## Authorized inventory — September 16, 2026

Strict existing SSH/sudo access succeeded on PVE and Debian. Reviewed Python used
bounded file reads, metadata/hash comparisons, redacted JSON summaries and kernel
`/proc/locks`; systemd commands were only `show` and `list-jobs`. No installed helper,
legacy status/check/verify, lock acquisition or reconciliation was invoked.
Detailed output remains outside the repo at
`/tmp/home-lab-nix-inventory.gOHZnR/`; full hashes/metadata are there, not rollback
plaintext. One supplemental probe failed with a missing local summary function;
the corrected read-only probe succeeded. Independent console/LAN readiness and
off-machine custody still require operator confirmation, not inference from SSH.

- PVE's five retained Nix sessions are `released-committed`, with zero actions,
  zero capture entries, no pending transition, and consistent plan/session,
  empty-action digest, begin/commit and terminal results. This is structural
  closure evidence, not replay or full historical attestation verification.
- All six bootstrap/access journal paths and the pending verified snapshot were
  absent. Nix/apply/Ansible ownership locks were absent on both hosts; sampled
  known lock inodes had no entries in `/proc/locks`. No systemd jobs or matching
  helper processes were observed. Persistent mutex files were left intact.
- Incoming and previous incoming bundles remain; their helper bytes match their
  recorded helper hashes. The previous-generation embedded helper/manifest bytes
  also match their stored hashes. The installed activator has two exact preserved
  copies: incoming bundle and previous-generation snapshot. Whole bundle-tree
  verification was not invoked. All six sampled historical Git commits are
  available controller-locally; only one of the five session bundle IDs matches
  the two inspected staged bundles. This is not complete historical/off-machine
  bundle custody, and no historical material is a cleanup candidate here.
- The console deploy attempt `3ae63844…` and observer attempt `6ad83aae…` lack
  `committed.json`; before-images remain. Later committed attempts reuse the same
  before/candidate bytes, explaining succession but not certifying the failed
  attempts' outcomes. Both private-preparer console attempts have matching
  committed candidate records. A separate package journal `2132aff6…` remains
  `prepared`; three others and both reboot journals say `committed`. Preserve all.
  These are separate scopes, not grounds to rerun anything or block every slice.
  Sampled identity/key/group/SSH access-cutover records are committed, except one
  obsolete-root-key attempt marked rolled-back; before-images remain preserved.
- Restic capability state and five deploy-upgrade receipts say `committed`, with
  rollback material retained. Firewall journal is `committed`, active ownership
  absent; watchdog is enabled/active and both boot recovery units enabled.
  Debian Restic timers remain enabled/active; fixed interruption, initialization
  and first-run journal paths were absent. No backup/recovery integrity claim.

Hash prefixes below identify the pre-removal inventory; the approved activator
removal is recorded below. PVE libexec helpers were root:root 0755, single-link
regular files; VFIO is root:root 0750 and its policy 0440.

| Component | Installed generation | Live consumers | Retained-operation dependency | Replacement needed | Retirement condition |
| --- | --- | --- | --- | --- | --- |
| Nix activator | `0765585fc10b…`, historical bootstrap `d6a6a966…` | No dispatch caller found; `tofu-apply`, its sudo/home and apply transport absent. Bootstrap/metadata still reference it. | Five closed no-op sessions; exact old bytes preserved | None for the unused generic writer | Removed in the approved slice below; both preserved copies retained |
| Nix observer/private preparer | `edb7ff95e6b8…` / `7d667609e11f…`, current Nix-rendered bytes | Installed plan transport/sudo, legacy audits; observer invokes preparer `summary` | Protected inputs/MAC/key remain required; upgrade history retained | Retire obsolete consumers or adopt only required observation; not blanket host adoption | Do not remove while these consumers remain |
| Neutral observer/collector/controller | Absent; installed package observer `e67e1d05149a…` also differs from current neutral render | No neutral runtime found | Source-only tooling is not deployment proof | No obligation to install unused legacy features | Separate source-consumer decision, not presumed live replacement |
| Deploy activator/transport | `7d27fafa16e9…` (source `99615eae…`) / `78ea4536a580…` (current source); plan transport `7210d4cbf51d…` (source `8d433ebe…`) | `ansible-deploy`/`ansible-plan` shells and sudo; package/boot/Restic routes | Prepared package journal, console attempt without terminal receipt, committed upgrade history | Keep required narrow recovery routes; completed handoffs need no replacement | Resolve only the affected transaction/callers before its retirement |
| Firewall + Debian NFS canary | Transaction `6753e228daee…`, boot/transport/canary match source | Persistent timer, boot units/drop-ins, firewall shell/sudo; controller canary | Committed journal, attestation key/snapshot retained | Autonomous rollback remains required; Ansible rescue is not equivalent | Preserve watchdog/boot behavior; installer retirement is a separate decision |
| Restic recovery + backup | PVE transport `186d6adf9164…`; Debian runner `d8b867c953fc…`, source-matching | Deploy network/snippet route, recovery VM helper, backup/boot units | Committed capability; ongoing backup/recovery and VM9900 dependencies retained | Preserve needed network/snippet and backup recovery capabilities | Not part of Nix writer removal |
| VFIO | Installed **legacy** `f87931ef5a87…`; policy `860953aba63b…` matches retained projection | Attended stopped-VM recovery; source projections/boot roles | Hardware policy and recovery access remain necessary | Preserve this capability or separately qualify the narrow native-owned helper | Source ownership alone is insufficient |
| Bootstrap/console writers | Copies remain in older `/root/home-lab` checkout; not separately installed libexec services | Manual ceremonies; no service/cron caller found | Bootstrap journals absent; console outcomes differentiated above; snapshots retained | Completed one-shots need no new installer | Retire independently after own lineage review; preserve historical checkout/material |

### Approved installed activator retirement — September 16, 2026

Removed **only** PVE `/usr/local/libexec/home-lab/proxmox-activator`, formerly
SHA-256 `0765585fc10b819bc6d1785750f0a3610cd7d6292739bf9c74cf31f56fcc9abd`,
77,311 bytes, root:root 0755, single-link regular file, device 64513/inode 393283.
The operator approved the exact command and confirmed independent privileged
recovery access to the preserved copies and an attended no-concurrent-change
window. This is **installed activator retirement**, not complete Nix retirement.

Fresh preflight passed with 710 caller entries, the same five terminal zero-action
sessions, both protected rollback copies and original target identity, and no
sampled conflicting owner, lock, process or systemd job. The approved command
repeated the checks, compared in-memory snapshots, reverified both copies and
protected ancestors immediately before the single unlink, and fsynced the held
parent directory. Its before/after helper, unit, protected-runtime-file, session
and copy comparisons passed. A separate read-only postcheck confirmed absence,
709 caller entries, five unchanged terminal sessions and both valid copies;
controller observation completed at **18:42:25 UTC**. No rollback was needed or run.

- **Preserved:** observer/preparer, transports, keys, policies, unit states,
  watchdogs, lock files, host checkout, state, bundles, manifests, journals,
  before-images, VM9900 and backups. Unclosed console/package records remain
  unresolved; this removal does not certify them. No installed helper, legacy
  check/status/verify/apply, bootstrap, upgrade or recovery command was invoked.
- **Rollback:** retain the exact raw helper at
  `/var/lib/home-lab/bootstrap/incoming/bundle/helpers/proxmox-activator` and the
  matching embedded copy in `/var/lib/home-lab/bootstrap/previous-generation.json`.
  Separately approved recovery restores only those bytes and root:root 0755 via
  verified exclusive staging and atomic no-replace promotion, not bootstrap replay
  or current-source regeneration. Original inode/timestamps are not restored.
  Failure preserves staging for review; no automatic repair or cleanup is allowed.
- **Source boundary:** keep the activator template/schemas for the retained bundle
  renderer and historical generations. Do not advance the older hash-bound host
  checkout or rewrite old bindings. No replacement generic writer is needed:
  retained observer `observe` → preparer `summary` does not read the activator;
  the old `prepare` branch has no live dispatch route.

The reviewed commands, output and diagnostics remain outside the repository at
`/tmp/home-lab-nix-inventory.gOHZnR/`, including `COMMANDS.md` and
`approved-{window-preflight,removal,postcheck}.out`. The streamed payload SHA-256 was
`88d39b563bd0915f127d93f731548c62cff46ef5c93dc23175be8da0a5133979`.
No one-use helper was installed or added to the repository. The observation
regression was folded into the existing test file below and its standalone draft
removed. Earlier draft preflights stopped at nine dangling optional-unit aliases
and standard pmxcfs group ownership; the approved scan pins those missing targets
and permits only the non-writable root:www-data PVE cron read. No alias, permission
or historical hash was repaired. Seven controller-only command-effect tests also
passed; atomic rollback remains simulated, not a live recovery qualification.

### Timezone parity consumer source retirement — September 16, 2026

Removed the obsolete `ansible/playbooks/proxmox-timezone-handoff-plan.yml` and
`ansible/roles/proxmox_parity/{defaults,tasks}/main.yml`. The playbook was the role's
only operational source caller; its reduced observation was published only as
Ansible facts/debug output, not as a persistent transaction or recovery input.
No installer or recovery consumer directly referenced these files. Historical
commit `415e4d1f` records the completed timezone ownership transfer; current contract
and source still declare Ansible ownership and exclude Nix timezone mutation.
This confirms the obsolete source purpose, not a new live parity qualification.

Trimmed the role/playbook assertions from the existing
`scripts/controller/test-proxmox-timezone-handoff.js`, retaining contract,
Ansible ownership-gate coverage and checking that retired entrypoints stay absent.
No replacement playbook, script or installer was added. Shared
`base`/`lifecycle_state` roles, contract/schema, Nix source, historical handoff
plans/evidence and older host checkout remain unchanged. No handoff was replayed, no historical binding
rewritten and no host was contacted for these source slices.

A separately approved follow-on removed the unused
`scripts/controller/proxmox-timezone-handoff.js` and its planner-only tests.
Its only tracked caller was the test; the module calculated an in-memory plan
and digest, with no host commands or persistent output. The retained test no
longer imports that planner or reads Nix projection/planner/activator source for
it. The unused planner and its source-binding reads were not ported elsewhere.

The next source slice removed
`scripts/controller/proxmox-timezone-handoff-transaction.py` and its tool-specific
test assertions. Its only tracked source consumer was the test; no installer or
recovery consumer referenced the tool, its output formats or the retained artifact
IDs. It created local plans/authorization receipts after SSH observation, but had
no apply or recovery command. It was inspected as source, never imported or run.

Bounded local reads found one canonical expired plan and one matching authorization
under `.local/proxmox-timezone-handoff/`. The receipt binds the same plan/commit and
was recorded within the plan window; the plan's immutable `authorized: false`
field is normal and does not negate that separate receipt. The historical commit
and tool source remain available in Git. Both artifacts retained identical bytes,
metadata and identities after source deletion. They are preserved historical
inputs, not permission to replay the ceremony or proof of a fresh host outcome.
Only reduced findings/fingerprints were recorded outside the repository in
`/tmp/home-lab-nix-inventory.gOHZnR/timezone-local-artifact-review.json`; no saved
plan contents were printed, artifacts deleted or hashes rewritten. The existing
test now checks the retained Ansible ownership gate and retired-tool absence,
without reading operational artifacts or recreating transaction machinery.

### Standalone audit entrypoint source retirement — September 16, 2026

Removed `ansible/playbooks/proxmox-audit.yml`, an audit-only wrapper with no tracked
operational caller or direct installer/recovery reference. Its shared role and
validator publish reduced results, not a wrapper-owned durable transaction.
`proxmox-packages-plan.yml` still requires `proxmox_complete_audit`; at this slice,
the validator also served controller-check/evidence and observer-capability
consumers. Those paths, historical parity evidence and full tracked-source binding
checks were unchanged. Native host facts are not a replacement for their 17-domain
audit. The subsequent controller-check retirement is recorded below.

Existing audit, firewall and bootstrap test assertions now cover the retained
package-planning entrypoint and its non-deploy boundary. The then-retained
check-evidence test used the retired path only as an invalid-scope fixture; that
test is now removed with its sole consumer below.
Removed the stale operations-document reference. No installed helper, shared role,
validator, receipt, source binding or host checkout was changed.

### Controller-check source retirement — September 16, 2026

The follow-on trace found a closed orphaned controller-admission branch, separate
from package planning. Removed only:

- `scripts/controller/proxmox-check-evidence.js`;
- `ansible/playbooks/proxmox-controller-check.yml`;
- `infrastructure/host-lifecycle/proxmox/check-evidence.schema.json`;
- `scripts/controller/test-proxmox-check-evidence.js` and
  `scripts/controller/test-proxmox-neutral-controller.js`.

The CLI/module had only test callers; its playbook and schema had no independent
operational consumer or installer. Its `collect`/`recheck` commands requested the
neutral locked observer, then generated fresh audit receipts; `verify` accepted
only version-6 steady/converge manifests with current source and five-minute
receipts. It was not package recovery or a historical offline verifier. No
surviving consumer was redirected to a weaker check, and no replacement receipt
framework was added. Exact deleted bytes remain in Git.

Bounded local reads covered 248 JSON files: 192 top-level plan/manifest records
(including six `manifest.json` files), 17 check-failure records,
31 maintenance plans and eight package activation/preparation records. No
`*.check.json` receipt, version-6 manifest or `proxmox_host_check` reference
was found in that scope. All 17 failure records remain; absence of accepted
receipts is not successful execution or authority to retry. This was not a
recursive/off-machine inventory or a new host observation. The earlier host
inventory found the neutral controller observer absent; at that slice, its source
capability installer remained blocked on unqualified VFIO coordination. Neither
was invoked; the installer is retired separately below.

The reviewed package records include four activations and four preparation
receipts. The exact activation for the last-inspected `2132aff6…` prepared host
journal and its referenced maintenance plan are present. The 31 maintenance plans
span Proxmox/Debian package and reboot paths, so their shared serializer is not an
orphan. Their continued presence is not current apply authorization.

| Retained consumer | Boundary established by this trace |
| --- | --- |
| `proxmox-packages-plan.yml` → `proxmox_complete_audit` / `proxmox_package_plan` | Still emits `proxmox_package_plan_observation`, parsed by `save-host-maintenance-plan.js`; keep the shared 17-domain audit and package observer. |
| `save-host-maintenance-plan.js` / `package-transaction-lock.js` | Shared forward proposal/lock generation, not a controller-check receipt consumer. Existing saved plans remain immutable. |
| `proxmox-package-activation.py` → deploy transport/activator | Recovery consumes the saved activation and host journal, not the controller-check playbook/schema. Preserve this narrow route and its bindings. The reviewed host-source `recover-package` branch accepts `applying` (or already committed), **not `prepared`**; do not invoke recovery merely to clear the prepared record. This source reading is not live recovery qualification. |
| Observer builder, audit validator, protected collector, controller-observer capability tooling | At this slice, coupled through artifact identities and capability transaction consumers. The installer is retired below; the shared renderer/audit bindings remain unchanged. Removing the receipt client did not install the neutral runtime. |

The prepared package record is not a blanket blocker for independently closed
source cleanup, nor proof that the forward package playbook must exist forever.
Its producer/consumer chain needs its own retirement decision. Boot/network
observation, installed plan/deploy transports, protected preparer, firewall,
Restic and VFIO remain separate dependencies. The following slice traced the
controller-observer capability/renderer consumers independently, rather than
assuming client removal retired them.

Useful shared audit and protected-reader regressions moved into the existing
`test-proxmox-neutral-artifact.js`: real artifact/fixture audit success, malformed
and drifting observations, helper-byte substitution, bounded reads, symlink/hardlink,
private-mode, FIFO and ancestor-alias refusal. Receipt-only tests were deleted;
no new test script was added. This test uses only a fresh temporary directory,
never `.local`, `.reconcile`, SSH or a host playbook. The retired end-to-end test,
which would write into `.reconcile`, was inspected but not run.

Reduced findings and fingerprints are outside Git in
`/tmp/home-lab-nix-inventory.gOHZnR/package-controller-source-review.json`.
Postchecks verified unchanged bytes, identities and checked metadata for all 248
reviewed files (access times excluded), with unchanged directory entry counts.
All six neutral-rendered artifact files also remain byte-identical to the earlier
source artifact. No historical content was printed, hash rewritten, host checkout
advanced or installed component changed in this slice.

### Controller capability installer source retirement — September 16, 2026

Removed the unused pair:

- `scripts/controller/proxmox-controller-observer-capability.py`;
- `infrastructure/proxmox-access/host/proxmox-controller-capability-transaction.py`.

The host-side program was streamed by the controller, not installed as a service
or account sudo helper. Its only operational source caller was that controller;
the controller otherwise had test consumers. Both files have one published source
generation, introduced at `85ea056d`, identical to their pre-removal HEAD bytes.
Controller `plan`/`apply` and streamed `observe`/`apply` unconditionally rejected
unqualified VFIO coordination before operational work. No gate was bypassed.

That forward blocker alone would not justify removing recovery: `rollback`,
`commit` and `cleanup-committed` bypassed it and consumed exact saved before/after
bytes, journal and owner identity. These branches were inspected separately.
The authorized host inventory captured at **17:23:26 UTC on September 16** recorded
`/var/lib/home-lab/controller-observer-capability` absent and no neutral controller
observer installed. Local no-follow metadata checks also found the capability
plan directory and `.local/locks/proxmox-controller-capability.lock` absent.
No retained operation for this protocol was identified in that reviewed scope.
This uses a dated inventory, not a fresh host probe, historical nonexecution proof
or standing maintenance lock. An unexpected journal on another/restored system
requires separate inspection against its historical generation, not blind replay.
Exact source remains in Git; no journal, lock, before-image or installed file was
removed. Review findings remain outside Git in
`/tmp/home-lab-nix-inventory.gOHZnR/controller-capability-source-review.json`.

At that stage, the two older `proxmox-plan-capability.py` and
`proxmox-package-observer-capability.py` installers still rejected `apply` before
I/O. Only their obsolete recommendation to invoke the removed successor changed;
neither was re-enabled or replaced. Their planning/artifact history was reviewed
separately in the following slice.

Kept the controller-observer template, builder output, manifest schema/field,
audit hash checks, fixed `observe-controller` transport branch and contract sudo
declaration. The package-planning audit still validates the complete artifact,
including that generated member. Removing it now would change a shared artifact
interface, not merely delete an isolated installer. This is source coupling, not
a claim that the neutral helper is installed. Installed observer/preparer,
package/deploy recovery, firewall, Restic and VFIO remain unchanged.

Installer-only tests/imports were removed from existing suites. The capability
boundary suite keeps retired-path absence, disabled predecessor refusal,
shared descriptor implementation parity and retained Nix rejection of reboot
ownership. All retained `NativeProtocolTests` bodies remain byte-identical;
`test-vfio-recover.py` still has its shared fixture module. Diagnostic tests keep
non-authorizing output and input-preservation assertions without importing the
retired admission validator. No validator was copied into a new module or script.

For that slice, four capability boundary tests, seven controller-observer tests
and two focused diagnostic CLI tests passed. All 14 confined Linux/root protocol cases were skipped
on this macOS controller; their execution is **not qualified** by compilation or
unchanged source. No Docker fixture or live installer/recovery command was run.
The neutral-artifact, complete-audit and package-plan JS suites passed; Python
compilation, Markdown links, quiet Compose and diff checks also passed. The six
rendered artifact files remain byte-identical to the earlier source artifact.

### Disabled predecessor installer source retirement — September 16, 2026

Removed `scripts/controller/proxmox-plan-capability.py` and
`scripts/controller/proxmox-package-observer-capability.py`. Only tests referenced
these tools operationally; the historical package-observer evidence remains.
Both `apply` functions already stopped unconditionally before I/O. Their surviving
`plan` commands performed SSH observation and wrote local plans, not host recovery.
Neither exposed a standalone rollback/resume command. The old shell error trap
and in-process package-helper before-images were not durable recovery interfaces.
No writer, observer or saved plan was executed to establish these facts.

Bounded reads found one canonical expired plan under `.local/access-plan-capability`
and two under `.local/proxmox-package-observer-capability`. Each retains its exact
content-addressed filename, 30-minute window and `authorized: false`; both package
plans retain valid before-state digests. The associated source exists at commits
`a305d0a0`, `7b6b1598` and `2019f0be`. Plan `cb369c62…` matches the preserved tracked
`infrastructure/evidence/proxmox-package-observer-capability-plan.json` record:
`do-not-apply`, no production mutation recorded. These are historical bindings,
not current authorization. An immutable `authorized: false` field alone does not
prove a plan was never separately approved or executed.

The package capability's persistent controller lock is present and preserved;
it was fingerprinted without acquiring, clearing or rewriting it. Existence alone
proves neither contention nor ownership. The earlier authorized host inventory
found the production owner absent and the package observer/plan transport still
installed. Their bytes happen to match the historical proposal identities; that
does not attribute installation to a particular plan or certify its outcome.
No fresh host observation or installed-file retirement occurred here.

All three plans, the lock and tracked evidence retained identical bytes, identities
and checked metadata (excluding access times), with unchanged plan-directory
entries. Reduced findings are outside Git at
`/tmp/home-lab-nix-inventory.gOHZnR/predecessor-capability-source-review.json`.
Historical source, access declarations, transports, observer/package artifacts,
prepared package journal and console before-images remain intact. This removes
obsolete producers, not their installed results or retained operational history.

Existing tests now check retired-path absence rather than import the removed
installers or inspect unreachable mutation code. Shared descriptor and Nix/reboot
ownership-refusal tests remain. Source assertions in
`test-proxmox-access-transports.py` were separated into `check_sources()` without
changing its transport-command cases. Only that source function ran, under
subprocess tripwires: the full suite invokes valid transport verbs and was **not
run** as local validation. No grammar or live capability qualification is claimed.
To repeat only the source checks from the repository root:

```sh
python3 -B - <<'PY'
import runpy
import subprocess
from unittest.mock import patch
with patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess forbidden')):
    tests = runpy.run_path('scripts/controller/test-proxmox-access-transports.py')
    tests['check_sources']()
print('proxmox_access_transport_sources=verified; no transport execution')
PY
```

Three capability-boundary tests, transport source assertions, neutral-artifact,
complete-audit and package-plan JS suites passed, along with Python compilation,
Markdown links, quiet Compose and diff checks. No replacement script was added;
shared rendering remains byte-identical. The following slice traces the
deploy-capability handoff separately from deploy upgrades and installed recovery.

### Deploy-capability handoff source retirement — September 16, 2026

Removed only `scripts/controller/proxmox-deploy-capability.py`. Its sole tracked
source consumer was the access-transport test; no surviving installer, upgrade or
recovery program imported it or consumed its plan/authorization formats. Unlike
the disabled predecessor installers, this tool still exposed a gated `apply`:
removal retires the obsolete one-time handoff, not merely unreachable code.

The tool offered `plan`, `authorize` and `apply` for an inert `ansible-deploy`
account: `/usr/sbin/nologin`, no sudo file or conventional authorized keys. Apply
required the deploy helpers already present with exact source identities, then
installed the Restic recovery helper/sudo rule and selected the fixed deploy shell.
Its shell error trap was not a standalone durable recovery command; there was no
resume/status/rollback interface. No part of this tool was imported or executed.

Bounded reads of `.local/proxmox-deploy-capability` found three canonical expired
plans and two canonical authorization receipts. Each plan's filename digest,
observation digest, historical contract/inventory and recorded helper source
hashes match its retained Git revision. Both receipts bind the exact plan/commit
and were recorded within the corresponding 30-minute window. The immutable
`authorized: false` plan fields do not negate those separate authorizations.
Authorization is not an execution receipt, and none of these facts certify the
outcome of every historical attempt.

The earlier authorized host inventory at **17:23:26 UTC on September 16** recorded
`ansible-deploy` already using the fixed deploy transport, all three deploy/Restic
helpers present as root-owned executable files, and the production owner absent.
That supports retiring the inert-account setup purpose, not replay, a fresh access
qualification or a claim about which plan enabled it. Historical helper generations
and the older host checkout remain intact; nothing was installed or uninstalled.

That slice kept `proxmox-deploy-upgrade.py`, the console upgrade scripts, deploy
activator and transport, Restic recovery transport, package/reboot executors and
all access policy declarations. Upgrades maintain an already-enabled account and
bind their own plans/authorizations and captured helper bytes; the controller
producer is reviewed separately below. Installed package and Restic
recovery paths do not depend on this initial handoff CLI. The prepared package
journal and unclosed console attempts remain separate unresolved operations.

The existing access-transport and capability-boundary tests now assert this path
is absent; assertions over the retained executors/upgrades remain unchanged.
Three capability tests, transport **source-only** assertions, neutral-artifact,
complete-audit and package-plan suites, Python compilation, 57 Markdown links,
quiet Compose and diff checks passed. No valid transport verb was invoked.
The five local artifacts and their directory retained identical bytes, identities
and checked metadata (access times excluded). The six neutral-rendered files also
remain byte-identical. Reduced findings/fingerprints remain outside Git at
`/tmp/home-lab-nix-inventory.gOHZnR/deploy-capability-source-review.json`.
No historical plan, receipt, lock or source binding was rewritten.

### Controller deploy-upgrade producer source retirement — September 16, 2026

Removed `scripts/controller/proxmox-deploy-upgrade.py` and its dedicated
`test-proxmox-deploy-upgrade.py`. The CLI had no surviving code caller outside
tests, but its saved plan/authorization identities also appear in console-upgrade
history. Those artifacts remain consumers' historical inputs, not cleanup targets.
The tool offered only `plan`, `authorize` and `apply`, with synchronous exception
rollback inside its streamed writer. It had no standalone recovery/resume command;
exclusive creation of an existing per-plan host journal directory prevents replay
as a continuation mechanism. Removing this forward producer also removes its
direct import of `nix/proxmox/bundle.py`, without changing that retained renderer.

Bounded reads found **32 canonical expired plans and 26 canonical authorizations**
under `.local/proxmox-deploy-upgrade`. Each filename digest and historical
contract/inventory binding matches; every referenced tool revision is available
in Git. All authorizations bind a retained plan/commit and fall within its
30-minute window. These checks do not prove every proposed upgrade executed, nor
do absent cached host records prove nonexecution.

The earlier authorized host inventory distinguishes two trees:

| Retained tree | Findings and limits |
| --- | --- |
| `/var/lib/home-lab/deploy-upgrade/<plan>/` | Five directory IDs match local plans. Cached receipt summaries report `committed`; each has a parsed root:root 0600 single-link `rollback.json`. The reduced inventory does not retain every receipt binding or rollback payload, so this pass did **not** independently verify all captured bytes or qualify recovery. |
| `/var/lib/home-lab/deploy-upgrade-transactions/<plan>/` | Three console attempts match local plans and authorizations. Cached hashes of both before-images match each plan. Two committed records match their plan, commit and helper-after fields. `3ae63844…` still has before-images but no terminal receipt: its outcome remains unresolved. |

The separately documented [Restic transport succession](proton-source-retirement.md#explained-transport-succession)
for `44faa638…` already records exact successor receipt/rollback hashes and
predecessor transport bytes. That explains one replacement lineage, not universal
operation closure. Its records are unchanged. The incomplete observer-console
attempt `6ad83aae…` is another separate scope, not resolved by controller receipts.

That controller-only slice kept all console upgrade scripts, installed
transports/activators, Nix observer/preparer rendering, bootstrap recovery,
firewall, Restic, package/reboot consumers and access declarations unchanged. Console scripts accept explicit
plan/authorization identities and helper hashes without importing this CLI;
retained plans remain available for inspection. No replacement forward installer
was added, and no console script or upgrade/recovery command was run. Unexpected
retained state needs its exact historical source and a separately reviewed recovery
decision, never replay or regenerated plans.

Existing transport-source and capability-boundary tests assert retired-path
absence while retaining installed-consumer checks. Deleted tests covered only
this producer's hash wrapper and explicit apply confirmation; no shared recovery
implementation or test was removed. Three capability tests, transport source-only
assertions, neutral-artifact/complete-audit/package-plan suites, compilation,
Markdown links, quiet Compose and diff checks passed. All 58 local upgrade files
and their directory retained identical bytes, identities and checked metadata
(access times excluded); cached inventory and six rendered files are unchanged.
Reduced findings are outside Git at
`/tmp/home-lab-nix-inventory.gOHZnR/deploy-upgrade-source-review.json`.

The following separately authorized live-state slice supersedes historical
console-lineage reconstruction as the next prerequisite. It does not establish
the outcome of old attempts or authorize cleanup of their before-images.

## Live-state boundary and console-source retirement — September 16, 2026

The operator selected [disposable controllers and live validation](decisions.md#disposable-controllers-and-live-validation):
current readiness comes from source-defined checks against live hosts, not local
agent-session files or committed outcome records. Historical reconstruction is
not a prerequisite when an obsolete forward writer has no surviving recovery
consumer. Host-local interruption state and rollback assets remain separate.

Fresh PVE inspection used the existing strict SSH/become route. Native
`observe-hosts.yml --limit proxmox` returned five successful tasks, `changed=0`,
`failed=0`, `unreachable=0`. Additional streamed, read-only Python compared current
source hashes/metadata and used `passwd -S`, effective `sudo -ll`, `sshd -T`,
`systemctl show/list-jobs` and kernel process/lock observations. No prior inventory,
local plan or historical receipt was an inspection input. Native sudo's entry
header included a source filename; the initial parser did not recognize it and
was corrected before claiming effective-policy agreement. Journal classification
was likewise corrected to include the existing `status` field. Neither issue
caused a host change or execution of a legacy helper.

At 20:50:26 UTC:

- All 21 selected helper/config/unit files had expected metadata; 19 matched
  current source. Observer/preparer, deploy and Restic transports, firewall
  helpers/units and VFIO helper/policy matched. The generic activator remained
  absent. This is selected file parity, not execution/health qualification.
- Four retained accounts matched projected shells, primary-only groups, locked
  passwords and absent conventional authorized-key files. Effective sudo matched
  the retained projection; OpenSSH's four baseline authentication settings
  matched. Tailscale SSH/become actually succeeded. Match-specific OpenSSH paths,
  remote Tailscale ACLs and independent console access were not qualified.
- The installed plan transport lacks only the newer `observe-controller` branch;
  the neutral controller observer is absent. Its sudo rule also omits that branch,
  matching the older projection but not the newer contract declaration.
- The installed deploy activator matches Git generation `99615eae…`, **not current
  source**. Later source adds descriptor/owner coordination, durable journal
  handling and a refusal for the unqualified queued-reboot/VFIO protocol. Do not
  infer those protections are installed or run upgrades to erase this difference.
- Nix/Ansible/firewall ownership paths were absent. No relevant held lock,
  matching helper/upgrade process, pending systemd job or `.new` helper remnant
  was observed. The operation mutex and console-upgrade lock files were retained.
  A scan of 678 systemd/cron/sudoers entries found no console-writer references
  or read errors. These are bounded samples, not proof of exclusivity.
- Five Nix journals remained `released-committed` with no pending transition;
  package journals reported three committed and one prepared; both reboot
  journals reported committed. The firewall journal reported committed, its
  watchdog remained active/enabled, and both boot-recovery units active/exited.
  Reading these records neither reconciled nor validated their full historical
  bindings. The prepared package record remains a recovery concern for its own
  operation, not a blanket block on source cleanup.

Removed only these forward console entrypoints:

- `scripts/physical-console-install-proxmox-deploy-upgrade`
- `scripts/physical-console-install-proxmox-observer-upgrade`
- `scripts/physical-console-install-proxmox-private-preparer-upgrade`

Each accepted only upgrade arguments, changed the host checkout, captured
before-images and replaced helpers. None exposed standalone resume/rollback;
rollback was an in-process shell trap. The only remaining tracked caller was a
source assertion for the private-preparer writer. Its obsolete assertions were
replaced with retired-path checks in existing suites; rendered observer/preparer
behavior tests remain. No replacement installer or repository script was added.

The incomplete deploy/observer attempts still have **historical outcome unknown;
no replay**. Their missing receipts need not be reconstructed to retire these
writers. Every host-side backup, transaction directory, installed helper, access
rule and old checkout was left intact. Bootstrap `recover`, protected inputs,
Nix rendering, package/reboot recovery, Restic, firewall and VFIO remain because
of actual consumers—not a requirement to preserve obsolete forward ceremonies.

Validation for this slice passed 12 focused Python methods, subprocess-forbidden
transport source assertions, neutral-artifact/complete-audit/package-plan suites,
changed-test compilation, 59 local Markdown links/anchors, quiet SOPS-backed
Compose validation and `git diff --check`. The existing rendered-observer tests
remain confined to fixtures; no Linux/root protocol qualification was claimed.
No historical local artifact was needed to run these checks.

The next boundary is migrating retained observation and operation-specific
preconditions into native, source-owned checks, explicitly addressing installed
implementation drift before authorizing those operations. Generic facts do not
replace protected hardware checks or qualify restore. This inspection did not
cover Docker or change CI, and its diagnostic output is not a future gate.

## Native observation and maintenance-input migration — September 16, 2026

Added `ansible/playbooks/observe-proxmox.yml`, the `proxmox_observe` role and native
Proxmox host variables. The [documented read-only invocation](operations.md#native-proxmox-capability-observation)
passed on the live host: 19 tasks, `changed=0`, `failed=0`, `unreachable=0`.
Protected access/hardware checks now run without a Nix renderer, installed
observer/preparer, generated artifact or historical runner output. The existing
neutral collector is streamed, not installed; sealed host inputs and their MAC
remain required configuration. No private values leave the collector. This does
not replace the broader legacy audit or authorize package/boot/access mutations.

Native repository/chrony/keyring declarations retain the same desired content.
Both current low-risk source consumers now read them instead of the Nix projection.
The deploy activator's package-ownership binding uses the already-existing
`infrastructure/host-lifecycle/proxmox/package-manifest.json`, byte-identical to
its Nix counterpart. Existing plan formats, contract/commit bindings and recovery
checks are preserved. No stored hash, receipt, journal or installed file changed.
The updated activator is **not installed**; the observer-artifact builder naturally
binds the changed current activator in its controller member. Do not mistake
current-source tests/renderings for installed-generation parity.

Removed the now-unconsumed `ansible/playbooks/proxmox-low-risk-plan.yml` and
`proxmox_low_risk_lifecycle` task/default files. This separate repository/chrony
handoff preview still reported `nix-remains-current-writer` despite both domains'
transferred ownership. Its only caller was that playbook; it neither supplied
the activation CLI nor exposed recovery. Native repository observation does not
claim replacement of its chrony tracking/keyring coverage. The activation CLI,
installed executor and their existing recovery paths remain, with new absence
assertions in the existing activation test. No historical plan was inspected or
changed to justify deleting this unused producer.

Existing tests cover native YAML/module/command scope, preserved policy values,
proxy clearing/no-log boundaries, low-risk refusal/rollback fixtures without a
Nix tree, and real controller-local Ansible assertions for nine response cases
plus active oneshot/inactive/missing-unit/retained-owner cases. The native play's
initial running-service assumption failed on active/exited NFS and was corrected
using live `systemctl show`, not by changing NFS or relaxing to any service state.

### Remaining completion gates

- The operator selected **replacement before retirement** for forward package,
  reboot and low-risk capabilities. Preserve those interfaces and their recovery
  state until native replacements are implemented and qualified; do not silently
  substitute manual-only maintenance.
- Migrate the remaining public audit and package-planning callers; do not replace
  a 17-domain audit with this narrower capability summary. Existing low-risk
  observation still uses the installed observer despite its native policy inputs.
- Complete operation-specific qualification before a separately approved host
  cutover. After the initial missing default Colima socket, the operator explicitly
  authorized a separate `home-lab-nix-retirement-tests` profile: two CPUs, 4 GiB
  RAM and 20 GiB total virtual disks. It has no home mounts or forwarded SSH agent;
  the default Docker context remains unchanged. Four allowlisted source files
  were streamed into a network-disabled, read-only-root, capability-limited
  Python 3.13 Linux/arm64 container. All 14 confined Linux/root descriptor,
  journal-failure and reboot-owner tests passed (not skipped). The official image
  resolved to `python@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285`.
  These synthetic tests do not qualify real PVE reboot/VFIO/hardware behavior;
  the production unqualified-reboot refusal remains intact. No production
  commands, credentials, repository mount or historical artifacts entered the
  container. The disposable container was removed and the dedicated VM stopped
  after testing; its disk/image remain available for further isolated qualification.
- Separate bootstrap/protected-input/key-rotation recovery consumers from bundle
  rendering without losing sealed inputs, exact before-images or autonomous
  recovery. The prepared package operation and installed generations remain
  operation-specific review inputs, not universal receipt gates.
- After consumer migration, separately approve installed observer/preparer and
  obsolete access retirement, then remove the unused Nix tree/planner/bundle and
  obsolete tests. Preserve the host's old checkout and all historical recovery
  material until their explicit disposition decision.

Complete Nix retirement is still false. No helper replacement, account/sudo change,
package operation, reboot, firewall change, archive cleanup or commit occurred.

## Native package observation, without forwarding mutation authority

`ansible/playbooks/observe-proxmox-packages.yml` adds a native package sample after
`proxmox_observe`. It streams the existing neutral package observer over stdin
with the canonical non-Nix manifest, without installed helpers, artifact builders,
controller-local plans or outcome receipts. It performs only existing-metadata
reads/simulation and reports bounded counts/booleans. No metadata refresh, lock
acquisition, package action or legacy-helper invocation is added. The registered
response is in-memory only, not a cacheable fact or saved plan.

The package age policy preserves 86,400 seconds. The new role distinguishes data
shape/transport failures from diagnostic blockers such as stale metadata, package
drift, holds, retained/held ownership and incomplete size estimates; none grants
apply authority. Existing audit/planning/activation/recovery callers are retained.
The existing package-plan suite checks native scope and source dependencies, and
the existing controller-observer suite exercises actual stdin rendering and 32
valid/invalid response cases through real local Ansible assertions, including
private-output suppression and ten fixed error categories with/without trailing
newlines. An initial diagnostic-escaping defect failed offline fixtures and was
corrected before any diagnostic production retry; the fixtures and syntax pass.

The separately authorized first PVE run passed 20 tasks with `changed=0`, then
failed at the package collector's nonzero exit (`unreachable=0`, `failed=1`). The
protected-output boundary concealed the raw error. A separately approved single
diagnostic rerun reported `apt-transition-unrecognized`, with `ok=21`, `changed=0`,
`unreachable=0`, `failed=1`. Production retries stopped there.

Two synthetic APT 3.0.3 cases in the isolated Linux profile reproduced that same
refusal on actual solver output: `Inst fixture-app [1] (2 localhost [all]) []`
and an upgrade with `[fixture-app:arm64 ]` appended. These are dependency-order
notes, not additional package actions. Their removal alone allowed the bare
transition to parse in the local regression. The candidate observer and current
activator source now accept only the defined optional-note grammar; unknown
trailing output is rejected, including removal lines previously accepted by a
prefix match. The complete original solver bytes still determine their hashes.

The existing package-observer suite tests 12 accepted and 10 rejected forms
through **both** parsers, with all native commands refused/replaced by fixtures.
An initial test-loader failure was corrected to exclude the activator's executable
stdin dispatcher, as the existing confined harness does. Both real-APT fixture
cases passed after the parser fix, and all 14 confined Linux/root protocol tests
passed again against the changed activator source. Only the synthetic container's
file-backed package metadata was refreshed; it had no network or credentials.
The container was removed and test VM stopped; the default Docker context stayed
unchanged. No installed activator, package, watchdog, lock or journal was changed.

The specific raw production transition was not disclosed, so the fixture proves
a matching parser defect rather than complete production causality. One separately
approved qualification run after the fix still reported
`apt-transition-unrecognized`, with `ok=21`, `changed=0`, `failed=1`,
`unreachable=0`. The parser fix is insufficient for PVE. Production diagnostics
are stopped: obtain an operator-provided redacted failing transition or a separately
approved minimal local fixture before changing more parsing behavior. Do not
broaden the grammar speculatively or retry progressively modified collectors.

No check was weakened to admit an old plan, and no saved bindings or receipts
were regenerated. Live package observation and native forward maintenance/recovery
remain unqualified and in progress. The operator's replacement-before-retirement
choice still governs: no remaining forward interface may be deleted on the
strength of these partial results.

## Focused local regressions

```sh
python3 -B scripts/controller/test-proxmox-nix-apply.py ProxmoxNixRetirementBoundaryTests
python3 -B scripts/controller/test-proxmox-nix-apply.py ProxmoxObservationWithoutActivatorTests
node scripts/controller/test-proxmox-timezone-handoff.js
node scripts/controller/test-proxmox-complete-audit.js
node scripts/controller/test-proxmox-package-plan.js
node scripts/controller/test-package-candidate-observer.js
node scripts/controller/test-proxmox-neutral-artifact.js
python3 -B scripts/controller/test-proxmox-controller-capability.py
python3 -B scripts/controller/test-proxmox-controller-observer.py
python3 -B scripts/controller/test-proxmox-predecessor-console-evidence.py CliTests.test_real_cli_non_tty_and_arguments
python3 -B scripts/controller/test-tailscale-access-evidence.py FileAndCliTests.test_real_cli_is_non_authorizing_and_preserves_inputs
python3 -B scripts/controller/test-proxmox-firewall-schemas.py SchemaTests.test_retained_package_planning_does_not_grant_firewall_authority
python3 -B scripts/controller/test-proxmox-nix-bootstrap.py ProxmoxNixBootstrapTests.test_contract_closes_apply_and_forces_both_service_identities
```

The low-risk activation fixture additionally requires PyYAML. The controller's
default `python3` lacked it; that invocation failed without installing anything.
The fixture passed using the already-installed Ansible tool environment's Python.
Use that existing environment for `scripts/controller/test-proxmox-low-risk-activation.py`.

The first uses the current frozen projection, mocks bundle verification and all
subprocess/transport/plan/sidecar/lock effects in the entrypoint tests, checks
standalone recovery-command rejection, and tests missing/substituted allowlisted
source files only in a temporary copy. It does not execute generated helpers,
contact hosts or read retained operational artifacts. These tests establish source
refusal behavior, not installed-state parity or successful recovery.

The second renders and hash-pins the actual installed observer/preparer generation,
then exercises observer `main`/`observe`/`protected_summaries`/dispatch → preparer
`main`/`summary` with and without a fixture activator. Protected readers, MAC/key
validation, parsers and fixture-only locking are real; root metadata, host command
responses, token HTTP responses and unrelated observer domains are simulated.
The successful canonical protected summaries are identical; no install manifest
is supplied and any activator read fails the fixture. Missing keys/bad MACs,
preparer hash/mode changes, hardware/token failures and Ansible ownership still
cause refusal or nonmatching/unavailable observations. It invokes no installed
helper, SSH, real network or host command. This proves the protected-observation
dependency, not complete host parity or recovery qualification.

Earlier slices passed all nine selected Python methods, the timezone/complete-audit/package-plan
and neutral-artifact JS tests, Python compilation, JS syntax, 57 local Markdown
links/anchors and `git diff --check`. The audit/package tests parse retained source YAML;
the two selected firewall/bootstrap methods inspect source and fixture-only setup,
not hosts or installed helpers. The timezone JS test parses retained YAML and checks retired
entrypoint absence and the shared timezone ownership gate. It does not read or
execute a retired planner/transaction or inspect historical plans. The initial
bare Compose check lacked interpolation
inputs; it is superseded by successful controller-local
[SOPS-backed quiet Compose validation](sops-age.md#controller-local-compose-validation)
on September 16. SOPS supplied values only to the child environment: no secrets
printed, plaintext environment file created, or dummy inputs substituted.
Source deletions are limited to the obsolete entrypoints, role, planners and
controller-check/schema/tests, unused capability installers and console-upgrade
writers listed above; no retained runtime YAML or HCL changed.
Beyond the approved single installed-file unlink above, no
deployment, installed-helper execution, lock acquisition, state/bundle/journal
cleanup, staging, commit or push occurred. Earlier unstaged changes remain intact.
