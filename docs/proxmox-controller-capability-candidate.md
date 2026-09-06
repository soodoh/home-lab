# Proxmox controller capability — unaccepted source candidate

ADR 0001 remains authoritative. This document is **not** installation, collection,
qualification, package, reboot, recovery or deployment approval.

## Offline legacy transition classifier (synthetic only)

`scripts/controller/legacy-transition-classifier.py` implements only the pure
`classify(value)` function over in-memory synthetic assertions. It has no CLI,
imports, host reads, clock/environment/network/subprocess access, helper execution,
collector, receipt issuance, dispatcher, publication or recovery operation.
ADR 0001 and the direct contract remain authoritative; no v1 format, consumer,
validator, installed helper or operational gate changes accompany this slice.

The distinct input format is `synthetic-only-legacy-transition-assertions-v0`.
The output format is `synthetic-only-legacy-transition-classification-v0`, with
only `well-formed-for-further-qualification` or `refused` status and fixed refusal
codes. **Every result permanently has `authorized:false`,
`admission_eligible:false` and all eight qualification blockers**, even for a
fabricated complete consistent assertion set. It establishes no readiness,
recovery success, present health or authenticity of terminal evidence.

The closed grammar models nine required legacy public roles: five replacement/
no-op roles (ordinary observer, package observer, plan transport, deploy activator,
ansible-plan sudo) and four preserved roles (private-preparer, firewall helper,
firewall transport, firewall sudo). Protected collector and controller observer
are two additional, separately declared-absent before/new-output roles, never
aliases or missing-prerequisite repairs. Exact fixed paths and unique role/object
references are checked; preserved/no-op identities cannot change. Replacement
restoration uses original content references but a distinct restoration object
reference, not a fictitiously restored original inode.

The top-level fields are exactly `format`, `original`, `recovery`, `current`.
`original` is an **asserted frozen checkpoint**, not an original admission receipt
or a durable journal: reference, owner_ref, state, generation, terminal_audit_ref,
and eleven role rows (`role`, `path`, `change`, `before`, `candidate`,
`restored_before`). Each present object has only `content_ref` and `object_ref`;
absence is null. `current` binds original_ref, owner_ref, state, generation,
terminal_audit_ref and role/path/object rows. `recovery` has a distinct reference,
original_ref, start_state, start_generation and one action. All references use
bounded `synthetic:` labels, not real hashes or measured installed identities.
Equality is consistency inside one call only: coherently rewriting all assertions
cannot be detected or authenticated, and cannot remove any blocker.

| Asserted checkpoint | Required current role profile | Sole action shape |
| --- | --- | --- |
| prepared | before | rollback-exact |
| candidate | candidate | rollback-exact |
| rollback-restored | restored-before | rollback-exact |
| committed | candidate | cleanup-committed |
| rolled-back | restored-before | cleanup-rolled-back |

`rollback-restored` describes only the fully restored preterminal shape, not an
interrupted publication algorithm. Mixed/installing/failed, ambiguous/foreign
ownership, detached/fully-cleaned and unknown states are unsupported and refuse;
no journal is inferred. State and positive integer generation must match exactly
across all three assertions. Terminal cleanup requires the unchanged original
terminal-audit reference; it neither invents a missing audit nor reruns rollback,
restamps history or asserts fresh health. Forward apply/commit/resume, wrong
terminal cleanup, committed rollback, automatic retry/receipt renewal and unknown
fields (including trust-me booleans) refuse.

Only built-in JSON-shaped values are accepted: depth at most 12, 4096 visited
nodes including keys, 32 entries per container, 256 printable ASCII characters
per string; references are at most 80 characters and generations 1..2147483647
with bool-as-int rejected. No parsing or normalization of access, measurement or
receipt v1 occurs. Real complete audit/support coverage, original/recovery
authority, origin/host/console/runtime, evidence-specific freshness, independently
approved compatible source/profiles, asynchronous-writer coordination, durable
crash/publication ownership and authentic original terminal audit all remain
independent permanent blockers, not caller-supplied evidence predicates.

The focused synthetic suite is registered as
`env -i PATH="$PATH" python3 -I -B -S scripts/controller/test-legacy-transition-classifier.py`.
The security regression executes that exact registered entry under synthetic
Python/SSH contamination. Tests load only the exact adjacent classifier source,
cover causal one-fault refusals, deterministic nonmutation, runtime-I/O tripwires
and three in-memory mutations of role, terminal-action and permanent-blocker
guards. These are offline grammar tests, not native/host/process qualification.
Independent source review of frozen candidate
`11c8a042cf150aebf460f38fd0da894104fc6281` found no issues and approved only
bounded offline integration. Parent verified exact source/patch provenance and
reran all 13 focused tests, 18 security regressions and full Nix-free repository
validation. The classifier never reads private evidence; the broader parent
validation uses separately retained evidence and establishes no live acceptance.

## Hard admission blockers

New capability planning/installation and new reboot application remain explicitly
and unconditionally blocked in code. The active VFIO helper now has the reviewed
**offline source** coordination migration; installed queued-reboot exclusion and
its dependency closure are still unqualified. There is no override, marker,
age/PID cleanup or source-hash-only exemption. `verify-reboot` and exact retained
capability rollback/commit are not behind this new-operation gate.

The self-contained VFIO participant acquires the operation descriptor first,
blanket-rejects retained iac/apply/historical owner/nix/firewall records, then
acquires VFIO and native QEMU descriptors in that order. Any retained shape,
including dangling links, FIFO and empty directories, refuses regardless of
boot ID, matching token or hash. It never reads, adopts or removes owner contents.
All mutexes must preexist as root:root single-link regular files, mode 0600, with
no-follow validated ancestry and named-inode rechecks. It creates or repairs none.
Inspection, mutation, same-invocation compensation and postconditions retain all
three descriptors; every partial acquisition closes on failure.

The fixed root:root policy (contract mode 0440) is read under operation protection,
not before locking, and must name the exact contract VFIO mutex. Confirmation is
checked against that protected policy without reinterpreting an earlier token.
The helper requires `/usr/bin/python3 -I`, invokes only absolute `/usr/sbin/qm`
with a bounded explicit environment, and refuses unsafe/missing dependencies.
Installed interpreter/import, native executable/Perl/PVE/library package integrity
and compatibility remain separate qualification, not established by these checks.
`observe` remains a lock-free, read-only **advisory** snapshot, never transaction
readiness. Recovery remains an explicitly confirmed stopped-VM unbind/rebind of
the exact already-vfio-bound group, not a boot-binding initializer.

The inspected source graph has **no normal startup call** to VFIO recovery and
no nested recovery call from deploy, transaction health or observation. Declarative
module/initramfs binding and native VM startup are distinct from recovery. Installed
callers, hooks, startup overrides and dependency closure remain **UNOBSERVED**.
If installed startup requires this recovery CLI, stop for a separate authority
review; no postboot token handoff, owner exception, journal, retry, automatic
recovery or boot service is authorized here.

Holding descriptors only until `systemctl reboot` returns does not exclude a
writer during the queued interval: the blanket retained-owner check supplies that
source barrier. The installer must not recognize a helper hash as qualification.
Helper **and policy** installation, interpreter/import/native closure qualification,
and safe preexisting/boot-time mutex provisioning are separate future work. The
capability install target set still excludes helper/policy; no installer, retained
Nix writer, contract, transport, sudo, boot unit or admission gate is changed.

Both maintenance observation consumers now recognize `reconciliation/apply.lock`
as retained ownership, including descriptor-free regular, symlink and FIFO cases.
These are source fixtures, not installed coordination qualification. The controller's
string-presence check is only an early missing-integration rejection. The unconditional
VFIO gate remains despite offline source completion; installed qualification and
separately reviewed admission work are still required.

Target topology has not been observed. Every mutex must already exist with safe
metadata and remain/reappear at boot through separately approved provisioning.
Neither this installer nor observation creates mutexes or repairs their metadata.
In particular, `/run/lock` persistence/provisioning across boot must be proven;
missing descriptors keep postboot verification fail-closed with ownership retained.
Do not chmod `/run`, `/run/lock`, or unrelated shared directories to pass admission.
The Debian backup runner's separately declared group-writable lock is **not**
authority to relax the root-owned PVE descriptor protocol.

## Descriptor and retained-record protocol

- Observer opens existing, root:root, single-link, no-follow regular mutexes and
  acquires nonblocking exclusive flocks (plus POSIX locks for APT). Modes remain
  0600/0640 for observation; protected boot/reboot participant locks require 0600.
- Ancestors must be root:root and not writable by group/other. Only canonical
  `/run/lock` may be exactly 1777. Sticky-root ownership protects existing
  root-owned entries; user-owned files, hardlinks, symlinks, unsafe ancestors,
  pathname replacement and missing files fail closed. No observer unlink/create.
- Order for protected boot/reboot is operation, VFIO, backup, low-risk,
  boot-configuration, package, reboot; this is a subsequence of observer order.
  Descriptors span the entire protected operation and every partial acquisition
  is closed on failure. Other deploy dispatches hold operation before owner
  checks and their domain locks. Package descriptors now close on every return.
- Persistent `operation.lock` is **not** a presence journal. The reboot record is
  exclusively created at `/var/lib/home-lab/reconciliation/apply.lock` under the
  operation descriptor. It has a distinct version, operation, exact plan digest,
  preboot identity and random token; its inode identity is bound into the journal.
  Root ownership, mode 0600, single-link metadata, ancestry and bytes are checked.
- Record fsync and journal publication precede workload stop. Workload-stop,
  scheduling, transport and postboot failures retain the barrier. No failed apply
  retry adopts it. The only self-owner continuation is exact postboot verification.
- Verification rechecks expected boot/kernel and health, durably commits the
  journal, then revalidates/removes only the exact owner while serialized. A crash
  after commit but before removal can repeat exact verification and health checks;
  it cannot silently remove a foreign/replaced record. Journals remain retained.
  Creation interrupted before the ownership identity reaches the journal needs
  separately reviewed recovery; it is deliberately not automatically adopted.
- Like the existing pathname ownership protocol, unlink safety assumes cooperating
  privileged writers retain the shared descriptor. An uncooperative root writer
  can replace a pathname; sticky-directory protection is not protection from root.

### Participant inventory

| Participant | Serialization / retained barrier |
| --- | --- |
| Controller observer | operation plus ordered domain/APT descriptors; rejects all historical journals and apply.lock |
| Deploy activator | operation before mutation; retained apply.lock barrier; exact reboot verification exception |
| Ansible apply_lock | operation before checking apply.lock and publishing iac owner directory |
| PVE firewall | operation before apply.lock/iac owner checks |
| Retained Nix activator | operation, legacy exact apply.lock shape; rejects new reboot record in ordinary, initializing and terminal/recovery paths |
| VFIO recovery | operation → blanket retained-owner rejection → VFIO → QEMU; offline source only, installed queued-reboot exclusion still unqualified |
| Legacy package/inert plan installers | apply entrypoints disabled; cannot overwrite incomplete sudo or bypass serialization |
| Maintenance/package observation consumers | retained apply.lock source integration; installed behavior still unqualified |

Backup, unmanaged root commands, reboot-time descriptor provisioning, all installed
participant bytes and exact target behavior remain admission/qualification work;
this is not a claim of universal exclusion for every privileged process.

## Fixed capability installation wiring

`scripts/controller/proxmox-controller-observer-capability.py` is an attended
controller tool, not a new host sudo command. It streams the bounded transaction
source through the existing human sudo route. The only added account authority is
`proxmox-controller-observer observe`, reached by the existing fixed
`observe-controller` transport verb. There is no account shell or generic sudo
expansion. Older package-observer and inert-plan apply paths explicitly refuse;
rollback to those historical installers is not an approved migration shortcut.

Disabled entrypoints are exactly:

- `scripts/controller/proxmox-package-observer-capability.py apply PLAN ARTIFACT`
  (`apply(path, artifact)`): now refuses before reading inputs or contacting a host.
- `scripts/controller/proxmox-plan-capability.py apply PLAN` (`apply(path)`): now
  refuses before changing sudo or the inert account's login shell.

The candidate replacement for an **already active** fixed plan account is
`proxmox-controller-observer-capability.py` (`plan`, `apply`, exact `rollback`, `cleanup-committed`). It
is currently blocked for new installation by unqualified VFIO coordination. It
is **not** a replacement inert bootstrap procedure: host prerequisites require
an already installed fixed transport/account, predecessor helper/sudo assets and
safe preexisting mutexes. Consequently a future inert/clean-recovery setup has no
newly approved enabling path in this patch. It requires a separately reviewed
bootstrap/recovery transaction and installed-byte/participant qualification;
do not revive either disabled installer or broaden the account shell/sudo to
bridge that gap. Historical plan creation alone does not authorize application.

The saved transaction binds clean pushed revision, contract/schema, inventory,
controller/transaction sources, exact rebuilt artifact bytes, installed before
bytes, dedicated strict host trust, fresh independent console/access evidence and
retained backup evidence. Separate exact apply/rollback confirmations are required.
The host checks its clean matching repository, account/key boundary, health,
installed metadata, all descriptors and owner journals before mutation.

Access admission validates the complete applicable v1 receipt shape: canonical bounded
bytes, commit/contract/combined-inventory/host bindings, exactly 30-minute lifetime,
ordered creation/physical-console attestation/current time/expiry, strict host trust,
positive and injection-rejection transport proofs, no-op tailnet policy and attributed
root-key inventory. Retirement-drift exceptions are not capability authority. Both
combined and Proxmox-specific inventory hashes are captured in the saved bindings.
Every remote phase rechecks these captured identities and streams the exact captured,
hash-verified transaction bytes; it never substitutes a newly current revision.

This consumer does not make the old capture command operationally qualified:
`proxmox-access-evidence.py capture` still invokes `local-controller plan steady`
without the now-required explicit generation. A reviewed generation-aware capture
and predecessor/bootstrap admission path remain setup work. Do not fabricate fresh
receipts or relax the consumer to bypass that gap.

The transaction captures rollback bytes and a versioned retained journal under an
owned iac directory before replacing helpers and sudo. Sudo syntax is checked
before publication; postchecks retain the owner as a candidate while the controller
runs the independent 17-domain exact artifact audit. Commit reacquires descriptors,
revalidates ownership, source/installed bytes, health and the exact audited
observation before releasing ownership. Failed/ambiguous audit or preterminal commit
retains ownership for separately confirmed exact rollback, never automatic
reinstallation. Rollback refuses foreign bytes or a replaced owner inode, restores
sudo first, checks the restored state, and releases only its exact owner. A failed
rollback retains its journal/barrier. Once a committed journal is published, its
remaining authority is terminal cleanup, not restoration of installed bytes. Partial owner publication without a journal requires
inspection rather than invented retry ownership. Exact rollback still requires
fresh source-bound admission evidence; expired prerequisites or a changed revision
need a separately reviewed recovery plan, not a bypass or automatic replan.

## Durable journal publication and terminal cleanup

Package/reboot journal writes persist validated directory ancestry, then the file,
then its creation/replacement directory entry. This ordering places durable owner
identity before workload stop and durable committed evidence before owner release.
Failures retain the existing barriers and do not authorize a failed-operation retry.
Transaction directories are created through no-follow, metadata-checked ancestry.

Capability publication uses unique exclusive temporary names. Interrupted temporary
files, including historical deterministic names, are not adopted or deleted by a
later invocation; retained orphan inspection remains separate recovery work.
After durable terminal state, cleanup renames the exact owner directory to a sibling
bound to its plan and recorded inode identity, fsyncs the parent, and only then
removes its exact record and directory with directory fsyncs. An interrupted empty
detached directory is removable only at the recorded inode. Foreign active or
detached records, including a different later active owner, are refused. An old
empty **active** barrier is not adopted: it still requires separately reviewed
recovery. Descriptor locks span all these transitions and are closed on failures.

The host request `operation: cleanup-committed` uses the same exact `commit`,
`bindings`, `plan_sha256`, `before`, and `files` fields as rollback. It accepts only
a bound committed journal and returns `{"status":"committed","live_acceptance":false}`.
It durably re-publishes terminal evidence before cleanup (covering interruption
between journal rename and fsync), never audits a candidate or mutates installed
bytes. Candidate/preterminal states and mismatched terminal operations are refused.
A rolled-back journal permits only exact `rollback` cleanup. Internal `commit`
remains the independently audited candidate transition, not its retry mechanism.
The controller exposes `cleanup-committed PLAN --artifact ARTIFACT --access ACCESS
--backup BACKUP`. It requires the separate `PROXMOX_CONTROLLER_OBSERVER_CAPABILITY_CONFIRMED`
value `cleanup-committed-proxmox-controller-observer-capability-<plan-sha256>`; an
apply confirmation cannot authorize it. It sends no observation hash, performs no
audit or installation, and accepts only the committed/non-live-acceptance response.
Re-running apply is not a substitute. Changed/expired prerequisites still require
separately reviewed recovery. None of this opens the VFIO gates.

## Offline evidence and limits

Focused source tests cover generated artifact/transport/sudo coherence, installed
activator binding, legacy installer refusal, legacy Nix owner rejection, descriptor
cleanup, sticky-root attacks, reboot record ordering/lifetime, queued scheduling
failure, postboot commit/removal interruption and installer rollback failure.
APT exclusion additionally uses real child-process POSIX whole-file write-lock
holders for every apt/dpkg mutex: a flock-only probe succeeds while observation
correctly refuses, partial record-lock acquisition is released, and a competing
POSIX holder is excluded while observation retains its descriptors. These are
native fcntl/lockf fixtures, never real apt/dpkg package operations.
Journal fixtures wrap actual file/directory fsync and rename syscalls, inject
creation/publication sync failures, and terminate real children after temporary
file sync and on both sides of terminal detachment, unlink, rmdir and their fsyncs.
They prove explicit exact continuation, mismatched terminal-operation refusal,
foreign replacement/later-owner refusal, orphan preservation and descriptor cleanup.
These are process-interruption/order proofs, not a storage power-loss qualification.
Native cases run in disposable child chroots in the existing arm64 Linux image
`ce40764625a4`, with network disabled, read-only image, disposable tmpfs, streamed
source only and every native transaction command replaced by a confined fake.
Dormant transaction tests explicitly substitute the unqualified-VFIO gate; separate
tests prove the real entrypoints refuse. This substitution is not admission proof.

No host contact, credentials, real workload state, real reboot/systemctl, image
pull, package install, launchd installation or public operation was used for these
repairs. The isolated writer lacked the retained AWS proof and did not run or waive
full validation. The parent checkout has legitimate retained proof and passed full
Nix-free validation after integration. Source checks include 12 controller cases,
21 confined native protocol cases and 14 confined reporting capability cases;
attestation, console, native commands and host prerequisites are fixture substitutes.
These are not target/live acceptance. The durability lane passed independent review.
Fresh review of `eb35c42` also found no issues in the combined admission/source-binding/
cleanup/reporting changes and approved bounded source integration. All operational
gates and setup/qualification gaps remain unchanged.


### VFIO migration evidence boundary

The VFIO suite retains the six original recovery semantics tests and adds real
`main`/`locked_recovery` hostile entry fixtures: zero backend writes on refusal,
all three missing/busy/unsafe/replaced mutexes, ancestry attacks, descriptor cleanup,
every retained barrier shape and inspection errors, protected policy replacement,
fixed dependency/environment checks, and compensation under every descriptor.
Real children exercise operation contention in both orders with observer/deploy,
including descriptor-free iac/apply publication. Dormant reboot fixtures additionally
prove exclusion before/after synthetic boot and failed verification/terminal release;
only successful exact owner release permits a later explicit recovery invocation.
Unconditional controller, streamed host and reboot gates remain independently tested.
The neutral artifact test binds active VFIO bytes into projection/observation hashes
and checks retained CLI/policy compatibility; unrelated asset parity remains intact.

The source-only confined Linux rerun passed all 15 VFIO, 21 protocol and 14
maintenance capability tests with no skips. macOS runs skip the Linux/root cases;
they are not substituted for native evidence. Focused projection/artifact, complete
17-domain audit, neutral controller, 12 controller-capability, seven controller-
observer and deploy/reboot regressions also pass.

Confined native checks substitute synthetic policy, VM 4242/group 77/device identity,
backend and native commands. The cached image has `/usr/local/bin/python3`, not the
fixed target `/usr/bin/python3`; main-entry fixtures substitute interpreter identity,
not installed execution qualification. No target, device, real proc/sys write,
package, reboot, VM or deployment operation is part of these tests. Existing dormant
reboot command fixtures remain substitutes. The parent passed full Nix-free validation
after exact patch integration, using legitimate retained AWS evidence unavailable in
the writer worktree. No prerequisite or operational gate is waived.

An earlier recursive test archive accidentally included one local source-derived
`.pyc`; that packaging deviation is retained and those runs are superseded, not counted.
The parent verified all nine regular source files against candidate `2594ed4`, then
reproduced the 15/21/14 passes from the hash-checked archive in fresh empty tmpfs,
with cache scans before/after. Interpreter/backend substitutions remain explicit.
The original workflow failed on unsupported `acceptanceReport.nativeEvidence`; its
failure was not rewritten as approval. After artifact recovery, a separate independent
review of `2594ed4` found no issues and approved bounded offline source integration.
Installed qualification, gate removal and live operations remain unauthorized.

## Offline imported Tailscale content diagnostic and remaining limits

`scripts/controller/tailscale-access-evidence.py` is the first **non-authorizing**
semantic diagnostic for future capability-only predecessor work. It does not
implement that protocol, acceptance, collection, a receipt, console attestation,
freshness, a generation, staging, repair or a blob/attempt store. Strict access v1,
all existing consumers and all installation/deployment/VFIO gates are unchanged.
Even a content-consistent result with its flags manually flipped is rejected by
the unchanged strict capability v1 validator; this is a distinct format, not an
alternate receipt. The suite is registered in authoritative validation and its
registration guard; full parent Nix-free validation passes after integration.

Supply all six existing private files explicitly, using absolute, non-symlink
paths; there is no stdin, latest-file selection or discovery:

```text
/usr/bin/python3 -I -B -S scripts/controller/tailscale-access-evidence.py \
  --plan /PRIVATE/decoded-plan.json \
  --live-before /PRIVATE/imported-before-policy.json \
  --live-after /PRIVATE/imported-after-policy.json \
  --headers-before /PRIVATE/imported-before-headers \
  --headers-after /PRIVATE/imported-after-headers \
  --expected-policy /PRIVATE/separately-selected-policy.json \
  --expected-sha256 <explicit-lowercase-sha256-of-selected-exact-policy-bytes>
```

The executable shebang is fixed `/usr/bin/python3 -IBS` (one correctly combined
kernel shebang argument); missing isolation, no-site or no-bytecode flags refuse.
The helper is loaded from the adjacent fixed reviewed
`tailscale-policy.py` **source bytes**, checked against its pinned SHA-256 and
compiled directly, never via ignored/unchecked bytecode or an input-selected
module. Python path/home/startup environment injection is excluded by actual
isolated CLI tests; startup site loading and bytecode writes are disabled before
script execution. Installed interpreter, standard libraries, source deployment
and runtime dependency closure remain **unqualified**. The
running script cannot certify the origin of its own interpreter/executing bytes.
Source and helper descriptors are checked during this invocation, not attested.

Output is one bounded canonical JSON object (sorted keys, compact UTF-8, terminal
newline), format `home-lab-tailscale-access-diagnostic-v1`, always
`authorized:false`, `admission_eligible:false`, `origin:unqualified-import`.
Exit 0 means **only imported content consistency**; refusal is exit 1. No raw
plan, policy, ETag, provider expression, credential, pathname or exception text is
emitted. Diagnostics include exact recomputed SHA-256 and byte size for every
fully bounded input set, plus canonical semantic policy and ETag hashes on
success. Unsafe/unreadable/oversized input sets are not partially hashed into a
successful diagnostic. Error codes are fixed and bounded, including argument
errors. Hashes are identifiers, not proofs of provenance (and can still be
sensitive correlators); retain output appropriately.

Four permanent blockers remain on **every** result: binary-to-JSON linkage,
live-collection origin, execution qualification and independent policy-review
provenance. Neither filenames nor imported plan timestamps prove any of these.
The diagnostic accepts no binary and runs no Tofu/SSH/HTTP/OAuth/Ansible/controller
or other subprocess/network operation. It cannot establish that the bodies were
live, that a binary produced the JSON, that policy selection was independently
approved, or that execution was qualified. The explicit expected digest prevents
substituting different selected bytes; calculating it yourself does **not**
self-approve a policy. No API policy tests or live denial canaries are run.

### Bounded semantic subset

- Strict UTF-8 JSON objects reject duplicate keys, BOMs, invalid Unicode,
  NaN/Infinity, floats, integers outside signed 64-bit range and wrong field
  types. The decoded plan is at most 2 MiB; each of the three policy bodies is
  at most 256 KiB; each header file is at most 16 KiB; total imported bytes are
  at most 3 MiB. JSON depth is at most 48 and the aggregate parse budget is
  100,000 nodes, including object keys and reparsed embedded policy strings.
  Bounds refuse rather than truncate. Diagnostics are below 4 KiB in the tests.
- Accepted plan structure is grounded in local OpenTofu 1.12.5 decoded JSON,
  format 1.2 (1.11/1.12 version markers are syntax only, not qualifications).
  Exactly one managed root `terraform_data.tailscale_policy[0]` must use the
  builtin `terraform.io/builtin/terraform`, index/schema version integer zero,
  and actions exactly `["no-op"]`. Resource changes, planned values, prior-state
  values and root configuration must agree; module aliases, moves/imports,
  additional/disabled/missing resources, drift, deferred work, unknown/incomplete
  values, errors, sensitive/unknown shape changes and non-noop actions refuse.
  The reviewed root has no outputs: any output entry/change is unsupported and
  refuses, even if labelled no-op. Configuration expressions support the observed
  HCL local-policy/count references or the constant synthetic fixture shape, not
  arbitrary expression evaluation. This is not configuration/source provenance.
- Complete before/after resource values must match, including ID, input, output
  and null `triggers_replace`; resource output must equal input. Each original
  embedded `policy_json` string must match its own embedded `policy_sha256`,
  separately from canonical semantic hashing. The real reviewed helper parses
  and extracts both policies and canonicalizes them; canonical before, after,
  both imported bodies and the independently selected expected policy must all
  agree.
- The helper is supplemented with a deliberately narrow structural check for
  the reviewed `tagOwners`, `grants`, `ssh`, `tests`, `sshTests` subset: nonempty
  string lists, TCP ports, accept SSH actions and well-formed accept/deny test
  entries with no overlapping outcomes. Unsupported policy features refuse.
  This is not a full Tailscale selector/API validator, policy approval, an API
  test runner, or proof that grants and SSH rules enforce the stated tests.
- Headers must describe one CRLF-terminated HTTP/1.0, HTTP/1.1 or HTTP/2 **200**
  response with JSON content type and one nonempty strong ASCII quoted ETag.
  Both ETags must match exactly. Duplicate header names (even identical values),
  multiple responses, redirects/errors, folding, controls, weak/conflicting
  ETags, compression/transfer encoding and mismatched content length refuse.
  This is a conservative imported decoded-body subset, not an HTTP client.
- The exact unused root `tailscale` provider-config entry is the sole bounded
  **opaque** exception (nonempty object, at most 16 KiB within all JSON bounds,
  no alias/module markers). Extra provider keys or any resource/config reference
  to it refuse. Its metadata, version, expressions, behavior and dependency
  closure are **not verified**; this limitation is explicit in output. The
  builtin-only native fixture does not observe this entry. Tests adding it use
  synthetic metadata, not an observed production-shaped plan. No provider
  download or live-root plan is used to bridge this gap.

### Private-file and offline test boundary

Inputs must already be owned by the invoking UID, mode 0400/0600, regular and
single-link. Every path component is opened no-follow with retained directory
FDs. Ancestry must be root/invoker-owned and not group/other writable, with only
canonical root-owned 1777 `/tmp` or `/private/tmp` exceptions. Symlinks (including
ancestors), FIFOs, hardlinks, unsafe modes and missing files refuse. Files are
bounded-read through nonblocking descriptors; named inode/metadata and exact
content are rechecked after reads and before output, including script/helper
sources. The diagnostic never creates, chmods, truncates, unlinks or repairs
inputs. It does not provide a simultaneous filesystem snapshot or protection
against an uncooperative privileged writer/interpreter. Normal filesystem read
access-time effects are not an attestation or a mutation transaction.

`test-tailscale-access-evidence.py` covers actual CLI output parsed as JSON and
rejected by the unchanged strict v1 validator (also with flags flipped), actual
policy helper semantics, hostile plan/policy/header cases, bounds/redaction,
private-file attacks and retained input/source/helper replacement, unchecked-hash
bytecode and ambient Python injection, and no diagnostic filesystem writes.
One native local test runs existing OpenTofu with builtin `terraform_data` only,
backend disabled, refresh disabled, an empty provider mirror, checkpoint
network checks disabled and macOS `sandbox-exec` denying all network operations.
It hand-writes wholly synthetic disposable state,
performs **no apply/import**, plans/decodes only that fixture and checks unchanged
synthetic state bytes. Its CLI result retains all unqualified-import blockers.
If local Tofu or the macOS network-denial sandbox is unavailable this case skips
explicitly; synthetic parser fixtures remain separate, never substituted
binary/collector provenance. The observed
local run used OpenTofu 1.12.5 and passed without skips. No production model,
credentials, host/API contact, Docker container, provider install/download or
live planning was used. Neither this test nor the diagnostic qualifies a future
collector, predecessor protocol, installed execution, review authority or access
admission; those remain separately approved work.

The independent review of `74d637c` approved this bounded diagnostic scope and
identified a P2 structural-policy test weakness. Parent separated structural and
substitution cases and requires the exact `policy-structure` error. A mutation
probe disabling structural validation passes the former matrix but fails the
strengthened one. All 15 focused tests pass, including the isolated local OpenTofu
fixture; these checks remain content-consistency evidence, not admission authority.

## Bounded predecessor console measurement slice (offline source only)

`infrastructure/proxmox-access/host/proxmox-predecessor-console-evidence.py` is
an offline-developed, **non-authorizing** fixed-asset collector. Live execution
has not been approved. It does not implement the aborted draft predecessor
protocol, approve a profile, issue a receipt, attest physical presence, install
anything or enable any consumer. Strict access v1, the imported Tailscale
diagnostic, transports, sudo, installers, gates and scheduling are unchanged.
The output is a distinct `home-lab-proxmox-predecessor-console-measurement-v1`
object; even manually flipped authority flags do not satisfy strict v1.

The fixed invocation shape is `/usr/bin/python3 -I -B -S <reviewed-source>
--challenge <64-lowercase-hex-characters>`, not a live execution instruction.
The shebang uses the combined `-IBS` argument. Linux, real/effective UID zero,
that interpreter spelling, actual isolated/no-site/no-bytecode flags and absence
of SSH/PYTHON environment indicators are required. No catalog, root, path,
expected-hash, output-file or console-bypass argument exists. Unknown/malformed
arguments refuse without echoing them. Startup/dependency installation remains
unqualified; source/interpreter self-hashes would not attest execution, and none
are presented as such.

The local guard requires a foreground controlling TTY, matching no-follow named
and descriptor identity, and Linux major 4 `/dev/tty1`–`/dev/tty63` or conventional
`/dev/ttyS0`–`/dev/ttyS3`. It rejects generic PTYs, non-TTY stdin, `/dev/console`
aliases, USB serial and SSH indicators; there is no WebShell/SSH support promise.
This conservative kernel check is **not** proof of independent physical presence,
channel, login origin or host identity. A privileged caller can fake execution
or route a console; independent console-origin qualification stays a blocker.

### Fixed source-grounded catalog, not an approved byte profile

All public files are root:root, regular, single-link, at most 1 MiB. The collector
measures metadata and SHA-256 only; it never imports or executes these files:

- `proxmox-observer`, `proxmox-protected-collector`,
  `proxmox-package-candidate-observer`, `proxmox-ansible-plan-transport` and
  `proxmox-ansible-deploy-activator` under `/usr/local/libexec/home-lab`, mode 0755:
  the capability transaction's fixed `TARGETS` predecessor subset and controller
  artifact map (`build-proxmox-ansible-observer.js`). The new controller observer
  is deliberately omitted: requiring it would recreate the bootstrap cycle.
- `proxmox-firewall-transaction` and `proxmox-firewall-transport` in that same
  directory, mode 0755: firewall fixed constants, deploy-upgrade source target
  map/metadata checks and final-key-retirement fixed transport metadata.
- `/etc/sudoers.d/ansible-plan` and `/etc/sudoers.d/firewall-apply`, mode 0440:
  transaction target and contract account sudo file declarations. No `visudo`
  execution or semantic sudo validation is claimed.

Prerequisites are existing protected root:root directory ancestry,
`/var/lib/home-lab/reconciliation`, and the firewall helper's exact mode-0700
`/var/lib/home-lab/firewall-transaction`. Missing runtime is a refusal, never a
call to firewall `ensure_dir()` or `main()`: even its inspect entry can create
missing runtime before inspection. This snapshot does **not** authorize later
firewall inspect. An existing root:root single-link regular `operation.lock` in
reconciliation, mode 0600/0640 as in the controller observer, is limited to 4 KiB
and exclusively flocked nonblocking through every measurement/recheck. Its bytes
are never read. No domain/APT lock or universal writer exclusion is claimed.

The firewall's `attestation.key` is included solely to expose the signing
prerequisite's safe **metadata**, mode 0600, at most 128 bytes (the source reader
bound), using Linux `O_PATH`. Its value is never opened for reading, hashed or
emitted; this does not validate the helper's required 32-byte key value. No other
secret/runtime-value files, keys, shadow, accounts, NSS, environment values,
service state, proc/sys identity, repository or dynamic path inventory is read.

Every shape of reconciliation `apply.lock`, `owner.lock`, `nix.lock`,
`/var/lib/iac-ansible-production.lock` or firewall `active.json` is a blanket
refusal. No retained bytes, PID, age, token or matching hash are read/adopted;
inspection errors do not establish absence. All ancestry and file FDs are
no-follow, retained and rechecked against their names. Only validated regular
public files receive nonblocking bounded content reads; exact hashes and
metadata are rechecked before returning. Symlinks, hardlinks, special files,
unsafe ownership/modes, missing/replaced objects and ambiguous errors refuse.
There are no writable-ancestor exceptions in this catalog, including sticky
ones, and no mkdir/chmod/chown/repair/cleanup by the collector.

Output is one canonical JSON object on stdout, at most 16 KiB. Exit zero and
`status:measured` mean only that this bounded slice was measured, never a complete
audit or readiness. Every result has `authorized:false`, `admission_eligible:false`,
`origin:unqualified-console` and permanent console-origin, execution,
independent-profile, host-binding, account/key-inventory, runtime/dependency and
freshness/recovery blockers. Refusals contain no partial asset evidence, exception
text, arbitrary argument or file body. No timestamp lifetime, expiry exception,
automatic retry/recovery or later authorization is inferred from the challenge.
Hashes are measurements for later comparison with separately approved expected
bytes, not self-adopted profiles or proof of executing those bytes.

The operation flock serializes cooperating writers only. Repeated byte/name/
metadata checks are not an atomic filesystem snapshot or protection against an
uncooperative privileged writer; read atime effects are possible. Remaining gaps
include all account/group/password/key absence, independent host keys/identity,
legacy/helper/profile coverage, deploy transport/sudo, firewall policy/boot units/
recovery assets, protected runtime values, domain/APT mutex provisioning, installed
callers/dependency closure and runtime qualification. Omitted paths must not be
inferred absent or safe. This first slice does not complete predecessor admission.

The focused `test-proxmox-predecessor-console-evidence.py` exercises real CLI
refusals and main-entry fixed reads, metadata/hashes, sentinel non-disclosure,
missing/hostile files and ancestry, replacements, error injection and unchanged
strict-v1 rejection. Confined Linux tests use disposable child chroots and real
conflicting flock holders, release/retained-owner cases and actual controlling
PTY rejection. Positive fixtures substitute only terminal identity and the cached
image's `/usr/local/bin/python3` interpreter spelling: **neither is hardware-console
or installed interpreter qualification**. Mac skips are not Linux evidence.
The suite and registration guard are wired into authoritative validation;
full parent Nix-free validation and completed independent review now pass;
no live collection, credentials, provider/package downloads or service changes
are part of this source slice.

The original writer failed on a WebSocket error after preserving `c69d8d5`.
Parent verified the exact candidate and source-only archive and reproduced all
12 original confined Linux tests. The subsequent review was aborted; its notes
are useful findings, not completed approval. Parent strengthened the startup
negatives to require exact interpreter/root/console reasons and forbid collection
after PTY/non-TTY/root refusal. Separate 128/129-byte key and 4096/4097-byte mutex
cases now check their own boundaries without reading or hashing either object.
The collector implementation remains unchanged. Completed review of `6f517fe`
closed both test findings but blocked plain-Python registration: its flags and
inherited `PYTHONDONTWRITEBYTECODE` made native positive fixtures fail. Registration
now uses `env -i PATH="$PATH" python3 -I -B -S`, with an exact guard and a regression
executing that extracted command under synthetic SSH/PYTHON contamination.
Parent reproduced the old failure and verified the corrected registered entry
and all 13 native tests without skips. Five mutation probes detect removed
interpreter/root/console guards and widened key/mutex size limits. Completed
follow-up review of `779a2d4` found no issues and closed the registration blocker.
These are bounded source-integration results, not permission to collect on a host.
