# Proxmox controller capability — unaccepted source candidate

ADR 0001 remains authoritative. This document is **not** installation, collection,
qualification, package, reboot, recovery or deployment approval.

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
