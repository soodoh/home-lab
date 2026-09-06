# Proxmox controller capability — unaccepted source candidate

ADR 0001 remains authoritative. This document is **not** installation, collection,
qualification, package, reboot, recovery or deployment approval.

## Hard admission blockers

New capability planning/installation and new reboot application are explicitly
blocked in code: the current VFIO recovery implementation has no qualified
queued-reboot ownership protocol. There is no override, marker, age/PID cleanup
or source-hash-only exemption. `verify-reboot` and exact retained capability
rollback/commit are not behind this new-operation gate.

A future separately reviewed change must migrate the VFIO writer to the shared
operation descriptor plus retained ownership protocol, prove ordinary and
recovery paths cannot bypass/remove foreign records, and bind its installed
executable **and dependencies** to reviewed source. Holding its descriptor only
until `systemctl reboot` returns does not exclude it during the queued interval.
The installer must not simply recognize the old source hash as qualification.

Both maintenance observation consumers now recognize `reconciliation/apply.lock`
as retained ownership, including descriptor-free regular, symlink and FIFO cases.
These are source fixtures, not installed coordination qualification. The controller's
string-presence check is only an early missing-integration rejection. The unconditional
VFIO gate remains until real reviewed protocol work replaces it.

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
| VFIO recovery | VFIO/QEMU descriptors only; **unqualified across queued reboot**, hard-blocks admission |
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
20 confined native protocol cases and 14 confined reporting capability cases;
attestation, console, native commands and host prerequisites are fixture substitutes.
These are not target/live acceptance. The durability lane passed independent review.
Fresh review of `eb35c42` also found no issues in the combined admission/source-binding/
cleanup/reporting changes and approved bounded source integration. All operational
gates and setup/qualification gaps remain unchanged.
