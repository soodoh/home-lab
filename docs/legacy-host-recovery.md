# Legacy host recovery

**Emergency reference for retained assets, not current mutation authority or a
qualified fresh rebuild.** Native adoption has not replaced these recovery
protocols. There is no general deploy command. Inspect installed generations,
exact journals/owners and independent console/LAN access before a separately
reviewed recovery invocation. Do not rerun completed bootstrap or cutover steps,
clear locks, disable watchdogs, or fabricate sidecars/receipts.
See [current scope](operations.md#what-is-available-now),
[staging-only data recovery](../recovery/README.md), and the
[source retirement assessment](legacy-nix-retirement.md).

- [Bootstrap interruption](#bootstrap-interruption) covers console-installed assets.
- [Retained host sessions](#retained-host-sessions) covers the old Nix protocol.
- [Autonomous firewall recovery](#autonomous-firewall-recovery) is a distinct
  PVE transaction with its own watchdog and two boot phases, not Ansible rescue.

## Bootstrap interruption

The old protocol keeps Nix controller-side; no Nix daemon/store is installed on
Proxmox. Historical forward ceremonies are in Git at `b65857a`, in the former
`docs/proxmox-bootstrap.md`. They are not native setup instructions.

Recovery must establish the exact reviewed/pushed source, installed bundle and
protected input identities. Hardware/access tokens, keys, disk/pool identities and
USB serials stay in root-owned mode-0600 inputs, never the Nix store, Git, plans,
logs or evidence. The three distinct public-key sets use fixed root-owned mode-0600
`/root/.config/home-lab/proxmox-{plan,apply,firewall}-authorized-keys` files.
The controller-built `path:./nix#proxmox-host-bundle` supplied only `bundle` and
`bundle.sha256` under `/var/lib/home-lab/bootstrap/incoming/`.

The official Debian-based bare-metal PVE baseline remains a deterministic manual assertion boundary: exact hostname/static bridge with console attached, existing
ZFS pool identified by independently verified protected GUID, ONLINE health and
exact six-mirror topology, existing dataset/storage preserved, exact official
packages/services/binaries, and contract-bound Tailscale hostname/tag/DNS/routes/
netfilter/SSH preferences. Missing identity is not permission to discover, import,
create, format, upgrade or delete infrastructure. This reference does not qualify
that baseline or authorize rebuilding it.

The access bootstrap's historical scope was exactly `tofu-plan`, `tofu-apply`,
`firewall-apply` and the locked non-SSH `proxmox` audit identity, separated forced
keys, contract SSH/sudo policy, fixed PVE roles/ACLs and privilege-separated tokens
with one-time root-only escrows. Current ownership may differ. The fixed apply
transport restricted both shell and forced command, with no supplementary groups
and sudo only for preparer `prepare` and activator `session`. It accepted no
caller-selected paths, identities, commands or token values. Interrupted creation
rolls back created authority; retained recovery must use its exact journal.

The historical host bootstrap exposed `check`, `install`, `verify`, gated
`recover` and `diagnose-recovery`; even its checks could reconcile pending files.
Its journaled installation included generated helpers plus autonomous-firewall
assets. The final bounded native inspection found the install journal and all
access/convergence/role/ACL/import journals absent. Their active-checkout writers
and dispatchers were therefore retired with `nix/`; **there is no supported current
bootstrap recovery command and the old Git version is not standing authority**.

For historical analysis only, exact source is available at checkpoint `d7a4e208`
and in the preserved host checkout. Previous-generation/install-manifest records,
sealed runtime inputs and old before-images remain untouched. If a future inspection
contradicts the final absence result, stop and review that exact generation at the
physical console; do not check out and execute it merely because it exists.
Autonomous firewall recovery remains independently installed and source-owned.

The historical operations below were distinct exact-before-state transactions,
not generic repair switches.
Legacy access convergence only accepted the proved old `/bin/bash`, unforced key,
sudo group and `NOPASSWD: ALL` apply state after proving every other account/key/
access file/token escrow/input. Role refresh only added contract-required `SDN.Use`
to the exact existing `HomeLabTofuApply` privileges. Qualification ACL refresh only
added the existing disk-inspection role at `/vms/9900` after the VM existed, without
changing roles/tokens/production ACLs/keys/accounts/sudo. Import-storage refresh
only added `import` to existing `local` content `backup,iso,vztmpl`, without creating
or deleting storage, images, volumes or VMs. Retain each journal and before-image.
Protected input refresh and session-key rotation have their own fixed tools/gates.

After approved recovery, verify the fixed plan identity and denial of arbitrary
SSH commands, not merely connectivity. Keep strict host-key checking and tested
independent console/LAN access. OpenTofu retains VM100 and hardware-mapping ownership;
reboot is separate. The retained planner exposes only `plan`, `prepare`, `apply`;
its session recovery invocation gap is described below.

## Retained host sessions

Protocol v4 below describes the pre-transfer Nix host session mechanism. New mutation
through this legacy protocol is not the supported native direction. Retained sessions
may still require its exact status/rollback behavior; source deletion does not
close their journals or retire installed transports.

**Invocation gap:** the retained `proxmox-host` planner exposes only `plan`,
`prepare` and `apply`, not standalone `status` or `rollback` commands. Current
`nixMutationFrozen=true` rejects `prepare` and `apply` after bundle validation but
before saved-plan/sidecar reads and retained-session status/rollback. The older
expired-plan recovery branches below are therefore not reachable through current
`apply`. Do not unfreeze policy or rewrite bindings to reach them.

The host session transitions below are protocol semantics, not a copy-paste
recovery CLI. Host-session `status` can reconcile initialization, action and
release checkpoints under its mutex; unlike firewall `status`, it is not passive.
Inspect the exact retained session/bindings and obtain a separately reviewed
recovery invocation; do not retry `apply` as a passive status query.

Historical apply accepted only `--repo-root`, `--plan-sha` and the identical
`--approve-plan-sha`. The controller derives `.reconcile/plans/<hash>.json`, `.reconcile/plans/<hash>.private.json`, and `.reconcile/controller-apply.lock`. Both plan files must be canonical, single-link, real mode-`0600` files. New mutation requires a clean worktree whose `HEAD` exactly equals `refs/remotes/origin/main`, an unexpired ready steady plan and sidecar, exact explicit approval, and matching Git, bundle, schema, observer, and activator hashes. Expiry forbids new mutation but does not prevent exact status or rollback of an already retained matching host session.
The reviewed host plan remains valid for 1,800 seconds from observation. This bounded window accommodates the mandatory full validation suite and human manifest review while still requiring apply-time host binding, protected-state, and plan-expiry checks. The host-generated private sidecar remains capped at 300 seconds and never extends beyond the reviewed plan.

The private sidecar is produced only by `proxmox-host prepare` through the fixed root `proxmox-private-preparer prepare` entry point after the console-only transport bootstrap. The observer invokes only the exact installed preparer `summary` bytes and receives five access and three hardware checks reduced to status/count/boolean summaries. `prepare` accepts the full exact canonical plan, rechecks installed bindings and protected state, rejects package/watchdog/API/OpenTofu/reboot actions, and generates opaque challenges, sessions, keyed summaries, and the complete sidecar MAC. The controller writes the response once as a no-follow mode-`0600` file and prints only a creation summary.

The private sidecar is produced only by the protected preparation workflow. It contains bounded opaque challenge/session handles and keyed attestations, not identities or stable unkeyed identity hashes. Its action-manifest hash is the canonical digest of the complete ordered `plan.actions` array. A host-session MAC authenticates the complete canonical sidecar signing projection—every binding, timestamp, gate, package-session field, protected summary/MAC, plan, challenge, session, and action-manifest hash—excluding only the host-session MAC field itself. Independent protected-access and protected-hardware MACs are still required. The host validates all MACs with its root-only session key. The generated activator embeds the noncircular reviewed observer, activation/private/plan schema, projection, package-manifest, and flake-lock hashes. Its own hash is checked from the installed helper. The bundle-content hash and exact Git commit cannot be embedded without a circular or build-time Git dependency, so they are trusted only when authenticated by the complete host-keyed sidecar and matched by the clean controller plan. Missing installed protocol-v4 helpers or session key fails `bootstrap-required`; do not hand-create a sidecar as a workaround.

### Locking and activation

The outer reconciler opens the fixed no-follow, user-owned, mode-`0600`, single-link `.reconcile/controller-apply.lock`, takes one nonblocking descriptor `flock`, and overwrites/fsyncs canonical commit/phase/owner metadata while held. It re-executes with an inherited descriptor plus ephemeral token; the reconciler verifies exact descriptor identity, metadata, parent PID, commit and phase. Nested guarded host/firewall apply validates and borrows that ownership (falling back to token + proof that the same file remains contended only when an intermediary closed the descriptor), and never reacquires or unlinks it. Standalone guarded apply acquires the same protocol directly. The file is inert and retained after close; process death or controller reboot releases the mutex without manual deletion. Before begin, apply queries exact host status. No retained session may begin only while fresh; a clean retained `begun` session resumes with the identical begin request; any prior/pending/failed/rollback mutation is rolled back and reported recovered without continuing; released recovery is reported; and released commit is fully re-observed before being reported already applied. The authenticated sidecar `createdAt` is the deterministic begin/ownership timestamp across controller restarts. The host ownership lock, per-transition mutex file, journals, and rollback root remain fixed under `/var/lib/home-lab/reconciliation/`. Every begin/action/status/commit/rollback transition holds a nonblocking descriptor-backed `flock` on the no-follow root-owned mode-`0600` single-link mutex file. Under that mutex, Ansible rejects Nix ownership before creating its persistent lock, while the Nix activator/preparer reject persistent Ansible ownership; no authority performs the persistent check before taking the shared mutex. Process death or reboot releases serialization automatically; `busy` means a live process still holds the descriptor. Transitions are journaled durably before their responses. After both ownership locks exist, the fixed `tofu-plan@proxmox` observer re-observes only saved affected preconditions. A mismatch stops without action derivation or replanning.

Begin carries the complete ordered action array. The activator validates its canonical digest against the private sidecar and validates every action/catalog/sequence/dependency before filesystem setup. It then persists the exact manifest and an authenticated `initializing` journal containing the exact begin request digest and intended ownership record before creating `apply.lock`. Exact begin retry or status under the live flock creates or validates that lock and durably advances to `begun`; a crash before the initialization journal has no ownership, and a later exact begin removes only known no-follow setup files before restarting. Unowned journal-less generations do not poison challenge replay and are safely reclaimed before retention is evaluated. Each later action and commit must exactly match the retained plan manifest. Retained challenge/session journals prevent replay. Each closed action envelope contains one saved action, and the activator independently checks and same-inode captures the immediate precondition. It derives target paths, desired bytes, owners, modes, and native commands internally. Initially dispatchable domains are automatic nonprotected managed files, managed fragments, managed artifacts, and the explicitly guarded `chrony.service`. SSH and Tailscale services are access-critical/watchdog-required and nonautomatic; NFS is data-critical and nonautomatic. Other access-critical/watchdog, account, package, API, audit-deletion, protected, and OpenTofu-owned actions remain rejected.

Each target is captured once in a bounded root-only rollback session using no-follow descriptors. Aggregate raw rollback bytes are capped at 32 MiB, and the canonical base64-expanded manifest is independently capped at 48 MiB before every write; reads use that identical serialized limit, so a successful capture cannot make its manifest unreadable. Regular-file reads require identical pre/post `fstat` fingerprints (device, inode, size, mode, owner, group, link count, mtime, and ctime); symlink reads require identical pre/post no-follow `lstat` fingerprints. The host-private fingerprint is retained and fully revalidated immediately before every replace, unlink, or symlink rename. A newly created begin generation that fails setup is removed only through no-follow descriptors and only when it contains known root-owned regular setup files; preexisting or unknown entries are never removed.

Before capture or mutation, an action persists an exact `action-pending` record containing only its request digest, action ID, sequence, and closed stage. Capture is then durable before mutation. Status under the flock reconciles a lost process: an exact postcondition finalizes completion (or requires one exact retry of an idempotent fixed post-write operation), an unchanged same-fingerprint precondition becomes `action-retryable`, and any other state becomes durable failure eligible for rollback. The controller makes at most one exact retry after a successful status proves that matching retryable intent; it never retries caller-selected work. Completed action history is usable only in a nonrollback `applying` state and can never prove success after rollback begins.

Rollback persists the exact reverse captured-action order as `rollback-in-progress` before restoring anything. After every idempotent restore it durably moves one action ID from remaining to restored, so an exact retry repeats at most the interrupted restore and resumes the saved order. Every action is postcondition-checked; final re-observation happens while locks remain held. Busy or unknown status retains the session and never starts a concurrent rollback. Commit and verified recovery first persist an explicit release-pending journal plus terminal result, then unlink and directory-`fsync` the ownership lock, and only afterward persist `released-committed` or `released-recovered`. Status under the live-only operation mutex reconciles release-pending state by verifying a matching ownership lock (or its already-durable absence), finishing release, and persisting the released terminal state. Strict journal/manifest consistency checks validate exact begin/action/terminal result shapes, completed action order, pending progress, `nextSequence`, capture coverage, and terminal results. A committed or commit-pending state requires every planned action to be captured and completed in exact order; recovered state binds the exact reverse restored set and never proves actions remain applied. The controller proves only released terminal states. Rollback restoration failure retains host ownership and diagnostics; an interruption during ownership release remains release-pending and recoverable rather than being mislabeled as restoration failure.

The reconciler requires `RECONCILE_PROXMOX_NO_CONCURRENT_MUTATION_CONFIRMED=confirm-no-concurrent-proxmox-mutation` for every guarded host apply. It derives watchdog necessity only from the exact saved action array. When any saved action requires the watchdog, it additionally requires `RECONCILE_PROXMOX_CONSOLE_CONFIRMED=physical-console-ready`, `RECONCILE_PROXMOX_LAN_ROLLBACK_CONFIRMED=tested-lan-rollback-ready`, and `RECONCILE_PROXMOX_BACKUPS_CONFIRMED=reviewed-backups-ready`; those flags are not passed for a plan that does not require them.

A reboot-required action reports `rebootRequired=true`; no reboot command exists. Reboot remains a separate reviewed operation.

### Package boundary

Package drift is represented as one complete-installed-map blocker. The private schema reserves an aggregate sealed package-session shape, but missing or null sessions cannot authorize package actions and non-null sessions remain bootstrap-gated. Apply never refreshes APT metadata, runs a solver, or performs a package transaction in this milestone.

## Autonomous firewall recovery

The following retained design describes the one-time cutover and autonomous recovery.
It is not evidence of current installed state or authorization to repeat activation.

The surrounding controller architecture is retired; this retained autonomous firewall/recovery protocol has not been replaced by native adoption. Trusted human operators and local root remain inside the host trust boundary; a malicious root operator can always bypass PVE, systemd, SSH, and helper controls, and this design does not claim otherwise. The firewall transaction remains an isolated fixed PVE API/CLI authority so unrelated host actions cannot leave a newly enabled default-deny firewall active after failure.

The ordinary template writer to `/etc/pve/firewall/cluster.fw` was a historical retirement prerequisite; its old roles are absent from source. Before execution, independently verify that no installed competing writer remains. `/etc/pve` remains PVE API/CLI-owned. All firewall reads and mutations use fixed `pvesh` commands; no helper opens, writes, renames, or unlinks a path below `/etc/pve`.

Historical pre-cutover qualification observed a disabled firewall, default options differing from the contract, and zero cluster rules; this is not current installed state. The desired terminal policy is:

- firewall enabled;
- inbound default `DROP`;
- outbound default `ACCEPT`;
- LAN SSH and PVE UI access;
- NFS from the fixed Docker host address only;
- tailnet SSH and PVE UI access; and
- UDP 41641 from `0.0.0.0/0`, because direct WireGuard packets arrive from peer underlay addresses rather than tailnet source addresses.

The unrestricted IPv4 source applies only to the Tailscale UDP listener. IPv6 underlay support is out of scope and remains a documented residual risk.

### Components

#### Nix bootstrap ownership

The console Nix host bootstrap installs and byte-verifies these fixed assets from `infrastructure/proxmox-firewall/host`:

- `/usr/local/libexec/home-lab/proxmox-firewall-transaction`;
- `home-lab-proxmox-firewall-rollback.service`;
- `home-lab-proxmox-firewall-rollback.timer`;
- a boot-recovery service ordered after `pve-cluster.service`; and
- the fixed Docker host NFS canary helper.

The helper embeds the projected reviewed firewall policy. It accepts no caller-selected host, path, command, rule, endpoint, or policy payload. Installation does not activate the firewall.

Ordinary guarded Nix convergence observes firewall policy but cannot perform the isolated activation transaction.

#### Host helper interface

The host helper exposes only:

```text
authorize
isolate-tofu-apply
restore-tofu-apply
inspect
begin
status
commit
rollback
rollback-if-pending
boot-config-recover
boot-post-recover
```

A distinct `firewall-apply` Unix identity is used only for this transaction. Its login shell itself is `/usr/local/libexec/home-lab/proxmox-firewall-transport`, so ordinary OpenSSH and Tailscale SSH both remain intrinsically closed. The transport accepts only OpenSSH's exact `shell -c` invocation of its own authorized-key forced command and rejects interactive, arbitrary `-c`, or direct Tailscale shell invocations. Its OpenSSH key has the fixed forced command `/usr/local/libexec/home-lab/proxmox-firewall-transport`, and its sudo policy permits only the five remote helper operations `inspect`, `begin`, `status`, `commit`, and `rollback`. It has no unrestricted shell or sudo capability and is not included in Tailscale SSH grants. The controller transport uses only this identity and its fixed SSH key.

Before authorization, the fixed local-console `isolate-tofu-apply` command durably snapshots the exact root-protected authorized-key bytes and login shell, removes the authorized keys, changes the shell to `/usr/sbin/nologin`, terminates the fixed `tofu-apply` login scope and all processes for that UID, and proves no such process remains within a bounded retry cycle. `begin` requires this isolation state. Only the fixed local-console `restore-tofu-apply` command can restore those exact bytes, ownership, mode, and shell, and only after a terminal commit or rollback. Authorized-key restoration writes a fixed temporary file, applies exact ownership and mode, fsyncs it, atomically promotes it, and fsyncs the parent; exact retry repairs any interrupted prior final file. This keeps retained Ansible authority unavailable during the transaction and makes crash recovery explicit.

`authorize` is a separate local-console/root-only preauthorization command. All three local commands require an actual controlling Linux virtual console matching `/dev/ttyN`; they are absent from the forced transport and narrow sudo policy. `authorize` accepts only a canonical ready plan, the same explicit plan SHA, and the exact typed gate `AUTHORIZE EXACT REVIEWED PROXMOX FIREWALL PLAN`; it records one root-only, no-follow, single-use authorization bound to that plan and expiry. `begin` atomically consumes that authorization and rejects replay or substitution. A consumed authorization without a journal can only be replaced by repeating the same local typed authorization ceremony, providing crash-safe recovery without granting the remote apply identity authorization authority. An expired unconsumed authorization may likewise be replaced from the console. The fixed console restore gate may cancel an unused authorization with no journal and atomically restore access, so an abandoned or expired plan cannot strand retained Ansible authority. `boot-config-recover` and `boot-post-recover` are fixed systemd-only phase commands; the ordinary timer never infers boot state from backend activity.

`inspect` and `status` accept no arguments. `inspect` returns the exact normalized non-secret PVE state, the current PVE digest, a fresh challenge, a 300-second expiry, and a host-keyed attestation over those fields plus the installed helper and policy identities. `begin`, `commit`, and `rollback` accept only bounded schema-closed canonical requests on standard input. `begin` carries the complete reviewed public plan and the exact `inspect` attestation; it cannot carry policy, paths, hosts, endpoints, or commands outside that plan schema. `commit` and `rollback` carry only the helper-generated session identifier, plan SHA, and the closed expected result shape. Unknown commands, arguments, environment overrides, oversized input, stale sessions, and malformed requests fail before mutation.

The helper uses fixed runtime locations under `/var/lib/home-lab/firewall-transaction/`, the shared mutex `/var/lib/home-lab/reconciliation/operation.lock`, and rejects any retained legacy ownership lock `/var/lib/iac-ansible-production.lock`. It rejects an active or retained Nix ownership lock before beginning. Runtime files are root-owned, no-follow, single-link, mode `0600` or `0700` as appropriate, atomically replaced, and directory-fsynced.

#### Controller interface

A separate fixed controller command exposes only:

```text
plan
apply --plan-sha SHA256 --approve-plan-sha SAME_SHA256
status
rollback --session-id EXACT_SESSION
```

It accepts no host, path, endpoint, identity, policy, or arbitrary command parameters. Fixed protected controller configuration supplies distinct LAN and tailnet endpoints and identities. During planning it is copied once into a no-follow, single-link, mode-`0600` private sidecar and assigned a random configuration identifier. A fixed controller key authenticates the complete sidecar, including the plan SHA, host inspection attestation, expiry, and protected canary values. The public plan records only the random identifier and bounded count/boolean summaries; it contains no values or stable protected hashes. Apply validates the sidecar metadata and keyed MAC and uses only that immutable snapshot for baseline and post-activation canaries. It never reloads mutable protected configuration.

The controller acquires the existing controller-wide apply lock. A canonical mode-`0600` plan binds:

- exact clean Git commit and tree equal to `origin/main`;
- host-helper, systemd-unit, controller, schema, and policy bytes;
- the exact normalized firewall before-state, PVE digest, challenge, and host-keyed inspection attestation;
- the exact ordered mutation catalogue;
- the fixed canary catalogue and random private-sidecar configuration identifier;
- a maximum 300-second freshness window; and
- the plan SHA-256.

Apply consumes only that reviewed plan and never replans.

### Host transaction

#### 1. Prepared

`begin` first validates the plan SHA, freshness, installed bindings, exact policy catalogue, and host-keyed `inspect` attestation. While holding the shared mutex, it re-reads the complete live option and rule state and requires byte-for-byte canonical equality with the plan's exact normalized before-state and PVE digest. The reviewed one-time before-state is firewall disabled and zero cluster rules, but those broad facts alone are never sufficient. A stale or changed digest/state fails before mutation.

The helper uses the PVE digest as compare-and-swap input wherever the API accepts it. During sequential staging it re-reads the new digest and exact expected intermediate state before every next fixed operation; an external API/UI change causes the next operation or observation to fail into rollback. It then captures a bounded rollback snapshot and persists the session and deadline before mutation.

The journal records only non-secret protocol state and the exact raw PVE values required for host-local rollback. Rollback bytes never leave the host. The helper creates the persistent ownership lock only while holding the shared mutex.

#### 2. Watchdog-bound

The enabled calendar timer is a continuously active watchdog rather than a per-transaction timer. Before creating the initial `prepared` journal, the helper proves the timer is active and reads its stable activation token. The first atomic journal write contains that non-null token, the snapshot, session, and deadline. The transaction never restarts or stops the watchdog, eliminating every pre-arm journal window. Failure to prove the watchdog active and tokenized aborts before journal or firewall mutation.

The enabled persistent calendar timer invokes only `rollback-if-pending`. Early calendar delivery returns temporary failure until the exact journal deadline, while `Persistent=true` queues missed delivery across reboot. Terminal and boot-owned journals are reconciled before comparing the pre-reboot monotonic token, so a queued delivery cannot retry forever solely because the monotonic clock changed. The helper binds delivery to the timer activation token recorded in the current journal. Its fixed service retries every two seconds with no start-limit when the shared mutex is busy; a busy-lock result is never treated as successful timer delivery. Retries continue until the service acquires the mutex and rolls back or reconciles a durable commit/rollback decision. Controller termination, SSH loss, or host-helper interruption leaves the continuous watchdog active. Host staging has a fixed 60-second budget. Post-activation canaries run concurrently, each with exactly three five-second connection attempts and two one-second gaps, under a 30-second aggregate controller deadline. `commit` refuses to start unless at least 120 seconds remain before the host deadline, preserving a fixed rollback margin.

#### 3. Staged

While the firewall is disabled, the helper uses fixed `pvesh` operations to:

1. keep or set enable to disabled;
2. set inbound `DROP` and outbound `ACCEPT`;
3. remove only the observed pre-cutover rule set captured in the snapshot;
4. create exactly the six reviewed rules in fixed order; and
5. re-read and strictly normalize all options and rules.

Staging fails on unknown, duplicate, disabled, additional, or malformed rules. Every intermediate state and returned digest must match the next state derived by the fixed catalogue. The helper never enables a partially verified policy.

#### 4. Activated

Enable is changed last. The helper then requires all of the following:

- API options exactly match enable=true, inbound `DROP`, and outbound `ACCEPT`;
- the normalized API rule set equals exactly the six reviewed rules, independent of API ordering and excluding only explicitly documented server-generated fields;
- both `pve-firewall.service` and `proxmox-firewall.service` are active; and
- `pve-firewall status` is exactly `Status: enabled/running`.

The journal advances to `activated` only after these postconditions pass. Any synchronous failure after the initial watchdog binding attempts immediate rollback and leaves the continuous watchdog as a backstop.

#### 5. Controller canaries

Before `begin`, the controller uses the immutable private sidecar to record all pre-activation baselines. A direct Tailscale path is mandatory: a DERP-only, unavailable, or ambiguous baseline blocks the plan and cannot be approved. After activation, the controller opens entirely new connections; existing sessions cannot satisfy a canary. TLS probes use an explicit no-proxy opener, so inherited `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` values cannot alter sidecar-bound LAN or tailnet routing.

Required post-activation canaries are:

1. authenticated SSH through the fixed LAN endpoint;
2. a TLS-validated PVE API request through the fixed LAN endpoint;
3. authenticated SSH through the distinct fixed tailnet endpoint;
4. a TLS-validated PVE API request through the fixed tailnet endpoint;
5. a Docker-host fixed fresh TCP connection to the PVE NFS port followed by an NFSv4 read-only mount to a fixed empty runtime mountpoint, read/stat, and clean unmount; and
6. a Tailscale direct-path probe that must remain direct; DERP fallback, ambiguity, or timeout fails the canary and prevents commit.

All six canaries launch concurrently under the fixed attempt and aggregate budgets above. The canary result contains only booleans, bounded timing/status categories, the random configuration identifier, the session identifier, and the reviewed plan SHA. It contains no endpoints, addresses, identity values, paths from protected configuration, or stable hashes of protected data.

Any missing, malformed, expired, or failed canary causes the controller to request rollback. If that request cannot be delivered, the continuous host watchdog remains active.

#### 6. Committed

`commit` has a fixed 30-second aggregate execution deadline. Every `pvesh`, `systemctl`, and backend-status subprocess has a five-second timeout and at most two attempts separated by one second; exhausting either bound aborts without recording a commit decision and releases the shared mutex so the retrying timer can roll back. `commit` takes the shared mutex, rejects an expired or non-`activated` session, validates the exact session-, plan-, and private-configuration-bound canary result, checks the 120-second margin, and re-observes the complete API/backend state within those bounds. It then durably advances through `commit-release-pending` and `commit-lock-released` before the terminal `committed` state. Once `commit-release-pending` is durable, exact retries and watchdog delivery complete only that release decision. Ownership-lock removal is idempotent and reconciled against the journal and actual filesystem state; the watchdog remains active.

A crash or exact retry in any release state resumes release; it never rolls back a durable commit decision and never leaves a terminal journal with an unexplained retained timer or ownership lock. `rollback-if-pending` and boot recovery complete commit release when they observe `commit-release-pending` or either later release state. Read-only `status` never mutates locks, timers, journals, or API state and therefore safely coexists with the enclosing fixed transaction status checks. A delayed commit cannot commit a later session because every request is bound to the helper-generated session identifier and plan SHA.

#### 7. Rollback

Rollback has a fixed 60-second aggregate attempt deadline. Every `pvesh`, `systemctl`, and backend-status subprocess uses the same five-second timeout, at most two attempts, and one-second gap as commit. It takes the shared mutex and transitions through durable per-operation checkpoints, `rollback-started`, `rollback-verified`, `rollback-release-pending`, and `rollback-lock-released` to terminal `rolled-back`:

1. disable the firewall first;
2. remove only the candidate rules;
3. restore snapshot rules and non-enable options through fixed `pvesh` calls;
4. restore the prior enable value last; and
5. re-read and require exact snapshot state and expected backend status.

Before and after every fixed restore operation, rollback records the exact expected step and observed digest. On a timeout, exhausted subprocess retry, or incomplete postcondition, it records `rollback-retry-pending`, releases the shared mutex within the aggregate deadline, and exits with a temporary-failure result. The timer service retries two seconds later and resumes from the durable checkpoint; no failed attempt claims restoration. Boot recovery uses the same bounded operation attempts inside its readiness/retry cycle, so a hung PVE command cannot retain the mutex indefinitely.

After exact restoration, rollback removes the persistent ownership lock and durably records each release step without stopping the watchdog. Exact retries resume from the recorded state. Rollback never recursively deletes PVE state. If exact restoration or release cannot be verified, the helper retains its journal and any still-required ownership lock, reports a console-required failure, and does not claim success.

`rollback-if-pending` exits without policy mutation only after reconciling all release steps for a verified commit or rollback decision. Commit/timer races serialize on the shared mutex; whichever valid decision obtains the mutex before expiry is durable and the other path reconciles that decision.

Boot recovery uses two fixed oneshot units. The configuration-recovery unit is `Required` and ordered after `pve-cluster.service` and local filesystems but before both `pve-firewall.service` and `proxmox-firewall.service`; drop-ins on both backends require this unit. It runs with no start timeout. At entry it durably records `boot-recovery-active` while leaving the persistent watchdog active; service ordering keeps queued delivery behind boot verification. It checks pmxcfs and fixed `pvesh` readiness 30 times at two-second intervals, then waits five seconds and repeats that closed cycle indefinitely while the journal requires recovery. It does not exit failed, so the already queued backend start jobs remain blocked rather than entering a failed-dependency state that would require manual requeue.

On a valid nonterminal pre-commit journal, configuration recovery restores and API-verifies the exact snapshot while both backends are stopped, then records `boot-config-restored` and exits successfully. For a durable commit decision it API-verifies the candidate and records `boot-commit-config-verified`. Only these configuration-verified states allow the backend units to start. API/config verification at this phase deliberately does not claim a backend postcondition.

A second post-recovery verifier is ordered after and requires the configuration-recovery unit and both firewall backends. It has the same bounded five-second/two-attempt subprocess policy and `Restart=on-failure`, `RestartSec=5`, with no start limit. It requires the exact API snapshot or candidate state plus the corresponding service and `pve-firewall status` postconditions. Only then does it remove the ownership lock and durably record terminal `rolled-back` or `committed`; the watchdog remains continuously active. On verification failure, its fixed failure handler stops both firewall backends before retrying, while the ownership lock and boot-verification journal remain.

The rollback timer service is explicitly ordered after the post-recovery verifier. A persistent missed firing therefore remains queued until both boot phases finish; it then observes the terminal decision and exits without policy mutation. The distinct `boot-config-recover` and `boot-post-recover` commands own boot phases. `rollback-if-pending` also treats `boot-recovery-active`, `boot-config-restored`, and `boot-commit-config-verified` as boot-owned states and returns temporary failure rather than entering ordinary rollback. A boot with no journal makes both recovery units and any missed timer firing deterministic no-ops. Unknown or malformed runtime remnants keep both backends blocked for console inspection.

### Testing required before approval

Repository and subprocess tests must cover:

- closed CLI and input schemas;
- strict PVE option/rule normalization, including duplicate, disabled, missing, and extra rule rejection;
- backend service and CLI status validation;
- proof that no helper opens or mutates `/etc/pve`;
- fixed `pvesh` command catalogues and mutation order;
- exact plan/inspection-attestation/digest binding at begin and compare-and-swap failure on external drift;
- immutable protected-sidecar metadata/MAC validation and rejection of configuration substitution;
- continuous watchdog activity and first-journal token binding before mutation, exact timeout budgets/commit margin, and enable-last behavior;
- crash injection before and after every journal boundary, every rule operation, enable, commit, and rollback;
- exact rollback order and snapshot verification;
- timer/commit busy-mutex retries, bounded commit and rollback attempts, rollback checkpoint resume after each subprocess timeout, every release boundary, idempotent release reconciliation, and delayed stale commits;
- shared legacy/Nix ownership-lock collisions;
- symlink, hard-link, owner, group, mode, and oversized-file attacks;
- controller plan freshness, exact-hash approval, and no-replan behavior;
- a new connection for every canary;
- rollback on each individual canary failure;
- Docker host NFS mount cleanup on success, failure, timeout, and interruption;
- mandatory direct-path baseline and rejection of DERP before and after activation;
- boot configuration-recovery/post-verification/timer ordering, persistent missed firings, boot-owned state rejection, indefinite readiness cycles, queued backend starts, failure-stop handling, postcondition retry, and release-state fixtures; and
- scans proving protected values and stable protected hashes do not enter plans, logs, fixtures, or shareable evidence.

The host implementation lives under `infrastructure/proxmox-firewall/host`; its historical Nix bootstrap installer is retired, while the installed autonomous runtime remains active. The controller is `scripts/controller/proxmox-firewall.py`. The controller reads only the fixed root-owned controller key and canonical protected configuration under `~/.config/home-lab/controller/`; its public plan never contains those values. Its closed commands are `plan`, exact-hash `apply`, `status`, and exact-session `rollback`. Repository changes alone do not authorize production execution.

Independent review must pass after implementation and test evidence. Only then may an operator separately approve helper installation and, later, live activation with a physical console and tested LAN rollback session open.
