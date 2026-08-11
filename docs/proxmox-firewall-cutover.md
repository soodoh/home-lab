# Proxmox firewall cutover design

## Status and authority

This document defines the required transaction for the one-time Proxmox firewall cutover. It is a reviewed design only. It does not authorize installation or live activation.

Ansible remains the Proxmox production authority until the wider Nix cutover. Trusted human operators and local root remain inside the host trust boundary; a malicious root operator can always bypass PVE, systemd, SSH, and helper controls, and this design does not claim otherwise. The firewall transaction is therefore Ansible-owned, but it is isolated from `proxmox-site.yml` so unrelated later tasks cannot leave a newly enabled default-deny firewall active after a failed play.

The existing ordinary template write to `/etc/pve/firewall/cluster.fw` must be retired before execution. `/etc/pve` remains PVE API/CLI-owned. All firewall reads and mutations use fixed `pvesh` commands; no helper opens, writes, renames, or unlinks a path below `/etc/pve`.

Current live qualification has established a disabled firewall, default options that differ from the contract, and zero cluster rules. The desired terminal policy is:

- firewall enabled;
- inbound default `DROP`;
- outbound default `ACCEPT`;
- LAN SSH and PVE UI access;
- NFS from the fixed Arch host address only;
- tailnet SSH and PVE UI access; and
- UDP 41641 from `0.0.0.0/0`, because direct WireGuard packets arrive from peer underlay addresses rather than tailnet source addresses.

The unrestricted IPv4 source applies only to the Tailscale UDP listener. IPv6 underlay support is out of scope and remains a documented residual risk.

## Components

### Ansible ownership

Ansible installs and byte-verifies these fixed assets:

- `/usr/local/libexec/home-lab/proxmox-firewall-transaction`;
- `home-lab-proxmox-firewall-rollback.service`;
- `home-lab-proxmox-firewall-rollback.timer`;
- a boot-recovery service ordered after `pve-cluster.service`; and
- the fixed Arch NFS canary helper.

The helper embeds the projected reviewed firewall policy. It accepts no caller-selected host, path, command, rule, endpoint, or policy payload. Installation does not activate the firewall.

The existing `proxmox_firewall_apply_confirmed` template path is removed. Steady Ansible convergence audits the terminal policy but cannot perform the one-time activation transaction.

### Host helper interface

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

The helper uses fixed runtime locations under `/var/lib/home-lab/firewall-transaction/`, the shared mutex `/var/lib/home-lab/reconciliation/operation.lock`, and the persistent Ansible ownership lock `/var/lib/iac-ansible-production.lock`. It rejects an active or retained Nix ownership lock before beginning. Runtime files are root-owned, no-follow, single-link, mode `0600` or `0700` as appropriate, atomically replaced, and directory-fsynced.

### Controller interface

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

## Host transaction

### 1. Prepared

`begin` first validates the plan SHA, freshness, installed bindings, exact policy catalogue, and host-keyed `inspect` attestation. While holding the shared mutex, it re-reads the complete live option and rule state and requires byte-for-byte canonical equality with the plan's exact normalized before-state and PVE digest. The reviewed one-time before-state is firewall disabled and zero cluster rules, but those broad facts alone are never sufficient. A stale or changed digest/state fails before mutation.

The helper uses the PVE digest as compare-and-swap input wherever the API accepts it. During sequential staging it re-reads the new digest and exact expected intermediate state before every next fixed operation; an external API/UI change causes the next operation or observation to fail into rollback. It then captures a bounded rollback snapshot and persists the session and deadline before mutation.

The journal records only non-secret protocol state and the exact raw PVE values required for host-local rollback. Rollback bytes never leave the host. The helper creates the persistent ownership lock only while holding the shared mutex.

### 2. Watchdog-bound

The enabled calendar timer is a continuously active watchdog rather than a per-transaction timer. Before creating the initial `prepared` journal, the helper proves the timer is active and reads its stable activation token. The first atomic journal write contains that non-null token, the snapshot, session, and deadline. The transaction never restarts or stops the watchdog, eliminating every pre-arm journal window. Failure to prove the watchdog active and tokenized aborts before journal or firewall mutation.

The enabled persistent calendar timer invokes only `rollback-if-pending`. Early calendar delivery returns temporary failure until the exact journal deadline, while `Persistent=true` queues missed delivery across reboot. Terminal and boot-owned journals are reconciled before comparing the pre-reboot monotonic token, so a queued delivery cannot retry forever solely because the monotonic clock changed. The helper binds delivery to the timer activation token recorded in the current journal. Its fixed service retries every two seconds with no start-limit when the shared mutex is busy; a busy-lock result is never treated as successful timer delivery. Retries continue until the service acquires the mutex and rolls back or reconciles a durable commit/rollback decision. Controller termination, SSH loss, or host-helper interruption leaves the continuous watchdog active. Host staging has a fixed 60-second budget. Post-activation canaries run concurrently, each with exactly three five-second connection attempts and two one-second gaps, under a 30-second aggregate controller deadline. `commit` refuses to start unless at least 120 seconds remain before the host deadline, preserving a fixed rollback margin.

### 3. Staged

While the firewall is disabled, the helper uses fixed `pvesh` operations to:

1. keep or set enable to disabled;
2. set inbound `DROP` and outbound `ACCEPT`;
3. remove only the observed pre-cutover rule set captured in the snapshot;
4. create exactly the six reviewed rules in fixed order; and
5. re-read and strictly normalize all options and rules.

Staging fails on unknown, duplicate, disabled, additional, or malformed rules. Every intermediate state and returned digest must match the next state derived by the fixed catalogue. The helper never enables a partially verified policy.

### 4. Activated

Enable is changed last. The helper then requires all of the following:

- API options exactly match enable=true, inbound `DROP`, and outbound `ACCEPT`;
- the normalized API rule set equals exactly the six reviewed rules, independent of API ordering and excluding only explicitly documented server-generated fields;
- both `pve-firewall.service` and `proxmox-firewall.service` are active; and
- `pve-firewall status` is exactly `Status: enabled/running`.

The journal advances to `activated` only after these postconditions pass. Any synchronous failure after the initial watchdog binding attempts immediate rollback and leaves the continuous watchdog as a backstop.

### 5. Controller canaries

Before `begin`, the controller uses the immutable private sidecar to record all pre-activation baselines. A direct Tailscale path is mandatory: a DERP-only, unavailable, or ambiguous baseline blocks the plan and cannot be approved. After activation, the controller opens entirely new connections; existing sessions cannot satisfy a canary. TLS probes use an explicit no-proxy opener, so inherited `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` values cannot alter sidecar-bound LAN or tailnet routing.

Required post-activation canaries are:

1. authenticated SSH through the fixed LAN endpoint;
2. a TLS-validated PVE API request through the fixed LAN endpoint;
3. authenticated SSH through the distinct fixed tailnet endpoint;
4. a TLS-validated PVE API request through the fixed tailnet endpoint;
5. an Arch-host fixed fresh TCP connection to the PVE NFS port followed by an NFSv4 read-only mount to a fixed empty runtime mountpoint, read/stat, and clean unmount; and
6. a Tailscale direct-path probe that must remain direct; DERP fallback, ambiguity, or timeout fails the canary and prevents commit.

All six canaries launch concurrently under the fixed attempt and aggregate budgets above. The canary result contains only booleans, bounded timing/status categories, the random configuration identifier, the session identifier, and the reviewed plan SHA. It contains no endpoints, addresses, identity values, paths from protected configuration, or stable hashes of protected data.

Any missing, malformed, expired, or failed canary causes the controller to request rollback. If that request cannot be delivered, the continuous host watchdog remains active.

### 6. Committed

`commit` has a fixed 30-second aggregate execution deadline. Every `pvesh`, `systemctl`, and backend-status subprocess has a five-second timeout and at most two attempts separated by one second; exhausting either bound aborts without recording a commit decision and releases the shared mutex so the retrying timer can roll back. `commit` takes the shared mutex, rejects an expired or non-`activated` session, validates the exact session-, plan-, and private-configuration-bound canary result, checks the 120-second margin, and re-observes the complete API/backend state within those bounds. It then durably advances through `commit-release-pending` and `commit-lock-released` before the terminal `committed` state. Once `commit-release-pending` is durable, exact retries and watchdog delivery complete only that release decision. Ownership-lock removal is idempotent and reconciled against the journal and actual filesystem state; the watchdog remains active.

A crash or exact retry in any release state resumes release; it never rolls back a durable commit decision and never leaves a terminal journal with an unexplained retained timer or ownership lock. `rollback-if-pending` and boot recovery complete commit release when they observe `commit-release-pending` or either later release state. Read-only `status` never mutates locks, timers, journals, or API state and therefore safely coexists with the enclosing steady Ansible lock. A delayed commit cannot commit a later session because every request is bound to the helper-generated session identifier and plan SHA.

### 7. Rollback

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

## Testing required before approval

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
- shared Ansible/Nix ownership-lock collisions;
- symlink, hard-link, owner, group, mode, and oversized-file attacks;
- controller plan freshness, exact-hash approval, and no-replan behavior;
- a new connection for every canary;
- rollback on each individual canary failure;
- Arch NFS mount cleanup on success, failure, timeout, and interruption;
- mandatory direct-path baseline and rejection of DERP before and after activation;
- boot configuration-recovery/post-verification/timer ordering, persistent missed firings, boot-owned state rejection, indefinite readiness cycles, queued backend starts, failure-stop handling, postcondition retry, and release-state fixtures; and
- scans proving protected values and stable protected hashes do not enter plans, logs, fixtures, or shareable evidence.

The offline implementation now lives in the `proxmox_firewall` and `firewall_nfs_canary` Ansible roles plus `scripts/controller/proxmox-firewall.py`. The controller reads only the fixed root-owned controller key and canonical protected configuration under `~/.config/home-lab/controller/`; its public plan never contains those values. Its closed commands are `plan`, exact-hash `apply`, `status`, and exact-session `rollback`. This repository state does not authorize running any of them against production.

Independent review must pass after implementation and test evidence. Only then may an operator separately approve helper installation and, later, live activation with a physical console and tested LAN rollback session open.

## Separate APT blocker

The other current shadow blocker is a single exact zero-byte stale APT source file. Its removal is independent of firewall activation. A reviewed closed allowlist entry may remove only that file after rechecking that it is a root-owned regular zero-byte file. Firewall approval does not authorize this cleanup, and APT cleanup approval does not authorize firewall activation.
