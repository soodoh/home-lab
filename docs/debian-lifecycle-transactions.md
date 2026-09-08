# Guarded Debian lifecycle transactions

Gate 7 recovery work uses `scripts/controller/debian-lifecycle-transactions.py`. It does not extend ordinary `site.yml` convergence. Each operation has its own protected canonical request, fresh protected canonical observation, operation-specific protected authority receipts, immutable 30-minute saved plan, exact typed confirmation, controller lock, shared host apply lock, and fixed root-side executor. Hostname, machine ID, Ed25519 host key, lifecycle marker, and direct contract values are rechecked before mutation.

## Boundaries

- `qualification-canary` is the only inert-profile transaction. It is routed only through the dedicated VM9900 inventory/host named by the contract, requires an explicit empty active-unit observation, independently proves every contract-defined production unit is inactive or absent on-host, and durably publishes one plan-digest canary receipt below the contract-fixed private root. It cannot select production inventory, storage, identity, Tailscale, Compose, state-disk, or SSH operations.
- `storage-activation` accepts only surviving filesystems named by stable `/dev/disk/by-id` identity, serial, byte size, filesystem type and UUID and bound to a canonical OpenTofu attachment receipt. It rejects aliases, holders, mounts, signatures that differ, symlinked mount targets, ownership/mode drift and insufficient free capacity. Only then may it durably create `/etc/home-lab/allow-storage-activation` with the plan digest and start the exact mount units; failed starts are stopped and verified.
- `identity-recovery` accepts a protected controller identity and a protected canonical recovery receipt whose bytes are bound into the plan. The host independently derives its public recipient with `age-keygen -y`; the contract-selected target must be absent and is opened with `O_EXCL|O_NOFOLLOW`, root ownership and mode `0600`, then file- and directory-fsynced. No identity is generated silently.
- `tailscale-enrollment` accepts a protected, fresh, preauthorized one-use key. The key is held only in root-only temporary files, never in the plan or normal output. The executor checks backend state, node ID, contract hostname/tag, address and DNS suffix. Caught enrollment or post-proof exceptions invoke `tailscale down` and a backend-status check; cleanup completion under abrupt death is not established.
- `production-activation` requires exact contract-derived mount sources/filesystems/UUIDs/options, the recovered recipient, the enrolled node, a digest-bound root environment, contract-selected Compose command/artifact/image override, a schema-validated Restic activation receipt and direct systemd dependencies. Every unit must initially be inactive. The executor records attempted starts in an in-memory list before invocation. Its exception handler attempts reverse-order stops and inactive-state checks, and attempts restoration of the saved recovery-marker bytes if its in-memory `marker_changed` flag is set. This is caught-exception cleanup, not a crash-safe transaction or a guarantee that every prior state and downstream effect is restored.
- `state-disk-initialization` accepts only a blank, unmounted, holder-free replacement disk bound to a protected canonical OpenTofu receipt and the contract serial, size, filesystem and UUID. `force` must be false. The confirmation contains both the serial and plan digest. An fsynced `started` journal is published before `mkfs.ext4`; any existing plan journal prohibits automatic retry, and success atomically records `committed`.
- `ssh-tightening` is a post-proof transaction. It requires the three protected canonical receipts from the existing `debian-access-cleanup.py` sequence and independently verifies the contract Tailscale tag, absent conventional key files and effective `PubkeyAuthentication no` / `PermitRootLogin no`. Key removal is deliberately not reimplemented.

On a caught controller interruption or timeout, `run_controlled()` attempts to signal the local Ansible process group and wait for its direct child. That wait does not prove that the entire process group, remote executor, queued systemd jobs or downstream effects have terminated. Host rollback checks depend on the relevant exception handlers executing and completing; `SIGKILL`, host loss and power loss do not provide that guarantee. In-memory attempted-unit/marker flags and successful fsync calls do not establish deployed crash-safe completion or recovery. Unresolved outcomes require independently observed state and separately authorized recovery, not automatic retry or marker-based adoption.

The transaction playbook places release of `/var/lib/iac-ansible-production.lock` after the exact successful host receipt check; retained ownership is not itself proof of rollback. `ansible/playbooks/recover-debian-lifecycle-apply-lock.yml` is restricted to inert `qualification-canary` recovery, not general production rollback. It may adopt and release only a fresh, revision-bound recovery plan whose exact controller, operation, owner-file hash, metadata, absent canary receipt, and absent host lock still match; it requires a separate owner-hash confirmation. Persistent package/reboot mutex files are tested with descriptor `flock` rather than treated as active by existence. Durable reconciliation/firewall ownership locks remain existence blockers.

The 2026-09-05 repository hardening includes token creation, fsync, daemon reload, and mount starts in one storage rollback scope. Revocation checks the still-open token inode and completed content, preserves preexisting tokens and refuses replacements observed before deletion, and continues stopping attempted mounts even if token cleanup fails. This assumes cooperating writers serialized by the host lock and a trusted root-owned parent directory: the inode check followed by pathname unlink is not an atomic inode CAS against a racing privileged writer. Storage and production preflight/rollback require explicit `LoadState=loaded`, `ActiveState=inactive`, `SubState=dead`; command failure is not proof of inactivity. These new executor bytes are not installed by editing the repository and require a fresh capability transaction and disposable proof.

### Production dependency admission

Production activation now binds `debian.transaction.production_systemd_dependencies` independently of the request and observation. Production requests and observations use `home-lab-debian-lifecycle-request-v2` and `home-lab-debian-lifecycle-observation-v2`; other operations retain v1. Each `systemd_dependencies` entry is an object with separate `Requires` and `After` arrays. The request must equal the contract minimum exactly. The observation must include each minimum edge under the correct property; additional systemd default dependencies are allowed, but unreviewed edges between the four production units are refused (including cycles or timer workload pull-in).

The contract preserves the existing Docker/Compose requirements and ordering on all three protected mounts and `home-lab-production-guard.service`, plus Compose's requirement and ordering on Docker. These edges were confirmed in supervisor-supplied read-only systemd output; that observation is not an activation rehearsal. The current timer templates have no Compose ordering. New additive drop-ins provide only `After=home-lab-compose.service` for both timers: they deliberately do **not** require Compose or backup targets, so starting a timer cannot pull in workloads or run a backup immediately. The executor starts and verifies Docker, then Compose, then the timers in contract order. Existing Restic target/worker chains and the production guard are retained.

The capability installs canonical root-owned mode-`0600` policy at `/etc/home-lab/debian-production-dependencies.json` and additive `50-home-lab-production-dependencies.conf` drop-ins. Policy bytes bind the contract hash, ordered unit set and graph; the saved plan binds the policy hash. The host rejects missing/stale policy or weakened requests independently, then reads named `Requires` and `After` properties for every production unit before any production-state mutation. Quoted escaped systemd mount names are decoded without losing their literal unit-name escapes. No property union or unlabelled `--value` output is accepted.

Legacy v1 production union evidence is **not** reinterpreted or upgraded. It remains historical and cannot authorize a new activation; regenerate independent v2 observations, requests and saved plans after a separately approved capability installation. Editing the repository installs nothing. The new capability also reloads changed systemd declarations, but never enables, starts or restarts units. Full durable ownership of the preexisting Docker/Compose/guard unit bodies, installation proof and disposable interruption/cold-boot qualification remain separate gates. Production activation is **not live-qualified** by these synthetic tests; see [the completion review](host-lifecycle-completion-review-2026-09-05.md) for the wider recovery gates.

Authority receipts are not standalone assertions. `scripts/controller/debian-lifecycle-authority-receipts.py` embeds its own source hash and produces OpenTofu receipts only after inspecting the actual saved binary with `tofu show -json`, proving each requested disk is absent before and present after as the sole VM delta, and matching the complete relevant planned VM result to protected current-state bytes. Age receipts require `age-keygen -y` and hash the complete decrypted plaintext from a full-read protected bundle. Fixed `restic-snapshot` and `restic-restore` commands verify repository/config/snapshot identity, run `restic check --read-data`, restore with `--verify` into an empty private root, and hash the restored tree before producing mutually bound manifests. `debian-access-cleanup.py` durably publishes source-hash-bound canonical per-stage operation receipts.

### Ordinary Compose role invocation binding

The production-gated `compose` role in `site.yml` asserts its resolved command,
current-directory Compose artifact, image override and root environment paths
against `debian.transaction.compose_command`, `compose_artifact_path`,
`compose_image_lock_path` and `root_environment_path` before the role's first
command. Missing, malformed or mismatched bindings refuse adoption; no path
normalization or equivalent-command fallback is accepted. Existing command order,
`HOME=/home/docker`, model counts, legacy volume checks and check-mode dry-run
create behavior are unchanged. Inert and recovery profiles still exclude the role.

This checks caller aliases against the loaded contract, not arbitrary redefinition
of that authority or deliberate task skipping. It does not precede every command
in `site.yml`, replace an installed startup guard, install units or authorize
activation. The registered `test-debian-lifecycle-profiles.js` test uses real
Ansible evaluation of the source role assertions and site Compose condition with
explicitly mocked command endpoints, including independent binding negatives and
guard-removal/order mutants. It is not a full site run or installed/startup proof;
the wider installation and recovery qualification gates above remain separate.

### Inactive Debian base provisioning (source only)

The `base` tag now has a bounded inert/recovery path. Before package facts or
baseline writes it requires the contract's Debian release, architecture and
kernel, image-provided Python APT bindings, and fully installed `python3`,
`python3-apt`, `openssh-server` and `cloud-init`. Missing prerequisites are a
refusal, not permission to bootstrap them. These observations do **not** prove
that the guest booted the pinned image digest or qualify first contact.

`debian.baseline` declares the package and service subset. Missing baseline
packages still require the existing separately authorized exact `name=version`
lock; there is no cache refresh, upgrade of present requested packages or implicit
Ansible dependency installation. Inactive installs require integer `policy_rc_d:
101`. This suppresses cooperating maintainer-script service starts only: package
dependencies, other maintainer effects and interruption-safe restoration of any
preexisting policy-rc.d remain native installation qualification gaps.

Hostname is bound to the existing qualification inventory/hostname pair, or the
existing VM hostname for other inert/recovery inventories; qualification cannot
inherit the production hostname. QGA is explicitly started, never enabled or
restarted (its Debian unit is static). Locale remains `C.UTF-8` and timezone
remains contract-derived. Production base behavior and all production-only role
conditions are unchanged. No access/account, enrollment, protected storage,
Compose/guard unit body, cloud-init payload or transaction gate is replaced.

The source regression in `test-debian-lifecycle-profiles.js` evaluates real
Ansible task imports, conditions, assertions and arguments with controller-only
synthetic endpoint plugins and no guest module execution. It covers baseline
subschema negatives, first/second-pass modeled idempotence, check-mode state
preservation, prerequisite/binding/lock refusal and production argument parity.
It is neither full contract validation nor installed package/service, first-boot,
cold-reboot or live acceptance. Only explicit modeled service calls are checked;
mocked APT cannot establish the absence of native package side effects.

This is the first durable provisioning slice of the full migration, not a reduced
completion boundary. Tool-only SOPS/age, Tailscale and Restic seams, durable mount
and workload unit ownership, safe recovery routing and production seed
minimization remain implementation work. Exact image-to-boot trust, native inert
convergence/no-op rerun and full synthetic recovery/interruption/cold-boot proof
remain validation work. Every installed operation/package/reboot requires fresh
separate approval; VM9900's failed qualification is not retried or reclassified,
and VM100/production disks are never rehearsal inputs. The installed production
guard remains. Scheduled reporting is explicitly deferred under ADR 0002.

### Inactive storage declarations (source only)

The ordinary `storage` tag now selects only `storage/tasks/inactive.yml` on inert
and recovery profiles, after the existing lifecycle/apply guards and host lock.
Production storage verification and the production firewall canary remain gated
and unchanged. The installer independently rejects production. The three shared
Jinja-rendered mount declarations derive UUIDs, NFS source, filesystems, paths and
options directly from the contract; names must match systemd path escaping and
the existing production dependency graph. `debian.storage.local_mount_boot_options`
owns the legacy local `nofail` boot policy separately from kernel-observed
`noatime`. Both condition directives, NFS network-online Wants/After and install
metadata are preserved. The current rendered bodies match the three cloud-init
bodies byte for byte; cloud-init payload and hashes remain unchanged pending
replacement qualification, not already retired ownership.

This is missing-only **disk declaration**, not storage activation or repair.
Before any copy it requires inactive/empty protected paths, trusted ancestry,
absent activation token, no foreign definitions/overrides/pull-in links, exact
existing body hashes and root-owned single-link regular `0644` metadata, and
independently explicit inactive/dead mount-unit observations with no jobs, aliases
or loaded drop-ins. Existing exact files are no-ops; divergent files refuse, even
in check mode. Check mode predicts missing copies without writing. Final checks
verify disk bytes only. There is no package installation (including `nfs-common`),
device/filesystem probing, mountpoint creation, token creation/removal/adoption,
mount, enable/start/stop/restart or daemon reload.

The conservative supported system-unit search-root superset is:

```text
/etc/systemd/system.control       /run/systemd/system.control
/run/systemd/transient            /run/systemd/generator.early
/etc/systemd/system               /etc/systemd/system.attached
/run/systemd/system               /run/systemd/system.attached
/run/systemd/generator            /usr/local/lib/systemd/system
/usr/lib/systemd/system           /run/systemd/generator.late
```

The manager's named `UnitPath` must contain no unsupported/custom roots. Only
`/lib/systemd/system` is additionally allowed, after observing `/lib` as the exact
root-owned `usr/lib` symlink and validating `/usr/lib/systemd/system` ancestry.
There is no general symlink normalization. Missing optional roots are allowed;
present unsafe ancestry refuses. Nonrecursive root metadata scans reject foreign
exact unit definitions, exact unit drop-in directories, `mnt-.mount.d`,
`srv-.mount.d` and global `mount.d`, including symlink entries. A second
nonrecursive level, limited to safely owned real `*.wants`/`*.requires`
directories, rejects exact protected-unit entries even when dangling. Unrelated
unit definitions are not read or rejected merely for existing. This bounded
supported topology and native systemd output/parsing still require qualification.

Pathname observations and `copy force:false/follow:false` assume trusted,
cooperating ancestry under the existing lock; they are not race-free publication,
atomic no-clobber, crash closure or boot proof. Token and loaded state are checked
near publication, but the complete observation is not an atomic snapshot. A
partial copy failure can leave some declarations on disk; retain the failed apply
for separately reviewed recovery, not automatic retry.

`nfs-common`, native package effects and native parsing/loading remain separate
prerequisites, not established by this slice. The activation executor already
requires loaded/inactive units **before** its own later daemon reload. The separate
capability installation reloads changed declarations; it is neither invoked here
nor evidence that a disk-only run satisfies that order. A separately reviewed
preparation and fresh loaded-state observation are required before activation.
The production guard, direct dependency policy, executors and all operational
admission remain unchanged.

`test-debian-storage-provisioning.js` uses actual Ansible imports, conditions,
assertions and template lookup with controller-only stat/find/command/copy effect
adapters. Its guard/lock witnesses are synthetic dispatch/refusal evidence, not
installed admission qualification. The inactive-path caller now adds only
`-I -B -S` to its existing stdlib program invocation; its exact argv is checked
before fixture creation, and the Linux/root helper is never executed natively by
this test. This closes that caller only, not every Python startup path. Native
inert convergence, loaded-unit/cold-boot/activation/recovery acceptance remain
unproven; VM9900's failed qualification is not retried and production inputs never
become rehearsal inputs.

## Installation and use

Install the fixed executor, dependency policy and additive drop-ins only through `ansible/playbooks/install-debian-lifecycle-capability.yml`, with lifecycle profile `inert` or `recovery`, exactly the `debian_lifecycle_capability` tag, and `debian_lifecycle_capability_confirmation=INSTALL_DEBIAN_LIFECYCLE_TRANSACTION_CAPABILITY`. Installation and execution use the same host apply lock, so the executor cannot be replaced between checksum verification and launch. The controller derives inventory and host routing from the saved profile: `inert` can route only to the contract-bound qualification inventory host, while `recovery` and `production` route only to the production inventory host.

Create canonical request and observation JSON, in an owned mode-private output directory, then run:

```text
scripts/controller/debian-lifecycle-transactions.py plan OPERATION REQUEST OBSERVATION OUTPUT_DIRECTORY [--evidence PROTECTED_RECEIPT ...]
scripts/controller/debian-lifecycle-transactions.py verify OPERATION SAVED_PLAN CURRENT_OBSERVATION [--secret PROTECTED_FILE] [--evidence PROTECTED_RECEIPT ...]
DEBIAN_LIFECYCLE_TRANSACTION_CONFIRMED=EXACT_VALUE \
  scripts/controller/debian-lifecycle-transactions.py apply OPERATION SAVED_PLAN CURRENT_OBSERVATION [--secret PROTECTED_FILE] [--evidence PROTECTED_RECEIPT ...]
scripts/controller/debian-lifecycle-transactions.py lock-plan RETAINED_LOCK_OBSERVATION OUTPUT_DIRECTORY
scripts/controller/debian-lifecycle-transactions.py lock-verify SAVED_LOCK_PLAN CURRENT_RETAINED_LOCK_OBSERVATION
DEBIAN_LIFECYCLE_LOCK_RECOVERY_CONFIRMED=release-debian-lifecycle-retained-lock-PLAN_SHA256 \
  scripts/controller/debian-lifecycle-transactions.py lock-apply SAVED_LOCK_PLAN CURRENT_RETAINED_LOCK_OBSERVATION
```

Planning never authorizes apply. Request, observation, authority receipts, identity, and auth-key files must be owned, single-link, mode-private regular files with no symlink path components. Observations must be collected independently and recollected immediately before exactly one apply. Executable fixture tests cover marker-publication rollback, partial unit-start rollback, interrupted Tailscale rollback, state-disk no-retry journaling, authority source-byte mismatches, and persistent-flock classification. `python3 scripts/controller/test-debian-production-dependencies.py` additionally covers empty/missing/weakened/swapped dependency properties, stale installed policy, legacy evidence refusal, quoted mount names, pre-mutation refusal and independent canaries. These fixtures do not authorize a live transaction.
