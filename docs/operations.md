# Operations

## What is available now

Supported native scope is observation, manual-update policy, Proxmox repository/
chrony convergence, guarded existing-host backup configuration (tools, account,
same-content runtime files and nine unit definitions), and native Compose
observation. Native Proxmox package maintenance and reboot have source-qualified
entrypoints but retain separate live cutover gates below. [Dated outcomes](#latest-scoped-deployment)
do not expand that scope. Broader host/application adoption is pending: there is
**no supported general deploy or host-convergence command**. The native Compose
`flaresolverr` canary has passed live observation and source-bound check mode.
Its first normal attempt refused an out-of-scope artifact delta before publication
or container mutation; the exact retained owner was later released while preserving
the failed candidate. A second authorized attempt stopped before ownership or
staging when a Restic interruption journal appeared. Both attempts are consumed;
no retry or deployment is authorized. Debian `site.yml` still includes lifecycle, lock
and backup prerequisites. Directly invoking retained mutation roles is not an
approved replacement for the removed controller.

## Latest scoped deployment

On September 15, 2026 (PDT), commit `154659cf` was pushed to `main` and deployed
through native Ansible. `update-policy.yml` ran on both hosts and
`configure-backups.yml` ran on `docker-host`, after fresh zero-change previews.
Both normal applies and their second normal runs reported `changed=0`, `failed=0`
and `unreachable=0`. Backup unit states/execution timestamps and runner/policy/input
hashes were unchanged; update checks and Tailscale SSH remained enabled.
No backup/maintenance job, Compose deployment, provider apply or cleanup was run.
This confirms scoped convergence, not backup integrity or restore readiness.
This supersedes the September 14–15 per-slice previews as deployment status;
no reinstall, content rollout, activation or restore was qualified.

## Native host observation

Native host observation now works through ordinary SSH/become over Tailscale:

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook \
  -i ansible/inventory/hosts.yml ansible/playbooks/observe-hosts.yml
```

This uses only core Ansible facts, `id -u`, assertions and a summary; it does not
change host configuration or contact application sockets. `--check` is supported.
Ansible may use temporary module files and SSH/sudo generate normal access logs.
The inventory deliberately avoids legacy groups/contract variables. It uses the
existing `ansible-deploy` Debian account and `proxmox` administrator account with
sudo, not Proxmox's restricted `ansible-deploy` transport. Tailscale authenticates
the connection; no new keys/accounts or Linux sshd changes are needed for this path.
Host-key aliases must already be trusted in `~/.ssh/known_hosts`; mismatches fail.
The source Tailscale policy no longer grants the retired `ansible-plan` identity.
The Tofu root now declares a native full-policy resource, but it is not imported and
no live write is authorized. Follow the provider-adoption procedure below; do not
claim the source policy is deployed.

### Native Proxmox capability observation

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook \
  -i ansible/inventory/hosts.yml ansible/playbooks/observe-proxmox.yml --check
```

This separate read-only play uses ordinary SSH/become, source-owned inputs in
`ansible/inventory/host_vars/proxmox.yml`, core facts/stat/assert tasks and native
read commands. It checks nine loaded/active services (including NFS's active
oneshot unit), the enabled/active firewall watchdog, five repository files and
absence of five persistent ownership markers. It does not acquire locks, refresh
apt, reconcile journals, restart services or install helpers.

The existing neutral protected collector is streamed to isolated Python over
stdin. It reads sealed host-local inputs, key/MAC and token escrows, performs
read-only native hardware/PVE queries and loopback token checks, and returns only
bounded access/hardware summaries under `no_log`. Proxy settings are explicitly
cleared for credential-bearing loopback requests. It neither invokes installed
Nix helpers nor reads `nix/`, an artifact directory, old plans or receipts. No
new collector is installed and no replacement receipt is produced. SSH/sudo logs
and Ansible's normal temporary module files remain ordinary observation effects.

September 16 validation passed 19 tasks with `changed=0`, `failed=0` and
`unreachable=0`, including protected access/hardware parity. The first attempt
incorrectly required the NFS oneshot to be running; native `systemctl show`
confirmed active/exited success, and the corrected loaded/active check passed.
This play deliberately reports **not full host parity, not an exclusive snapshot,
not maintenance authorization**. It does not replace operation-specific package
preview, firewall-policy/backend validation, restore checks or independent
recovery access. The former 17-domain artifact audit and custom solver are retired. Persistent marker
absence is not proof that no mutex is held or no prepared transaction exists.

Native repository/keyring/chrony declarations replace direct Nix projection
reads. Desired bytes/hashes are unchanged. The low-risk controller, deploy
activator source, full-machine package manifest and projection were retired after
native cutover rather than retained as a second authority. No old host checkout,
saved plan or journal was rewritten.

### Native Proxmox package sampling

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook \
  -i ansible/inventory/hosts.yml ansible/playbooks/observe-proxmox-packages.yml --check
```

This play first runs the capability observation above, then uses
`ansible.builtin.package_facts` with the APT backend, `dpkg --audit` and
`apt-mark showhold`. It does not run a custom collector, parse solver output,
compare a full-machine package manifest, refresh metadata or save a plan.
Missing Python APT bindings fail rather than being installed. Package facts and
native command output are protected by `no_log`; only counts and a clean-dpkg
summary are published. The configured default fact cache is in-memory; do not
configure a persistent fact cache for protected observations.

**Installed inventory is not a candidate preview.** This deliberately narrower
entrypoint does not claim candidate freshness, a frozen dependency solution,
complete host parity, exclusive ownership or maintenance authority. Source and
controller-local assertion/redaction tests pass. A separately approved single
PVE run on September 16 passed **26 tasks, changed=0, failed=0, unreachable=0**:
1,355 installed package names, no holds and a clean dpkg audit. No solver or metadata
refresh ran. This approval and all three prior package-read approvals are consumed.

The superseded parser-based prototype failed three separately approved PVE runs,
most recently with `apt-transition-unrecognized`, even after an isolated matching
parser defect was fixed. That history is retained in the
[retirement assessment](legacy-nix-retirement.md#native-package-observation-without-forwarding-mutation-authority).
**No production transition or further parser diagnosis is needed for retirement.**
The shared parser remains only for its legacy callers until those migrate.

### Native package maintenance — adopted with exact scope

`ansible/playbooks/maintain-proxmox-packages.yml` uses core `ansible.builtin.apt`
after native capability/inventory checks. Choose exactly one operation:
`proxmox_package_specs` containing exact `name=version` entries, or the explicit
boolean `proxmox_package_dist_upgrade=true`. Neither is selected by default.
A separately approved PVE cutover used exact installed scope
`pve-manager=9.2.11`: check mode passed 31 tasks and the normal no-op invocation
passed 30, both with `changed=0`, `failed=0`, `unreachable=0`. Neither refreshed
metadata nor changed a package; the retained prepared legacy journal was untouched.
Combined with the isolated real-module mutation cases below, this removed the
source-only check guard. It qualifies the entrypoint and safety boundary, not a
particular future package change.

The tasks prohibit removals, downgrades, held-package overrides, unauthenticated
packages, dependency auto-installation and cache cleanup. They preserve the
legacy `force-confold` conffile policy. Metadata refresh is an independent boolean
that defaults false and is refused in check mode; callers must approve it separately.
Without refresh, existing metadata is used and its freshness is not established. There is no saved solver plan or custom receipt. Exact requested
versions do not freeze transitive dependencies, and check results do not authorize
later changes. Native APT output stays under `no_log`, with only a change boolean
reported; do not mistake it for a detailed human-reviewed solver diff.

**APT check mode is not a strict no-write boundary.** Inspection of the installed
Ansible implementation found that `get_cache()` can call `apt-get update` to
repair missing/corrupt lists even with `update_cache=false` and check mode.
Use the inventory-only play above for no-refresh observations. A maintenance
preview therefore needs approval covering possible metadata repair. The approved
no-refresh preview above performed no repair or change. Do not wrap the module in
another custom parser.

APT/dpkg locks serialize package tools, not backups, firewall/VFIO work or reboot.
`serial: 1` only serializes this play; `lock_timeout: 0` refuses package contention.
Before each change, recheck host-local writer coordination and define explicit
operation-specific service postconditions. Native dpkg status and APT/dpkg logs
survive runner loss; they support inspection and forward repair, not automatic
package rollback or permission to replay an interrupted legacy operation. The
retained prepared package record remains historical evidence: it was neither
replayed nor deleted during native cutover.

### Native maintenance configuration — adopted

`ansible/playbooks/configure-proxmox-maintenance.yml` uses core stat/find/assert,
`copy` and `systemd_service` for the five existing repository files and chrony.
It checks existing root-owned files/directories, exact signing-key links/hashes
and unknown active source definitions before writing. It neither bootstraps
missing files nor downloads keys, deletes unknown repositories, refreshes APT,
changes packages or restarts a healthy chrony service. Desired values remain in
`ansible/inventory/host_vars/proxmox.yml`, unchanged from the previous policy.

Copies use native atomic replacement and host-local `backup: true` before-images;
file contents/diffs remain hidden. Copies are individually atomic, **not a
multi-file transaction**. On interruption, stop and inspect current files and
host-local backups, then explicitly choose completion or exact-file restoration.
Do not roll back unrelated subsequent changes or blindly replay the old installer.
The play shares only the native persistent-owner checks, not the full legacy audit.
Marker absence is not exclusion; application still needs a coordinated window.

A separately approved September 16 cutover ran one check preview and two normal
runs. The preview passed 18 tasks and each normal run passed 17; all three reported
`changed=0`, `failed=0`, `unreachable=0`. No repository bytes, keyring, service,
APT metadata or package changed. The source-only check guard was then removed;
future use still requires the narrow play and ordinary operational approval.

### Isolated native module qualification — September 16, 2026

The approved dedicated Colima profile stayed within two CPUs, 4 GiB RAM and
20 GiB total disks, with no home/repository/credential mounts or SSH-agent
forwarding. Debian/PyPI downloads installed Python APT and Ansible Core 2.21.2
only into a disposable test image based on the previously pinned official Python
image. No controller or production dependency was installed.

Ten `NativeAptModuleTests` in the existing controller-observer suite passed on
Linux/root, **not skipped**. Real core APT tasks exercised exact installation,
no-change preview state, upgrades, idempotence, dist-upgrade, removal/hold/downgrade
refusals, actual POSIX package-lock contention, conffile preservation and failed
configuration retained in native dpkg/APT state/logs. Real stat/find/copy tasks
exercised preview nonmutation, host-local before-images, idempotence and unknown
source/alias/key refusals. Synthetic package repositories and every mutable file
were under container `/tmp`; runtime networking was disabled and root read-only.
Only four allowlisted source files were streamed into the container.

The first fixture attempt failed because Ansible's default remote temp directory
was under read-only `/root`; the fixture now keeps both local and remote temporary
files under its private `/tmp` tree and rejects unreachable results. The final ten
cases passed in 18.712 seconds. The non-systemd container does **not** qualify
chrony service management, PVE package effects, reboot/VFIO or independent recovery.
Containers were removed and the dedicated VM stopped; default Docker context was
unchanged. Normal controller tests explicitly skip these opt-in Linux cases rather
than counting them as executions.

### Native Proxmox reboot — attended run completed September 17, 2026

`ansible/playbooks/reboot-proxmox.yml` composes native capability/package checks
with a dedicated reboot role. It requires VM100 already running with `onboot: 1`,
all four Docker-host Restic writers explicitly loaded and inactive, no retained
ownership marker, explicit attended console and backup confirmation, and an absent
transient recovery unit. The backup checks are delegated to `docker-host`; missing,
failed, activating or otherwise ambiguous units refuse the reboot. Check mode
performs only those reads.

For an approved real run, `systemd-run` arms a host-local transient timer that
starts VM100 if the controller disappears after shutdown but before reboot. The
play shuts down VM100 with `qm`, uses `ansible.builtin.reboot`, reruns protected
host observation and waits for VM100's existing on-boot recovery. This is narrow
controller-loss protection, not a new plan/receipt framework. The timer and VM
on-boot policy are durable on the affected host/controller boundary; no runner
artifact is needed. A separately approved live check-mode run passed 37 tasks with
`changed=0`, `failed=0`, `unreachable=0`. The approved normal run then armed the
timer, stopped VM100 and rebooted PVE. The controller command ended while the
Ansible reboot module was waiting for reconnection, but independent postboot reads
confirmed boot time `2026-09-17 15:01:32`, VM100 running and the transient recovery
timer absent. Native observation subsequently passed all 20 tasks, including the
protected VM disk, ZFS topology and USB mappings. This qualifies one attended
reboot and native VM recovery, not application-level workload health or unattended
future reboots.

Postboot ZFS status reported pool `storage` ONLINE, a completed 15.7 GiB resilver
with zero scan errors and no known data errors, but one device checksum counter of
one. The operator explicitly deferred that storage warning. It was not cleared or
repaired. The reboot role retains its strict `pool 'storage' is healthy` pre/post
refusal, so another run remains blocked until ZFS reports fully healthy or a new
operation-specific decision changes that boundary.

### Active Nix source retirement — September 16, 2026

After the final bounded inspection found every bootstrap/access interruption
journal absent, two low-risk and two reboot journals committed, and no generic
activator, the active `nix/` tree, flake, planner, bundle, generated templates,
bootstrap/access/protected-input writers and Nix-only tests were removed. The
custom artifact/17-domain package audit and completed access/boot/network/storage
plan producers were also retired rather than re-created around Ansible. Native
observation, package facts/APT, repository/chrony and reboot source are the current
paths. Historical hashes/plans were not rewritten.

The old PVE checkout, sealed inputs, previous generation, install manifest,
committed journals and one prepared package record remain untouched. A later
bounded read found every boot/network/storage/NFS/Tailscale/package ownership
record committed and active apply/firewall/legacy owners absent. The persistent
operation mutex path existed but was not opened or acquired. Installed observer/private-preparer/plan/deploy helpers were a separate cleanup
boundary after source retirement. Autonomous firewall source/runtime and deploy
transport Restic recovery are not Nix dependencies and remain.

On September 17 the approved native installed-access retirement rechecked retained
operation statuses and the operation mutex, preserved root-only before-images,
disabled the three obsolete plan/apply shells, removed obsolete sudo grants and
helpers, and narrowed `ansible-deploy` to Restic recovery. The strengthened preview
passed 37 tasks and predicted five change groups. The normal run passed 42 tasks
with six changed task groups; after an idempotence assertion was corrected to
distinguish preserved original bytes from the newly installed retained files, a
second normal run passed 42 tasks with `changed=0`. The retained role now also pins
the reviewed SHA-256, mode and single-link identity of every expected predecessor
and permanent before-image, and refuses to publish sudo unless the exact retained
Restic recovery transport is present. After commit `8a7a0705` was pushed, a normal
revalidation passed 44 tasks with `changed=0`, `failed=0` and `unreachable=0`;
all exact identities and the installed postcondition remained intact.

PVE restored its conventional root key path during reboot. The retained file
contains only the source-attributed `current-proxmox-root-identity`, and
`/root/.ssh/authorized_keys` is the expected link to the PVE-managed file.
The checked root-specific effective sshd context still has public-key authentication and root login disabled. The
operator explicitly chose to preserve this inert PVE state. Native protected
observation now verifies that exact fingerprint/link, both effective sshd refusals,
and absence of every other conventional key path; it does not admit additional
keys. The contract access cutover is complete. Historical journals, old checkout,
sealed inputs, prepared package record and before-images remain preserved.

### Live validation, not controller-local receipts

Future disposable-runner workflows follow the
[live-validation decision](decisions.md#disposable-controllers-and-live-validation).
The observation play above already requires no prior outcome artifacts; it checks
native access and service facts, not full helper, hardware or application parity.
The Proxmox capability play above adds repeatable source-owned checks. Further
domain checks should likewise use native observation rather than consume this
document's dated results.

On September 16 at 20:50 UTC, separately authorized PVE-only native inspection
confirmed ordinary SSH/become, the retained account/sudo and baseline OpenSSH
settings, observer/preparer bytes, and active/enabled firewall watchdog. Sampled
ownership paths were absent and no relevant held locks, matching processes or
pending systemd jobs appeared. A prepared package journal still exists; it is
not evidence of a running process or permission to replay or discard it.

The deploy activator and plan transport **do not match current source**. The
former lacks later locking/queued-reboot guards; the latter lacks the undeployed
controller-observer route. The installed plan sudo rule likewise omits that route,
matching the retained Nix projection rather than the newer contract declaration.
No helpers were invoked, replaced or upgraded. Current-source tests therefore
cannot qualify installed package/boot/reboot behavior. See the
[bounded findings and console-source retirement](legacy-nix-retirement.md#live-state-boundary-and-console-source-retirement--september-16-2026).
This is neither comprehensive host health nor a standing maintenance window;
Docker, hardware/API policy, backups and independent recovery access were outside
this inspection. Do not turn this dated result into a future workflow gate.

Ordinary OpenTofu saved plans remain a next target. Source now contains a pinned
`community.docker.docker_compose_v2` observation and canary deployment role. Live
observation and a check-mode source/active boundary run have qualified its read
path on `docker-host`; this does not authorize configuration changes.

### Native Compose qualification

`ansible/playbooks/observe-compose.yml` is the intended read-only entrypoint for a
fresh runner. It loads only native inventory variables, not the global contract or
legacy `docker_host` group variables. It checks the active root-owned artifact,
environment, override and image locks; installed SOPS/age identities; actual games,
state and NFS mounts; backup files, writer units, interruption journal and mutex;
production/reconciliation ownership paths; systemd jobs; declared/running services,
digest-pinned images and required health; local availability of every image in
current, previous, retained and interrupted locks; and a
`community.docker.docker_compose_v2` dry run against live containers. Registry
availability is not treated as recovery proof and remains a fail-closed prune-time
check; deployment observation does not consume unauthenticated registry quota.
Its bounded summary explicitly does not claim restore readiness. It consumes no
receipt, `.local`, `.reconcile` or prior runner result.

`ansible/playbooks/deploy-compose.yml` is check-mode qualified but has not performed
a normal deployment. Its initial mutation allowlist contains only `flaresolverr`.
It re-runs observation, acquires the durable production owner lock,
derives an artifact hash directly from tracked checkout bytes, stages only the
existing deterministic artifact selection, decrypts SOPS only on the host and
requires the resulting environment to be byte-identical to production. Credential,
service-set, database migration, mount/topology and Restic-policy changes are out
of scope. LiteLLM config bytes are frozen, and every non-requested normalized
service plus top-level network/volume/config/secret topology must equal active
state. Any changed artifact requires explicit canary recreation.

The module calls fix `project_name=docker-compose`, disable builds, pull only the
explicit canary services with `policy=missing`, and then use `pull=never` for
full-project preview and convergence. They prohibit orphan and anonymous-volume
replacement, wait for running/healthy state, and use automatic recreation except
for an explicitly supplied forced-recreation subset. A full-project module preview
must contain only canary-container actions before convergence, and a full-project
post-preview must be idempotent. The role preserves `current`, `previous`,
hash-addressed older artifacts/environments and a durable pre-deployment image
checkpoint. The narrow image-lock helper extension makes prune protect
hash-addressed retained and interrupted generations in addition to current/previous;
it neither prunes volumes nor changes the installed cron wrapper. Failures after
checkpoint capture retain the production owner and checkpoint for inspection. A
refusal before checkpoint capture retains the owner but creates no checkpoint
because no deployment generation has changed. The workflow never clears a lock or
attempts database rollback. Only complete success updates current/previous image
locks and releases ownership.

A fresh runner needs reviewed Ansible Core 2.21.x, the pinned collections installed
from `ansible/collections/requirements.yml`, Tailscale connectivity and the trusted
`docker-host` known-host entry. It does not need a SOPS private key. Check mode
intentionally does not stage protected inputs; it reports the source/active identity
boundary rather than pretending to preview an unpublished generation. Any future
check and normal run must use the same explicit clean source commit. No GitHub
workflow exists until short-lived Tailscale identity, authoritative host-key custody
and protected-environment approval are decided. The production SOPS identity
remains host-only.

On September 18, 2026, live observation passed with all 38 declared services
running, 38 immutable image references, both required health checks, exact canary
mounts, inactive backup writers, no active-model drift and locally available
rollback images. The original approved check-mode invocation passed 44 tasks. An
intermediate registry check hit Docker Hub's unauthenticated rate limit, so
observation now proves local retained image availability while the installed prune
path keeps its fail-closed registry check.

Commit `b5408f2e` was then pushed to `main`. Its same-commit check passed 49 tasks
with no failures or unreachable hosts; the one reported change was the intentional
artifact boundary from active
`2f12e384fdc0ce759d23b0bd9e16ad402d3ecd2985b4ecdfe048127f1c5748be`
to candidate
`fbd84ff2fd70b0a7cd6a560930db0a66f8f88b56cd5472a9fe167bc404fe04b5`.
The one authorized normal attempt acquired production ownership and staged that
exact candidate, then refused three out-of-scope paths before environment staging,
artifact publication, image pull, checkpoint capture or container mutation:

- `scripts/compose-artifact.py` contained controller Git hardening;
- `services/authentik.yml` contained only a documentation-comment update;
- `services/data/litellm/config.yaml` contained the separately undeployed model update.

The two admitted differences were `.sops.yaml` recovery-publication metadata and
`scripts/compose-image-lock.py`. The failed play reported 65 successful, seven
changed and one failed task. It retained
`/var/lib/iac-ansible-production.lock` with owner SHA-256
`5af8bb373ce87c55ad50b3237805c9b8413f5f2bf8df5bd11671d6fc66329706`,
the exact candidate under `/srv/docker-compose/staging/`, and the newly created
empty mode-0700 retained-image directory. It created no candidate environment or
interruption checkpoint and left `current`, its artifact marker, containers and
image generations unchanged. At that point the authorized attempt was consumed;
retry, lock release, candidate deletion and container mutation were not authorized.

A subsequent approved read-only audit passed ten tasks with `changed=0`. It
recomputed both artifact identities, confirmed the exact five changed paths, found
no archived image record or unpublished incoming directory, and preserved the
staged candidate. A second five-task read found LiteLLM running with restart count
zero, active config SHA-256
`6a93d7caee70b924d80c628250441a78be5ebe9844735982ab9c532e4f4595d2`,
three retained `.litellm-*` workspaces, three retained capture-attempt markers and
no `/srv/docker-compose/.litellm-*` recovery directory. Those retained records are
not success evidence and remain untouched.

The narrow follow-up source restores LiteLLM config to those exact active bytes,
adds only the helper and comment paths to the artifact allowlist, freezes LiteLLM
bytes, and requires every non-requested normalized service plus network/volume/
config/secret topology to equal the active model. Its source-only candidate hash is
`3e5600bfa5ff9441d729e4e81634854435cea13f15568337adbc87911468569e`;
that is not a live qualification or deployment approval.
`ansible/playbooks/release-failed-compose-canary.yml` binds the exact owner,
active and failed-candidate hashes, requires the audited pre-publication state,
adopts/releases only that owner and preserves the staged evidence. After commit
`1676a419` was pushed, its separately authorized check-mode run passed 13 tasks
with one expected preview change and no failures. The separately authorized normal
run then passed 17 tasks with one reported change: it released only owner SHA-256
`5af8bb373ce87c55ad50b3237805c9b8413f5f2bf8df5bd11671d6fc66329706`.
It preserved failed candidate
`fbd84ff2fd70b0a7cd6a560930db0a66f8f88b56cd5472a9fe167bc404fe04b5`,
found no candidate environment or interruption checkpoint, and performed no
container mutation. That release authority is consumed.

Commit `c5df0686` recorded that closure and was pushed from a clean checkout.
Fresh observation then passed 38 tasks with `changed=0`: all 38 services were
running with immutable images, required health checks passed, backup writers were
inactive and active-model drift was absent. The same-commit canary check passed 49
tasks with one expected source-boundary preview change, candidate
`3e5600bfa5ff9441d729e4e81634854435cea13f15568337adbc87911468569e`,
and no failure. One separately authorized normal attempt repeated the live gates
but found `/var/lib/home-lab-restic/interruption.json` after the mutex check. It
stopped after 12 successful tasks with `changed=0` and one failure, before
production ownership, candidate staging, environment decryption, checkpointing,
publication, image pull or container work. That attempt is consumed.

A separately approved eight-task read-only audit then found the Restic interruption
journal absent, no relevant backup process, all four writer units loaded/inactive,
and the existing mutex available. It also confirmed no production owner and no
candidate directory, candidate environment or image checkpoint for the new hash.
The audit performed no recovery. Journal appearance and disappearance alone do not
prove which backup outcome occurred, and they do not authorize a canary retry or
journal manipulation. There is no authorization to combine the deferred LiteLLM
change with the canary.

The general legacy stage/deploy lane is retired: `compose_stage` and its review
entrypoint now require an explicit allowlisted retained operation, and
`compose_deploy` refuses every plan that is not its exact Nextcloud migration,
Restic-policy recovery or interrupted Calibre rollback lane. These internals remain
only because deleting them would strand recovery inputs. Both rollback plays still
use `compose_rollback`, and archive recovery still uses `compose_recovery`.
`compose-artifact.py` remains a first-run/retirement dependency.
`compose-image-lock.py` remains consumed by those roles and by installed
`/usr/local/sbin/home-lab-safe-image-prune`; that helper continues image-only
pruning and protects retained/interrupted generation locks. No installed helper,
artifact, environment, lock or journal was removed.

## Manual-update policy

The operator approved and applied this narrow native playbook on September 14:

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook \
  -i ansible/inventory/hosts.yml ansible/playbooks/update-policy.yml --check --diff
# After reviewing the preview, apply by omitting --check.
```

It owns only Debian's unattended-install flag in the existing `20auto-upgrades`
file and Tailscale auto-apply on the two hosts. Package-list updates remain enabled;
Tailscale checking and SSH preferences are preserved. No timer is stopped, no
package installed/upgraded, and no service restarted or host rebooted. It does not
cancel an already running updater. Updates now require attended maintenance.

The apt task uses native `lineinfile`. Tailscale has no core Ansible module for this
preference: the play uses upstream `tailscale debug prefs` (output hidden), changes
only `tailscale set --auto-update=false` when needed, and verifies the result. In
check mode it reports the proposed CLI change without executing it. A successful
preview is not an immutable transaction. A second actual run changed nothing on
both hosts. This is not the old retirement policy that disabled all apt timers;
legacy contract/bootstrap source are not authoritative for these adopted settings.

### Superseded unattended-retirement source

On September 15, 2026 at 20:41 UTC, separately approved read-only SSH/sudo checks
on Debian `docker-host` found both `unattended-retirement-*` helpers absent from
`/usr/local/libexec/home-lab/`, the `/var/lib/home-lab/unattended-retirement`
plan/journal tree absent, and no retirement or production apply lock. No relevant
held apt/retirement locks, retirement processes or systemd jobs were observed.
A bounded scan of 433 systemd, cron and sudoers entries found no lane references.
The running unattended-upgrades process was the normal shutdown-wait helper;
it and its service were left alone. Effective apt values remained package-list
updates `1`, unattended installation `0`; both apt timers were enabled/active.
This is a scoped observation, not proof of historical nonexecution or exclusivity.

The lane-only planner, test, planning playbook/role, observer and executor were
removed, along with their shared-installer branches. Package/reboot capability
installation and its guards remain; unsupported kinds are rejected before source
lookup or apply-lock acquisition. Native `update-policy.yml` is unchanged.
No host components were installed/uninstalled and no legacy lane was executed.

The local plan `f6e231c4a7ba7ae3ec6826dfa310cc756ada05c7268f7b797f224fe902405578`
(expired September 3, explicitly unauthorized), its historical logs and all other
operational evidence remain intact. The contract's `unattended_upgrade_retirement`
field and schema are retained as inert legacy data: surviving maintenance plans
bind whole-contract hashes. They do not authorize disabling timers/list updates;
no receipts or hashes were rewritten. Historical code remains in Git. An unexpected
retained plan/journal on another host or restored system needs separate inspection
and a recovery decision, not replay of the superseded policy.

## Backup unit definitions

`configure-backups.yml` first verifies/converges the existing pinned tools through
`restic_backup`'s `tools-native` entrypoint, preserves the existing confined account
through `identity-native`, adopts same-content runner/input files through
`runtime-native`, then configures all nine Restic service, target and timer
definitions through `systemd` and
conditionally reloads systemd definitions. It requires explicit existing-host inputs in
`ansible/inventory/host_vars/docker-host.yml` and all nine installed regular unit
files. Unit management is definitions-only: enabled and active states are untouched. Calendars,
jitter and non-persistence are preserved; no backup or maintenance is invoked.

These entrypoints bypass legacy main tasks: no human accounts, credentials,
policy installation, tmpfiles, runtime locks or receipt checks. It is not backup
bootstrap, schedule activation, boot-enablement adoption or backup-health proof.
The render-only `units.yml` and template list are shared with legacy convergence;
legacy activation and its evidence guards remain separate. Native unit inputs no
longer load the global contract. Its remaining consumers use the explicitly named
`restic_systemd_legacy_contract` bridge in legacy group variables.

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook \
  -i ansible/inventory/hosts.yml ansible/playbooks/configure-backups.yml --check --diff
```

The September 14 inspection found all nine units matching rendered bytes and
root:root 0644 metadata, both timers active/enabled, boot recovery enabled and no
unit drop-ins. This is configuration parity, not maintenance or restoration proof.

### Pinned backup tools

Native host variables own the same Restic **0.19.1** and Proton-qualified rclone
**1.76.0-beta.10267.220fe7619** URLs, archive/binary SHA-256s and version lines.
The play gathers minimal core facts and requires Debian/Linux/x86_64/Python 3.
It reads the existing `/etc/home-lab/restic-policy.json` under `no_log` and asserts
only its `tools` object matches the desired pins before any tool/unit effects.
Missing or incompatible policy fails closed; nothing bootstraps or rewrites it.
This is existing-host consistency, not backup-health proof. The installer validates
binary hashes; the unchanged runner uses policy tool paths and checks version
output in preflight.
Future upgrades therefore require coordinated runtime-policy changes and Proton backend
qualification, **not independent Renovate pin bumps** or switching to latest.

Legacy `tools.yml` retains exact contract/platform guards and delegates to the
same `tools-install.yml` implementation; native configuration never loads that
contract. Shared core stat/download/checksum/copy tasks retain unsafe-destination
refusal, isolated stdlib extraction, workspace cleanup and final metadata/hash/
version checks. Both extracted hashes are checked before either binary is copied.
Check mode reports drift without downloading, extracting, installing or executing
drifted tools. Verified no-drift binaries may run their version commands. This is
not an atomic pair upgrade or protection against concurrent privileged path writers.

No desired versions, units, runner, backup data or activation policy changed.
Zero-change validation does not test a real reinstall or archive availability.

Local `scripts/controller/test-debian-tool-provisioning.js` passed 444 Ansible
controller-only synthetic-effect cases and 14 tiny real stdlib extractor cases;
it does not download releases or install tools on a host.

### Confined backup account

`identity-native` requires the existing `restic-proton` account and group to have
UID/GID **60000** before reaching shared core Ansible `group`/`user` declarations.
Missing identities or numeric drift fail; this is not account creation or UID/GID
migration. Existing restrictions remain: primary group only, locked password,
`/usr/sbin/nologin`, home `/var/lib/restic-proton`, no home creation or movement.
No data tree ownership is managed here. Legacy identity-collision/source-ownership
guards still precede those same declarations in the legacy main entrypoint.

`scripts/test-restic-systemd.py` checks native task scope and rendered unit semantics
with Jinja2/PyYAML. It also executes only the identity assertion tasks through local
Ansible with nine synthetic fact sets, including absent and mismatched identities.
It never invokes account modules, imports a role, queries NSS or contacts hosts.
These fixtures do not prove account-module effects, migration, bootstrap or recovery.

### Same-content backup runtime files

`runtime-native` adopts only the existing
`/usr/local/libexec/home-lab/restic-backup` (root:root 0755) and
`/etc/home-lab/restic/{files-from,excludes}` (root:restic-proton 0440).
September 15 validation found all three byte-identical to source with desired
metadata; runner hash, 46 source paths and 67 exclusions matched installed policy.

Before any runtime-file copy, core stat/assert tasks require existing non-symlink,
root-controlled ancestors, a protected single-link regular policy, and three existing
root-owned single-link regular files with exactly the source bytes and no group/other
write permission. Non-root ownership or write access is refused, not repaired into
trusted metadata. A fresh no-log policy read
checks fixed runner/policy/input path bindings, native systemd runner agreement,
source runner SHA-256 and input lines against policy. File hashing retains trailing
newlines. Shared `inputs.yml` and `runner.yml` copy declarations can maintain file
metadata only after these guards; they preserve legacy inputs → policy → runner →
remaining helpers ordering. No directories are created or permissioned.

This is **same-content/metadata adoption, not content rollout or a generic installer**.
Policy and backup scope remain tied to installed policy and legacy source generation;
neither is migrated here. Future content changes need coordinated policy and
retained-journal review. No credentials, journals, locks, repositories or activation
states are managed. These observations/checks do not serialize privileged writers,
resolve retained operations or establish backup health.

`scripts/test-restic-runtime.py` checks source routes/shared declarations and runs
only real local Ansible assertions over synthetic stat/policy facts and isolated
copies of the three source files. Its 49 refusal/no-log cases are not native copy,
metadata repair, installation or content-rollout proof.

### Proton maintenance unit

The Proton fix was independently reviewed and installed with explicit operator approval
on September 14. The preview and apply changed only the two mount-masking lines;
a second Ansible run changed nothing. Loaded systemd properties match the fixed
template. Maintenance remained inactive with its original September 1 execution
timestamps; both backup timers stayed enabled and scheduled, and the runner bytes
are unchanged. The temporary diagnostic units were collected automatically.

Two authorized temporary Linux units ran only the installed runner's
`check_mount` as UID 60000. The monthly unit's `InaccessiblePaths=/mnt/games`
reproduced `mount_identity`. The daily unit's `TemporaryFileSystem=/mnt/games:ro`
passed while the repository remained read-only and application/Wolf data hidden.
The template now uses that working masking scheme, retaining the repository-only
bind and existing locks-subdirectory exception. No runner, credentials or retention
policy changed. The local regression is `scripts/test-restic-proton-sandbox.py`;
its configuration assertions complement, not replace, the Linux probe.

The September 1 journal records an actual exit 1 before maintenance progressed.
A later `Result=success` does not override that history; the old exit status remains
recorded because maintenance was not rerun or reset. Fixing mount traversal is
not proof that a full repository check/prune/subset verification will succeed; do
not run destructive maintenance merely to clear the historical status.

## Proton incident source retirement

The [source retirement audit](proton-source-retirement.md) removes the completed
TOTP cutover lane, superseded v2 migration writer and, after September 15 read-only
inspection, the transaction-closed password-reset/authentication, quota diagnostic
and one-off staged qualification supervisors. Generic qualification recovery and
its immutable evidence consumers remain. The later
[VM reconciliation](proton-source-retirement.md#vm-recovery--partial-lineage-closure-source-retained)
records 16 unresolved attempts, six additional resource-cohort bindings and explained
transport succession; resource destruction/supersession is not plaintext-cleanup proof.
**Leave VM9900 unchanged: it belongs to Debian lifecycle qualification. Never apply
an old Proton destroy plan to it.** Active recovery capabilities and consumer inputs
remain; lifecycle continuation/retirement is a separate task. The audit holds the
[exact local archive/delete candidates](proton-source-retirement.md#historical-material--disposition-choices-pending-approval),
all pending approval, with no retention schedule or further host operations.
Those source passes and read-only reconciliation changed no installed helpers,
receipts, locks or backup behavior; the separately authorized exception is below.

At **22:14:48 UTC on September 15**, a separately approved
[exact-file host retirement](proton-source-retirement.md#approved-host-artifact-retirement)
removed only `/var/lib/restic-proton/migrate-proton-restic-v2` and
`/usr/local/libexec/home-lab/__pycache__/cleanup-damaged-proton-restic-v1cpython-313.pyc`
after fresh identity/hash and caller/process checks. Both paths were verified
absent; parent directories, neighboring caches, migration journal, incident
evidence, active helpers, policy/inputs, backup lock and unit definitions/states
were preserved. No backup/recovery job or repository operation ran. VM9900,
disks, ACLs, transports and qualification infrastructure were not touched.

## Tailscale policy provider adoption

`infrastructure/tofu/tailscale` declares `tailscale_acl.policy[0]` as the native
owner of the tailnet's complete policy file when `tailscale_enable_management=true`.
It pins provider `0.29.2`, keeps `overwrite_existing_content=false`, disables reset
on destroy and uses `prevent_destroy`. The completed adoption removed the former
`terraform_data` placeholder from both remote state and source; do not recreate it.

The provider's create guard refuses to overwrite a non-default policy before import,
and planning validates policy syntax and embedded tests against Tailscale. Its update
path does **not** send the previously observed ETag, however, and therefore does not
protect against a dashboard edit after planning. Before any change, establish an
independent recovery/admin path, freeze dashboard edits and use the dedicated OAuth
client with only the policy permissions required by the provider. Supply its
ID and secret through `TAILSCALE_OAUTH_CLIENT_ID` and
`TAILSCALE_OAUTH_CLIENT_SECRET`; never place the secret in source or a plan file.
Set `TAILSCALE_TAILNET` explicitly when the credential's owning tailnet is not an
adequate unambiguous default.

Import mutates remote state but not the live policy and requires separate exact
operational authorization:

```sh
tofu -chdir=infrastructure/tofu/tailscale import \
  -var=tailscale_enable_management=true \
  'tailscale_acl.policy[0]' acl
```

Immediately produce a saved plan with the same variable, inspect it through
`infrastructure/policy/inspect-plan.py` and the reviewed
`infrastructure/policy/allow/tailscale.txt`, then re-read the live policy before any
apply. Apply only that saved plan under separate authorization while dashboard edits
remain frozen. Import, plan, and apply can acquire the S3 lock; neither state-lock
history nor import is a live-policy deployment. Until an authorized apply succeeds,
the protected API comparison—not source—is authoritative for deployed policy.

On September 18, 2026 (PDT), the dedicated credential passed bounded policy-read and
plan-validation checks. An initial import using the read-only AWS plan profile read
the policy but could not upload state (`PutObject` returned 403); remote state and the
live policy remained unchanged and no local recovery state was created. Retrying the
same import with the state-writing apply profile succeeded. Protected before/after
reads showed unchanged policy bytes and ETag. Remote state then had the native policy
resource and retained placeholder. A fresh temporary post-import plan passed the
allowlisted plan inspector and proposed exactly two updates, one for each address.

The separately authorized apply used a new temporary saved plan after its two actions
and four bounded policy-list differences were checked. A protected read immediately
before apply matched the planned-before policy. The apply removed `ansible-plan` from
two SSH grants, moved its SSH test expectation from accept to deny and updated the
local placeholder. A protected post-apply read exactly matched planned-after content;
the policy body and ETag changed. After convergence, the explicitly authorized state
removal retired the redundant placeholder without changing the policy body or ETag;
its source and policy fixture were removed at the same boundary. Remote state now
contains only the native policy owner, and a fresh provider-backed plan returned exit
0 with no changes. Temporary plans and logs were removed.

## AWS controller permissions boundaries

The plan and apply Roles Anywhere roles now use distinct external owner policies:
`home-lab-controller-plan-boundary` and
`home-lab-controller-apply-boundary`. Each copies its role's reviewed desired Allows
and adds an unconditional `DenyActionsOutsideRetainedBaseline` action ceiling. A
boundary limits identity-policy grants; it is not an attached grant and does not
make other account principals safe. The apply role retains S3/KMS foundation
administration but no longer has IAM or Roles Anywhere mutation authority beyond
`Get*`/`List*` reads.

The non-secret reviewed binding is
`~/.config/home-lab/controller/reviewed-controller-boundaries.json`. Its exact file
path, bytes and provenance remain an input boundary; the validator does not by itself
prove live policy content. The independently controlled bootstrap bundle under
`~/.config/home-lab/owner/aws-controller-boundaries/` contains the reviewed policy
bytes, all pre-cutover managed-policy versions, owner mutation result and refresh-only
saved plan. Preserve that bundle and its independent recovery copy.

For a read-only foundation plan, load the manifest without printing it and pass its
exact pair as root variables:

```sh
manifest=$HOME/.config/home-lab/controller/reviewed-controller-boundaries.json
IFS=$'\t' read -r plan_boundary apply_boundary boundary_binding < <(
  python3 -B -E -s -S scripts/controller/controller-boundary-manifest.py \
    load --manifest "$manifest"
)
TF_VAR_controller_plan_permissions_boundary_arn=$plan_boundary \
TF_VAR_controller_apply_permissions_boundary_arn=$apply_boundary \
tofu -chdir=infrastructure/tofu/aws-foundation plan
```

Keep `boundary_binding` for any saved-plan workflow that verifies the accepted
manifest; do not substitute similarly named controller-owned state policies. Normal
plan locking can add lock-object history. Applying a saved plan requires the apply
AWS profile and separate authorization.

On September 18, 2026 (PDT), the independent owner created both reviewed boundary
policies, attached them to the matching roles and replaced broad apply-policy version
13 with reduced version 14. All five prior versions were archived before oldest
nondefault version 9 was deleted. A reviewed refresh-only plan recorded exactly the
two role updates and one apply-policy update in existing state; applying that saved
refresh plan changed state only. Both Roles Anywhere identities then issued
successfully. Independent readback matched both boundary canonical hashes and the
reduced apply-policy hash. A fresh plan had no drift and passed policy inspection; its
only action removes ten obsolete lifecycle rules for the five retired, already empty
state keys while retaining the five active lock-history rules. No foundation resource
plan has applied that lifecycle change.

## Local source checks

From the repository root, without deployment or secret decryption:

```sh
docker compose config --quiet
python3 -B scripts/test-compose-artifact.py
python3 -B scripts/test-compose-action-plan.py
python3 -B scripts/test-compose-image-lock.py
python3 -B scripts/test-compose-native.py
```

Bare Compose validation requires interpolation inputs already available locally;
it does not decrypt `secrets/production.sops.env`. With the matching controller-local
recovery identity, use the [SOPS-backed quiet validation](sops-age.md#controller-local-compose-validation)
instead. It supplies inputs without creating a plaintext environment file or
starting containers.

These fixture tests do not contact Docker or hosts. Inspect other tests before
execution: some opt-in tests use Ansible or disposable infrastructure.
Use YAML parsing/lint and `tofu fmt -check` for relevant edits. Ansible syntax
checking needs the existing collections and inventory configuration; it does not
prove check-mode behavior or deployment readiness. Report missing dependencies
rather than automatically installing them.

`scripts/update-provider-locks` is **mutating manual maintenance**, not passive
validation: it runs `tofu providers lock` for five provider roots/three platforms
and only then checks Git differences. This includes the pinned Tailscale policy
provider. The script can contact providers and rewrite lock files; execution requires
separate approval. Keep the existing locks unchanged for source checks.
The misleading aggregate recovery rehearsal launcher has been removed.
For the opt-in Docker role test, read the
[disposable-fixture requirements](docker-version-admission-qualification.md) first:
it can change boot enablement and is not a production or ordinary local check.

### Offline contract source validation

With Node and the declared JS dependencies already available (no install or network
is performed), run:

```sh
node scripts/validate-contract
node scripts/controller/test-contract-source.js
node scripts/controller/test-contract-schema.js
node scripts/controller/test-restic-policy.js
```

The source-only validator checks configuration schema/semantics, source helper/package
bindings and generated Restic input parity. It does not read historical receipts,
the Offen retirement manifest, credentials, `.local` or `.reconcile`. Existing
legacy outcome fields are checked for structural consistency, not asserted as true.
Source success is **not backup health, restore qualification or deployment permission**.

Historical modes have been removed. `--historical-evidence` and `--operational`
explicitly exit with status 2 before validation; they never fall back to source-only
success. All other arguments are also rejected. Receipt requirements in
[operational consumers](decisions.md#why-legacy-code-remains), including first-run
finalization and lock release, remain unchanged.

The offline regression exports only source inputs into a temporary checkout, with
an empty home/environment, Node 24 read-only filesystem permissions, no subprocess
permission and network tripwires. Missing receipts and synthetic malformed receipts
must not block source checks; synthetic invalid configuration must fail. Retired
flags must exit 2 without printing source success, even with malformed inputs.
The other two tests inspect source and synthetic objects only, never execute host roles.

The closed [custody audit](decisions.md#custody-is-separate-from-receipt-cleanup)
leaves independent recovery access and two local qualification-state dependencies
unresolved. Those gaps do not block bounded receipt-dependency source cleanup;
working logging/backup configuration and operational safety gates remain unchanged.

## Intended native adoption workflow — not deployment authorization

1. Independently verify current SSH host keys, privileged accounts, console access,
   outstanding operations, mounts, timers and backups. Keep the old access route
   until standard SSH/become works independently. A normal privileged Ansible
   account can execute arbitrary root code; check mode and tags do not constrain it.
2. Per OpenTofu root, identify the actual backend/workspace and imported resource
   bindings before initialization. Use the existing partial backend declaration
   with reviewed nonsecret backend inputs; **do not add a duplicate backend block**.
   Keep provider locks and protected state history.
3. Once separately authorized, use native `init -lockfile=readonly`, `validate`,
   `plan -out=<private-file>`, privately review `show`, then apply that exact plan.
   Do not initialize against guessed buckets or run the VM9900 roots concurrently.
   A state lock serializes one state key, not UI/API writers or other tools.
4. Adopt benign Ansible domains using explicit inventory and become. Review
   check-mode limitations and the full changed scope. Keep storage, network,
   packages and reboot in separate maintenance windows. A second run should be
   genuinely idempotent, not merely match a normalized log.
5. Qualify one native Compose role with explicit project identity, protected
   environment, health waiting, no builds, reviewed pull/recreation policy and no
   implicit orphan/volume deletion. Bind-file changes require explicit service
   restart decisions. Database upgrades remain separate migrations.

## Stable application and host identities

The project name is `docker-compose`. Legacy delivery and recovery select these
paths explicitly, not the repository checkout or a checkout `.env`:

```text
/srv/docker-compose/current
/srv/docker-compose/previous
/srv/docker-compose/staging/<artifact-sha256>
/etc/docker-compose/production.env
/etc/docker-compose/previous.env
/etc/docker-compose/staging/<artifact-sha256>.env
/var/lib/docker-compose/current-images.json
/var/lib/docker-compose/previous-images.json
/var/lib/home-lab/production-image-override.json
```

Environment files remain `root:root 0600`. Preserve current/previous artifacts,
image sets and overrides independently; images cannot restore migrated databases.
The installed prune helper keeps rollback images and fails closed on missing or
ambiguous locks. Never substitute `docker image prune -a` or volume pruning.

VM100's source identity is Debian 13 `docker-host`, LAN `192.168.0.100`, tailnet
`100.116.163.42`. The deployment account is `ansible-deploy`; `docker` is the
interactive workload account. Native observation uses the existing Tailscale SSH
route. The fixed Proxmox firewall route and Restic-only recovery transport remain
installed. Obsolete Nix plan/apply routes were removed by the separately approved
installed-access retirement described above.
The guest key captured through Proxmox QGA and matched by tailnet keyscan is
recorded in `infrastructure/evidence/vm-100-debian-ssh-host-key.json`; that record
does not establish an independent LAN capture. Verify current trust rather than
accepting a new key on first use.

Keep `/srv/home-lab-state`, games UUID `31602ce7-0054-498a-9f24-f51ca491e7b3`
at `/mnt/games`, and the NFS mount identities intact. Backup temporary storage is
`/mnt/games/backups/.tmp`, `root:root 0700`, not the small root filesystem.

## Updates and application hooks

Updates and reboots are manual, separately reviewed operations. The native policy
above corrected the automatic-install settings found by observation. Legacy
cloud-init still contains older automatic-update policy and is not an adopted
bootstrap path. Package versions
alone do not freeze the full apt solution. Preserve package/reboot journals and
require post-boot mount, kernel, service and hardware checks.

Renovate retains digest-pinned isolated manual Docker updates, PostgreSQL-major
handling and provider locks. Merge is not deploy approval. Reporting workflows
were removed from source; actual remote jobs/settings have not been inspected.

Gluetun forwarded-port/MAM hooks, the LiteLLM callback, Caddy configuration and Wolf
assets remain application inputs. Wolf can create child containers via the Docker
socket: account for these writers in maintenance and backup. Keep its ports on
trusted networks and its generated pairings/profiles under `/mnt/games/wolf`.
ROMs, BIOSes, Steam downloads and regenerable scraped media are excluded from the
application-state backup.

Wolf host assets still need explicit installation/adoption: `wolf-input.conf` in
`/etc/modules-load.d/`, `85-wolf-virtual-inputs.rules` in `/etc/udev/rules.d/`, and
`waybar-disabled` (0755), `sway-borderless-frontends.conf`, ES-DE `es_systems.xml`
and `wolf-xbox-one.cfg` under `${GAMES_PATH}/wolf/cfg/`. The executable Dolphin
helper belongs at `${GAMES_PATH}/roms/dolphin-config/Configure Dolphin.sh`.
Modules are `uinput`/`uhid`. Move installation into Ansible during separately
approved host adoption; source-only edits do not install or reload these files.

## Observed baseline — 2026-09-14

The list below records the **pre-change** inventory, not current desired state.
The [manual-update policy](#manual-update-policy) subsequently corrected automatic
installation; other findings remain outstanding except as explicitly noted.

Read-only SSH and native Ansible observation succeeded on both hosts with effective
UID 0 and `changed=0`. This is a dated observation, not a configuration declaration
or proof of independent console custody.

- Debian guest: Debian 13.7, kernel `6.12.107+deb13-amd64`; packaged `docker.io`
  `26.1.5+dfsg1-9+deb13u1`, Compose `2.26.1-4`. All 38 observed containers were
  running; this is not an application correctness check.
- Proxmox: PVE `9.2.11` on Debian 13.6, kernel `7.0.14-14-pve`; VM100 running,
  VM9900 still present and stopped. ZFS pool `storage` reported ONLINE. VM100 boot,
  games and state disks retain the identities documented in migrations.
- Guest mounts: local games and application-state filesystems mounted; NFS
  `192.168.0.123:/storage/docker` mounted at `/mnt/storage`.
- Debian apt configuration has `APT::Periodic::Unattended-Upgrade=1` and its upgrade
  timer enabled. Tailscale auto-apply is false on Debian but **true on Proxmox**;
  checking is enabled on both. No settings were changed. PVE apt timers alone are
  not evidence of enabled unattended installation; its queried periodic settings
  were unset and `unattended-upgrades` was absent.
- Daily local/NFS and Proton backup units exited 0 on September 14 (05:09 and
  05:17 PDT); both schedules are enabled. No snapshots or data were restored or
  checked. Monthly Proton maintenance retains `ExecMainStatus=1` from September 1
  despite `Result=success` and an empty `SuccessExitStatus`. The journal and
  isolated probes identified the mount-confinement defect described above; full
  maintenance success remains unverified.
- Authentik's active bind contains PostgreSQL `18/docker/PG_VERSION=18`; the
  retained `postgresql-16/PG_VERSION=16` still exists. Nextcloud and its running
  cron container have the five intended data/configuration mounts. These facts
  supersede assumptions that those cutovers have not started; acceptance and
  rollback-retirement checks are still outstanding.
- Legacy helpers, the firewall watchdog, current/previous Compose artifacts and
  image locks remain installed. Three LiteLLM attempt directories remain. No
  systemd jobs or relevant held locks appeared in the sampled listings, and the
  guest production apply lock was absent; this does not resolve retained journals
  or establish an exclusive maintenance window. Nothing was cleaned up.

Provider state/imports, remote CI, independent recovery credentials/console, full
journal outcomes and restore integrity were not verified. OpenTofu is not on this
controller's current PATH; no tool installation or provider plan was attempted.
