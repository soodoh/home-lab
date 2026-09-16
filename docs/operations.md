# Operations

## What is available now

Supported native scope is observation, manual-update policy and guarded existing-host
backup configuration (tools, account, same-content runtime files and nine unit
definitions). [Dated outcomes](#latest-scoped-deployment) do not expand that scope.
Broader host/application adoption is pending: there is **no supported general deploy
or host-convergence command**. `proxmox-audit.yml` is only an audit; Debian `site.yml`
still includes lifecycle, lock and backup prerequisites. Directly invoking retained
mutation roles is not an approved replacement for the removed controller.

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

The next target is ordinary OpenTofu saved plans and
`community.docker.docker_compose_v2`. That collection and a native deployment role
have not been adopted here. Observation does not authorize configuration changes.

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

## Local source checks

From the repository root, without deployment or secret decryption:

```sh
docker compose config --quiet
python3 -B scripts/test-compose-artifact.py
python3 -B scripts/test-compose-action-plan.py
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
validation: it runs `tofu providers lock` for five roots/three platforms and only
then checks Git differences. It can contact providers and rewrite lock files;
execution requires separate approval. Keep the existing locks unchanged for source checks.
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
route. Fixed Proxmox transports remain installed for legacy consumers; no access
route has been removed or replaced.
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
