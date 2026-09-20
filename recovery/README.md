# Recovery

## Honest capability boundary

The generic Restic path restores an **exact snapshot into private staging** with
native `restic restore --verify`. It is not yet a qualified fresh-server rebuild or
production activation procedure. It is the only supported Compose-data disaster
recovery flow: the older archive activator and service-specific migration recovery
paths are retired rather than retained as competing interfaces.

`recovery/groups.json` declares recovery groups as data. `restore-critical-backup`
accepts either `--all` or one or more `--recovery-group NAME` arguments. A partial
restore includes the selected groups' exact Restic paths plus common protected
Compose environment input; it does not imply production activation. The encrypted
bundle consumer accepts the same repeated group option and defaults to all groups.

Keep independent recovery access, protected state, credentials, the matching tracked
application generation and all retained operation journals. Preserve transaction-local
before-images while an owner is retained. A failed or ambiguous operation requires
inspection and a specific recovery decision, not lock deletion.
The [custody decision](../docs/decisions.md#custody-is-separate-from-receipt-cleanup)
separates remote provider state, independently held key material and actual bundle
retrieval. The operator-confirmed offsite USB closes age-key location custody, but
metadata and key possession alone do not qualify AWS access, bundle retrieval or
recovery.

Future native actions must not depend on a previous runner's local validation
artifacts or committed success receipts. Re-observe current host state and preserve
durable ownership, journals, before-images and independently available protected
recovery state so runner loss is recoverable. The current
[native generation activation](../docs/compose-generation-activation.md) keeps
transaction-local artifact/environment publication, coordination, Compose health and
final zero-change checks, but no longer creates or consumes deployment image
checkpoints.

Ordinary Compose rollback is a Git revert plus authoritative
`ansible/playbooks/site.yml` convergence from the latest reviewed automation. Missing
old images are pulled by their tracked exact digest; registry and network availability
are accepted dependencies. Do not activate an old automation checkout or local image
ID as a generic rollback transaction.

Service-specific Nextcloud migration rollback, older archive activation, Compose
image locks/action plans and previous-artifact activation are retired. Ordinary
configuration rollback remains a Git revert plus authoritative native site
convergence. Disaster recovery remains the generic Restic staging flow above;
database ordering and production activation must be implemented generically from
recovery-group metadata before they can be claimed as qualified. Historical
September 19 recovery results do not establish independent custody or make a healthy
service a restore test. See the
[disposable-controller decision](../docs/decisions.md#disposable-controllers-and-live-validation).

## Select and restore to staging

This procedure requires separate operational approval; it is not a source check.

1. Establish independent console/network access, no conflicting production apply,
   backup or restore, and trustworthy binary/mount identities. Inspect interruption
   state before starting anything. Never format or initialize a repository because
   its mount or password is unavailable.
2. Select one exact 64-hex snapshot and repository ID, policy hash and artifact
   hash from reviewed evidence. Confirm the snapshot's `cadence=daily`, policy and
   artifact tags and copied-snapshot ancestry. Historical snapshots below are
   provenance, not automatic choices for today's restore.
3. Retrieve a verified independently encrypted bundle if the host is unavailable.
   `build-restic-recovery-bundle` and `run-restic-recovery-bundle` retain this path;
   their tool/runner/source bindings are not waived by source simplification. The
   [current bundle record](current-restic-recovery-bundles.md) separates the
   secret-free metadata plan, completed local encrypted build and still-unauthorized
   publication/decryption/restore phases.
4. Prepare an empty root-owned mode-0700 `/srv/home-lab-recovery/restic-*` directory;
   its real non-symlink parent must be root-owned mode 0700 or 0750. Keep plaintext
   off the small system disk and preserve production/user-data paths.
5. Supply the protected environment inputs required by
   [`restore-critical-backup`](../scripts/restore-critical-backup), then run:

   ```sh
   scripts/restore-critical-backup --restic-snapshot-id <64-hex-id> \
     --confirmed-empty-target --all

   # Or restore one or more declared groups:
   scripts/restore-critical-backup --restic-snapshot-id <64-hex-id> \
     --confirmed-empty-target --recovery-group nextcloud
   ```

   `RECOVERY_TARGET`, `RECOVERY_RESTIC_REPOSITORY`, password-file path, expected
   repository/policy/artifact IDs and binary hashes are required; Proton adds the
   pinned rclone hash and its protected config or environment-only remote fields.
   These are environment inputs, not automatic reads of the Ansible
   [`extra-vars.example.yml`](extra-vars.example.yml). Keep passwords/keys out of
   arguments, shell history, terminal output and Git. The password file is owned
   by the effective user, single-link, regular mode 0400/0600.
6. Require native verification, inspect representative configuration and database
   integrity without starting services, and record only secret-free identities
   and outcomes. Production activation remains blocked pending an isolated tested
   procedure with stopped writers, preservation rules and interruption recovery.

The completed [Nextcloud and Calibre restore rehearsal](nextcloud-calibre-restore-rehearsal.md)
binds this staging procedure to an exact natural local snapshot and explicit
migration-retirement checks. The follow-on
[Nextcloud isolated logical recovery plan](nextcloud-isolated-recovery-plan.md)
separates database, application-control-plane and external-user-data claims. Its
[detached-NIC isolation design](nextcloud-detached-nic-isolation.md) evaluates a
firewall-confined retrieval phase followed by physical virtual-NIC removal; it is not
provider or firewall authority. None of these documents grants execution authority.

Allowed repositories are `/mnt/games/restic/home-lab`,
`/mnt/storage/restic/home-lab`, installed
`rclone:proton-backup:Backups/home-lab-restic`, or the bundle's environment-only
`rclone:proton_backup:Backups/home-lab-restic`. The underscore form is intentionally
separate: no cached client credentials, caching false, optional protected TOTP,
`RCLONE_CONFIG=/dev/null`. Never copy Restic repository directories with rclone,
use `rclone sync`, or restore directly over `/srv/home-lab-state`/with `--delete`.

## Backup consistency and exclusions

The retained runner accepts `preflight`, `daily-local`, `daily-proton`,
`maintenance`, `status`. It records originally running writers durably, stops
applications before databases, snapshots locally, restores only those writers,
and accepts/copies to NFS before Proton. NFS failure must not prevent the local
snapshot; pending replicas must survive retention. Every nonzero Restic result,
including exit 3, is failure. The interruption journal drives boot-time recovery.
Preserve its owner and restart intent across controller or host failure.

Source declares one non-persistent 05:00 daily target (local/NFS then confined
Proton) and one non-persistent monthly maintenance target; no independent Proton
timer. Preserve actual enabled/active states; legacy activation still requires the
evidence below. The September 19
[passive observation](../docs/operations.md#latest-passive-backup-observation--september-19-2026)
matched one current, fully copied September 18 games → NFS → Proton chain with zero
pending entries and a source age below 24 hours. It used `--no-lock --no-cache` reads
and ran no backup or maintenance; it is point-in-time chain/RPO evidence, not restore
integrity. Other [operational outcomes](../docs/operations.md#latest-host-configuration-deployment)
and [mount probes](../docs/operations.md#proton-maintenance-unit) likewise do not
prove snapshot integrity, full maintenance success or restore readiness.
`restic-proton` stays UID/GID **60000**, without login, supplementary groups or
production-tree access. Do not reuse the historically conflicting UID 999 or
recursively chown application data. Preserve `/run/lock/home-lab-backup.lock` and
its root:60000 ownership/coordination.

The contract and rendered `services/data/restic/{files-from,excludes}` still own
backup scope. Native [runtime-file adoption](../docs/operations.md#same-content-backup-runtime-files)
is same-content metadata maintenance, not a recovery installer. Content/tool-policy
changes require coordinated policy/journal review, never receipt regeneration.
Preserve path classes: `replace-tree`, `replace-entries`, `preserve`,
`regenerate`, `retain`, `external`; they are not interchangeable. External-data
services remain `state-restored-user-data-pending` until independent data is
available. Nextcloud `/mnt/storage/media/nextcloud/data` is never populated,
replaced or deleted by application-state recovery. Calibre's complete local
library is included; NFS rollback, Caro's split storage and Nextcloud migration
instructions are in [migrations](../docs/migrations.md). ROMs, BIOSes, downloads,
Steam game data and regenerable scraped media need separate retention. Wolf child
containers are writers too; preserve generated profiles and pairings.

## Tools, credentials and historical incident facts

Retain Restic **0.19.1**, archive SHA-256
`f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c`,
and rclone **1.76.0-beta.10267.220fe7619**, archive SHA-256
`8d836165cfc92b273f8735dc91e4158c55267dfa69f9e35ed838805802a89dec`.
Installed-binary hashes are separate and remain in source policy/bundle inputs.
Upgrades need coordinated runtime-policy/bundle inputs and Proton qualification,
not independent pin bumps. Native [tool configuration](../docs/operations.md#pinned-backup-tools)
is existing-policy-bound, not backup bootstrap or recovery proof.
rclone 1.75.0 could report successful uploads with truncated Proton packs (upstream
#9722; fix `a06df7a2de46ee15932a0fbfa27bc4bb0045acf8`). A stable replacement needs
its own pinned backend/full-data restore proof; source deletion does not qualify it.

The promoted canonical Proton repository ID is
`dce8dbc3cde106047631317a09257c23ee5eab4d9ece5f88d52108ae384a8503`,
historically verified with snapshot
`a42e4694ac164d62bb1c815144ea6407f70ab1e8ee91c54f293b2acdb77dcfea`.
`proton-qualified-promotion.json`, `proton-canonical-recovery-vm.json` and
`proton-incident-resolution.json` under `infrastructure/evidence/` supersede the
old incident freeze. Terminal resolution SHA-256 is
`7f44b0883b87541f662750adbf4b0b24a515fa8815e7ddb675a6311a1ec42d4d`;
old `cleanup-started`/`copied` journals remain immutable, not retry instructions.
The operator subsequently reported emptying account-wide Trash manually: previously
trashed incident artifacts must be treated as permanently deleted. Automated Trash
cleanup is not maintenance. Keep the 100 GB free-space reserve; warn at 100 GB used
or ten times active repository size, whichever is greater.

The first post-incident daily canary mapped games
`3877b600d37c2f2003af9e765f137da8175fee473fda7b1b2407c97b1898de76`
to Proton `4ae03d04658d45a25534008a26b642722f35d08839e3fb4e3c0e4d8de31760d2`.
This old success does not prove fresh backups. The role still gates scheduling on
`restic-restore-proof.json` SHA-256
`b68550eb34e3c8b3832ae9ddf64857364b54538a719cc9501620cb3fd0735f0f`
and terminal `offen-retirement.json` SHA-256
`5bd285796ab04d9cc7370768fae2ed284215492c76791cd75b01d22950fde2d0`.
All manifest-bound local Offen archives were retired. The last
`daily-local-backup-2026-08-23T05-00-00.tar.gz.gpg` (2,411,062,883 bytes,
SHA-256 `8034bcf7a03d19c446a23c30a56c1b9a8c4ffdd2d829557a5a16e39c0aab1f08`)
is historical proof, not an available fallback. Its restore evidence remains
`offen-final-archive-2026-08-23-restore-proof.json`.

Keep two independent encrypted bundles: A in protected local custody, B in
versioned KMS-encrypted AWS recovery storage. Canonical bundle B ciphertext
SHA-256 `4b62aaa4857ec68822392752d3cce758af981e106b79d8cb969cd6538bb14164`
is recorded in `proton-canonical-recovery-bundles.json`; verify the selected current
version privately. Publication credential rotation evidence remains
`aws-recovery-publication-credential-rotation.json`. The encrypted publication
credential at `secrets/recovery-publication.sops.json` is controller-only, never
part of the Compose artifact or production installation.

[SOPS/age custody and decryption constraints](../docs/sops-age.md) remain required:
production identity `/etc/sops/age/keys.txt` (0600, parent 0700), the controller-local
independent identity and its operator-confirmed exact copy on an offline offsite USB.
The USB is the canonical independent key path; the home Vaultwarden copy is only a
convenience, and historical GPG ciphertext is a preserved optional legacy envelope.
The separately authorized [AWS retrieval drill](aws-bundle-retrieval.md) used the
operator-accepted equivalent controller copy and proved publication-credential,
AWS/KMS and exact historical bundle access on September 19; it did not decrypt the
bundle or prove a current recovery point. Bootstrap must not overwrite rotating
rclone client state. Obscured rclone values are plaintext-equivalent.
Restore/rotate credentials only with independent recovery proof and without logging
values or reusing historical transaction confirmations.

## Host/network and interrupted-operation recovery

Retain the distinct [bootstrap, session and autonomous firewall protocols](../docs/legacy-host-recovery.md).
These are emergency references, not enabled new writers. The host-session protocol
has no standalone status/rollback CLI; the current Nix freeze also rejects
`apply` before retained-session recovery. A retained-session recovery needs a
separately reviewed invocation, not an unfreeze or rewritten source hashes. The
[source retirement assessment](../docs/legacy-nix-retirement.md) traces remaining
historical installers, consumers and native replacement boundaries. The final
bounded inspection found every bootstrap/access interruption journal absent, so
the forward installers and their active-checkout recovery dispatchers were retired
with the Nix tree. Their exact source remains at Git checkpoint `d7a4e208` and in
the preserved old host checkout; that historical code is not standing mutation
authority. Previous-generation/install-manifest records, sealed inputs and before-images
remain intact. The approved September 17 installed cleanup removed the obsolete
observer/private-preparer/plan/deploy generation and disabled obsolete account
shells while preserving those records. Autonomous firewall recovery is independent
and unchanged.
Preserve strict host-key checking, independent console, VM100 disk identities,
ZFS topology, NFS mount/export state and selected VFIO helper/policy. The dedicated
Proxmox Restic transport and its snippet staging/removal path are retired; do not
reconstruct them. The Docker-host `ansible-deploy` lifecycle/recovery route remains,
but it is not independent recovery access. A network-disconnected controller cannot
execute Ansible rescue; the firewall's persistent watchdog must remain available.

For an interrupted native Compose deployment, keep the durable production owner.
After artifact publication or partial container convergence, inspect exact owner,
source/artifact/environment identities, running containers, native preview, health
and Restic state. Prefer completing the exact committed desired state with current
automation. If owner adoption is necessary, create a narrow reviewed entrypoint using
`apply_lock` `adopt`, bound to the exact owner SHA-256, operation, controller and
source/artifact identities; release only after health and a zero-change full preview.
Do not clear ownership or recreate an image checkpoint.

For a failed `restic_backup` convergence, inspect the exact owner at
`/var/lib/iac-ansible-production.lock`. The retained `clear-failed-apply-lock.yml`
requires `iac_failed_lock_expected_operation=restic_backup` and separately approved
`iac_lock_clear_confirmed=true`. This is not generic permission to clear backup
qualification, initialization, first-run, firewall or retirement transactions.
Use their exact journal-aware recovery paths after inspection. Never rerun a
completed incident operation or delete lock/retirement artifacts to unblock work.
The [Proton source retirement audit](../docs/proton-source-retirement.md) records
exact recovery receipts and read-only host checks supporting removal of the completed
password-reset/authentication writers and one-off staged qualification supervisors.
Their immutable evidence is still consumed by generic qualification/empty/resume
recovery. The audit is canonical for VM lineage, historical plaintext-cleanup limits,
transport succession and [pending historical-material choices](../docs/proton-source-retirement.md#historical-material--disposition-choices-pending-approval).
For inactive attempts, **historical outcome unknown; attempt abandoned; no replay**
does not certify cleanup or release files with surviving consumers. Current bundles,
identities, consumer-required evidence and active recovery capabilities remain.
VM9900 and both provider-owned import images are retired through their exact owning
states; those states now contain no resources. The dedicated Proxmox capability and
Tailscale grants are also retired, and callable VM9900 source is removed. Never apply
an old Proton or qualification plan, reconstruct a retired root against the preserved
state, use `state rm`, erase lineage or treat closure as permission to reuse VMID
9900. The [retirement assessment](../docs/vm9900-retirement-assessment.md) records the
exact plans, live-policy binding and postconditions. Preserve all ignored `.local`,
`.reconcile` and `.terraform` generations, journals, plans, receipts, diagnostics,
capability evidence and recovery inputs.

The historical VM9900 restore fixtures demonstrated staging/structural validation
without running applications (22,031 files/6,982,221,998 bytes); they did not qualify
production activation or clean rebuild. Generic Restic bundle, restore and critical
backup recovery remain supported independently of the removed VM harness. Retain
transaction directories when plaintext cleanup fails. The assessment-only eight-hour
service-recovery criterion remains unqualified until a timed end-to-end isolated
exercise succeeds.
Source tests and the retired VM harness do not satisfy that live recovery gate. The
[current readiness assessment and qualification plan](../docs/recovery-readiness-assessment.md)
separates independent staging proof from service activation and lists the required
admission, custody and authorization gates.
