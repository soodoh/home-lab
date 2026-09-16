# Recovery

## Honest capability boundary

The retained Restic path restores an **exact snapshot into private staging** with
native `restic restore --verify`. It is not a qualified fresh-server rebuild or
production activation procedure. `compose_recovery`/`activate-recovered-data.py`
still expect the older `backup/` archive layout; **never point that activator at a
Restic staging tree** or relax its guards. The contract advertises staging only.
The old generic controller is removed, not an alternative recovery path.

Keep independent recovery access, protected state, credentials, current/previous
application generations and all retained operation journals. A failed or ambiguous
operation requires inspection and a specific recovery decision, not lock deletion.
The closed [custody audit](../docs/decisions.md#custody-is-separate-from-receipt-cleanup)
separates remote provider state from unresolved independent recovery access and
two local qualification-state dependencies. The operator owns external-escrow
verification; metadata alone does not qualify recovery.

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
   their tool/runner/source bindings are not waived by source simplification.
4. Prepare an empty root-owned mode-0700 `/srv/home-lab-recovery/restic-*` directory;
   its real non-symlink parent must be root-owned mode 0700 or 0750. Keep plaintext
   off the small system disk and preserve production/user-data paths.
5. Supply the protected environment inputs required by
   [`restore-critical-backup`](../scripts/restore-critical-backup), then run:

   ```sh
   scripts/restore-critical-backup --restic-snapshot-id <64-hex-id> --confirmed-empty-target
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
evidence below. [Operational outcomes](../docs/operations.md#latest-scoped-deployment)
and [mount probes](../docs/operations.md#proton-maintenance-unit) do not prove
snapshot integrity, full maintenance success or restore readiness.
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
production identity `/etc/sops/age/keys.txt` (0600, parent 0700), independent identity
and GPG escrow under `~/.config/sops/home-lab-recovery`. The recovery key is currently
on the developer machine; custody of the documented external ciphertext copy remains
unverified. Independent off-machine custody is an open gap, not established recovery access.
Bootstrap must not overwrite rotating rclone client state. Obscured rclone values
are plaintext-equivalent. Restore/rotate credentials only with independent recovery
proof and without logging values or reusing historical transaction confirmations.

## Host/network and interrupted-operation recovery

Retain the distinct [bootstrap, session and autonomous firewall protocols](../docs/legacy-host-recovery.md).
These are emergency references, not enabled new writers. The host-session protocol
has no standalone status/rollback CLI; a retained-session recovery needs a
separately reviewed invocation.
Preserve strict host-key checking, independent console, VM100 disk identities,
ZFS topology, NFS mount/export state and selected VFIO helper/policy. The deploy
transport also handles Restic recovery network identity and snippet staging/removal;
removing it would strand recovery. A network-disconnected controller cannot execute
Ansible rescue; the firewall's persistent watchdog must remain available.

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
VM9900 belongs to Debian lifecycle qualification: leave it unchanged and never apply
an old Proton destroy plan. Its continuation/retirement is a separate task.

VM9900 restore fixtures demonstrated staging/structural validation without running
applications (historically 22,031 files/6,982,221,998 bytes); they did not qualify
production activation or clean rebuild. Recovery and lifecycle qualification roots
share VM9900 on production PVE: separate local state is not hypervisor isolation.
Check actual VM/disks/snippets/ACLs/firewall/keys and failed-operation lineage before
any use or cleanup. Retain transaction directories when plaintext cleanup fails.
The eight-hour recovery objective remains unqualified until a timed end-to-end
isolated exercise succeeds. None of these live gates is satisfied by source tests.
