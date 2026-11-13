# Recovery

Recovery begins with live repository discovery and ends at a verified private staging
directory. Production activation is not yet qualified.

## Scope

The `books` group includes the NFS library roots `/mnt/storage/media/books` and
`/mnt/storage/media/audiobooks`, both Tachidesk download roots
(`/mnt/storage/media/tachidesk` and `/mnt/storage/media/caro-tachidesk`), and local
Grimmory/Tachidesk database/application state. Restore checks must validate local
state and the NFS content together. The NFS
repository is on the same export as the live library; use games or Proton for
independent recovery if that storage is lost.

[`groups.json`](groups.json) maps named service groups to managed paths. The common
protected Compose interpolation environment and credential-file directory are
included in every scope. Individual credentials remain plaintext after a restore;
keep staging private and preserve their declared ownership/permissions. Nextcloud
user data at `/mnt/storage/media/nextcloud/data` is included, along with its
configuration and logical database export. Nextcloud Redis is excluded: it
contains cache, locks and sessions; an isolated recovery starts it empty and
users log in again. Never flush production Redis during capture or restore.

Validate the resolver and recovery tools locally:

```sh
scripts/test-recovery-tools
```

CI additionally runs `scripts/test-restic-native-restore` with the checksum-pinned
Restic binary in a disposable Linux mount namespace. It exercises the unchanged
restore helper against a real local repository, checks restored bytes and verifies
that group selection includes common paths but excludes unrelated data. The
synthetic guard/bundle fixtures do not themselves qualify Restic or Proton.
Never run the native fixture directly on a managed host.

## 1. Observe current repositories

From a fresh reviewed checkout:

```sh
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/playbooks/observe-backups.yml
```

Use the default **strict** observer to select current-artifact protection with an
exact NFS match. Proton may lag this capture by at most 48 hours; independently select and verify its
actual copied snapshot when it is the recovery source. Routine admission uses
bounded capture-time lag and may accept an earlier artifact.

The observer refuses active owners, opens each live repository and reports current
repository IDs, policy/artifact identities and latest snapshots. Select one chain
from this output. Do not use a snapshot ID copied from Git history or a previous run.

Before restoring, independently confirm:

- the selected snapshot's `policy=` and `artifact=` tags;
- Proton copied-snapshot ancestry where Proton is the source;
- tool checksums against the current reviewed host variables;
- the target is a new empty root-owned directory directly below
  `/srv/home-lab-recovery`.

## 2. Stage a restore

[`scripts/restore-critical-backup`](../scripts/restore-critical-backup) accepts either
`--all` or one or more `--recovery-group NAME` arguments plus the exact
`--restic-snapshot-id`. It requires protected environment bindings for the repository,
password file, repository ID, policy/artifact identities and tool checksums.

Example shape, with values supplied from the current observation through a private
environment rather than shell history:

```sh
RECOVERY_TARGET=/srv/home-lab-recovery/restic-<reviewed-name> \
RECOVERY_RESTIC_REPOSITORY=<live-repository> \
RECOVERY_RESTIC_PASSWORD_FILE=<protected-file> \
RECOVERY_EXPECTED_RESTIC_REPOSITORY_ID=<live-id> \
RECOVERY_EXPECTED_POLICY_SHA256=<live-policy> \
RECOVERY_EXPECTED_COMPOSE_ARTIFACT_SHA256=<live-artifact> \
RECOVERY_EXPECTED_RESTIC_SHA256=<reviewed-tool-digest> \
  scripts/restore-critical-backup \
    --restic-snapshot-id <live-snapshot-id> \
    --recovery-group identity \
    --confirmed-empty-target
```

Proton additionally requires the current protected rclone configuration or the
explicit recovery-only `RCLONE_CONFIG_PROTON_BACKUP_*` environment and current rclone
digest. The helper validates repository identity, snapshot identity, copied ancestry,
tags, target ownership and restored data before success.

### Proton chunker storage format

Use the exact reviewed inline chunker repository URL from the current policy
(or the recovery-only `proton_backup` equivalent carried in bundle metadata). It
contains the 3 MiB chunk size, SHA-1 transport hashes, simple JSON metadata, chunk
naming, rename transactions and fail-closed missing-chunk policy. No additional
credential or hand-written reassembly program is needed: stock rclone reconstructs
the encrypted Restic objects transparently. Keep these nonsecret settings with
the independently protected recovery tools; do not depend on the surviving host
or memory to reconstruct them.

The raw Proton folder contains both ordinary historical objects and chunked
objects plus metadata. Its direct, unwrapped URL is not interchangeable with the
overlay. Missing pieces/metadata must fail recovery, not be skipped. The legacy
unwrapped recovery contract remains for genuinely unwrapped repositories; it is
not a fallback for a damaged chunked repository. Changing or removing the overlay
requires a reviewed conversion, not simply editing a URL. Local/NFS recovery is
unchanged.

Keep the restore private. Inspect application paths, database integrity and
representative content without printing private filenames or values.

### Complete capture format (full-v2)

Physical historical snapshots remain supported unchanged. New complete snapshots
have `format=full-v2` and `complete=full-v2` tags. Only an exit-0 local backup is
completed; partial/unqualified captures must not be selected. Legacy snapshots
must have no `format=` tag; unknown or conflicting format tags are refused before
restoring any files.

The helper verifies Restic bytes then uses `prepare-restic-files.py` to move
captured files into their original relative layout beneath private staging.
SQLite online exports replace their live file at that path, without stale
WAL/SHM/journal files. Cold-copied databases retain their complete physical set;
never combine restored files with journals left in an existing destination.
Logical exports and native archives remain in `recovery-exports/`:

- `databases/authentik.dump`: native PostgreSQL custom format, for `pg_restore`
  into an empty compatible database with separately reviewed roles/ownership.
- `databases/books.sql`, `databases/nextcloud.sql`: native MariaDB logical
  exports for compatible empty databases. Restore database and coupled files
  from this same capture before enabling application/background writers.
- `native/jellyfin.zip`: use Jellyfin's supported backup restore facility with
  the compatible pinned application. It includes metadata/subtitles but not
  generated attachments/fonts, trickplay or transcoding caches. The file layout
  also holds configuration/plugin files and online auxiliary SQLite exports.
- `manifest.json`: format, policy/artifact/owner identities, capture timestamps,
  database descriptors, Wolf symlink mappings and the exact ZFS source receipt
  when Nextcloud uses snapshot-backed capture. Follow these mappings when
  reconstructing original links; the helper never activates host links.

Group selection filters ordinary file paths; native/SQL exports and the manifest
are included as explicit recovery inputs, not automatically imported. A group is
a recovery convenience, not an authorization boundary or an independent snapshot.
The preparer does not unpack archives, connect databases or start containers.

Coverage includes both Tachidesk download trees, karaoke database/configuration
(not bulk karaoke media), Frigate exports (not rolling recordings/previews),
both production ACME stores/private keys and selected Wolf saves/settings.
Wolf selection covers Steam userdata, save-bearing Proton user directories and
registry files, never whole Steam installations/prefixes. The native /home/retro launcher/icon links are mapped into their owning host
profile. Wolf must have no sessions/lobbies or other running profile writers;
backup refuses active gaming rather than killing/recreating ephemeral apps.
Unknown external or broken link mappings fail closed pending inspection; no complete gaming coverage
is claimed until the live selection and representative restores are qualified.

Nextcloud user files retain their original staged layout even when Restic reads
through a temporary read-only NFS snapshot mount. The ZFS snapshot is a temporary
source, not the recovery destination: recovery needs only the encrypted Restic
snapshot and its independent keys, not a surviving ZFS pool or snapshot. Restore
the SQL export and captured configuration/data from the same capture. Snapshot
cleanup after local completion does not remove the Restic recovery set.

### Scope-specific rescue captures

A manually approved `scope=nextcloud-rescue-v1` snapshot is deliberately **not** a
complete lab capture or deployment-admission baseline. It has no `cadence=daily`
or `complete=full-v2` tag and is outside automated daily replication/expiry. Native
`restic snapshots --tag scope=nextcloud-rescue-v1` discovers these live; use native
`restic restore --verify` into a new protected private target. Inspect its scoped
`manifest.json`: `files/` holds original-relative paths, `databases/nextcloud.sql`
is a logical export and the image pins identify compatible import tools. The
archive's private capture prefix is not a production destination. Do not force
these captures through the full-v2 normalizer or treat a successful SQL import as
production activation. Offsite copy and eventual disposal require explicit review.

### Other application coverage

Home Assistant includes the complete configuration and consistent database plus
ZHA native network backups. Z-Wave includes store/security keys and actual fresh
scheduled NVM files. Use supported radio migration/recovery tools; files alone
cannot guarantee replacement-hardware compatibility.

CLIProxyAPI is never stopped for capture. Codex per-file locks and bounded JSON
validation protect online reads; other provider/concurrent writers remain a
residual risk. Restored tokens can already be expired, rotated or revoked.

## 3. Optional encrypted recovery bundle

[`scripts/build-restic-recovery-bundle`](../scripts/build-restic-recovery-bundle)
builds one deterministic plaintext archive and encrypts it directly to an age
recipient. Its metadata is a current observation projection with exactly:

- version and repository path;
- current repository and snapshot IDs;
- original snapshot ID for a copied Proton snapshot;
- current policy and Compose artifact digests;
- current Restic, rclone and restore-runner digests.

Historical receipt or qualification hashes are intentionally absent. Build metadata
in a mode-0600 file inside a new mode-0700 temporary directory, using the current live
observation. Supply bundle credentials only through the documented
`RECOVERY_BUNDLE_*` environment. Store the encrypted result and its age identity in
independent protected locations; neither belongs in Git.

[`scripts/run-restic-recovery-bundle`](../scripts/run-restic-recovery-bundle) is for a
fresh disposable recovery VM. It refuses host tokens and host recovery state,
verifies every member and binding, and stages the selected groups into the fixed
private target.

## Interruption and cleanup

A recovery lock or workspace on a managed host remains authoritative while the
operation is incomplete or ambiguous. Inspect and resolve it on that host. Do not
replace it with a controller-side receipt.

After a verified terminal run, remove plaintext credentials, decrypted bundles and
temporary workspaces. Retain only independently protected recovery material required
for the next disaster. Logs and Git history provide historical context; no outcome
file is committed.

## Production activation

A Git revert followed by authoritative site convergence rolls back configuration;
it does not restore application data.

Do not copy staged data over production or start services from this runbook.
Activation must define writer exclusion, database validation, external-storage
handling, exact before-images, rollback and post-activation health for the selected
scope. Until that interface is implemented and qualified from a fresh snapshot,
private staging is the supported completion boundary.
