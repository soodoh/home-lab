# Nextcloud 34 configuration and maintenance runbook

This is a retained migration/recovery reference, not a deployment quick start.
The September 14 observation found the five intended mounts and cron already
running; **do not rerun forward migration or initial activation**. Application
acceptance and old-copy retention still require verification. See
[migrations](migrations.md) for outstanding gates.

## Review boundary

Any separately approved recovery or maintenance requires:

- a clean reviewed commit and clean working tree;
- the independently restored pre-change config/theme recovery point;
- the current reduced database backup and canonical SOPS/recovery material;
- no active deployment, backup, restore, database maintenance, or storage migration;
- at least 2 GiB free under `/srv/home-lab-state`;
- old `/mnt/storage/media/nextcloud` application copies retained for seven days after full proof.

The external `/mnt/storage/media/nextcloud/data` tree remains under its existing
retention decision. It is mounted in place and is never copied into, restored over,
or deleted with managed application state. The other four mounts hold managed
application code, config, custom apps and themes under `/srv/home-lab-state`.

## Historical staging and five-mount migration

The original forward procedure is in Git history for this file (baseline
`1165675`). Its paired `stage-compose.yml` and `deploy-nextcloud-migration.yml`
plays remain source/recovery dependencies, not a supported native deployment path.
The procedure required an exact `compose_artifact_hash` and
`compose_artifact_controller_dir`, lock-held metadata-preserving/checksum
synchronization, stopped writers, activation of four local paths and proof that
the external-data device/inode was unchanged. It allowed no image-version changes
or removal of old NFS application/config copies. It required an explicit Caddy
restart for changed bind-mounted configuration and initially stopped cron/backup
schedulers. These requirements are not completed acceptance proof.

Staging confines canonical SOPS decryption to a root-only temporary directory and
materializes these root-owned mode-0600 files without logging values:

- `/etc/docker-compose/credentials/nextcloud-mysql-password`;
- `/etc/docker-compose/credentials/nextcloud-mariadb-root-password`.

Retain the selected artifact hash, current/previous artifacts and environments,
image locks, old paths, database recovery point and any migration journal before
reviewing rollback. Reconcile actual service/timer state rather than substituting
new names into the historical procedure.

## Web proof before cron

These remain acceptance checks, not instructions to start already-running cron:

- `occ status --output=json` reports installed, not in maintenance mode, and no database upgrade;
- `/var/www/html/data` resolves to `/mnt/storage/media/nextcloud/data`;
- config, current themes, and any custom apps are visible;
- login, representative file listing/read, WebDAV, and a representative upload succeed;
- HTTPS URL generation remains correct;
- only Caddy at `172.23.0.250` is trusted and real client addresses are correct;
- the external response contains exactly `Strict-Transport-Security: max-age=15552000`;
- Compose inspection and logs contain file references, not password values.

## Start cron and observe native maintenance

Initial cron startup is historical. Verify `/cron.sh` as PID 1 and the installed
five-minute `cron.php` schedule; observe at least two cadences under separate
operational approval. Do not manually execute arbitrary queued job IDs.
Record only aggregate, secret-free evidence:

- last-cron timestamp and pending-job count;
- class counts and last-run values for native upload cleanup and `OC\Log\Rotate` when registered;
- upload-staging bytes and oldest timestamp;
- current and rotated log sizes.

The pre-change queue contained metadata jobs but no registered `UploadCleanup`
class. Let normal cron register or run the current native cleanup path. Never use
`rm` in user upload directories. Investigate permissions or exact job errors if
stale chunks are not removed natively. Delete the oversized rotated log only after
native rotation is proven and an exact private cleanup manifest is separately approved.

## Database maintenance

Each operation requires separate approval during the UTC maintenance window
beginning at hour `6`, fresh setup checks and a proven database recovery point.
The historical sequence was `occ setupchecks --output=json`,
`occ db:add-missing-indices`, `occ maintenance:repair --include-expensive`, then
setup checks again, as `www-data`. A reviewed invocation must bind the explicit
[production project/artifact/environment](operations.md#stable-application-and-host-identities),
not checkout Compose defaults.

For non-DYNAMIC tables, use only the documentation URL and exact affected table
names emitted by the installed Nextcloud 34 setup check. Do not copy SQL from an
older release. Re-run setup checks immediately afterward and restore the database
on any database error through a separately reviewed recovery invocation.

Classify recent log errors without recording private paths, filenames, tokens or
user content. AppAPI, single-server ID, SMTP, 2FA enforcement, monitoring and direct
upload-directory cleanup remain scope exclusions.

## Rollback

The retained `ansible/playbooks/rollback-nextcloud-migration.yml` requires a reviewed
rollback plan, the old paths and previous artifact, and:

```text
compose_rollback_nextcloud_migration_confirmation=rollback-reviewed-nextcloud-five-mount-migration
```

Its historical bounded rollback stops cron/web/backup writers, removes only the
new cron container and converges the previous **41-service** artifact against the
untouched old parent mount, retaining new paths for diagnosis and never modifying
external user data. That service count and its Offen scheduler assumptions are
historical, not a currently runnable recovery recipe. A separately reviewed
invocation must reconcile these with actual retained inputs; do not guess a
replacement or run the play unchanged merely because it remains in source.

## Recovery and cleanup gate

Before old-path deletion:

- inspect and safely run the focused `scripts/test-restic-recovery-bundle` and `scripts/test-restic-restore-branch` checks;
- separately rehearse a fresh restore of config, custom apps/themes, MariaDB, SOPS-backed secret files and pinned application code while retaining external data;
- prove the previous-artifact rollback;
- confirm representative user-file counts and hashes are unchanged;
- retain old copies for seven days after these proofs.

Build a private exact-path cleanup manifest with device, inode, size, mtime and
path identities. Its allowlist may include only stale old application/config/
custom-app/theme copies and an approved legacy rotated log. It must exclude
`data`, `files`, `files_versions` and `files_trashbin`. Apply only after approval
of the manifest hash.

The original final restart of `daily-local-backup` and `weekly-remote-backup` is
obsolete: Offen is retired; do not reinstall or start it. Recovery must separately
review restoration of actual Restic timer state outside trigger windows, verifying
no unintended immediate run.
