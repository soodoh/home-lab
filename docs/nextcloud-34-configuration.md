# Nextcloud 34 configuration and maintenance runbook

This runbook activates the contract in `infrastructure/contract/home-lab.yml`. It does not add health monitoring, SMTP, 2FA enforcement, AppAPI deployment, or direct upload-directory cleanup.

## Review boundary

Production activation requires:

- a clean reviewed commit and clean working tree;
- the independently restored pre-change config/theme recovery point;
- the current reduced database backup and canonical SOPS/recovery material;
- no active deployment, backup, restore, database maintenance, or storage migration;
- at least 2 GiB free under `/srv/home-lab-state`;
- old `/mnt/storage/media/nextcloud` application copies retained for seven days after full proof.

The external `/mnt/storage/media/nextcloud/data` tree remains under its existing retention decision. It is mounted in place and is never copied into, restored over, or deleted with managed application state.

## Stage the reviewed artifact

From the clean reviewed commit:

```sh
artifact_hash=$(python3 scripts/compose-artifact.py hash)
cd ansible
ANSIBLE_CONFIG=ansible.cfg ansible-playbook -i inventory/production.yml \
  playbooks/stage-compose.yml \
  -e "compose_artifact_hash=$artifact_hash" \
  -e "compose_artifact_controller_dir=$PWD/.." \
  -e compose_stage_confirmed=true
```

Staging decrypts the canonical SOPS dotenv only in a root-only temporary directory. It atomically materializes these mode-`0600`, root-owned files without logging values:

- `/etc/docker-compose/credentials/nextcloud-mysql-password`;
- `/etc/docker-compose/credentials/nextcloud-mariadb-root-password`.

Review the staged artifact, secret-free model inventory, image availability, action plan, backup schedule, and current service inventory before activation.

## Check and activate the five-mount migration

First run the migration playbook in check mode. Apply only when the plan contains:

- one new service: `nextcloud-cron`;
- bounded recreation of Nextcloud web/database and the backup schedulers affected by mount changes, plus an explicit Caddy restart for the changed bind-mounted configuration;
- no image-version change;
- no removal or replacement of external user data.

```sh
ANSIBLE_CONFIG=ansible.cfg ansible-playbook -i inventory/production.yml \
  playbooks/deploy-nextcloud-migration.yml --check \
  -e "compose_artifact_hash=$artifact_hash" \
  -e nextcloud_path_migration_confirmation=activate-reviewed-nextcloud-five-mount-paths \
  -e compose_deploy_nextcloud_migration_confirmation=deploy-reviewed-nextcloud-five-mount-migration
```

Apply with both confirmations plus `compose_deploy_confirmed=true`. The playbook:

1. acquires the global production lock;
2. makes an initial metadata-preserving copy while web remains available;
3. stops both backup schedulers;
4. enables native maintenance mode and stops the web writer;
5. performs a final checksum-proven synchronization;
6. atomically activates the four `/srv/home-lab-state` paths;
7. proves the external-data device and inode are unchanged;
8. deploys `_FILE` credentials, MariaDB upgrade settings, Caddy HSTS, and the reviewed mounts, then explicitly restarts Caddy to load its changed bind-mounted configuration;
9. starts MariaDB before web and recreates cron and backup schedulers in a stopped state;
10. applies the declared native Nextcloud settings and disables maintenance mode;
11. verifies `occ status`, the external HSTS value, and the intentionally stopped services before releasing the lock.

The old NFS application/config copies remain untouched.

## Web proof before cron

Require all of the following before starting cron:

- `occ status --output=json` reports installed, not in maintenance mode, and no database upgrade;
- `/var/www/html/data` resolves to `/mnt/storage/media/nextcloud/data`;
- config, current themes, and any custom apps are visible;
- login, representative file listing/read, WebDAV, and a representative upload succeed;
- HTTPS URL generation remains correct;
- only Caddy at `172.23.0.250` is trusted and real client addresses are correct;
- the external response contains exactly `Strict-Transport-Security: max-age=15552000`;
- Compose inspection and logs contain file references, not password values.

## Start cron and observe native maintenance

Start only the reviewed cron container:

```sh
docker compose start nextcloud-cron
docker inspect nextcloud-cron --format '{{.Path}} {{.State.Status}}'
docker exec nextcloud-cron crontab -l
```

Require `/cron.sh` as PID 1 and the installed five-minute `cron.php` schedule. Observe at least two cadences. Do not manually execute arbitrary queued job IDs.

Record only aggregate, secret-free evidence:

- last-cron timestamp and pending-job count;
- class counts and last-run values for native upload cleanup and `OC\Log\Rotate` when registered;
- upload-staging bytes and oldest timestamp;
- current and rotated log sizes.

The pre-change queue contained metadata jobs but no registered `UploadCleanup` class. Let normal cron register or run the current native cleanup path. Never use `rm` in user upload directories. Investigate permissions or exact job errors if the stale 2024 chunks are not removed natively.

Delete the oversized rotated log only after native rotation is proven and an exact private cleanup manifest is separately approved.

## Database maintenance

Run every operation separately during the UTC maintenance window beginning at hour `6`, with fresh setup checks and the proven database recovery point available:

```sh
docker compose exec --user www-data nextcloud php occ setupchecks --output=json
docker compose exec --user www-data nextcloud php occ db:add-missing-indices
docker compose exec --user www-data nextcloud php occ maintenance:repair --include-expensive
docker compose exec --user www-data nextcloud php occ setupchecks --output=json
```

For non-DYNAMIC tables, use only the documentation URL and exact affected table names emitted by the installed Nextcloud 34 setup check. Do not copy SQL from an older release. Re-run setup checks immediately afterward and restore the database on any database error.

Classify recent log errors without recording private paths, filenames, tokens, or user content. AppAPI, single-server ID, SMTP, 2FA enforcement, and monitoring findings remain accepted scope exclusions.

## Rollback

While old paths and the previous artifact remain available, derive and review the normal rollback plan, then use `playbooks/rollback-nextcloud-migration.yml` with:

```text
compose_rollback_nextcloud_migration_confirmation=rollback-reviewed-nextcloud-five-mount-migration
```

The bounded rollback stops cron/web/backup writers, removes only the new cron container, converges the previous 41-service artifact against the untouched old parent mount, and retains the new paths for diagnosis. It never modifies external user data.

## Recovery and cleanup gate

Before old-path deletion:

- run `./scripts/test-restic-recovery-bundle` and `./scripts/test-restic-restore-branch`;
- rehearse a fresh restore of config, custom apps/themes, MariaDB, SOPS-backed secret files, and pinned application code while retaining external data;
- prove the previous-artifact rollback;
- confirm representative user-file counts and hashes are unchanged;
- retain the old copies for seven days after these proofs.

Build a private exact-path cleanup manifest with device, inode, size, mtime, and path identities. Its allowlist may include only stale old application/config/custom-app/theme copies and an approved legacy rotated log. It must exclude `data`, `files`, `files_versions`, and `files_trashbin`. Apply only after approval of the manifest hash.

Finally, outside either backup trigger window, start `daily-local-backup` and `weekly-remote-backup`. Verify they schedule normally and do not immediately run unless explicitly intended.
