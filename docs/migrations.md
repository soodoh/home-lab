# Outstanding migrations and adoption

These are retained hazards and next adoption boundaries, not permission to run
mutations. The [September 14 read-only observation](operations.md#observed-baseline--2026-09-14)
updates selected installed-state assumptions; it does not close migration or
rollback-retirement checks. The check-qualified
[native Compose canary](operations.md#native-compose-qualification) refuses
database, service-set, mount, credential and Restic-policy changes; it neither
completes nor retires any migration below.

## Authentik PostgreSQL

**PostgreSQL 18 is already in use.** On September 14 the running Authentik database
container mounted `/srv/home-lab-state/authentik-data/postgresql` at
`/var/lib/postgresql`, containing `18/docker/PG_VERSION=18`. The retained
`postgresql-16/PG_VERSION=16` was also present. Do not rerun the forward migration.

PostgreSQL 16 used `/var/lib/postgresql/data`; 18 uses
`PGDATA=/var/lib/postgresql/18/docker` and the parent mount `/var/lib/postgresql`.
18 cannot open a 16 cluster directly. This was a logical dump/restore, not an
image-only update. Original forward commands are in Git (`1165675`, former
`docs/authentik-postgres-18-migration.md`). They stopped Authentik/Redis writers,
validated the dump table of contents, stopped PostgreSQL and preserved the old
cluster, then restored into 18 with exit-on-error, rebuilt optimizer statistics
and compared extensions, public-table and `django_migrations` counts against the
stopped source. This provenance does not prove acceptance.

### Acceptance and custody

Preserve all three sensitive root-only rollback inputs:

1. `authentik-postgres-16.dump` and validated `.toc` under
   `/var/lib/authentik-postgres-migration/<candidate-hash>`;
2. the original `postgresql-16` cluster under `authentik-data`;
3. the cold copy in `authentik-postgres-16-backup-<first-12-candidate-hash>`.

Keep before/after extension/count records, the exact digest-pinned
`postgres:16-alpine@sha256:*` image, both generations' artifacts/environments/image
locks and the failed 18 cluster. The historical 18 image was
`postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`.
The old Docker volume had the `authentik-data` Compose label; its identity came
from the stopped 16 container, not today's bind mount. The original cold-copy
operation used no network and a read-only source and refused existing backup
volume or `postgresql-16` destinations. Do not recreate or overwrite them.

Before acceptance or rollback retirement, verify:

- PostgreSQL health, `PG_VERSION=18` and the exact PGDATA above;
- Redis/server health and a running worker;
- retained extension/schema-count comparisons;
- Authentik admin login and dashboard/directory objects;
- authentication through at least one protected application;
- PostgreSQL/server/worker logs free of restore/migration errors, without exposing sensitive output;
- Home Assistant health;
- active artifact idempotence, with no further PostgreSQL recreation proposed;
- a new encrypted scheduled backup containing 18, with independently verified
  integrity and [restore coverage](../recovery/README.md), not old archive-replica checks.

### Rollback limits

There is no qualified post-promotion invocation or general deploy command here.
No generic Compose update or automatic database rollback is safe. Review actual
retained inputs before separately approving artifact publication or recovery; the
removed controller and retained roles are not implicit replacements.

An invocation must recover the old volume/image identity from retained evidence,
verify the exact 64-hex candidate artifact/content and existing paths, root:root
0600 environments and root-only migration directory. Use root, fail-fast shell
handling (`set -euo pipefail`) and `umask 077`. The original current/candidate
environments had to be byte-equal: do not combine database migration with secret
or configuration changes. Bind the explicit
[project/artifact/environment paths](operations.md#stable-application-and-host-identities).
After promotion, “current” no longer means 16 and “candidate” no longer reliably
means the retained 18 generation.

Rollback loses writes accepted by 18 after cutover. Stop all Authentik/Redis/database
writers and keep users out throughout the reviewed window. Preserve the failed 18
cluster separately (the old pre-promotion procedure used `postgresql-18-failed`
and refused an existing destination), restore the exact 16 artifact and old
cluster, and verify database health before admitting writers. Never start 16
against the 18 directory; images cannot undo database migration.

Both clusters consume backup space until explicit rollback retirement. Only after
all acceptance and new-backup proofs may an approved exact old subdirectory,
backup volume and root-only migration directory be removed. Never use unrestricted
volume prune.

References: [Authentik upgrade guidance](https://docs.goauthentik.io/troubleshooting/postgres/upgrade_docker/),
[image PGDATA change](https://github.com/docker-library/docs/blob/master/postgres/README.md#pgdata),
[PostgreSQL 18 upgrade](https://www.postgresql.org/docs/18/upgrading.html).

## Nextcloud

On September 14 both Nextcloud and cron were running with the five intended
mounts. **Do not rerun forward migration or initial activation.** Application
integrity, retained copies and rollback acceptance remain outstanding. Keep the
paired migration/configuration/rollback playbooks and roles as recovery inputs,
not a supported standalone native deployment path.

### Review boundary

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

### Historical staging and five-mount migration

The original forward procedure is in Git (`1165675`, former
`docs/nextcloud-34-configuration.md`). Its paired `stage-compose.yml` and
`deploy-nextcloud-migration.yml` plays remain source/recovery dependencies, not a
supported deployment path. Generic staging now refuses execution unless
`compose_stage_retained_operation` names an allowlisted recovery case; the retained
`compose_deploy` role likewise refuses every non-operation-specific plan.
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

### Web acceptance

These remain acceptance checks, not instructions to start already-running cron:

- `occ status --output=json` reports installed, not in maintenance mode, and no database upgrade;
- `/var/www/html/data` resolves to `/mnt/storage/media/nextcloud/data`;
- config, current themes, and any custom apps are visible;
- login, representative file listing/read, WebDAV, and a representative upload succeed;
- HTTPS URL generation remains correct;
- only Caddy at `172.23.0.250` is trusted and real client addresses are correct;
- the external response contains exactly `Strict-Transport-Security: max-age=15552000`;
- Compose inspection and logs contain file references, not password values.

### Cron and native maintenance acceptance

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

### Database maintenance

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

### Rollback

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

### Recovery and cleanup gate

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

## Calibre and Caro

The complete Calibre library (`metadata.db`, books and covers) belongs at
`/srv/home-lab-state/calibre-data/books` and is included in Restic. The NFS copy is
retained as a rollback source. Caro application/database state belongs at
`/srv/home-lab-state/caro-tachidesk-data`; only downloads use
`${MEDIA_PATH}/caro-tachidesk`. The preserved-data forward migration is historical;
do not rerun it simply because its recovery-dependent role remains.

The 2026-08-27 Calibre local correction recorded artifact
`2468c26a15c921877da3d1ca6887cd9c2e81be1f467873d9f9edc1386782c6db`,
2,195 files, 8,004,800,651 bytes and 1,063 ebooks plus `metadata.db`, with snapshots:

- games `91e4e2378de3ae97efa075468ac0334fec80b324c7c8df664b05089f1254390f`;
- NFS `32f2e3c378df0238c3e99da59701dc7e33fe73a13f88eda01b02f0c1e2f4e9ed`;
- Proton `41f4fac702126014bb6989b09dd158a2f9a3c56e4a99440df799bb55e4a28d55`.

The retained `compose_deploy` role contains the interrupted Calibre lane, bound to
`rollback-calibre-to-local:<artifact-hash>`. It requires exact three-consumer and
two-policy-file scope, endpoint/device/UUID identity checks, stops both Restic
timers, holds the backup mutex, reconciles NFS into local with checksum/delete
semantics, checks zero difference and SQLite integrity, then activates policy
before container convergence. A resume must adopt only the exact retained owner
and repeat all guards. The general deploy entrypoint was already non-operational
and is removed; the retained role is **not** a newly supported standalone recovery
command. A separately reviewed recovery invocation is needed for an actual retained
operation; preserve its inputs meanwhile.

## Retired LiteLLM deployment lane

The callback/config remain; the dedicated source-only approval/transport lane is
removed rather than carried into native delivery. Its installed success was not
established. Preserve any `/var/lib/docker-compose/.litellm-<document-sha256>`
attempts and `/srv/docker-compose/.litellm-<plan-sha256>/` recovery sets, current
and previous artifacts/environments, image locks/override and old marker. The
previous generation was deliberately untouched by that lane. Failure after
publication can leave new files with old/failed processes; a lost result does not
prove the host failed. There was no automatic rollback/resume lane. Inspect actual
host/process/owner state and get a recovery decision; never retry or clear an owner
based only on delivery failure. Native replacement must explicitly recreate
LiteLLM for changed bind-file contents and distinguish liveness from provider/model
usability.

The September 18 native canary attempt found commit `a43c4b17`'s model update still
undeployed: active config SHA-256 remained
`6a93d7caee70b924d80c628250441a78be5ebe9844735982ab9c532e4f4595d2`,
LiteLLM was running with zero restarts, and three retained transport workspaces plus
three capture-attempt markers remained under `/var/lib/docker-compose`. No matching
`/srv/docker-compose/.litellm-*` recovery directory existed. The canary refused
before publication or container mutation. Current source restores the active config
bytes and defers the model update rather than admitting it through the canary. The
historical commit remains in Git; reintroduction requires an explicit native
LiteLLM recreation and separate liveness/provider-model acceptance decision.

## Provider and host adoption gaps

- **Proxmox VM100:** `scsi1` games, `scsi2` state, `scsi3` boot and `ide2` cloud-init
  identities stay fixed. The production HCL does not fully model the boot disk;
  ignored disk-list positions encode adoption history. Do not reorder/remove the
  tombstone or change addresses/imports. Existing image/snippet prerequisites and
  the stale candidate move require separate state-aware adoption, not cosmetic cleanup.
- **Tailscale:** the Tofu root is a `terraform_data` placeholder, not a policy
  writer. The universal reconciler that issued policy API writes is removed.
  Source policy now removes the retired `ansible-plan` SSH user and tests require
  that denial, but running the current root will not converge the live tailnet.
  Native provider adoption/import, current-policy comparison and concurrency
  semantics remain follow-on work; do not claim that source correction as deployed.
- **Omada:** the LAN/reservation root reads a private export in the
  [required input shape](../infrastructure/tofu/omada/EXPORT_SCHEMA.md). Verify imports,
  desired ownership, TLS/CA and certificate hostname (`Omada`) before replacing
  that input. Setting management false after adoption may propose destruction.
- **Authentik API:** source expects 23 applications/18 proxies/5 OAuth providers/
  28 bindings; historical adoption reported 25/19/6/30 and 85 imported objects.
  Verify actual desired and imported identities before plan. Factory objects and
  users/groups/runtime identities remain database-owned. Proxy factory mapping
  membership is deliberately omitted from resource configuration. Client secrets
  remain encrypted separately and also occur in protected resource state; tokens
  are ephemeral inputs. Historical token expiry was `2026-11-25T19:16:43Z`—verify
  current credentials privately rather than assuming they still work.
- **Access/host convergence:** native SSH/become observation now works over the
  existing Tailscale route; no account/key changes were needed. Retain other routes
  and verify independent console access before risky work. The approved native
  [manual-update policy](operations.md#manual-update-policy) supersedes legacy
  automatic-install settings. Other host domains and legacy bootstrap policy
  still need adoption.
- **Recovery/VM9900:** VM9900 was observed present and stopped on September 14;
  preserve failed qualification and state ownership. Separate local backends do
  not isolate two roots using the same VMID on production PVE. Stopped state alone
  does not authorize reuse or destruction.
  Fresh boot and end-to-end production activation remain unqualified.
